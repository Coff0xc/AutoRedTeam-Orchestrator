"""
攻面发现器 - 发现目标的攻击面并抽取注入点

按照 Web安全能力分析与优化方案.md 设计:
- 复用 modules/js_analyzer.py 做 JS 端点发现
- HTML 表单/链接解析
- 输出标准化注入点列表
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from .injection_point import (
    InjectionPoint,
    InjectionPointCollection,
    InjectionPointSource,
    InjectionPointType,
)

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    """攻面发现结果"""

    target: str
    success: bool
    injection_points: InjectionPointCollection
    pages_crawled: int = 0
    forms_found: int = 0
    links_found: int = 0
    js_files_found: int = 0
    api_endpoints_found: int = 0
    duration_seconds: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（用于 MCP 输出）"""
        return {
            "success": self.success,
            "target": self.target,
            "discovery": {
                "pages_crawled": self.pages_crawled,
                "forms_found": self.forms_found,
                "links_found": self.links_found,
                "js_files_found": self.js_files_found,
                "api_endpoints_found": self.api_endpoints_found,
                "injection_points_total": len(self.injection_points),
            },
            "injection_points": [p.to_dict() for p in self.injection_points],
            "stats": self.injection_points.get_stats(),
            "duration_seconds": round(self.duration_seconds, 2),
            "errors": self.errors,
        }


class HTMLFormParser(HTMLParser):
    """HTML 表单和链接解析器"""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: List[Dict[str, Any]] = []
        self.links: Set[str] = set()
        self.scripts: List[str] = []

        # 当前表单上下文
        self._current_form: Optional[Dict[str, Any]] = None
        self._in_script = False
        self._script_content = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attrs_dict = {k: v or "" for k, v in attrs}

        if tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "GET").upper(),
                "enctype": attrs_dict.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": [],
            }

        elif tag == "input" and self._current_form is not None:
            input_info = {
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
                "required": "required" in attrs_dict,
                "placeholder": attrs_dict.get("placeholder", ""),
            }
            if input_info["name"]:  # 只保留有名称的 input
                self._current_form["inputs"].append(input_info)

        elif tag == "textarea" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attrs_dict.get("name", ""),
                    "type": "textarea",
                    "value": "",
                    "required": "required" in attrs_dict,
                }
            )

        elif tag == "select" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attrs_dict.get("name", ""),
                    "type": "select",
                    "value": "",
                    "required": "required" in attrs_dict,
                }
            )

        elif tag == "a":
            href = attrs_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)

        elif tag == "script":
            self._in_script = True
            src = attrs_dict.get("src", "")
            if src:
                self.scripts.append(urljoin(self.base_url, src))

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            if self._current_form["inputs"]:  # 只保留有输入的表单
                self.forms.append(self._current_form)
            self._current_form = None

        elif tag == "script":
            self._in_script = False
            self._script_content = ""

    def handle_data(self, data: str):
        if self._in_script:
            self._script_content += data


class AttackSurfaceDiscovery:
    """
    攻面发现器

    发现目标网站的攻击面，包括：
    - HTML 表单和输入字段
    - URL 链接和查询参数
    - JavaScript 中的 API 端点
    - 隐藏参数探测
    """

    # 常见的敏感参数名（用于识别可能的注入点）
    SENSITIVE_PARAMS = {
        "id",
        "user",
        "username",
        "password",
        "pass",
        "pwd",
        "email",
        "token",
        "key",
        "secret",
        "api_key",
        "apikey",
        "auth",
        "session",
        "cookie",
        "file",
        "path",
        "url",
        "redirect",
        "next",
        "return",
        "goto",
        "dest",
        "callback",
        "cb",
        "ref",
        "referer",
        "page",
        "p",
        "q",
        "search",
        "query",
        "sort",
        "order",
        "filter",
        "type",
        "action",
        "cmd",
        "command",
        "exec",
        "debug",
        "test",
        "admin",
        "role",
        "access",
        "level",
        "privilege",
    }

    # API 端点模式（用于 JS 分析）
    API_PATTERNS = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.ajax\s*\(\s*\{\s*url\s*:\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*\.open\s*\(["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
    ]

    def __init__(
        self,
        timeout: int = 10,
        max_pages: int = 50,
        max_depth: int = 2,
        concurrency: int = 5,
        verify_ssl: bool = False,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        self.timeout = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent

        self._visited: Set[str] = set()
        self._session = None

    async def _get_session(self):
        """获取或创建 HTTP 会话"""
        if self._session is None:
            try:
                import aiohttp

                connector = aiohttp.TCPConnector(
                    limit=self.concurrency,
                    ssl=self.verify_ssl,
                )
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={"User-Agent": self.user_agent},
                )
            except ImportError:
                logger.warning("aiohttp 未安装，将使用同步 HTTP 请求")
                self._session = None
        return self._session

    async def _close_session(self):
        """关闭会话"""
        if self._session:
            await self._session.close()
            self._session = None

    async def _fetch(self, url: str, allow_js: bool = False) -> Tuple[Optional[str], int]:
        """获取页面内容

        Args:
            url: 要获取的 URL
            allow_js: 是否允许获取 JS 文件（用于 JS 分析）
        """
        session = await self._get_session()

        # 支持的 content-type 列表
        allowed_types = ["text/html"]
        if allow_js or url.endswith(".js"):
            allowed_types.extend(
                [
                    "text/javascript",
                    "application/javascript",
                    "application/x-javascript",
                    "text/plain",  # 某些服务器用 text/plain 返回 JS
                ]
            )

        if session:
            try:
                async with session.get(url) as resp:
                    content_type = resp.headers.get("content-type", "").lower()
                    if resp.status == 200 and any(t in content_type for t in allowed_types):
                        return await resp.text(), resp.status
                    return None, resp.status
            except Exception as e:
                logger.debug(f"获取 {url} 失败: {e}")
                return None, 0
        else:
            # 降级使用 urllib
            import ssl
            import urllib.request

            try:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    return resp.read().decode("utf-8", errors="ignore"), resp.status
            except Exception as e:
                logger.debug(f"获取 {url} 失败: {e}")
                return None, 0

    def _parse_url_params(self, url: str) -> List[InjectionPoint]:
        """解析 URL 查询参数"""
        points = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param, values in params.items():
                point = InjectionPoint(
                    url=base_url,
                    param=param,
                    point_type=InjectionPointType.QUERY,
                    method="GET",
                    source=InjectionPointSource.HTML_LINK,
                    source_url=url,
                    original_value=values[0] if values else "",
                    value_type=self._infer_value_type(values[0] if values else ""),
                )
                points.append(point)

        return points

    def _parse_form(self, form: Dict[str, Any], source_url: str) -> List[InjectionPoint]:
        """解析表单为注入点"""
        points = []
        action_url = form.get("action", source_url)
        method = form.get("method", "POST")
        enctype = form.get("enctype", "")

        for inp in form.get("inputs", []):
            name = inp.get("name", "")
            if not name:
                continue

            # 判断注入点类型
            if "json" in enctype.lower():
                point_type = InjectionPointType.JSON
            elif "multipart" in enctype.lower():
                point_type = InjectionPointType.MULTIPART
            else:
                point_type = InjectionPointType.FORM

            point = InjectionPoint(
                url=action_url,
                param=name,
                point_type=point_type,
                method=method,
                source=InjectionPointSource.HTML_FORM,
                source_url=source_url,
                original_value=inp.get("value", ""),
                value_type=self._infer_value_type(inp.get("value", "")),
                required=inp.get("required", False),
                form_action=action_url,
                form_method=method,
                form_enctype=enctype,
                input_type=inp.get("type", "text"),
            )
            points.append(point)

        return points

    def _extract_api_endpoints(self, content: str, base_url: str) -> List[str]:
        """从内容中提取 API 端点"""
        endpoints = set()

        for pattern in self.API_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                endpoint = match.group(1)
                # 规范化 URL
                if endpoint.startswith("/"):
                    endpoint = urljoin(base_url, endpoint)
                elif not endpoint.startswith("http"):
                    endpoint = urljoin(base_url, endpoint)

                # 只保留同域的端点
                if urlparse(base_url).netloc in endpoint:
                    endpoints.add(endpoint)

        return list(endpoints)

    def _infer_value_type(self, value: str) -> str:
        """推断值类型"""
        if not value:
            return "string"

        # 尝试解析为数字
        try:
            int(value)
            return "integer"
        except ValueError:
            pass

        try:
            float(value)
            return "number"
        except ValueError:
            pass

        # 布尔值
        if value.lower() in ("true", "false", "1", "0", "yes", "no"):
            return "boolean"

        # JSON 数组或对象
        if value.startswith("[") or value.startswith("{"):
            return "json"

        # UUID
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.I):
            return "uuid"

        # Email
        if "@" in value and "." in value:
            return "email"

        return "string"

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """检查是否同域"""
        return urlparse(url).netloc == urlparse(base_url).netloc

    async def discover(self, target: str, include_js: bool = True) -> DiscoveryResult:
        """
        发现目标攻击面

        Args:
            target: 目标 URL
            include_js: 是否分析 JS 文件

        Returns:
            DiscoveryResult: 发现结果
        """
        start_time = datetime.now()
        result = DiscoveryResult(
            target=target,
            success=False,
            injection_points=InjectionPointCollection(target=target),
        )

        self._visited.clear()
        queue = [(target, 0)]  # (url, depth)
        all_forms = []
        all_links = set()
        all_scripts = []
        all_api_endpoints = []

        try:
            while queue and len(self._visited) < self.max_pages:
                url, depth = queue.pop(0)

                if url in self._visited:
                    continue

                if depth > self.max_depth:
                    continue

                if not self._is_same_domain(url, target):
                    continue

                self._visited.add(url)

                # 获取页面
                html, status = await self._fetch(url)
                if not html:
                    continue

                result.pages_crawled += 1

                # 解析 HTML
                try:
                    parser = HTMLFormParser(url)
                    parser.feed(html)

                    all_forms.extend(parser.forms)
                    all_links.update(parser.links)
                    all_scripts.extend(parser.scripts)

                    # 提取 API 端点
                    api_endpoints = self._extract_api_endpoints(html, url)
                    all_api_endpoints.extend(api_endpoints)

                    # 添加新链接到队列
                    for link in parser.links:
                        if link not in self._visited:
                            queue.append((link, depth + 1))

                except Exception as e:
                    logger.debug(f"解析 {url} 失败: {e}")
                    result.errors.append(f"Parse error: {url}")

            # 处理表单
            for form in all_forms:
                points = self._parse_form(form, form.get("action", target))
                result.injection_points.add_many(points)
            result.forms_found = len(all_forms)

            # 处理链接参数
            for link in all_links:
                points = self._parse_url_params(link)
                result.injection_points.add_many(points)
            result.links_found = len(all_links)

            # 处理 API 端点
            for endpoint in all_api_endpoints:
                points = self._parse_url_params(endpoint)
                for p in points:
                    p.source = InjectionPointSource.JS_ANALYSIS
                result.injection_points.add_many(points)
            result.api_endpoints_found = len(set(all_api_endpoints))

            # 分析 JS 文件
            if include_js:
                result.js_files_found = len(set(all_scripts))
                for script_url in set(all_scripts)[:20]:  # 限制 JS 文件数量
                    try:
                        js_content, _ = await self._fetch(script_url, allow_js=True)
                        if js_content:
                            api_endpoints = self._extract_api_endpoints(js_content, target)
                            for endpoint in api_endpoints:
                                points = self._parse_url_params(endpoint)
                                for p in points:
                                    p.source = InjectionPointSource.JS_ANALYSIS
                                result.injection_points.add_many(points)
                    except Exception as e:
                        logger.debug(f"分析 JS {script_url} 失败: {e}")

            result.success = True

        except Exception as e:
            logger.error(f"攻面发现失败: {e}")
            result.errors.append(str(e))

        finally:
            await self._close_session()
            result.duration_seconds = (datetime.now() - start_time).total_seconds()

        return result


# 便捷函数
async def quick_discover(target: str, **kwargs) -> Dict[str, Any]:
    """
    快速攻面发现

    Args:
        target: 目标 URL
        **kwargs: 传递给 AttackSurfaceDiscovery 的参数

    Returns:
        发现结果字典
    """
    discovery = AttackSurfaceDiscovery(**kwargs)
    result = await discovery.discover(target)
    return result.to_dict()


def sync_discover(target: str, **kwargs) -> Dict[str, Any]:
    """同步版本的攻面发现"""
    return asyncio.run(quick_discover(target, **kwargs))
