"""纯 Python Nuclei 模板引擎 — 无需 nuclei 二进制

解析 Nuclei YAML 模板并执行 HTTP 请求匹配，
大幅扩展检测覆盖面（可接入 185,000+ 社区模板）。

使用示例:
    from core.detectors.nuclei_engine import NucleiEngine

    engine = NucleiEngine("data/nuclei-templates")
    count = engine.load_templates(tags=["cve"], severity=["high", "critical"])
    results = await engine.scan("http://target.com", concurrency=10)

模板格式参考: https://docs.projectdiscovery.io/templates/introduction
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# 默认模板搜索路径
_DEFAULT_TEMPLATE_DIRS = [
    Path("data/nuclei-templates"),
    Path.home() / ".nuclei-templates",
    Path("nuclei-templates"),
]


# ─────────────────────── 数据模型 ───────────────────────


@dataclass
class NucleiMatcher:
    """Nuclei 匹配器

    支持 status / word / regex / size 四种匹配类型。
    """

    type: str  # status | word | regex | size
    words: Optional[List[str]] = None
    regex: Optional[List[str]] = None
    status: Optional[List[int]] = None
    size: Optional[List[int]] = None
    negative: bool = False
    condition: str = "or"  # and | or
    part: str = "body"  # body | header | all

    @classmethod
    def from_dict(cls, data: dict) -> "NucleiMatcher":
        """从字典创建 Matcher"""
        return cls(
            type=data.get("type", "word"),
            words=data.get("words"),
            regex=data.get("regex"),
            status=data.get("status"),
            size=data.get("size"),
            negative=data.get("negative", False),
            condition=data.get("condition", "or"),
            part=data.get("part", "body"),
        )


@dataclass
class NucleiExtractor:
    """Nuclei 提取器"""

    type: str  # regex | kval | json | xpath
    name: str = ""
    regex: Optional[List[str]] = None
    group: int = 0
    part: str = "body"

    @classmethod
    def from_dict(cls, data: dict) -> "NucleiExtractor":
        return cls(
            type=data.get("type", "regex"),
            name=data.get("name", ""),
            regex=data.get("regex"),
            group=data.get("group", 0),
            part=data.get("part", "body"),
        )


@dataclass
class NucleiRequest:
    """单个 HTTP 请求定义"""

    method: str = "GET"
    path: List[str] = field(default_factory=lambda: ["/"])
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    matchers: List[NucleiMatcher] = field(default_factory=list)
    matchers_condition: str = "or"  # and | or
    extractors: List[NucleiExtractor] = field(default_factory=list)
    redirects: bool = False
    max_redirects: int = 3

    @classmethod
    def from_dict(cls, data: dict) -> "NucleiRequest":
        """从字典创建 Request"""
        matchers = [NucleiMatcher.from_dict(m) for m in data.get("matchers", [])]
        extractors = [NucleiExtractor.from_dict(e) for e in data.get("extractors", [])]

        # 兼容 nuclei 的 path 字段（可能是字符串或列表）
        raw_path = data.get("path", ["/"])
        if isinstance(raw_path, str):
            raw_path = [raw_path]

        return cls(
            method=data.get("method", "GET").upper(),
            path=raw_path,
            headers=data.get("headers", {}),
            body=data.get("body"),
            matchers=matchers,
            matchers_condition=data.get("matchers-condition", "or"),
            extractors=extractors,
            redirects=data.get("redirects", False),
            max_redirects=data.get("max-redirects", 3),
        )


@dataclass
class NucleiTemplate:
    """解析后的 Nuclei 模板"""

    id: str
    name: str
    severity: str  # info / low / medium / high / critical
    tags: List[str]
    author: str = ""
    description: str = ""
    reference: List[str] = field(default_factory=list)
    requests: List[NucleiRequest] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> "NucleiTemplate":
        """从 YAML 文件加载模板

        Args:
            path: YAML 文件路径

        Returns:
            NucleiTemplate 实例

        Raises:
            ValueError: YAML 格式不合法或缺少必要字段
        """
        try:
            import yaml
        except ImportError as e:
            raise ImportError("需要 pyyaml: pip install pyyaml") from e

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError("模板文件格式不正确: %s" % path)

        return cls.from_dict(data, source=str(path))

    @classmethod
    def from_dict(cls, data: dict, source: str = "<dict>") -> "NucleiTemplate":
        """从字典创建模板

        Args:
            data: 模板字典
            source: 来源标识（用于错误提示）

        Returns:
            NucleiTemplate 实例
        """
        template_id = data.get("id", "")
        if not template_id:
            raise ValueError("模板缺少 'id' 字段: %s" % source)

        info = data.get("info", {})
        if not info:
            raise ValueError("模板缺少 'info' 字段: %s" % source)

        # 解析 tags
        raw_tags = info.get("tags", "")
        if isinstance(raw_tags, str):
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, list):
            tags = raw_tags
        else:
            tags = []

        # 解析 reference
        raw_ref = info.get("reference", [])
        if isinstance(raw_ref, str):
            reference = [raw_ref]
        elif isinstance(raw_ref, list):
            reference = raw_ref
        else:
            reference = []

        # 解析 HTTP 请求列表
        # Nuclei 模板中 http/requests 字段可以是列表
        raw_requests = data.get("http", data.get("requests", []))
        if isinstance(raw_requests, dict):
            raw_requests = [raw_requests]

        requests = []
        for req_data in raw_requests:
            if isinstance(req_data, dict):
                requests.append(NucleiRequest.from_dict(req_data))

        return cls(
            id=template_id,
            name=info.get("name", template_id),
            severity=info.get("severity", "info").lower(),
            tags=tags,
            author=info.get("author", ""),
            description=info.get("description", ""),
            reference=reference,
            requests=requests,
        )


# ─────────────────────── 变量替换 ───────────────────────

# 支持的 Nuclei 核心变量
_VAR_PATTERN = re.compile(r"\{\{(\w+)\}\}")


def _build_variables(target: str) -> Dict[str, str]:
    """根据目标 URL 构建变量替换表

    Args:
        target: 目标 URL

    Returns:
        变量名 -> 值 的映射
    """
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme or "http"
    port = parsed.port
    root_url = f"{scheme}://{hostname}"
    if port and port not in (80, 443):
        root_url = f"{scheme}://{hostname}:{port}"

    # 确保 BaseURL 不以 / 结尾
    base_url = target.rstrip("/")

    return {
        "BaseURL": base_url,
        "RootURL": root_url,
        "Hostname": hostname,
        "Host": hostname,
        "Port": str(port) if port else ("443" if scheme == "https" else "80"),
        "Path": parsed.path or "/",
        "Scheme": scheme,
    }


def _substitute(text: str, variables: Dict[str, str]) -> str:
    """替换模板字符串中的 {{变量}}

    Args:
        text: 包含 {{变量}} 占位符的字符串
        variables: 变量映射表

    Returns:
        替换后的字符串
    """
    if not text:
        return text

    def _replacer(match: re.Match) -> str:
        var_name = match.group(1)
        return variables.get(var_name, match.group(0))

    return _VAR_PATTERN.sub(_replacer, text)


# ─────────────────────── Matcher 执行 ───────────────────────


def check_matcher(
    matcher: NucleiMatcher,
    status_code: int,
    headers: Dict[str, str],
    body: str,
) -> bool:
    """检查单个 matcher 是否匹配

    Args:
        matcher: 匹配器实例
        status_code: HTTP 状态码
        headers: 响应头
        body: 响应体

    Returns:
        是否匹配（已考虑 negative 取反）
    """
    # 根据 part 选择目标文本
    if matcher.part == "header":
        target_text = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    elif matcher.part == "all":
        header_text = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        target_text = header_text + "\r\n\r\n" + body
    else:
        target_text = body

    matched = False

    if matcher.type == "status" and matcher.status:
        # 状态码匹配: 只要命中其中一个即可
        matched = status_code in matcher.status

    elif matcher.type == "word" and matcher.words:
        results = [w in target_text for w in matcher.words]
        if matcher.condition == "and":
            matched = all(results)
        else:
            matched = any(results)

    elif matcher.type == "regex" and matcher.regex:
        results = []
        for pattern in matcher.regex:
            try:
                results.append(bool(re.search(pattern, target_text)))
            except re.error:
                logger.debug("无效正则: %s", pattern)
                results.append(False)
        if matcher.condition == "and":
            matched = all(results)
        else:
            matched = any(results)

    elif matcher.type == "size" and matcher.size:
        body_len = len(body)
        matched = body_len in matcher.size

    # negative 取反
    if matcher.negative:
        matched = not matched

    return matched


def check_matchers(
    matchers: List[NucleiMatcher],
    condition: str,
    status_code: int,
    headers: Dict[str, str],
    body: str,
) -> bool:
    """检查所有 matchers

    Args:
        matchers: 匹配器列表
        condition: matchers 之间的关系 (and / or)
        status_code: HTTP 状态码
        headers: 响应头
        body: 响应体

    Returns:
        所有 matchers 的综合结果
    """
    if not matchers:
        return False

    results = [check_matcher(m, status_code, headers, body) for m in matchers]

    if condition == "and":
        return all(results)
    return any(results)


# ─────────────────────── Extractor 执行 ───────────────────────


def run_extractors(
    extractors: List[NucleiExtractor],
    headers: Dict[str, str],
    body: str,
) -> Dict[str, str]:
    """执行提取器，返回提取到的数据

    Args:
        extractors: 提取器列表
        headers: 响应头
        body: 响应体

    Returns:
        提取器名 -> 提取值 的映射
    """
    extracted: Dict[str, str] = {}
    for ext in extractors:
        if ext.type == "regex" and ext.regex:
            target = body if ext.part == "body" else "\r\n".join(
                f"{k}: {v}" for k, v in headers.items()
            )
            for pattern in ext.regex:
                try:
                    m = re.search(pattern, target)
                    if m:
                        value = m.group(ext.group) if ext.group <= len(m.groups()) else m.group(0)
                        key = ext.name or f"extract_{len(extracted)}"
                        extracted[key] = value
                except re.error:
                    pass
    return extracted


# ─────────────────────── 引擎 ───────────────────────


class NucleiEngine:
    """Nuclei 模板执行引擎

    纯 Python 实现，不依赖 nuclei 二进制。
    解析 YAML 模板 → 构造 HTTP 请求 → 匹配响应 → 生成结果。

    Args:
        template_dir: 模板目录路径，默认自动搜索常见位置
    """

    # 合法的 severity 值
    VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

    def __init__(self, template_dir: Union[str, Path, None] = None):
        self.template_dir: Optional[Path] = None
        self.templates: List[NucleiTemplate] = []

        if template_dir is not None:
            self.template_dir = Path(template_dir)
        else:
            # 自动搜索默认路径
            for candidate in _DEFAULT_TEMPLATE_DIRS:
                if candidate.is_dir():
                    self.template_dir = candidate
                    break

    def load_templates(
        self,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        limit: Optional[int] = None,
    ) -> int:
        """加载模板，支持按 tag/severity 过滤

        Args:
            tags: 只加载包含指定 tag 的模板（OR 关系）
            severity: 只加载指定 severity 的模板
            limit: 最大加载数量

        Returns:
            成功加载的模板数量
        """
        if self.template_dir is None or not self.template_dir.is_dir():
            logger.warning("Nuclei 模板目录不存在: %s", self.template_dir)
            return 0

        # 规范化过滤条件
        tag_set = set(t.lower() for t in tags) if tags else None
        severity_set = set(s.lower() for s in severity) if severity else None

        loaded = []
        yaml_files = sorted(self.template_dir.rglob("*.yaml"))

        for yaml_path in yaml_files:
            if limit is not None and len(loaded) >= limit:
                break
            try:
                tmpl = NucleiTemplate.from_yaml(yaml_path)
            except Exception as e:
                logger.debug("跳过无效模板 %s: %s", yaml_path, e)
                continue

            # 过滤: severity
            if severity_set and tmpl.severity not in severity_set:
                continue

            # 过滤: tags（模板的任一 tag 命中即可）
            if tag_set:
                tmpl_tags = set(t.lower() for t in tmpl.tags)
                if not tag_set & tmpl_tags:
                    continue

            loaded.append(tmpl)

        self.templates = loaded
        logger.info("已加载 %d 个 Nuclei 模板", len(loaded))
        return len(loaded)

    def load_template_from_dict(self, data: dict) -> NucleiTemplate:
        """从字典加载单个模板并追加到引擎

        Args:
            data: 模板字典

        Returns:
            加载的模板实例
        """
        tmpl = NucleiTemplate.from_dict(data)
        self.templates.append(tmpl)
        return tmpl

    async def scan(
        self,
        target: str,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        concurrency: int = 10,
        timeout: float = 15,
    ) -> List[Dict[str, Any]]:
        """扫描目标

        对每个模板:
        1. 构造 HTTP 请求（替换 {{BaseURL}} 等变量）
        2. 发送请求
        3. 检查 matchers
        4. 如果匹配，记录发现

        Args:
            target: 目标 URL
            tags: 运行时 tag 过滤（覆盖 load_templates 的结果）
            severity: 运行时 severity 过滤
            concurrency: 最大并发数
            timeout: 单个请求超时（秒）

        Returns:
            匹配结果列表，每个元素包含 template_id, name, severity 等
        """
        from utils.async_utils import gather_with_limit

        # 运行时过滤
        templates = self._filter_templates(self.templates, tags, severity)
        if not templates:
            logger.info("无可用模板，跳过扫描")
            return []

        logger.info(
            "开始 Nuclei 扫描: %s, 模板数: %d, 并发: %d",
            target,
            len(templates),
            concurrency,
        )

        # 构建协程列表
        coros = [
            self._execute_template_async(tmpl, target, timeout)
            for tmpl in templates
        ]
        raw_results = await gather_with_limit(coros, limit=concurrency, return_exceptions=True)

        findings: List[Dict[str, Any]] = []
        for result in raw_results:
            if isinstance(result, Exception):
                logger.debug("模板执行异常: %s", result)
                continue
            if result is not None:
                findings.append(result)

        logger.info("Nuclei 扫描完成: 发现 %d 个匹配", len(findings))
        return findings

    async def _execute_template_async(
        self,
        template: NucleiTemplate,
        target: str,
        timeout: float = 15,
    ) -> Optional[Dict[str, Any]]:
        """异步执行单个模板

        Args:
            template: Nuclei 模板
            target: 目标 URL
            timeout: 请求超时

        Returns:
            匹配则返回结果字典，否则 None
        """
        from core.http import HTTPClient, HTTPConfig

        variables = _build_variables(target)

        config = HTTPConfig()
        config.timeout = timeout
        config.verify_ssl = False

        # 每个模板使用独立的 HTTP 客户端实例
        client = HTTPClient(config=config, ssrf_protection=False)

        try:
            for request in template.requests:
                for raw_path in request.path:
                    url = _substitute(raw_path, variables)
                    # 如果 path 是相对路径，拼接 BaseURL
                    if url.startswith("/"):
                        url = variables["BaseURL"] + url

                    # 替换 headers 和 body 中的变量
                    headers = {k: _substitute(v, variables) for k, v in request.headers.items()}
                    body = _substitute(request.body, variables) if request.body else None

                    try:
                        response = await client.async_request(
                            method=request.method,
                            url=url,
                            headers=headers if headers else None,
                            data=body.encode("utf-8") if body else None,
                        )
                    except Exception as e:
                        logger.debug(
                            "[%s] 请求失败 %s: %s", template.id, url, e
                        )
                        continue

                    # 检查 matchers
                    resp_headers = dict(response.headers) if response.headers else {}
                    matched = check_matchers(
                        request.matchers,
                        request.matchers_condition,
                        response.status_code,
                        resp_headers,
                        response.text or "",
                    )

                    if matched:
                        # 运行提取器
                        extracted = run_extractors(
                            request.extractors,
                            resp_headers,
                            response.text or "",
                        )

                        return {
                            "template_id": template.id,
                            "name": template.name,
                            "severity": template.severity,
                            "tags": template.tags,
                            "author": template.author,
                            "description": template.description,
                            "matched_url": url,
                            "matched_status": response.status_code,
                            "extracted": extracted,
                            "reference": template.reference,
                        }
        finally:
            # 清理客户端资源
            try:
                if hasattr(client, "close"):
                    client.close()
            except Exception:
                pass

        return None

    def execute_template_sync(
        self,
        template: NucleiTemplate,
        target: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> Optional[Dict[str, Any]]:
        """同步执行模板（用给定的响应数据匹配）

        适用于已经拿到响应、只需判断是否命中模板的场景。

        Args:
            template: Nuclei 模板
            target: 目标 URL（用于变量替换）
            status_code: 响应状态码
            headers: 响应头
            body: 响应体

        Returns:
            匹配则返回结果字典，否则 None
        """
        for request in template.requests:
            matched = check_matchers(
                request.matchers,
                request.matchers_condition,
                status_code,
                headers,
                body,
            )
            if matched:
                extracted = run_extractors(request.extractors, headers, body)
                return {
                    "template_id": template.id,
                    "name": template.name,
                    "severity": template.severity,
                    "tags": template.tags,
                    "matched_url": target,
                    "matched_status": status_code,
                    "extracted": extracted,
                    "reference": template.reference,
                }
        return None

    @staticmethod
    def _filter_templates(
        templates: List[NucleiTemplate],
        tags: Optional[List[str]],
        severity: Optional[List[str]],
    ) -> List[NucleiTemplate]:
        """按 tag / severity 运行时过滤"""
        result = templates

        if severity:
            severity_set = set(s.lower() for s in severity)
            result = [t for t in result if t.severity in severity_set]

        if tags:
            tag_set = set(t.lower() for t in tags)
            result = [
                t for t in result
                if set(tg.lower() for tg in t.tags) & tag_set
            ]

        return result
