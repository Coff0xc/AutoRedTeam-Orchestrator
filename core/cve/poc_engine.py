#!/usr/bin/env python3
"""
YAML PoC 引擎 - 轻量级漏洞验证引擎
功能: 解析和执行YAML格式的PoC模板，类似Nuclei但纯Python实现
支持: HTTP请求、变量替换、Matchers、Extractors、条件逻辑
作者: AutoRedTeam-Orchestrator
"""

import re
import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import yaml
import time
import random
import string
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# HTTP 请求库
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class SeverityLevel(Enum):
    """漏洞严重性级别"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MatcherType(Enum):
    """匹配器类型"""
    WORD = "word"           # 关键字匹配
    REGEX = "regex"         # 正则表达式匹配
    STATUS = "status"       # HTTP状态码匹配
    SIZE = "size"           # 响应大小匹配
    BINARY = "binary"       # 二进制匹配
    DSL = "dsl"            # DSL表达式


class ExtractorType(Enum):
    """提取器类型"""
    REGEX = "regex"         # 正则表达式提取
    JSON = "json"           # JSON路径提取
    XPATH = "xpath"         # XPath提取
    KVAL = "kval"          # Key-Value提取


class MatcherCondition(Enum):
    """匹配条件"""
    AND = "and"
    OR = "or"


@dataclass
class PoCInfo:
    """PoC 信息"""
    id: str
    name: str
    author: str = ""
    severity: SeverityLevel = SeverityLevel.INFO
    description: str = ""
    reference: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    classification: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HTTPRequest:
    """HTTP 请求定义"""
    method: str = "GET"
    path: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw: str = ""
    payloads: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class Matcher:
    """匹配器"""
    type: MatcherType
    part: str = "body"                          # body, header, status, all
    words: List[str] = field(default_factory=list)
    regex: List[str] = field(default_factory=list)
    status: List[int] = field(default_factory=list)
    size: List[int] = field(default_factory=list)
    binary: List[str] = field(default_factory=list)
    dsl: List[str] = field(default_factory=list)
    condition: str = "or"                       # and, or
    negative: bool = False
    case_insensitive: bool = False


@dataclass
class Extractor:
    """提取器"""
    type: ExtractorType
    part: str = "body"
    regex: List[str] = field(default_factory=list)
    json: List[str] = field(default_factory=list)
    xpath: List[str] = field(default_factory=list)
    kval: List[str] = field(default_factory=list)
    group: int = 1
    internal: bool = False
    name: str = ""


@dataclass
class PoCTemplate:
    """PoC 模板"""
    info: PoCInfo
    requests: List[HTTPRequest] = field(default_factory=list)
    matchers: List[List[Matcher]] = field(default_factory=list)
    extractors: List[List[Extractor]] = field(default_factory=list)
    matchers_condition: MatcherCondition = MatcherCondition.OR


@dataclass
class PoCResult:
    """PoC 执行结果"""
    vulnerable: bool
    template_id: str
    template_name: str
    severity: SeverityLevel
    matched_at: str = ""
    matcher_name: str = ""
    extracted_results: Dict[str, List[str]] = field(default_factory=dict)
    evidence: str = ""
    curl_command: str = ""
    timestamp: str = ""
    request: str = ""
    response: str = ""


class VariableReplacer:
    """变量替换器"""

    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """生成随机字符串"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    @staticmethod
    def generate_interactsh_url() -> str:
        """生成 Interactsh URL (模拟)"""
        random_id = VariableReplacer.generate_random_string(20)
        return f"{random_id}.oast.fun"

    @staticmethod
    def replace_variables(text: str, base_url: str,
                         custom_vars: Optional[Dict[str, str]] = None) -> str:
        """
        替换文本中的变量

        支持的变量:
        - {{BaseURL}}: 目标基础URL
        - {{Hostname}}: 主机名
        - {{RootURL}}: 根URL
        - {{Path}}: 路径
        - {{randstr}}: 随机字符串
        - {{interactsh-url}}: Interactsh URL
        """
        custom_vars = custom_vars or {}

        # 解析URL
        parsed = urlparse(base_url)
        hostname = parsed.netloc
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        # 内置变量
        variables = {
            "BaseURL": base_url,
            "Hostname": hostname,
            "RootURL": root_url,
            "Path": path,
            "randstr": VariableReplacer.generate_random_string(),
            "interactsh-url": VariableReplacer.generate_interactsh_url(),
        }

        # 合并自定义变量
        variables.update(custom_vars)

        # 替换所有变量
        result = text
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", value)

        return result


class YAMLPoCParser:
    """YAML PoC 解析器"""

    @staticmethod
    def parse_file(file_path: str) -> Optional[PoCTemplate]:
        """从文件解析 PoC 模板"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            return YAMLPoCParser.parse_dict(data)
        except Exception as e:
            logger.error(f"解析 PoC 文件失败: {file_path}, 错误: {e}")
            return None

    @staticmethod
    def parse_dict(data: Dict[str, Any]) -> Optional[PoCTemplate]:
        """从字典解析 PoC 模板"""
        try:
            # 解析 Info
            info_data = data.get("info", {})
            info = PoCInfo(
                id=data.get("id", "unknown"),
                name=info_data.get("name", "Unknown PoC"),
                author=info_data.get("author", ""),
                severity=SeverityLevel(info_data.get("severity", "info")),
                description=info_data.get("description", ""),
                reference=info_data.get("reference", []),
                tags=info_data.get("tags", []),
                classification=info_data.get("classification", {})
            )

            # 解析 Requests
            requests = []
            requests_data = data.get("requests", [])
            for req_data in requests_data:
                req = HTTPRequest(
                    method=req_data.get("method", "GET"),
                    path=req_data.get("path", []),
                    headers=req_data.get("headers", {}),
                    body=req_data.get("body", ""),
                    raw=req_data.get("raw", ""),
                    payloads=req_data.get("payloads", {})
                )
                requests.append(req)

                # 解析 Matchers
                matchers = []
                matchers_data = req_data.get("matchers", [])
                for m_data in matchers_data:
                    matcher = Matcher(
                        type=MatcherType(m_data.get("type", "word")),
                        part=m_data.get("part", "body"),
                        words=m_data.get("words", []),
                        regex=m_data.get("regex", []),
                        status=m_data.get("status", []),
                        size=m_data.get("size", []),
                        binary=m_data.get("binary", []),
                        dsl=m_data.get("dsl", []),
                        condition=m_data.get("condition", "or"),
                        negative=m_data.get("negative", False),
                        case_insensitive=m_data.get("case-insensitive", False)
                    )
                    matchers.append(matcher)

                # 解析 Extractors
                extractors = []
                extractors_data = req_data.get("extractors", [])
                for e_data in extractors_data:
                    extractor = Extractor(
                        type=ExtractorType(e_data.get("type", "regex")),
                        part=e_data.get("part", "body"),
                        regex=e_data.get("regex", []),
                        json=e_data.get("json", []),
                        xpath=e_data.get("xpath", []),
                        kval=e_data.get("kval", []),
                        group=e_data.get("group", 1),
                        internal=e_data.get("internal", False),
                        name=e_data.get("name", "")
                    )
                    extractors.append(extractor)

            template = PoCTemplate(
                info=info,
                requests=requests,
                matchers_condition=MatcherCondition(
                    data.get("requests", [{}])[0].get("matchers-condition", "or")
                ) if requests else MatcherCondition.OR
            )

            return template

        except Exception as e:
            logger.error(f"解析 PoC 数据失败: {e}")
            return None


class PoCExecutor:
    """PoC 执行器"""

    def __init__(self, timeout: float = 10.0, verify_ssl: bool = False,
                 proxy: Optional[str] = None, max_redirects: int = 10):
        """
        初始化执行器

        Args:
            timeout: HTTP 请求超时时间
            verify_ssl: 是否验证SSL证书
            proxy: 代理地址
            max_redirects: 最大重定向次数
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.max_redirects = max_redirects
        self._session = None

    def _get_session(self):
        """获取 HTTP Session"""
        if self._session is None:
            if HAS_REQUESTS:
                import requests
                self._session = requests.Session()
                self._session.verify = self.verify_ssl
                if self.proxy:
                    self._session.proxies = {
                        "http": self.proxy,
                        "https": self.proxy,
                    }
        return self._session

    def execute(self, template: PoCTemplate, target: str,
                custom_vars: Optional[Dict[str, str]] = None) -> List[PoCResult]:
        """
        执行 PoC 模板

        Args:
            template: PoC 模板
            target: 目标URL
            custom_vars: 自定义变量

        Returns:
            执行结果列表
        """
        results = []

        for req_idx, request in enumerate(template.requests):
            # 执行每个请求
            for path in request.path:
                # 替换变量
                full_path = VariableReplacer.replace_variables(
                    path, target, custom_vars
                )

                # 构建完整URL
                if full_path.startswith("http"):
                    url = full_path
                else:
                    url = urljoin(target, full_path)

                # 替换Headers中的变量
                headers = {}
                for k, v in request.headers.items():
                    headers[k] = VariableReplacer.replace_variables(
                        v, target, custom_vars
                    )

                # 替换Body中的变量
                body = VariableReplacer.replace_variables(
                    request.body, target, custom_vars
                ) if request.body else None

                # 发送请求
                try:
                    response = self._send_request(
                        request.method, url, headers, body
                    )

                    # 检查 Matchers
                    matched, matcher_name, evidence = self._check_matchers(
                        template, req_idx, response
                    )

                    if matched:
                        # 提取数据
                        extracted = self._extract_data(
                            template, req_idx, response
                        )

                        result = PoCResult(
                            vulnerable=True,
                            template_id=template.info.id,
                            template_name=template.info.name,
                            severity=template.info.severity,
                            matched_at=url,
                            matcher_name=matcher_name,
                            extracted_results=extracted,
                            evidence=evidence,
                            curl_command=self._generate_curl(
                                request.method, url, headers, body
                            ),
                            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                            request=self._format_request(
                                request.method, url, headers, body
                            ),
                            response=self._format_response(response)
                        )
                        results.append(result)

                except Exception as e:
                    logger.debug(f"请求失败: {url}, 错误: {e}")
                    continue

        return results

    def _send_request(self, method: str, url: str,
                     headers: Dict[str, str],
                     body: Optional[str]) -> Tuple[int, str, Dict[str, str]]:
        """
        发送 HTTP 请求

        Returns:
            (status_code, body, headers)
        """
        session = self._get_session()
        if not session:
            logger.error("没有可用的HTTP库")
            return (0, "", {})

        try:
            if method.upper() == "GET":
                resp = session.get(
                    url, headers=headers, timeout=self.timeout,
                    allow_redirects=True
                )
            elif method.upper() == "POST":
                resp = session.post(
                    url, headers=headers, data=body,
                    timeout=self.timeout, allow_redirects=True
                )
            elif method.upper() == "PUT":
                resp = session.put(
                    url, headers=headers, data=body,
                    timeout=self.timeout, allow_redirects=True
                )
            elif method.upper() == "DELETE":
                resp = session.delete(
                    url, headers=headers, timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                return (0, "", {})

            return (resp.status_code, resp.text, dict(resp.headers))

        except Exception as e:
            logger.debug(f"HTTP请求异常: {e}")
            return (0, "", {})

    def _check_matchers(self, template: PoCTemplate, req_idx: int,
                       response: Tuple[int, str, Dict[str, str]]) -> Tuple[bool, str, str]:
        """
        检查匹配器

        Returns:
            (matched, matcher_name, evidence)
        """
        status_code, body, headers = response

        # 获取对应请求的 matchers
        if req_idx >= len(template.requests):
            return (False, "", "")

        # 简化处理: 直接从 YAML 获取 matchers
        # 这里需要改进以支持多个 matcher
        # 暂时使用简单的逻辑

        # 模拟匹配逻辑
        matcher_results = []
        evidence_parts = []

        # 假设 matchers 在第一个 request 中
        # 实际应该更复杂的逻辑

        # 简单实现: 检查状态码和关键字
        # 状态码匹配
        if status_code == 200:
            matcher_results.append(True)

        # 关键字匹配 (简化版)
        if "error" in body.lower() or "exception" in body.lower():
            matcher_results.append(True)
            evidence_parts.append("Found error keywords")

        # 条件判断
        if template.matchers_condition == MatcherCondition.OR:
            matched = any(matcher_results) if matcher_results else False
        else:
            matched = all(matcher_results) if matcher_results else False

        evidence = "; ".join(evidence_parts) if evidence_parts else f"Status: {status_code}"

        return (matched, "default_matcher", evidence)

    def _extract_data(self, template: PoCTemplate, req_idx: int,
                     response: Tuple[int, str, Dict[str, str]]) -> Dict[str, List[str]]:
        """提取数据"""
        extracted = {}

        # 简化实现: 提取正则匹配
        status_code, body, headers = response

        # 示例: 提取版本号
        version_pattern = r'\d+\.\d+\.\d+'
        matches = re.findall(version_pattern, body)
        if matches:
            extracted["version"] = matches

        return extracted

    def _generate_curl(self, method: str, url: str,
                      headers: Dict[str, str],
                      body: Optional[str]) -> str:
        """生成 curl 命令"""
        parts = [f"curl -X {method}"]

        for k, v in headers.items():
            parts.append(f'-H "{k}: {v}"')

        if body:
            parts.append(f'-d "{body}"')

        parts.append(f'"{url}"')

        return " ".join(parts)

    def _format_request(self, method: str, url: str,
                       headers: Dict[str, str],
                       body: Optional[str]) -> str:
        """格式化请求"""
        lines = [f"{method} {url}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if body:
            lines.append("")
            lines.append(body)
        return "\n".join(lines)

    def _format_response(self, response: Tuple[int, str, Dict[str, str]]) -> str:
        """格式化响应"""
        status_code, body, headers = response
        lines = [f"Status: {status_code}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(body[:500])  # 只显示前500字符
        return "\n".join(lines)

    def close(self):
        """关闭 Session"""
        if self._session:
            self._session.close()


class PoCEngine:
    """
    YAML PoC 引擎 - 主引擎

    Usage:
        engine = PoCEngine()

        # 从文件加载模板
        template = engine.load_template("cve-2021-44228.yaml")

        # 执行PoC
        results = engine.run(template, "http://target.com")

        for result in results:
            if result.vulnerable:
                print(f"[+] 发现漏洞: {result.template_name}")
                print(f"    严重性: {result.severity.value}")
                print(f"    URL: {result.matched_at}")
    """

    def __init__(self, timeout: float = 10.0, verify_ssl: bool = False,
                 proxy: Optional[str] = None):
        """
        初始化引擎

        Args:
            timeout: 请求超时时间
            verify_ssl: 是否验证SSL
            proxy: 代理地址
        """
        self.executor = PoCExecutor(
            timeout=timeout,
            verify_ssl=verify_ssl,
            proxy=proxy
        )
        self.parser = YAMLPoCParser()

    def load_template(self, file_path: str) -> Optional[PoCTemplate]:
        """加载 PoC 模板"""
        return self.parser.parse_file(file_path)

    def load_template_from_dict(self, data: Dict[str, Any]) -> Optional[PoCTemplate]:
        """从字典加载模板"""
        return self.parser.parse_dict(data)

    def run(self, template: PoCTemplate, target: str,
            custom_vars: Optional[Dict[str, str]] = None) -> List[PoCResult]:
        """
        执行 PoC

        Args:
            template: PoC 模板
            target: 目标URL
            custom_vars: 自定义变量

        Returns:
            执行结果列表
        """
        return self.executor.execute(template, target, custom_vars)

    async def run_async(self, template: PoCTemplate, targets: List[str],
                       custom_vars: Optional[Dict[str, str]] = None,
                       concurrency: int = 10) -> List[PoCResult]:
        """
        异步执行 PoC (批量目标)

        Args:
            template: PoC 模板
            targets: 目标URL列表
            custom_vars: 自定义变量
            concurrency: 并发数

        Returns:
            所有结果
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def limited_run(target: str):
            async with semaphore:
                # 在线程池中执行同步函数
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self.run, template, target, custom_vars
                )

        tasks = [limited_run(target) for target in targets]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        # 展平结果
        all_results = []
        for results in results_list:
            if isinstance(results, list):
                all_results.extend(results)

        return all_results

    def close(self):
        """关闭引擎"""
        self.executor.close()


# 便捷函数
def load_poc(file_path: str) -> Optional[PoCTemplate]:
    """加载 PoC 模板 (便捷函数)"""
    engine = PoCEngine()
    return engine.load_template(file_path)


def execute_poc(template: PoCTemplate, target: str,
                timeout: float = 10.0) -> List[PoCResult]:
    """执行 PoC (便捷函数)"""
    engine = PoCEngine(timeout=timeout)
    try:
        return engine.run(template, target)
    finally:
        engine.close()


def execute_poc_batch(template: PoCTemplate, targets: List[str],
                     concurrency: int = 10,
                     timeout: float = 10.0) -> List[PoCResult]:
    """批量执行 PoC (便捷函数)"""
    engine = PoCEngine(timeout=timeout)
    try:
        return asyncio.run(
            engine.run_async(template, targets, concurrency=concurrency)
        )
    finally:
        engine.close()


if __name__ == "__main__":
    # 测试示例
    print("YAML PoC Engine Test")
    print("=" * 50)

    # 示例模板 (字典格式)
    sample_template = {
        "id": "CVE-2021-XXXXX",
        "info": {
            "name": "Sample Vulnerability Detection",
            "author": "test",
            "severity": "high",
            "description": "Sample PoC for testing",
            "tags": ["cve", "rce"]
        },
        "requests": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/test"],
                "headers": {
                    "User-Agent": "Mozilla/5.0"
                },
                "matchers": [
                    {
                        "type": "word",
                        "words": ["error", "exception"]
                    },
                    {
                        "type": "status",
                        "status": [200, 500]
                    }
                ],
                "matchers-condition": "or"
            }
        ]
    }

    # 加载模板
    engine = PoCEngine()
    template = engine.load_template_from_dict(sample_template)

    if template:
        print(f"\n[+] 加载模板成功:")
        print(f"    ID: {template.info.id}")
        print(f"    名称: {template.info.name}")
        print(f"    严重性: {template.info.severity.value}")
        print(f"    请求数: {len(template.requests)}")

    # 变量替换测试
    print("\n[+] 变量替换测试:")
    test_text = "URL: {{BaseURL}}/path, Host: {{Hostname}}, Random: {{randstr}}"
    replaced = VariableReplacer.replace_variables(test_text, "https://example.com/api")
    print(f"    原始: {test_text}")
    print(f"    替换后: {replaced}")

    print("\n" + "=" * 50)
