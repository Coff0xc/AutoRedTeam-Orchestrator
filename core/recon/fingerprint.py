#!/usr/bin/env python3
"""
fingerprint.py - 指纹识别引擎

识别Web服务器、框架、CMS等指纹信息。

使用方式:
    from core.recon.fingerprint import FingerprintEngine, Fingerprint

    engine = FingerprintEngine()
    fingerprints = engine.identify("https://example.com")

    for fp in fingerprints:
        print(f"{fp.category}: {fp.name} {fp.version}")
"""

import re
import ssl
import socket
import logging
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Pattern, Tuple
from enum import Enum


logger = logging.getLogger(__name__)


class FingerprintCategory(Enum):
    """指纹类别"""
    SERVER = "server"           # Web服务器
    FRAMEWORK = "framework"     # Web框架
    CMS = "cms"                 # 内容管理系统
    LANGUAGE = "language"       # 编程语言
    JAVASCRIPT = "javascript"   # JavaScript库/框架
    CDN = "cdn"                 # CDN/负载均衡
    OS = "os"                   # 操作系统
    DATABASE = "database"       # 数据库
    CACHE = "cache"             # 缓存
    OTHER = "other"             # 其他


@dataclass
class Fingerprint:
    """指纹信息

    Attributes:
        category: 类别 (server, framework, cms, etc.)
        name: 名称 (nginx, laravel, wordpress, etc.)
        version: 版本号
        confidence: 置信度 (0-1)
        evidence: 证据
        metadata: 额外元数据
    """
    category: str
    name: str
    version: Optional[str] = None
    confidence: float = 0.8
    evidence: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "category": self.category,
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence[:200] if self.evidence else None,
            "metadata": self.metadata,
        }

    def __str__(self) -> str:
        """字符串表示"""
        if self.version:
            return f"{self.name}/{self.version}"
        return self.name


@dataclass
class FingerprintRule:
    """指纹规则

    Attributes:
        category: 类别
        name: 名称
        header: 匹配的HTTP头
        header_value: 头部值匹配模式
        cookie: 匹配的Cookie名
        body: Body内容匹配模式
        url: URL路径检查
        meta: HTML meta标签匹配
        version_pattern: 版本提取正则
        confidence: 置信度
    """
    category: str
    name: str
    header: Optional[str] = None
    header_value: Optional[str] = None
    cookie: Optional[str] = None
    body: Optional[str] = None
    url: Optional[str] = None
    meta: Optional[str] = None
    version_pattern: Optional[str] = None
    confidence: float = 0.8


class FingerprintEngine:
    """指纹识别引擎

    基于HTTP响应头、Cookie、Body内容等识别Web指纹。

    Attributes:
        timeout: 请求超时时间
        verify_ssl: 是否验证SSL证书
        user_agent: 自定义User-Agent
    """

    # 内置指纹规则
    FINGERPRINTS: Dict[str, Dict[str, List[FingerprintRule]]] = {
        "server": {
            "nginx": [
                FingerprintRule(
                    category="server", name="nginx",
                    header="Server", header_value=r"nginx(?:/([0-9.]+))?",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="server", name="nginx",
                    header="X-Powered-By", header_value=r"nginx",
                    confidence=0.8
                ),
            ],
            "apache": [
                FingerprintRule(
                    category="server", name="Apache",
                    header="Server", header_value=r"Apache(?:/([0-9.]+))?",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="server", name="Apache",
                    body=r"Apache/[0-9.]+ Server at",
                    confidence=0.9
                ),
            ],
            "iis": [
                FingerprintRule(
                    category="server", name="Microsoft-IIS",
                    header="Server", header_value=r"Microsoft-IIS(?:/([0-9.]+))?",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="server", name="Microsoft-IIS",
                    header="X-Powered-By", header_value=r"ASP\.NET",
                    confidence=0.7
                ),
            ],
            "openresty": [
                FingerprintRule(
                    category="server", name="openresty",
                    header="Server", header_value=r"openresty(?:/([0-9.]+))?",
                    confidence=0.95
                ),
            ],
            "tengine": [
                FingerprintRule(
                    category="server", name="Tengine",
                    header="Server", header_value=r"Tengine(?:/([0-9.]+))?",
                    confidence=0.95
                ),
            ],
            "caddy": [
                FingerprintRule(
                    category="server", name="Caddy",
                    header="Server", header_value=r"Caddy",
                    confidence=0.9
                ),
            ],
            "litespeed": [
                FingerprintRule(
                    category="server", name="LiteSpeed",
                    header="Server", header_value=r"LiteSpeed",
                    confidence=0.95
                ),
            ],
        },
        "framework": {
            "laravel": [
                FingerprintRule(
                    category="framework", name="Laravel",
                    cookie="laravel_session",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="framework", name="Laravel",
                    cookie="XSRF-TOKEN",
                    body=r"laravel",
                    confidence=0.7
                ),
            ],
            "django": [
                FingerprintRule(
                    category="framework", name="Django",
                    cookie="csrftoken",
                    confidence=0.8
                ),
                FingerprintRule(
                    category="framework", name="Django",
                    header="X-Frame-Options", header_value=r"DENY|SAMEORIGIN",
                    body=r"django",
                    confidence=0.6
                ),
            ],
            "flask": [
                FingerprintRule(
                    category="framework", name="Flask",
                    header="Server", header_value=r"Werkzeug",
                    confidence=0.9
                ),
            ],
            "spring": [
                FingerprintRule(
                    category="framework", name="Spring",
                    header="X-Application-Context",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="framework", name="Spring Boot",
                    body=r"Whitelabel Error Page",
                    confidence=0.9
                ),
                FingerprintRule(
                    category="framework", name="Spring",
                    cookie="JSESSIONID",
                    confidence=0.5
                ),
            ],
            "express": [
                FingerprintRule(
                    category="framework", name="Express",
                    header="X-Powered-By", header_value=r"Express",
                    confidence=0.95
                ),
            ],
            "rails": [
                FingerprintRule(
                    category="framework", name="Ruby on Rails",
                    header="X-Powered-By", header_value=r"Phusion Passenger",
                    confidence=0.8
                ),
                FingerprintRule(
                    category="framework", name="Ruby on Rails",
                    cookie="_session_id",
                    body=r"rails",
                    confidence=0.6
                ),
            ],
            "aspnet": [
                FingerprintRule(
                    category="framework", name="ASP.NET",
                    header="X-Powered-By", header_value=r"ASP\.NET",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="framework", name="ASP.NET",
                    header="X-AspNet-Version",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="framework", name="ASP.NET",
                    cookie="ASP.NET_SessionId",
                    confidence=0.95
                ),
            ],
            "thinkphp": [
                FingerprintRule(
                    category="framework", name="ThinkPHP",
                    header="X-Powered-By", header_value=r"ThinkPHP",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="framework", name="ThinkPHP",
                    body=r"ThinkPHP",
                    confidence=0.8
                ),
            ],
            "fastapi": [
                FingerprintRule(
                    category="framework", name="FastAPI",
                    body=r'"openapi":\s*"3\.',
                    url="/docs",
                    confidence=0.8
                ),
            ],
        },
        "cms": {
            "wordpress": [
                FingerprintRule(
                    category="cms", name="WordPress",
                    body=r"/wp-content/",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="cms", name="WordPress",
                    body=r"/wp-includes/",
                    confidence=0.95
                ),
                FingerprintRule(
                    category="cms", name="WordPress",
                    meta=r'name="generator" content="WordPress ([0-9.]+)"',
                    confidence=0.99
                ),
                FingerprintRule(
                    category="cms", name="WordPress",
                    header="X-Powered-By", header_value=r"WordPress",
                    confidence=0.95
                ),
            ],
            "drupal": [
                FingerprintRule(
                    category="cms", name="Drupal",
                    header="X-Generator", header_value=r"Drupal ([0-9.]+)?",
                    confidence=0.99
                ),
                FingerprintRule(
                    category="cms", name="Drupal",
                    body=r'Drupal\.settings',
                    confidence=0.9
                ),
                FingerprintRule(
                    category="cms", name="Drupal",
                    body=r"/sites/default/files/",
                    confidence=0.8
                ),
            ],
            "joomla": [
                FingerprintRule(
                    category="cms", name="Joomla",
                    meta=r'name="generator" content="Joomla',
                    confidence=0.99
                ),
                FingerprintRule(
                    category="cms", name="Joomla",
                    body=r"/media/jui/",
                    confidence=0.9
                ),
            ],
            "shopify": [
                FingerprintRule(
                    category="cms", name="Shopify",
                    header="X-ShopId",
                    confidence=0.99
                ),
                FingerprintRule(
                    category="cms", name="Shopify",
                    body=r"cdn\.shopify\.com",
                    confidence=0.95
                ),
            ],
            "magento": [
                FingerprintRule(
                    category="cms", name="Magento",
                    body=r"/skin/frontend/",
                    confidence=0.9
                ),
                FingerprintRule(
                    category="cms", name="Magento",
                    cookie="frontend",
                    body=r"Mage\.Cookies",
                    confidence=0.8
                ),
            ],
            "discuz": [
                FingerprintRule(
                    category="cms", name="Discuz!",
                    body=r"Discuz!",
                    confidence=0.9
                ),
                FingerprintRule(
                    category="cms", name="Discuz!",
                    body=r"/uc_server/",
                    confidence=0.85
                ),
            ],
            "dedecms": [
                FingerprintRule(
                    category="cms", name="DedeCMS",
                    body=r"/dede/",
                    confidence=0.7
                ),
                FingerprintRule(
                    category="cms", name="DedeCMS",
                    body=r"DedeTag Engine",
                    confidence=0.95
                ),
            ],
            "phpcms": [
                FingerprintRule(
                    category="cms", name="PHPCMS",
                    body=r"phpcms",
                    cookie="PHPSESSID",
                    confidence=0.7
                ),
            ],
        },
        "javascript": {
            "jquery": [
                FingerprintRule(
                    category="javascript", name="jQuery",
                    body=r'jquery[.-]?([0-9.]+)?(?:\.min)?\.js',
                    confidence=0.95
                ),
            ],
            "react": [
                FingerprintRule(
                    category="javascript", name="React",
                    body=r'react[.-]?(?:dom)?[.-]?([0-9.]+)?(?:\.min)?\.js',
                    confidence=0.9
                ),
                FingerprintRule(
                    category="javascript", name="React",
                    body=r'data-reactroot',
                    confidence=0.95
                ),
            ],
            "vue": [
                FingerprintRule(
                    category="javascript", name="Vue.js",
                    body=r'vue[.-]?([0-9.]+)?(?:\.min)?\.js',
                    confidence=0.9
                ),
                FingerprintRule(
                    category="javascript", name="Vue.js",
                    body=r'data-v-[a-f0-9]+',
                    confidence=0.85
                ),
            ],
            "angular": [
                FingerprintRule(
                    category="javascript", name="Angular",
                    body=r'ng-app|ng-controller|ng-model',
                    confidence=0.9
                ),
                FingerprintRule(
                    category="javascript", name="Angular",
                    body=r'angular[.-]?([0-9.]+)?(?:\.min)?\.js',
                    confidence=0.95
                ),
            ],
            "bootstrap": [
                FingerprintRule(
                    category="javascript", name="Bootstrap",
                    body=r'bootstrap[.-]?([0-9.]+)?(?:\.min)?\.(?:js|css)',
                    confidence=0.9
                ),
            ],
            "layui": [
                FingerprintRule(
                    category="javascript", name="Layui",
                    body=r'layui[.-]?([0-9.]+)?\.(?:js|css)',
                    confidence=0.9
                ),
            ],
        },
        "cdn": {
            "cloudflare": [
                FingerprintRule(
                    category="cdn", name="Cloudflare",
                    header="CF-RAY",
                    confidence=0.99
                ),
                FingerprintRule(
                    category="cdn", name="Cloudflare",
                    header="Server", header_value=r"cloudflare",
                    confidence=0.99
                ),
                FingerprintRule(
                    category="cdn", name="Cloudflare",
                    cookie="__cf_bm",
                    confidence=0.95
                ),
            ],
            "akamai": [
                FingerprintRule(
                    category="cdn", name="Akamai",
                    header="X-Akamai-Transformed",
                    confidence=0.99
                ),
            ],
            "fastly": [
                FingerprintRule(
                    category="cdn", name="Fastly",
                    header="X-Served-By",
                    header_value=r"cache-",
                    confidence=0.8
                ),
            ],
            "aliyun": [
                FingerprintRule(
                    category="cdn", name="Aliyun CDN",
                    header="Via", header_value=r"ali",
                    confidence=0.8
                ),
            ],
        },
        "language": {
            "php": [
                FingerprintRule(
                    category="language", name="PHP",
                    header="X-Powered-By", header_value=r"PHP(?:/([0-9.]+))?",
                    confidence=0.99
                ),
                FingerprintRule(
                    category="language", name="PHP",
                    cookie="PHPSESSID",
                    confidence=0.9
                ),
            ],
            "python": [
                FingerprintRule(
                    category="language", name="Python",
                    header="Server", header_value=r"Python",
                    confidence=0.9
                ),
            ],
            "java": [
                FingerprintRule(
                    category="language", name="Java",
                    cookie="JSESSIONID",
                    confidence=0.7
                ),
                FingerprintRule(
                    category="language", name="Java",
                    header="X-Powered-By", header_value=r"Servlet",
                    confidence=0.9
                ),
            ],
        },
    }

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ):
        """初始化指纹识别引擎

        Args:
            timeout: 请求超时时间
            verify_ssl: 是否验证SSL证书
            user_agent: 自定义User-Agent
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent

        # 编译正则表达式
        self._compiled_rules = self._compile_rules()

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _compile_rules(self) -> Dict[str, Dict[str, List[Tuple[FingerprintRule, Optional[Pattern]]]]]:
        """编译所有规则的正则表达式"""
        compiled = {}
        for category, names in self.FINGERPRINTS.items():
            compiled[category] = {}
            for name, rules in names.items():
                compiled[category][name] = []
                for rule in rules:
                    pattern = None
                    if rule.header_value:
                        pattern = re.compile(rule.header_value, re.IGNORECASE)
                    elif rule.body:
                        pattern = re.compile(rule.body, re.IGNORECASE)
                    elif rule.meta:
                        pattern = re.compile(rule.meta, re.IGNORECASE)
                    compiled[category][name].append((rule, pattern))
        return compiled

    def identify(self, url: str) -> List[Fingerprint]:
        """识别目标指纹

        Args:
            url: 目标URL

        Returns:
            识别到的指纹列表
        """
        fingerprints: List[Fingerprint] = []

        # 发送HTTP请求
        response = self._make_request(url)
        if not response:
            return fingerprints

        headers = response.get("headers", {})
        body = response.get("body", "")
        cookies = response.get("cookies", "")

        # 检查所有规则
        seen = set()  # 避免重复
        for category, names in self._compiled_rules.items():
            for name, rules in names.items():
                for rule, pattern in rules:
                    fp = self._check_rule(rule, pattern, headers, body, cookies)
                    if fp:
                        key = f"{fp.category}:{fp.name}"
                        if key not in seen:
                            seen.add(key)
                            fingerprints.append(fp)
                        break  # 一个名称只需要一个匹配

        # 按置信度排序
        fingerprints.sort(key=lambda x: x.confidence, reverse=True)
        return fingerprints

    def identify_from_response(
        self,
        headers: Dict[str, str],
        body: str,
        cookies: str = ""
    ) -> List[Fingerprint]:
        """从响应数据识别指纹

        Args:
            headers: 响应头
            body: 响应体
            cookies: Cookie字符串

        Returns:
            识别到的指纹列表
        """
        fingerprints: List[Fingerprint] = []
        seen = set()

        for category, names in self._compiled_rules.items():
            for name, rules in names.items():
                for rule, pattern in rules:
                    fp = self._check_rule(rule, pattern, headers, body, cookies)
                    if fp:
                        key = f"{fp.category}:{fp.name}"
                        if key not in seen:
                            seen.add(key)
                            fingerprints.append(fp)
                        break

        fingerprints.sort(key=lambda x: x.confidence, reverse=True)
        return fingerprints

    def _check_rule(
        self,
        rule: FingerprintRule,
        pattern: Optional[Pattern],
        headers: Dict[str, str],
        body: str,
        cookies: str
    ) -> Optional[Fingerprint]:
        """检查单个规则

        Args:
            rule: 指纹规则
            pattern: 编译的正则
            headers: 响应头
            body: 响应体
            cookies: Cookie

        Returns:
            匹配的指纹，不匹配返回 None
        """
        version = None
        evidence = None
        matched = False

        # 检查HTTP头
        if rule.header:
            header_value = headers.get(rule.header, "")
            if header_value:
                if rule.header_value and pattern:
                    match = pattern.search(header_value)
                    if match:
                        matched = True
                        evidence = f"Header {rule.header}: {header_value}"
                        # 尝试提取版本
                        if match.groups():
                            version = match.group(1)
                else:
                    # 只检查头部是否存在
                    matched = True
                    evidence = f"Header {rule.header} exists"

        # 检查Cookie
        if rule.cookie and not matched:
            if rule.cookie.lower() in cookies.lower():
                matched = True
                evidence = f"Cookie: {rule.cookie}"

        # 检查Body
        if rule.body and pattern:
            if not matched or rule.cookie:  # Cookie和Body可以组合
                match = pattern.search(body)
                if match:
                    if rule.cookie and rule.cookie.lower() not in cookies.lower():
                        return None  # Cookie条件不满足
                    matched = True
                    evidence = f"Body pattern: {rule.body[:50]}..."
                    if match.groups():
                        version = match.group(1)

        # 检查Meta标签
        if rule.meta and pattern and not matched:
            match = pattern.search(body)
            if match:
                matched = True
                evidence = f"Meta tag matched"
                if match.groups():
                    version = match.group(1)

        if matched:
            return Fingerprint(
                category=rule.category,
                name=rule.name,
                version=version,
                confidence=rule.confidence,
                evidence=evidence
            )

        return None

    def _make_request(self, url: str) -> Optional[Dict[str, Any]]:
        """发送HTTP请求

        Args:
            url: 目标URL

        Returns:
            响应数据字典
        """
        # 创建SSL上下文
        if self.verify_ssl:
            ssl_context = ssl.create_default_context()
        else:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        headers = {"User-Agent": self.user_agent}

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers)
                cookies = resp_headers.get("Set-Cookie", "")

                return {
                    "status": resp.status,
                    "headers": resp_headers,
                    "body": body[:100000],  # 限制大小
                    "cookies": cookies,
                }
        except urllib.error.HTTPError as e:
            # HTTP错误也可以获取头信息
            try:
                return {
                    "status": e.code,
                    "headers": dict(e.headers) if e.headers else {},
                    "body": "",
                    "cookies": "",
                }
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        except Exception as e:
            self._logger.debug(f"Request error for {url}: {e}")

        return None

    def get_favicon_hash(self, url: str) -> Optional[str]:
        """获取favicon哈希值

        用于识别特定应用（如Shodan使用的方式）。

        Args:
            url: 目标URL

        Returns:
            Favicon的MMH3哈希值
        """
        import base64

        favicon_url = url.rstrip("/") + "/favicon.ico"

        try:
            # 创建SSL上下文
            if self.verify_ssl:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            headers = {"User-Agent": self.user_agent}
            req = urllib.request.Request(favicon_url, headers=headers)

            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as resp:
                content = resp.read()
                if content:
                    # 计算MD5哈希
                    md5_hash = hashlib.md5(content).hexdigest()
                    # 计算Base64编码后的哈希（类似Shodan）
                    b64 = base64.b64encode(content).decode("utf-8")
                    return md5_hash

        except Exception as e:
            self._logger.debug(f"Favicon fetch error: {e}")

        return None

    def add_custom_rule(
        self,
        category: str,
        name: str,
        rule: FingerprintRule
    ) -> None:
        """添加自定义指纹规则

        Args:
            category: 类别
            name: 名称
            rule: 指纹规则
        """
        if category not in self.FINGERPRINTS:
            self.FINGERPRINTS[category] = {}
        if name not in self.FINGERPRINTS[category]:
            self.FINGERPRINTS[category][name] = []

        self.FINGERPRINTS[category][name].append(rule)
        # 重新编译规则
        self._compiled_rules = self._compile_rules()


# 便捷函数
def identify_fingerprints(
    url: str,
    timeout: float = 10.0,
    verify_ssl: bool = True
) -> List[Fingerprint]:
    """便捷函数：识别目标指纹

    Args:
        url: 目标URL
        timeout: 超时时间
        verify_ssl: 是否验证SSL

    Returns:
        指纹列表
    """
    engine = FingerprintEngine(timeout=timeout, verify_ssl=verify_ssl)
    return engine.identify(url)


# 导出
__all__ = [
    "FingerprintCategory",
    "Fingerprint",
    "FingerprintRule",
    "FingerprintEngine",
    "identify_fingerprints",
]
