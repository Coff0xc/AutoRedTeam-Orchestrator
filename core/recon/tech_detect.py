#!/usr/bin/env python3
"""
tech_detect.py - 技术栈识别模块

基于Wappalyzer规则进行Web技术栈识别。

使用方式:
    from core.recon.tech_detect import TechDetector, Technology

    detector = TechDetector()
    technologies = detector.detect("https://example.com")

    for tech in technologies:
        print(f"{tech.name} ({tech.category}): {tech.version}")
"""

import re
import json
import ssl
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Pattern, Set, Tuple
from pathlib import Path


logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """技术信息

    Attributes:
        name: 技术名称
        category: 类别
        version: 版本号
        confidence: 置信度 (0-100)
        website: 官方网站
        icon: 图标文件名
        cpe: CPE标识
        implies: 依赖的其他技术
        metadata: 额外元数据
    """
    name: str
    category: str
    version: Optional[str] = None
    confidence: int = 100
    website: Optional[str] = None
    icon: Optional[str] = None
    cpe: Optional[str] = None
    implies: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
            "website": self.website,
            "cpe": self.cpe,
            "implies": self.implies,
        }


class TechDetector:
    """技术栈检测器

    基于Wappalyzer规则进行Web技术栈识别。

    Attributes:
        timeout: 请求超时时间
        verify_ssl: 是否验证SSL证书
        user_agent: 自定义User-Agent
    """

    # 内置技术规则（简化版Wappalyzer规则）
    TECHNOLOGIES: Dict[str, Dict[str, Any]] = {
        # Web服务器
        "Nginx": {
            "category": "Web Server",
            "headers": {"Server": r"nginx(?:/([0-9.]+))?"},
            "website": "https://nginx.org",
        },
        "Apache": {
            "category": "Web Server",
            "headers": {"Server": r"Apache(?:/([0-9.]+))?"},
            "website": "https://apache.org",
        },
        "Microsoft-IIS": {
            "category": "Web Server",
            "headers": {"Server": r"Microsoft-IIS(?:/([0-9.]+))?"},
            "website": "https://www.iis.net",
        },
        "OpenResty": {
            "category": "Web Server",
            "headers": {"Server": r"openresty(?:/([0-9.]+))?"},
            "website": "https://openresty.org",
        },
        "LiteSpeed": {
            "category": "Web Server",
            "headers": {"Server": r"LiteSpeed"},
            "website": "https://www.litespeedtech.com",
        },
        "Caddy": {
            "category": "Web Server",
            "headers": {"Server": r"Caddy"},
            "website": "https://caddyserver.com",
        },

        # 编程语言
        "PHP": {
            "category": "Programming Language",
            "headers": {"X-Powered-By": r"PHP(?:/([0-9.]+))?"},
            "cookies": {"PHPSESSID": ""},
            "website": "https://php.net",
        },
        "Python": {
            "category": "Programming Language",
            "headers": {"Server": r"Python(?:/([0-9.]+))?"},
            "website": "https://python.org",
        },
        "Java": {
            "category": "Programming Language",
            "cookies": {"JSESSIONID": ""},
            "website": "https://java.com",
        },
        "Ruby": {
            "category": "Programming Language",
            "headers": {"X-Powered-By": r"Phusion Passenger"},
            "website": "https://www.ruby-lang.org",
        },
        "ASP.NET": {
            "category": "Programming Language",
            "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": ""},
            "cookies": {"ASP.NET_SessionId": ""},
            "website": "https://dotnet.microsoft.com",
        },

        # Web框架
        "Laravel": {
            "category": "Web Framework",
            "cookies": {"laravel_session": "", "XSRF-TOKEN": ""},
            "website": "https://laravel.com",
            "implies": ["PHP"],
        },
        "Django": {
            "category": "Web Framework",
            "cookies": {"csrftoken": ""},
            "html": [r"__django_", r"csrfmiddlewaretoken"],
            "website": "https://djangoproject.com",
            "implies": ["Python"],
        },
        "Flask": {
            "category": "Web Framework",
            "headers": {"Server": r"Werkzeug(?:/([0-9.]+))?"},
            "website": "https://flask.palletsprojects.com",
            "implies": ["Python"],
        },
        "Express": {
            "category": "Web Framework",
            "headers": {"X-Powered-By": r"Express"},
            "website": "https://expressjs.com",
            "implies": ["Node.js"],
        },
        "Spring": {
            "category": "Web Framework",
            "headers": {"X-Application-Context": ""},
            "html": [r"Whitelabel Error Page"],
            "website": "https://spring.io",
            "implies": ["Java"],
        },
        "Ruby on Rails": {
            "category": "Web Framework",
            "headers": {"X-Powered-By": r"Phusion Passenger"},
            "html": [r"csrf-token", r"data-turbolinks-track"],
            "website": "https://rubyonrails.org",
            "implies": ["Ruby"],
        },
        "ThinkPHP": {
            "category": "Web Framework",
            "headers": {"X-Powered-By": r"ThinkPHP"},
            "html": [r"ThinkPHP"],
            "website": "https://www.thinkphp.cn",
            "implies": ["PHP"],
        },
        "FastAPI": {
            "category": "Web Framework",
            "html": [r'"openapi":\s*"3\.'],
            "website": "https://fastapi.tiangolo.com",
            "implies": ["Python"],
        },
        "Koa": {
            "category": "Web Framework",
            "headers": {"X-Powered-By": r"koa"},
            "website": "https://koajs.com",
            "implies": ["Node.js"],
        },

        # CMS
        "WordPress": {
            "category": "CMS",
            "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
            "meta": {"generator": r"WordPress(?:\s([0-9.]+))?"},
            "headers": {"X-Powered-By": r"WordPress"},
            "website": "https://wordpress.org",
            "implies": ["PHP", "MySQL"],
        },
        "Drupal": {
            "category": "CMS",
            "headers": {"X-Generator": r"Drupal(?:\s([0-9.]+))?"},
            "html": [r"Drupal\.settings", r"/sites/default/files/"],
            "website": "https://drupal.org",
            "implies": ["PHP"],
        },
        "Joomla": {
            "category": "CMS",
            "meta": {"generator": r"Joomla"},
            "html": [r"/media/jui/"],
            "website": "https://www.joomla.org",
            "implies": ["PHP"],
        },
        "Shopify": {
            "category": "E-commerce",
            "headers": {"X-ShopId": ""},
            "html": [r"cdn\.shopify\.com"],
            "website": "https://www.shopify.com",
        },
        "Magento": {
            "category": "E-commerce",
            "html": [r"/skin/frontend/", r"Mage\.Cookies"],
            "cookies": {"frontend": ""},
            "website": "https://magento.com",
            "implies": ["PHP"],
        },
        "Discuz!": {
            "category": "CMS",
            "html": [r"Discuz!", r"/uc_server/"],
            "website": "https://www.discuz.net",
            "implies": ["PHP"],
        },
        "DedeCMS": {
            "category": "CMS",
            "html": [r"DedeTag Engine", r"/dede/"],
            "website": "https://www.dedecms.com",
            "implies": ["PHP"],
        },
        "Typecho": {
            "category": "CMS",
            "html": [r"Typecho", r"/usr/themes/"],
            "meta": {"generator": r"Typecho"},
            "website": "https://typecho.org",
            "implies": ["PHP"],
        },

        # JavaScript框架
        "React": {
            "category": "JavaScript Framework",
            "html": [r"data-reactroot", r"data-reactid", r"react\."],
            "scripts": [r"react(?:\.min)?\.js"],
            "website": "https://reactjs.org",
        },
        "Vue.js": {
            "category": "JavaScript Framework",
            "html": [r"data-v-[a-f0-9]", r"__vue__"],
            "scripts": [r"vue(?:\.min)?\.js"],
            "website": "https://vuejs.org",
        },
        "Angular": {
            "category": "JavaScript Framework",
            "html": [r"ng-app", r"ng-controller", r"ng-model", r"\[ng-"],
            "scripts": [r"angular(?:\.min)?\.js"],
            "website": "https://angular.io",
        },
        "jQuery": {
            "category": "JavaScript Library",
            "scripts": [r"jquery[.-]?([0-9.]+)?(?:\.min)?\.js"],
            "html": [r"jQuery"],
            "website": "https://jquery.com",
        },
        "Bootstrap": {
            "category": "UI Framework",
            "html": [r'class="[^"]*\b(?:container|row|col-(?:xs|sm|md|lg|xl)-\d+)\b'],
            "scripts": [r"bootstrap(?:\.min)?\.js"],
            "website": "https://getbootstrap.com",
        },
        "Layui": {
            "category": "UI Framework",
            "scripts": [r"layui(?:\.all)?(?:\.min)?\.js"],
            "html": [r"layui-"],
            "website": "https://www.layui.com",
        },
        "Element UI": {
            "category": "UI Framework",
            "html": [r"el-button", r"el-input", r"el-form"],
            "website": "https://element.eleme.io",
            "implies": ["Vue.js"],
        },
        "Ant Design": {
            "category": "UI Framework",
            "html": [r"ant-btn", r"ant-input", r"antd"],
            "website": "https://ant.design",
            "implies": ["React"],
        },

        # CDN/Cloud
        "Cloudflare": {
            "category": "CDN",
            "headers": {"CF-RAY": "", "Server": r"cloudflare"},
            "cookies": {"__cf_bm": "", "__cfduid": ""},
            "website": "https://www.cloudflare.com",
        },
        "Akamai": {
            "category": "CDN",
            "headers": {"X-Akamai-Transformed": ""},
            "website": "https://www.akamai.com",
        },
        "Fastly": {
            "category": "CDN",
            "headers": {"X-Served-By": r"cache-", "Via": r"varnish"},
            "website": "https://www.fastly.com",
        },
        "Amazon CloudFront": {
            "category": "CDN",
            "headers": {"X-Amz-Cf-Id": "", "Via": r"CloudFront"},
            "website": "https://aws.amazon.com/cloudfront",
        },
        "Vercel": {
            "category": "PaaS",
            "headers": {"X-Vercel-Id": "", "Server": r"Vercel"},
            "website": "https://vercel.com",
        },

        # 安全
        "ModSecurity": {
            "category": "Security",
            "headers": {"Server": r"mod_security|NOYB"},
            "website": "https://modsecurity.org",
        },
        "Sucuri": {
            "category": "Security",
            "headers": {"X-Sucuri-ID": "", "Server": r"Sucuri"},
            "website": "https://sucuri.net",
        },

        # 分析/追踪
        "Google Analytics": {
            "category": "Analytics",
            "html": [r"google-analytics\.com/(?:ga|urchin)\.js", r"_gaq\.push", r"gtag\("],
            "scripts": [r"google-analytics\.com"],
            "website": "https://analytics.google.com",
        },
        "Baidu Analytics": {
            "category": "Analytics",
            "html": [r"hm\.baidu\.com"],
            "scripts": [r"hm\.baidu\.com/hm\.js"],
            "website": "https://tongji.baidu.com",
        },

        # 数据库
        "MySQL": {
            "category": "Database",
            "website": "https://www.mysql.com",
        },
        "PostgreSQL": {
            "category": "Database",
            "website": "https://www.postgresql.org",
        },
        "MongoDB": {
            "category": "Database",
            "website": "https://www.mongodb.com",
        },
        "Redis": {
            "category": "Database",
            "website": "https://redis.io",
        },

        # 运行时
        "Node.js": {
            "category": "Runtime",
            "website": "https://nodejs.org",
        },
    }

    # 技术类别
    CATEGORIES: List[str] = [
        "Web Server",
        "Programming Language",
        "Web Framework",
        "CMS",
        "E-commerce",
        "JavaScript Framework",
        "JavaScript Library",
        "UI Framework",
        "CDN",
        "PaaS",
        "Security",
        "Analytics",
        "Database",
        "Runtime",
    ]

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ):
        """初始化技术检测器

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

    def _compile_rules(self) -> Dict[str, Dict[str, Any]]:
        """编译所有规则的正则表达式"""
        compiled = {}

        for name, rules in self.TECHNOLOGIES.items():
            compiled[name] = {"category": rules.get("category", "Other")}

            # 编译headers规则
            if "headers" in rules:
                compiled[name]["headers"] = {}
                for header, pattern in rules["headers"].items():
                    if pattern:
                        compiled[name]["headers"][header] = re.compile(pattern, re.IGNORECASE)
                    else:
                        compiled[name]["headers"][header] = None

            # 编译cookies规则
            if "cookies" in rules:
                compiled[name]["cookies"] = list(rules["cookies"].keys())

            # 编译html规则
            if "html" in rules:
                compiled[name]["html"] = [
                    re.compile(p, re.IGNORECASE) for p in rules["html"]
                ]

            # 编译scripts规则
            if "scripts" in rules:
                compiled[name]["scripts"] = [
                    re.compile(p, re.IGNORECASE) for p in rules["scripts"]
                ]

            # 编译meta规则
            if "meta" in rules:
                compiled[name]["meta"] = {}
                for key, pattern in rules["meta"].items():
                    compiled[name]["meta"][key] = re.compile(pattern, re.IGNORECASE)

            # 保留其他信息
            compiled[name]["website"] = rules.get("website")
            compiled[name]["implies"] = rules.get("implies", [])

        return compiled

    def detect(self, url: str) -> List[Technology]:
        """检测目标使用的技术

        Args:
            url: 目标URL

        Returns:
            识别到的技术列表
        """
        technologies: List[Technology] = []
        detected_names: Set[str] = set()

        # 发送HTTP请求
        response = self._make_request(url)
        if not response:
            return technologies

        headers = response.get("headers", {})
        body = response.get("body", "")
        cookies = response.get("cookies", "")

        # 检查所有技术规则
        for name, rules in self._compiled_rules.items():
            tech = self._check_technology(name, rules, headers, body, cookies)
            if tech:
                detected_names.add(name)
                technologies.append(tech)

        # 处理implies（隐含的技术）
        for tech in technologies.copy():
            for implied_name in tech.implies:
                if implied_name not in detected_names and implied_name in self._compiled_rules:
                    implied_tech = Technology(
                        name=implied_name,
                        category=self._compiled_rules[implied_name].get("category", "Other"),
                        confidence=50,  # 隐含技术置信度较低
                        website=self._compiled_rules[implied_name].get("website"),
                    )
                    technologies.append(implied_tech)
                    detected_names.add(implied_name)

        # 按置信度排序
        technologies.sort(key=lambda x: x.confidence, reverse=True)
        return technologies

    def detect_from_response(
        self,
        headers: Dict[str, str],
        body: str,
        cookies: str = ""
    ) -> List[Technology]:
        """从响应数据检测技术

        Args:
            headers: 响应头
            body: 响应体
            cookies: Cookie字符串

        Returns:
            识别到的技术列表
        """
        technologies: List[Technology] = []
        detected_names: Set[str] = set()

        for name, rules in self._compiled_rules.items():
            tech = self._check_technology(name, rules, headers, body, cookies)
            if tech:
                detected_names.add(name)
                technologies.append(tech)

        # 处理implies
        for tech in technologies.copy():
            for implied_name in tech.implies:
                if implied_name not in detected_names and implied_name in self._compiled_rules:
                    implied_tech = Technology(
                        name=implied_name,
                        category=self._compiled_rules[implied_name].get("category", "Other"),
                        confidence=50,
                        website=self._compiled_rules[implied_name].get("website"),
                    )
                    technologies.append(implied_tech)
                    detected_names.add(implied_name)

        technologies.sort(key=lambda x: x.confidence, reverse=True)
        return technologies

    def _check_technology(
        self,
        name: str,
        rules: Dict[str, Any],
        headers: Dict[str, str],
        body: str,
        cookies: str
    ) -> Optional[Technology]:
        """检查单个技术

        Args:
            name: 技术名称
            rules: 编译后的规则
            headers: 响应头
            body: 响应体
            cookies: Cookie字符串

        Returns:
            Technology对象，不匹配返回None
        """
        version = None
        confidence = 0

        # 检查headers
        if "headers" in rules:
            for header_name, pattern in rules["headers"].items():
                header_value = headers.get(header_name, "")
                if header_value:
                    if pattern:
                        match = pattern.search(header_value)
                        if match:
                            confidence += 50
                            if match.groups():
                                version = match.group(1)
                    else:
                        # 只检查头部是否存在
                        confidence += 30

        # 检查cookies
        if "cookies" in rules:
            for cookie_name in rules["cookies"]:
                if cookie_name.lower() in cookies.lower():
                    confidence += 40

        # 检查html
        if "html" in rules:
            for pattern in rules["html"]:
                match = pattern.search(body)
                if match:
                    confidence += 30
                    if match.groups():
                        version = version or match.group(1)

        # 检查scripts
        if "scripts" in rules:
            for pattern in rules["scripts"]:
                match = pattern.search(body)
                if match:
                    confidence += 40
                    if match.groups():
                        version = version or match.group(1)

        # 检查meta标签
        if "meta" in rules:
            for meta_name, pattern in rules["meta"].items():
                # 提取meta标签内容
                meta_pattern = rf'<meta[^>]*name=["\']?{meta_name}["\']?[^>]*content=["\']?([^"\'>\s]+)'
                meta_match = re.search(meta_pattern, body, re.IGNORECASE)
                if meta_match:
                    content = meta_match.group(1)
                    if pattern.search(content):
                        confidence += 50
                        version_match = pattern.search(content)
                        if version_match and version_match.groups():
                            version = version or version_match.group(1)

        if confidence > 0:
            # 限制置信度最大值
            confidence = min(confidence, 100)

            return Technology(
                name=name,
                category=rules.get("category", "Other"),
                version=version,
                confidence=confidence,
                website=rules.get("website"),
                implies=rules.get("implies", []),
            )

        return None

    def _make_request(self, url: str) -> Optional[Dict[str, Any]]:
        """发送HTTP请求"""
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
                    "body": body[:200000],  # 限制大小
                    "cookies": cookies,
                }
        except urllib.error.HTTPError as e:
            try:
                return {
                    "status": e.code,
                    "headers": dict(e.headers) if e.headers else {},
                    "body": "",
                    "cookies": "",
                }
            except Exception:
                pass
        except Exception as e:
            self._logger.debug(f"Request error for {url}: {e}")

        return None

    def get_categories(self) -> List[str]:
        """获取所有技术类别"""
        return self.CATEGORIES.copy()

    def get_technologies_by_category(self, category: str) -> List[str]:
        """获取指定类别的所有技术"""
        return [
            name for name, rules in self.TECHNOLOGIES.items()
            if rules.get("category") == category
        ]

    def add_custom_technology(
        self,
        name: str,
        rules: Dict[str, Any]
    ) -> None:
        """添加自定义技术规则

        Args:
            name: 技术名称
            rules: 规则字典
        """
        self.TECHNOLOGIES[name] = rules
        # 重新编译规则
        self._compiled_rules = self._compile_rules()


# 便捷函数
def detect_technologies(
    url: str,
    timeout: float = 10.0,
    verify_ssl: bool = True
) -> List[Technology]:
    """便捷函数：检测目标技术栈

    Args:
        url: 目标URL
        timeout: 超时时间
        verify_ssl: 是否验证SSL

    Returns:
        技术列表
    """
    detector = TechDetector(timeout=timeout, verify_ssl=verify_ssl)
    return detector.detect(url)


# 导出
__all__ = [
    "Technology",
    "TechDetector",
    "detect_technologies",
]
