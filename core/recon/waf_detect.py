#!/usr/bin/env python3
"""
waf_detect.py - WAF检测模块

检测目标是否部署了Web应用防火墙（WAF）。

使用方式:
    from core.recon.waf_detect import WAFDetector, WAFInfo

    detector = WAFDetector()
    waf = detector.detect("https://example.com")

    if waf:
        print(f"Detected WAF: {waf.name}")
"""

import re
import ssl
import socket
import logging
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Pattern, Tuple


logger = logging.getLogger(__name__)


@dataclass
class WAFInfo:
    """WAF信息

    Attributes:
        name: WAF名称
        vendor: 厂商
        confidence: 置信度 (0-100)
        evidence: 检测证据
        bypass_hints: 绕过提示
        metadata: 额外元数据
    """
    name: str
    vendor: Optional[str] = None
    confidence: int = 0
    evidence: List[str] = field(default_factory=list)
    bypass_hints: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "vendor": self.vendor,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "bypass_hints": self.bypass_hints,
            "metadata": self.metadata,
        }


class WAFDetector:
    """WAF检测器

    通过发送特定请求并分析响应来检测WAF。

    Attributes:
        timeout: 请求超时时间
        verify_ssl: 是否验证SSL证书
        user_agent: 自定义User-Agent
        aggressive: 是否使用激进模式（发送恶意payload）
    """

    # WAF签名规则
    WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
        # 国际WAF
        "Cloudflare": {
            "vendor": "Cloudflare, Inc.",
            "headers": {
                "CF-RAY": None,
                "Server": r"cloudflare",
                "CF-Cache-Status": None,
            },
            "cookies": ["__cf_bm", "__cfduid", "cf_clearance"],
            "body": [r"Attention Required! \| Cloudflare", r"cloudflare\.com/cdn-cgi/"],
            "status_codes": [403, 503],
            "bypass_hints": [
                "尝试找到源站IP绑定Host访问",
                "查找DNS历史记录获取真实IP",
                "使用Cloudflare支持的HTTP方法绕过",
            ],
        },
        "AWS WAF": {
            "vendor": "Amazon Web Services",
            "headers": {
                "X-Amzn-ErrorType": None,
                "X-Amzn-RequestId": None,
            },
            "body": [r"Request blocked", r"AWS WAF"],
            "status_codes": [403],
            "bypass_hints": [
                "尝试使用不同的Content-Type",
                "参数污染可能有效",
            ],
        },
        "Akamai": {
            "vendor": "Akamai Technologies",
            "headers": {
                "X-Akamai-Transformed": None,
                "Server": r"AkamaiGHost",
            },
            "cookies": ["ak_bmsc", "_abck", "bm_sz"],
            "body": [r"Access Denied", r"AkamaiGHost"],
            "status_codes": [403],
            "bypass_hints": [
                "Akamai规则通常较严格，建议尝试编码绕过",
            ],
        },
        "Imperva/Incapsula": {
            "vendor": "Imperva",
            "headers": {
                "X-CDN": r"Incapsula",
                "X-Iinfo": None,
            },
            "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
            "body": [r"Incapsula incident", r"_Incapsula_Resource"],
            "status_codes": [403],
            "bypass_hints": [
                "尝试使用Unicode编码",
                "检查是否有白名单路径",
            ],
        },
        "Sucuri": {
            "vendor": "Sucuri",
            "headers": {
                "X-Sucuri-ID": None,
                "X-Sucuri-Cache": None,
                "Server": r"Sucuri",
            },
            "body": [r"Sucuri WebSite Firewall", r"sucuri\.net"],
            "status_codes": [403],
            "bypass_hints": [
                "尝试查找源站IP",
            ],
        },
        "F5 BIG-IP ASM": {
            "vendor": "F5 Networks",
            "headers": {
                "X-WA-Info": None,
            },
            "cookies": ["TS", "BIGipServer", "F5_"],
            "body": [r"Request Rejected", r"BIG-IP"],
            "status_codes": [403],
            "bypass_hints": [
                "尝试HPP（HTTP参数污染）",
                "使用分块传输编码",
            ],
        },
        "Fortinet FortiWeb": {
            "vendor": "Fortinet",
            "headers": {
                "Server": r"FortiWeb",
            },
            "cookies": ["FORTIWAFSID"],
            "body": [r"FortiWeb", r"\.fwb"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "Barracuda": {
            "vendor": "Barracuda Networks",
            "headers": {},
            "cookies": ["barra_counter_session"],
            "body": [r"Barracuda", r"barracudanetworks\.com"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "ModSecurity": {
            "vendor": "OWASP/Trustwave",
            "headers": {
                "Server": r"mod_security|NOYB",
            },
            "body": [r"Mod_Security", r"ModSecurity", r"OWASP"],
            "status_codes": [403, 406],
            "bypass_hints": [
                "尝试使用不同的编码方式",
                "检查CRS规则集版本",
            ],
        },

        # 国内WAF
        "阿里云盾": {
            "vendor": "阿里云",
            "headers": {
                "X-Server-Id": None,
            },
            "cookies": ["aliyungf_tc"],
            "body": [r"alicdn\.com", r"aliyun", r"阿里云盾"],
            "status_codes": [405],
            "bypass_hints": [
                "尝试使用分块传输",
                "参数位置变换可能有效",
            ],
        },
        "腾讯云WAF": {
            "vendor": "腾讯云",
            "headers": {
                "Server": r"tencent",
            },
            "cookies": ["TGWSESSIONID"],
            "body": [r"waf\.tencent", r"腾讯云"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "百度云加速": {
            "vendor": "百度",
            "headers": {
                "Server": r"Yunjiasu",
            },
            "cookies": ["__bsi"],
            "body": [r"yunjiasu", r"百度云加速"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "安全狗": {
            "vendor": "安全狗",
            "headers": {
                "X-Powered-By-Anquanbao": None,
            },
            "cookies": ["safedog"],
            "body": [r"安全狗", r"safedog", r"www\.safedog\.cn"],
            "status_codes": [403],
            "bypass_hints": [
                "安全狗规则可能较旧，尝试新的绕过技术",
            ],
        },
        "云锁": {
            "vendor": "云锁",
            "headers": {
                "Server": r"yunsuo",
            },
            "cookies": ["yunsuo_session"],
            "body": [r"云锁", r"yunsuo"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "360网站卫士": {
            "vendor": "360",
            "headers": {
                "X-Powered-By-360WZB": None,
                "Server": r"360wzb",
            },
            "cookies": ["360wzws"],
            "body": [r"360wzb", r"360网站卫士"],
            "status_codes": [493],
            "bypass_hints": [],
        },
        "知道创宇加速乐": {
            "vendor": "知道创宇",
            "headers": {},
            "cookies": ["jsl_clearance", "jsluid"],
            "body": [r"加速乐", r"jiasule"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "创宇盾": {
            "vendor": "知道创宇",
            "headers": {},
            "cookies": ["kreep_token"],
            "body": [r"创宇盾", r"knownsec"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "长亭SafeLine": {
            "vendor": "长亭科技",
            "headers": {
                "X-Protected-By": r"SafeLine",
            },
            "body": [r"SafeLine", r"长亭"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "D盾": {
            "vendor": "D盾",
            "headers": {},
            "cookies": [],
            "body": [r"D盾", r"d_safe"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "网神SecGate": {
            "vendor": "网神信息",
            "headers": {},
            "cookies": [],
            "body": [r"SecGate", r"网神"],
            "status_codes": [403],
            "bypass_hints": [],
        },
        "宝塔WAF": {
            "vendor": "宝塔",
            "headers": {},
            "cookies": [],
            "body": [r"宝塔", r"BTPanel", r"bt\.cn"],
            "status_codes": [403],
            "bypass_hints": [
                "宝塔WAF规则相对简单",
            ],
        },
    }

    # 恶意payload用于触发WAF
    MALICIOUS_PAYLOADS = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../etc/passwd",
        "<?php echo 1; ?>",
        "${7*7}",
        "{{7*7}}",
        "cmd=whoami",
        "exec('/bin/bash')",
    ]

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        aggressive: bool = True
    ):
        """初始化WAF检测器

        Args:
            timeout: 请求超时时间
            verify_ssl: 是否验证SSL证书
            user_agent: 自定义User-Agent
            aggressive: 是否使用激进模式
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.aggressive = aggressive

        # 编译正则表达式
        self._compiled_signatures = self._compile_signatures()

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _compile_signatures(self) -> Dict[str, Dict[str, Any]]:
        """编译所有签名的正则表达式"""
        compiled = {}

        for name, sig in self.WAF_SIGNATURES.items():
            compiled[name] = {
                "vendor": sig.get("vendor"),
                "bypass_hints": sig.get("bypass_hints", []),
                "status_codes": sig.get("status_codes", []),
            }

            # 编译headers规则
            if sig.get("headers"):
                compiled[name]["headers"] = {}
                for header, pattern in sig["headers"].items():
                    if pattern:
                        compiled[name]["headers"][header] = re.compile(pattern, re.IGNORECASE)
                    else:
                        compiled[name]["headers"][header] = None

            # 保存cookies规则
            if sig.get("cookies"):
                compiled[name]["cookies"] = sig["cookies"]

            # 编译body规则
            if sig.get("body"):
                compiled[name]["body"] = [
                    re.compile(p, re.IGNORECASE) for p in sig["body"]
                ]

        return compiled

    def detect(self, url: str) -> Optional[WAFInfo]:
        """检测目标WAF

        Args:
            url: 目标URL

        Returns:
            WAFInfo对象，未检测到返回None
        """
        # 首先发送正常请求
        normal_response = self._make_request(url)
        if not normal_response:
            return None

        detected = self._check_signatures(normal_response)
        if detected:
            return detected

        # 如果正常请求未检测到，尝试发送恶意请求
        if self.aggressive:
            for payload in self.MALICIOUS_PAYLOADS:
                malicious_url = f"{url}?test={urllib.parse.quote(payload)}"
                malicious_response = self._make_request(malicious_url)
                if malicious_response:
                    detected = self._check_signatures(malicious_response, is_blocked=True)
                    if detected:
                        return detected

        return None

    def detect_from_response(
        self,
        headers: Dict[str, str],
        body: str,
        cookies: str = "",
        status_code: int = 200
    ) -> Optional[WAFInfo]:
        """从响应数据检测WAF

        Args:
            headers: 响应头
            body: 响应体
            cookies: Cookie字符串
            status_code: HTTP状态码

        Returns:
            WAFInfo对象
        """
        response = {
            "headers": headers,
            "body": body,
            "cookies": cookies,
            "status": status_code,
        }
        return self._check_signatures(response)

    def _check_signatures(
        self,
        response: Dict[str, Any],
        is_blocked: bool = False
    ) -> Optional[WAFInfo]:
        """检查响应是否匹配WAF签名

        Args:
            response: 响应数据
            is_blocked: 是否为被拦截的响应

        Returns:
            WAFInfo对象
        """
        headers = response.get("headers", {})
        body = response.get("body", "")
        cookies = response.get("cookies", "")
        status = response.get("status", 200)

        best_match: Optional[Tuple[str, int, List[str]]] = None

        for name, sig in self._compiled_signatures.items():
            confidence = 0
            evidence = []

            # 检查状态码
            if is_blocked and sig.get("status_codes"):
                if status in sig["status_codes"]:
                    confidence += 20
                    evidence.append(f"Status code: {status}")

            # 检查headers
            if sig.get("headers"):
                for header_name, pattern in sig["headers"].items():
                    header_value = headers.get(header_name, "")
                    if header_value:
                        if pattern:
                            if pattern.search(header_value):
                                confidence += 40
                                evidence.append(f"Header {header_name}: {header_value[:50]}")
                        else:
                            confidence += 30
                            evidence.append(f"Header {header_name} exists")

            # 检查cookies
            if sig.get("cookies"):
                for cookie_name in sig["cookies"]:
                    if cookie_name.lower() in cookies.lower():
                        confidence += 30
                        evidence.append(f"Cookie: {cookie_name}")

            # 检查body
            if sig.get("body"):
                for pattern in sig["body"]:
                    if pattern.search(body):
                        confidence += 30
                        evidence.append("Body pattern matched")
                        break

            # 更新最佳匹配
            if confidence > 0:
                if best_match is None or confidence > best_match[1]:
                    best_match = (name, confidence, evidence)

        if best_match:
            name, confidence, evidence = best_match
            sig = self._compiled_signatures[name]

            return WAFInfo(
                name=name,
                vendor=sig.get("vendor"),
                confidence=min(confidence, 100),
                evidence=evidence,
                bypass_hints=sig.get("bypass_hints", []),
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
                    "body": body[:50000],
                    "cookies": cookies,
                }
        except urllib.error.HTTPError as e:
            # HTTP错误响应也可能包含WAF信息
            try:
                body = ""
                if e.fp:
                    body = e.fp.read().decode("utf-8", errors="replace")
                return {
                    "status": e.code,
                    "headers": dict(e.headers) if e.headers else {},
                    "body": body[:50000],
                    "cookies": e.headers.get("Set-Cookie", "") if e.headers else "",
                }
            except Exception:
                pass
        except Exception as e:
            self._logger.debug(f"Request error for {url}: {e}")

        return None

    def quick_check(self, url: str) -> bool:
        """快速检查是否存在WAF

        Args:
            url: 目标URL

        Returns:
            是否检测到WAF
        """
        waf = self.detect(url)
        return waf is not None

    def get_all_waf_names(self) -> List[str]:
        """获取所有支持检测的WAF名称"""
        return list(self.WAF_SIGNATURES.keys())

    def get_waf_info(self, name: str) -> Optional[Dict[str, Any]]:
        """获取指定WAF的签名信息"""
        return self.WAF_SIGNATURES.get(name)


# 便捷函数
def detect_waf(
    url: str,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    aggressive: bool = True
) -> Optional[WAFInfo]:
    """便捷函数：检测目标WAF

    Args:
        url: 目标URL
        timeout: 超时时间
        verify_ssl: 是否验证SSL
        aggressive: 是否使用激进模式

    Returns:
        WAFInfo对象
    """
    detector = WAFDetector(
        timeout=timeout,
        verify_ssl=verify_ssl,
        aggressive=aggressive
    )
    return detector.detect(url)


def is_waf_protected(url: str) -> bool:
    """便捷函数：检查URL是否有WAF保护"""
    detector = WAFDetector()
    return detector.quick_check(url)


# 导出
__all__ = [
    "WAFInfo",
    "WAFDetector",
    "detect_waf",
    "is_waf_protected",
]
