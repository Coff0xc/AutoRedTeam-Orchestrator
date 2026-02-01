#!/usr/bin/env python3
"""
指纹伪装模块 - TLS/Browser Fingerprint Spoofer
功能: JA3指纹伪装、浏览器指纹模拟、TLS配置定制
用于绕过基于TLS指纹的WAF检测
"""

import hashlib
import logging
import random
import ssl
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 尝试导入高级 TLS 库
try:
    pass

    HAS_URLLIB3 = True
except ImportError:
    HAS_URLLIB3 = False


class BrowserType(Enum):
    """浏览器类型"""

    CHROME = "chrome"
    FIREFOX = "firefox"
    SAFARI = "safari"
    EDGE = "edge"
    CURL = "curl"
    PYTHON_REQUESTS = "python_requests"


@dataclass
class TLSFingerprint:
    """TLS 指纹配置"""

    # TLS 版本
    tls_version: str = "TLSv1.2"

    # Cipher Suites (按优先级排序)
    cipher_suites: List[str] = field(default_factory=list)

    # TLS Extensions
    extensions: List[int] = field(default_factory=list)

    # Elliptic Curves
    elliptic_curves: List[str] = field(default_factory=list)

    # EC Point Formats
    ec_point_formats: List[str] = field(default_factory=list)

    # ALPN Protocols
    alpn_protocols: List[str] = field(default_factory=list)

    # JA3 指纹 (自动计算)
    _ja3_hash: Optional[str] = None

    @property
    def ja3_hash(self) -> str:
        """计算 JA3 指纹哈希"""
        if self._ja3_hash:
            return self._ja3_hash

        # JA3 = TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
        # 这里是简化版本，实际 JA3 需要从原始 ClientHello 计算
        ja3_string = f"{self.tls_version},{','.join(self.cipher_suites[:10])}"
        self._ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()
        return self._ja3_hash


@dataclass
class BrowserProfile:
    """浏览器完整指纹配置"""

    browser_type: BrowserType
    version: str
    os: str

    # HTTP Headers
    user_agent: str
    accept: str
    accept_language: str
    accept_encoding: str

    # TLS 配置
    tls_fingerprint: TLSFingerprint

    # HTTP/2 配置
    http2_settings: Dict[str, int] = field(default_factory=dict)
    http2_window_size: int = 65535
    http2_header_table_size: int = 4096

    # 额外 Headers
    extra_headers: Dict[str, str] = field(default_factory=dict)


class JA3Spoofer:
    """
    JA3 指纹伪装器

    JA3 是一种 TLS 客户端指纹方法，用于识别 TLS 客户端。
    许多 WAF (如 Cloudflare) 使用 JA3 来识别和阻止非浏览器流量。

    工作原理:
    - JA3 基于 TLS ClientHello 中的以下字段:
      1. TLS Version
      2. Cipher Suites
      3. Extensions
      4. Elliptic Curves
      5. EC Point Formats

    伪装方法:
    - 使用与真实浏览器相同的 TLS 配置
    - 定制 SSL Context 的 Cipher Suites 顺序
    """

    # 真实浏览器的 JA3 指纹库
    BROWSER_JA3 = {
        BrowserType.CHROME: {
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
            "cipher_suites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
            "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27],
        },
        BrowserType.FIREFOX: {
            "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28,29-23-24-25,0",
            "cipher_suites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ],
            "extensions": [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28],
        },
        BrowserType.SAFARI: {
            "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49188-49187-49162-49161-49192-49191-49172-49171-157-156-61-60-53-47-255,0-23-65281-10-11-16-5-13-18-51-45-43-27,29-23-24,0",
            "cipher_suites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            ],
            "extensions": [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27],
        },
    }

    # Python requests 默认 JA3 (容易被检测)
    PYTHON_JA3 = "771,49200-49196-49192-49188-49172-49162-159-107-57-52393-52392-52394-65413-196-136-129-157-61-53-192-132-49199-49195-49191-49187-49171-49161-158-103-51-190-69-156-60-47-186-65-49169-49159-5-4-49170-49160-22-10-255,0-11-10-35-16-22-23-13,29-23-25-24,0-1-2"

    def __init__(self, browser: BrowserType = BrowserType.CHROME):
        self.browser = browser
        self._ja3_config = self.BROWSER_JA3.get(browser, self.BROWSER_JA3[BrowserType.CHROME])

    def create_ssl_context(self) -> ssl.SSLContext:
        """
        创建伪装的 SSL Context

        注意: Python 的 ssl 模块对 Cipher Suites 顺序控制有限，
        完整的 JA3 伪装需要使用底层 TLS 库或专用工具
        """
        # 创建现代化的 SSL Context
        context = ssl.create_default_context()

        # 设置最低 TLS 版本
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # 设置 Cipher Suites (按浏览器配置)
        cipher_string = self._build_cipher_string()
        try:
            context.set_ciphers(cipher_string)
        except ssl.SSLError as e:
            logger.warning(f"Failed to set ciphers: {e}, using default")

        # 设置 ALPN (HTTP/2 支持)
        try:
            context.set_alpn_protocols(["h2", "http/1.1"])
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 禁用证书验证 (渗透测试场景)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        return context

    def _build_cipher_string(self) -> str:
        """构建 Cipher Suite 字符串"""
        # OpenSSL 格式的 Cipher 名称映射
        cipher_map = {
            "TLS_AES_128_GCM_SHA256": "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384": "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256": "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
        }

        ciphers = []
        for suite in self._ja3_config.get("cipher_suites", []):
            if suite in cipher_map:
                ciphers.append(cipher_map[suite])
            else:
                ciphers.append(suite)

        return ":".join(ciphers) if ciphers else "DEFAULT"

    def get_ja3_fingerprint(self) -> str:
        """获取当前配置的 JA3 指纹"""
        return self._ja3_config.get("ja3", "")


class BrowserProfileFactory:
    """浏览器配置工厂"""

    @staticmethod
    def create_chrome_profile(version: str = "120") -> BrowserProfile:
        """创建 Chrome 浏览器配置"""
        return BrowserProfile(
            browser_type=BrowserType.CHROME,
            version=version,
            os="Windows NT 10.0; Win64; x64",
            user_agent=f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36",
            accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            accept_language="en-US,en;q=0.9",
            accept_encoding="gzip, deflate, br",
            tls_fingerprint=TLSFingerprint(
                tls_version="TLSv1.3",
                cipher_suites=[
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ],
                alpn_protocols=["h2", "http/1.1"],
            ),
            http2_settings={
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 1000,
                "INITIAL_WINDOW_SIZE": 6291456,
                "MAX_HEADER_LIST_SIZE": 262144,
            },
            extra_headers={
                "Sec-Ch-Ua": f'"Not_A Brand";v="8", "Chromium";v="{version}", "Google Chrome";v="{version}"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            },
        )

    @staticmethod
    def create_firefox_profile(version: str = "121") -> BrowserProfile:
        """创建 Firefox 浏览器配置"""
        return BrowserProfile(
            browser_type=BrowserType.FIREFOX,
            version=version,
            os="Windows NT 10.0; Win64; x64",
            user_agent=f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}.0) Gecko/20100101 Firefox/{version}.0",
            accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            accept_language="en-US,en;q=0.5",
            accept_encoding="gzip, deflate, br",
            tls_fingerprint=TLSFingerprint(
                tls_version="TLSv1.3",
                cipher_suites=[
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                ],
                alpn_protocols=["h2", "http/1.1"],
            ),
            http2_settings={
                "HEADER_TABLE_SIZE": 65536,
                "INITIAL_WINDOW_SIZE": 131072,
                "MAX_FRAME_SIZE": 16384,
            },
            extra_headers={
                "Upgrade-Insecure-Requests": "1",
                "DNT": "1",
            },
        )

    @staticmethod
    def create_safari_profile(version: str = "17.2") -> BrowserProfile:
        """创建 Safari 浏览器配置"""
        return BrowserProfile(
            browser_type=BrowserType.SAFARI,
            version=version,
            os="Macintosh; Intel Mac OS X 10_15_7",
            user_agent=f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15",
            accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            accept_language="en-US,en;q=0.9",
            accept_encoding="gzip, deflate, br",
            tls_fingerprint=TLSFingerprint(
                tls_version="TLSv1.3",
                cipher_suites=[
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ],
                alpn_protocols=["h2", "http/1.1"],
            ),
            http2_settings={
                "HEADER_TABLE_SIZE": 4096,
                "INITIAL_WINDOW_SIZE": 65535,
            },
            extra_headers={},
        )

    @staticmethod
    def create_random_profile() -> BrowserProfile:
        """创建随机浏览器配置"""
        profiles = [
            BrowserProfileFactory.create_chrome_profile,
            BrowserProfileFactory.create_firefox_profile,
            BrowserProfileFactory.create_safari_profile,
        ]
        return random.choice(profiles)()


class FingerprintSpoofer:
    """
    综合指纹伪装器

    Usage:
        spoofer = FingerprintSpoofer()

        # 获取伪装配置
        config = spoofer.get_request_config()

        # 使用配置发送请求
        # requests.get(url, headers=config['headers'], ...)

        # 或获取 SSL Context
        ssl_ctx = spoofer.get_ssl_context()
    """

    def __init__(self, browser: BrowserType = None):
        """
        Args:
            browser: 指定浏览器类型，None 则随机选择
        """
        if browser:
            self.profile = self._create_profile(browser)
        else:
            self.profile = BrowserProfileFactory.create_random_profile()

        self.ja3_spoofer = JA3Spoofer(self.profile.browser_type)

    def _create_profile(self, browser: BrowserType) -> BrowserProfile:
        """创建指定浏览器配置"""
        factory_map = {
            BrowserType.CHROME: BrowserProfileFactory.create_chrome_profile,
            BrowserType.FIREFOX: BrowserProfileFactory.create_firefox_profile,
            BrowserType.SAFARI: BrowserProfileFactory.create_safari_profile,
        }
        factory = factory_map.get(browser, BrowserProfileFactory.create_chrome_profile)
        return factory()

    def get_headers(self) -> Dict[str, str]:
        """获取伪装的 HTTP Headers"""
        headers = {
            "User-Agent": self.profile.user_agent,
            "Accept": self.profile.accept,
            "Accept-Language": self.profile.accept_language,
            "Accept-Encoding": self.profile.accept_encoding,
        }

        # 添加额外的浏览器特定 Headers
        headers.update(self.profile.extra_headers)

        return headers

    def get_ssl_context(self) -> ssl.SSLContext:
        """获取伪装的 SSL Context"""
        return self.ja3_spoofer.create_ssl_context()

    def get_request_config(self) -> Dict[str, Any]:
        """
        获取完整的请求配置

        Returns:
            Dict with keys: headers, ssl_context, http2_settings
        """
        return {
            "headers": self.get_headers(),
            "ssl_context": self.get_ssl_context(),
            "http2_settings": self.profile.http2_settings,
            "browser_type": self.profile.browser_type.value,
            "ja3_fingerprint": self.ja3_spoofer.get_ja3_fingerprint(),
        }

    def apply_to_session(self, session) -> None:
        """
        将指纹配置应用到 requests.Session

        Args:
            session: requests.Session 实例
        """
        session.headers.update(self.get_headers())

        # 注意: requests 默认不支持自定义 SSL Context
        # 需要使用 HTTPAdapter 或其他方式
        logger.info(f"Applied {self.profile.browser_type.value} fingerprint to session")


class HTTPAdapter:
    """
    自定义 HTTP 适配器 (用于 requests 库)

    Usage:
        import requests
        from fingerprint_spoofer import HTTPAdapter, FingerprintSpoofer

        session = requests.Session()
        spoofer = FingerprintSpoofer()
        adapter = HTTPAdapter(spoofer)

        session.mount('https://', adapter)
    """

    def __init__(self, spoofer: FingerprintSpoofer):
        self.spoofer = spoofer
        self._ssl_context = spoofer.get_ssl_context()

    def get_connection(self, url: str, proxies=None):
        """获取连接 (需要配合 urllib3 使用)"""
        if not HAS_URLLIB3:
            return None

        from urllib3.util.ssl_ import create_urllib3_context

        # 创建自定义 SSL Context
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        return ctx


# 便捷函数
def get_stealth_headers(browser: str = "chrome") -> Dict[str, str]:
    """获取隐蔽的 HTTP Headers"""
    browser_map = {
        "chrome": BrowserType.CHROME,
        "firefox": BrowserType.FIREFOX,
        "safari": BrowserType.SAFARI,
    }
    browser_type = browser_map.get(browser.lower(), BrowserType.CHROME)
    spoofer = FingerprintSpoofer(browser_type)
    return spoofer.get_headers()


def get_stealth_ssl_context(browser: str = "chrome") -> ssl.SSLContext:
    """获取隐蔽的 SSL Context"""
    browser_map = {
        "chrome": BrowserType.CHROME,
        "firefox": BrowserType.FIREFOX,
        "safari": BrowserType.SAFARI,
    }
    browser_type = browser_map.get(browser.lower(), BrowserType.CHROME)
    spoofer = FingerprintSpoofer(browser_type)
    return spoofer.get_ssl_context()


if __name__ == "__main__":
    # 测试
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    spoofer = FingerprintSpoofer(BrowserType.CHROME)

    logger.info("Browser Profile:")
    logger.info(f"  Type: {spoofer.profile.browser_type.value}")
    logger.info(f"  Version: {spoofer.profile.version}")
    logger.info(f"  User-Agent: {spoofer.profile.user_agent[:60]}...")

    logger.info("Headers:")
    for k, v in spoofer.get_headers().items():
        logger.info(f"  {k}: {v[:50]}..." if len(str(v)) > 50 else f"  {k}: {v}")

    logger.info(f"JA3 Fingerprint: {spoofer.ja3_spoofer.get_ja3_fingerprint()[:50]}...")
