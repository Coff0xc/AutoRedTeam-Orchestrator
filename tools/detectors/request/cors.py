#!/usr/bin/env python3
"""
CORS 检测器 - 基于 BaseDetector 重构

支持检测类型:
- Origin 反射漏洞
- 通配符 Origin (*)
- Null Origin 允许
- 子域名绕过
- 凭证泄露风险
"""

import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.detectors.base import BaseDetector, Vulnerability


class CORSDetector(BaseDetector):
    """CORS 跨域资源共享配置检测器"""

    # 测试 Origin 列表
    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "https://malicious-site.com",
        "null",  # iframe sandbox
    ]

    # CORS 相关响应头
    CORS_HEADERS = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
        "Access-Control-Expose-Headers",
        "Access-Control-Max-Age",
    ]

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取 Payload 库 - CORS 检测使用 Origin 头"""
        return {
            "Origin Reflection": self.TEST_ORIGINS,
            "Subdomain Bypass": [],  # 动态生成
            "Null Origin": ["null"],
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 CORS 漏洞"""
        if not response or not response.get("success"):
            return False

        headers = response.get("headers", {})
        acao = self._get_header(headers, "Access-Control-Allow-Origin")

        # 检查是否反射了恶意 Origin
        if acao and (acao == payload or acao == "*"):
            return True

        return False

    def _get_header(self, headers: Dict[str, str], name: str) -> Optional[str]:
        """获取响应头 (不区分大小写)"""
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def _generate_subdomain_origins(self, url: str) -> List[str]:
        """生成子域名绕过 Origin"""
        parsed = urlparse(url)
        domain = parsed.netloc
        scheme = parsed.scheme

        # 移除端口
        if ":" in domain:
            domain = domain.split(":")[0]

        origins = [
            # 前缀绕过
            f"{scheme}://evil.{domain}",
            f"{scheme}://attacker.{domain}",
            # 后缀绕过
            f"{scheme}://{domain}.evil.com",
            f"{scheme}://{domain}.attacker.com",
            # 子域名
            f"{scheme}://sub.{domain}",
            f"{scheme}://test.{domain}",
            # 相似域名
            f"{scheme}://{domain}evil.com",
            f"{scheme}://evil{domain}",
        ]

        return origins

    def _send_cors_request(
        self,
        url: str,
        origin: str,
        method: str = "GET"
    ) -> Optional[Dict[str, Any]]:
        """发送带 Origin 头的请求"""
        if not self.session:
            return None

        try:
            headers = {
                "User-Agent": self.user_agent,
                "Origin": origin,
            }

            if method.upper() == "OPTIONS":
                # Preflight 请求
                headers["Access-Control-Request-Method"] = "POST"
                headers["Access-Control-Request-Headers"] = "Content-Type"
                resp = self.session.options(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
            else:
                resp = self.session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

            return {
                "success": True,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "response_text": resp.text,
                "response_length": len(resp.text),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def detect_origin_reflection(self, url: str) -> List[Vulnerability]:
        """检测 Origin 反射漏洞"""
        vulnerabilities = []

        for origin in self.TEST_ORIGINS:
            response = self._send_cors_request(url, origin)

            if not response or not response.get("success"):
                continue

            headers = response.get("headers", {})
            acao = self._get_header(headers, "Access-Control-Allow-Origin")
            acac = self._get_header(headers, "Access-Control-Allow-Credentials")

            if not acao:
                continue

            # 检查 Origin 反射
            if acao == origin:
                severity = "HIGH" if acac and acac.lower() == "true" else "MEDIUM"

                vulnerabilities.append(Vulnerability(
                    type="CORS Origin Reflection",
                    severity=severity,
                    url=url,
                    payload=origin,
                    evidence=f"ACAO: {acao}" + (f", ACAC: {acac}" if acac else ""),
                    verified=True,
                    confidence=0.9,
                    details={
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "allows_credentials": acac and acac.lower() == "true"
                    }
                ))

        return vulnerabilities

    def detect_wildcard_origin(self, url: str) -> List[Vulnerability]:
        """检测通配符 Origin (*)"""
        vulnerabilities = []

        # 使用任意 Origin 测试
        response = self._send_cors_request(url, "https://test.com")

        if not response or not response.get("success"):
            return vulnerabilities

        headers = response.get("headers", {})
        acao = self._get_header(headers, "Access-Control-Allow-Origin")
        acac = self._get_header(headers, "Access-Control-Allow-Credentials")

        if acao == "*":
            # 通配符 + 凭证是严重问题
            if acac and acac.lower() == "true":
                severity = "CRITICAL"
                evidence = "ACAO: * 且允许携带凭证 (浏览器会阻止，但配置错误)"
            else:
                severity = "MEDIUM"
                evidence = "ACAO: * 允许任意来源访问"

            vulnerabilities.append(Vulnerability(
                type="CORS Wildcard Origin",
                severity=severity,
                url=url,
                evidence=evidence,
                verified=True,
                confidence=0.95,
                details={
                    "acao": acao,
                    "acac": acac,
                    "allows_credentials": acac and acac.lower() == "true"
                }
            ))

        return vulnerabilities

    def detect_null_origin(self, url: str) -> List[Vulnerability]:
        """检测 Null Origin 允许"""
        vulnerabilities = []

        response = self._send_cors_request(url, "null")

        if not response or not response.get("success"):
            return vulnerabilities

        headers = response.get("headers", {})
        acao = self._get_header(headers, "Access-Control-Allow-Origin")
        acac = self._get_header(headers, "Access-Control-Allow-Credentials")

        if acao == "null":
            severity = "HIGH" if acac and acac.lower() == "true" else "MEDIUM"

            vulnerabilities.append(Vulnerability(
                type="CORS Null Origin Allowed",
                severity=severity,
                url=url,
                payload="null",
                evidence=f"允许 null Origin，可通过 iframe sandbox 利用",
                verified=True,
                confidence=0.9,
                details={
                    "acao": acao,
                    "acac": acac,
                    "allows_credentials": acac and acac.lower() == "true",
                    "exploitation": "使用 <iframe sandbox='allow-scripts' src='data:text/html,...'> 发起请求"
                }
            ))

        return vulnerabilities

    def detect_subdomain_bypass(self, url: str) -> List[Vulnerability]:
        """检测子域名绕过"""
        vulnerabilities = []

        subdomain_origins = self._generate_subdomain_origins(url)

        for origin in subdomain_origins:
            response = self._send_cors_request(url, origin)

            if not response or not response.get("success"):
                continue

            headers = response.get("headers", {})
            acao = self._get_header(headers, "Access-Control-Allow-Origin")
            acac = self._get_header(headers, "Access-Control-Allow-Credentials")

            if acao == origin:
                severity = "HIGH" if acac and acac.lower() == "true" else "MEDIUM"

                vulnerabilities.append(Vulnerability(
                    type="CORS Subdomain Bypass",
                    severity=severity,
                    url=url,
                    payload=origin,
                    evidence=f"子域名/相似域名被允许: {origin}",
                    verified=True,
                    confidence=0.85,
                    details={
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "allows_credentials": acac and acac.lower() == "true"
                    }
                ))
                break  # 找到一个就停止

        return vulnerabilities

    def detect_preflight_bypass(self, url: str) -> List[Vulnerability]:
        """检测 Preflight 请求处理问题"""
        vulnerabilities = []

        # 发送 OPTIONS 请求
        response = self._send_cors_request(url, "https://evil.com", method="OPTIONS")

        if not response or not response.get("success"):
            return vulnerabilities

        headers = response.get("headers", {})
        acao = self._get_header(headers, "Access-Control-Allow-Origin")
        acam = self._get_header(headers, "Access-Control-Allow-Methods")
        acah = self._get_header(headers, "Access-Control-Allow-Headers")

        issues = []

        # 检查是否允许危险方法
        if acam:
            dangerous_methods = ["PUT", "DELETE", "PATCH"]
            allowed_dangerous = [m for m in dangerous_methods if m in acam.upper()]
            if allowed_dangerous:
                issues.append(f"允许危险方法: {', '.join(allowed_dangerous)}")

        # 检查是否允许敏感头
        if acah:
            sensitive_headers = ["Authorization", "X-Api-Key", "Cookie"]
            allowed_sensitive = [h for h in sensitive_headers if h.lower() in acah.lower()]
            if allowed_sensitive:
                issues.append(f"允许敏感头: {', '.join(allowed_sensitive)}")

        if issues and acao:
            vulnerabilities.append(Vulnerability(
                type="CORS Preflight Misconfiguration",
                severity="MEDIUM",
                url=url,
                evidence="; ".join(issues),
                verified=True,
                confidence=0.7,
                details={
                    "acao": acao,
                    "acam": acam,
                    "acah": acah,
                    "issues": issues
                }
            ))

        return vulnerabilities

    def detect(
        self,
        url: str,
        param: Optional[str] = None,
        deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        CORS 检测入口

        Args:
            url: 目标 URL
            param: 未使用 (保持接口一致)
            deep_scan: 是否深度扫描 (包含子域名绕过和 Preflight 检测)

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 1. 通配符 Origin 检测
        wildcard_vulns = self.detect_wildcard_origin(url)
        all_vulnerabilities.extend(wildcard_vulns)

        # 2. Origin 反射检测
        reflection_vulns = self.detect_origin_reflection(url)
        all_vulnerabilities.extend(reflection_vulns)

        # 3. Null Origin 检测
        null_vulns = self.detect_null_origin(url)
        all_vulnerabilities.extend(null_vulns)

        if deep_scan:
            # 4. 子域名绕过检测
            subdomain_vulns = self.detect_subdomain_bypass(url)
            all_vulnerabilities.extend(subdomain_vulns)

            # 5. Preflight 配置检测
            preflight_vulns = self.detect_preflight_bypass(url)
            all_vulnerabilities.extend(preflight_vulns)

        # 生成修复建议
        recommendations = []
        if all_vulnerabilities:
            recommendations = [
                "使用白名单验证 Origin，不要反射任意 Origin",
                "避免使用通配符 (*) 作为 Access-Control-Allow-Origin",
                "不要允许 null Origin",
                "谨慎使用 Access-Control-Allow-Credentials: true",
                "限制 Access-Control-Allow-Methods 只包含必要的方法",
                "限制 Access-Control-Allow-Headers 只包含必要的头",
            ]

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in all_vulnerabilities],
            "total": len(all_vulnerabilities),
            "verified_count": sum(1 for v in all_vulnerabilities if v.verified),
            "by_type": {
                "wildcard": sum(1 for v in all_vulnerabilities if "Wildcard" in v.type),
                "reflection": sum(1 for v in all_vulnerabilities if "Reflection" in v.type),
                "null_origin": sum(1 for v in all_vulnerabilities if "Null" in v.type),
                "subdomain_bypass": sum(1 for v in all_vulnerabilities if "Subdomain" in v.type),
                "preflight": sum(1 for v in all_vulnerabilities if "Preflight" in v.type),
            },
            "recommendations": recommendations
        }


# 便捷函数 - 兼容旧接口
def cors_detect(url: str, deep_scan: bool = True) -> Dict[str, Any]:
    """CORS 检测 (兼容旧接口)"""
    with CORSDetector() as detector:
        return detector.detect(url, deep_scan=deep_scan)


# 别名 - 兼容 cors_deep_check
cors_deep_check = cors_detect
