#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) 检测器

检测不安全的直接对象引用漏洞，包括:
- 数字 ID 遍历
- UUID/GUID 可预测性
- 路径参数越权
- 水平/垂直越权
"""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ..base import BaseDetector, Vulnerability


class IDORDetector(BaseDetector):
    """
    IDOR 漏洞检测器

    通过遍历对象引用参数检测不安全的直接对象引用漏洞。
    """

    # IDOR 专用测试参数
    DEFAULT_PARAMS = [
        "id",
        "user_id",
        "uid",
        "userid",
        "user",
        "account",
        "account_id",
        "profile",
        "profile_id",
        "doc",
        "document",
        "doc_id",
        "file",
        "file_id",
        "order",
        "order_id",
        "invoice",
        "invoice_id",
        "item",
        "item_id",
        "product",
        "product_id",
        "record",
        "record_id",
        "report",
        "report_id",
    ]

    # 测试 ID 值
    TEST_IDS = {
        "numeric": ["1", "2", "100", "1000", "0", "-1", "999999", "2147483647"],
        "sequential": ["1", "2", "3", "4", "5"],
        "boundary": ["0", "-1", "2147483647", "9999999999"],
        "special": ["null", "undefined", "NaN", "true", "false"],
    }

    # 敏感数据指示符
    SENSITIVE_INDICATORS = [
        # 个人信息
        r"email[\"']?\s*[:=]\s*[\"']?[\w.+-]+@[\w.-]+",
        r"phone[\"']?\s*[:=]\s*[\"']?[\d\s\-\+\(\)]+",
        r"address[\"']?\s*[:=]",
        r"ssn[\"']?\s*[:=]",
        r"credit[_\s]?card",
        r"password[\"']?\s*[:=]",
        # 财务信息
        r"balance[\"']?\s*[:=]\s*[\"']?[\d.,]+",
        r"amount[\"']?\s*[:=]\s*[\"']?[\d.,]+",
        r"salary[\"']?\s*[:=]",
        r"account[_\s]?number",
        # 用户数据
        r"username[\"']?\s*[:=]\s*[\"']?\w+",
        r"user[_\s]?name[\"']?\s*[:=]",
        r"full[_\s]?name[\"']?\s*[:=]",
        r"first[_\s]?name[\"']?\s*[:=]",
        r"last[_\s]?name[\"']?\s*[:=]",
    ]

    # 错误响应指示符
    ERROR_INDICATORS = [
        r"access\s*denied",
        r"unauthorized",
        r"forbidden",
        r"permission\s*denied",
        r"not\s*allowed",
        r"invalid\s*user",
        r"user\s*not\s*found",
        r"record\s*not\s*found",
        r"no\s*permission",
    ]

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取 IDOR 测试 Payload 库"""
        return self.TEST_IDS

    def validate_response(
        self, response: Dict[str, Any], payload: str, baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 IDOR 漏洞"""
        if not response.get("success"):
            return False

        status = response.get("status_code", 0)
        text = response.get("response_text", "")
        length = response.get("response_length", len(text))

        # 200 响应且有实质内容
        if status == 200 and length > 100:
            # 检查是否包含敏感数据
            for pattern in self.SENSITIVE_INDICATORS:
                if re.search(pattern, text, re.IGNORECASE):
                    return True

            # 如果有基线，比较响应差异
            if baseline:
                baseline_length = baseline.get("response_length", 0)
                # 响应长度显著不同可能表明返回了不同用户的数据
                if abs(length - baseline_length) > 50:
                    return True

        return False

    def detect(
        self, url: str, param: Optional[str] = None, deep_scan: bool = False
    ) -> Dict[str, Any]:
        """执行 IDOR 检测"""
        from tools._common import reset_failure_counter

        reset_failure_counter()

        vulnerabilities = []
        test_params = self.get_test_params(param)
        baseline = self.get_baseline(url)

        # 解析 URL
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        for test_param in test_params[:8]:  # 限制参数数量
            findings = []
            responses_by_id = {}

            # 测试不同的 ID 值
            for test_id in self.TEST_IDS["numeric"][:5]:
                try:
                    # 构建测试 URL
                    test_url = self._build_test_url(url, test_param, test_id)
                    response = self.send_request(test_url)

                    if not response or not response.get("success"):
                        continue

                    status = response.get("status_code", 0)
                    length = response.get("response_length", 0)
                    text = response.get("response_text", "")

                    # 记录响应
                    responses_by_id[test_id] = {
                        "status": status,
                        "length": length,
                        "has_data": length > 100 and status == 200,
                    }

                    # 检查是否返回了有效数据
                    if status == 200 and length > 100:
                        # 检查是否包含敏感数据
                        sensitive_found = []
                        for pattern in self.SENSITIVE_INDICATORS:
                            if re.search(pattern, text, re.IGNORECASE):
                                sensitive_found.append(pattern.split("[")[0])

                        findings.append(
                            {
                                "id": test_id,
                                "status": status,
                                "size": length,
                                "sensitive_data": sensitive_found[:3] if sensitive_found else None,
                            }
                        )

                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            # 分析结果
            if len(findings) > 1:
                # 检查不同 ID 是否返回不同内容
                sizes = [f["size"] for f in findings]
                unique_sizes = len(set(sizes))

                # 多个 ID 返回不同大小的响应，可能存在 IDOR
                if unique_sizes > 1:
                    # 检查是否有敏感数据泄露
                    has_sensitive = any(f.get("sensitive_data") for f in findings)
                    severity = "CRITICAL" if has_sensitive else "HIGH"
                    confidence = 0.8 if has_sensitive else 0.6

                    vuln = Vulnerability(
                        type="IDOR",
                        severity=severity,
                        param=test_param,
                        url=url,
                        evidence=f"参数 {test_param} 可遍历，{len(findings)} 个 ID 返回不同内容",
                        verified=False,
                        confidence=confidence,
                        details={
                            "findings": findings[:5],
                            "unique_response_sizes": unique_sizes,
                            "has_sensitive_data": has_sensitive,
                        },
                    )
                    vulnerabilities.append(vuln)

                    if not deep_scan:
                        break

            # 检查路径参数 IDOR (如 /user/1/profile)
            path_vulns = self._check_path_idor(url, deep_scan)
            vulnerabilities.extend(path_vulns)

            if vulnerabilities and not deep_scan:
                break

        # 二次验证
        verified_vulns = []
        for vuln in vulnerabilities:
            if self._verify_idor(url, vuln):
                vuln.verified = True
                vuln.confidence = min(1.0, vuln.confidence + 0.15)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": "IDORDetector",
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "recommendations": self._get_recommendations() if verified_vulns else [],
        }

    def _build_test_url(self, url: str, param: str, value: str) -> str:
        """构建测试 URL"""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # 更新或添加参数
        query_params[param] = [value]

        # 重建 URL
        new_query = urlencode(query_params, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    def _check_path_idor(self, url: str, deep_scan: bool) -> List[Vulnerability]:
        """检查路径参数 IDOR"""
        vulnerabilities = []
        parsed = urlparse(url)
        path = parsed.path

        # 查找路径中的数字 ID
        id_pattern = r"/(\d+)(?:/|$)"
        matches = list(re.finditer(id_pattern, path))

        for match in matches:
            original_id = match.group(1)
            findings = []

            # 测试不同的 ID
            for test_id in ["1", "2", str(int(original_id) + 1), str(int(original_id) - 1)]:
                if test_id == original_id:
                    continue

                try:
                    # 替换路径中的 ID
                    new_path = path[: match.start(1)] + test_id + path[match.end(1) :]
                    new_parsed = parsed._replace(path=new_path)
                    test_url = urlunparse(new_parsed)

                    response = self.send_request(test_url)

                    if response and response.get("success"):
                        status = response.get("status_code", 0)
                        length = response.get("response_length", 0)

                        if status == 200 and length > 100:
                            findings.append({"id": test_id, "status": status, "size": length})

                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            if findings:
                vuln = Vulnerability(
                    type="Path IDOR",
                    severity="HIGH",
                    url=url,
                    evidence=f"路径参数 ID 可遍历 (原始: {original_id})",
                    verified=False,
                    confidence=0.7,
                    details={
                        "original_id": original_id,
                        "findings": findings,
                        "path_pattern": path,
                    },
                )
                vulnerabilities.append(vuln)

                if not deep_scan:
                    break

        return vulnerabilities

    def _verify_idor(self, url: str, vuln: Vulnerability) -> bool:
        """二次验证 IDOR 漏洞"""
        if vuln.type == "Path IDOR":
            # 路径 IDOR 验证
            original_id = vuln.details.get("original_id", "")
            if original_id:
                try:
                    # 尝试访问另一个 ID
                    test_id = str(int(original_id) + 100)
                    parsed = urlparse(url)
                    path = parsed.path
                    new_path = re.sub(rf"/{original_id}(?=/|$)", f"/{test_id}", path)
                    new_parsed = parsed._replace(path=new_path)
                    test_url = urlunparse(new_parsed)

                    response = self.send_request(test_url)
                    if response and response.get("success"):
                        return response.get("status_code") == 200
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            return False

        # 参数 IDOR 验证
        if not vuln.param:
            return False

        try:
            # 使用不同的 ID 重新测试
            test_url = self._build_test_url(url, vuln.param, "12345")
            response = self.send_request(test_url)

            if response and response.get("success"):
                status = response.get("status_code", 0)
                length = response.get("response_length", 0)
                return status == 200 and length > 100
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return False

    def _get_recommendations(self) -> List[str]:
        """获取修复建议"""
        return [
            "实施基于角色的访问控制 (RBAC)",
            "使用间接对象引用 (如 UUID) 替代顺序 ID",
            "在服务端验证用户对资源的访问权限",
            "记录并监控异常的资源访问模式",
            "使用不可预测的随机标识符",
            "实施速率限制防止枚举攻击",
            "对敏感操作添加二次验证",
        ]
