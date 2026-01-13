#!/usr/bin/env python3
"""
SQL注入检测器 - 基于 BaseDetector 重构

支持检测类型:
- 错误型注入 (Error-based)
- 时间盲注 (Time-based Blind)
- 布尔盲注 (Boolean-based Blind)
"""

import re
import time
from typing import Dict, List, Any, Optional

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.detectors.base import BaseDetector, Vulnerability


class SQLiDetector(BaseDetector):
    """SQL注入检测器"""

    # 覆盖默认测试参数
    DEFAULT_PARAMS = [
        "id", "page", "cat", "search", "q", "query",
        "user", "name", "item", "product", "order", "sort",
        "limit", "offset", "filter", "type", "category"
    ]

    # 错误型注入 Payload
    ERROR_PAYLOADS = [
        "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
        "1' AND '1'='1", "1 AND 1=1", "' UNION SELECT NULL--",
        "1'1", "1 AND 1=1--", "' OR ''='", "') OR ('1'='1",
        "1' ORDER BY 1--", "1' ORDER BY 100--",
    ]

    # 时间盲注 Payload (payload, expected_delay)
    TIME_PAYLOADS = [
        ("' AND SLEEP(3)--", 3),
        ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", 3),
        ("'; WAITFOR DELAY '0:0:3'--", 3),
        ("' AND pg_sleep(3)--", 3),
        ("' AND DBMS_LOCK.SLEEP(3)--", 3),
        ("'; SELECT SLEEP(3);--", 3),
    ]

    # 布尔盲注 Payload (true_payload, false_payload)
    BOOLEAN_PAYLOADS = [
        ("' AND '1'='1", "' AND '1'='2"),
        ("' AND 1=1--", "' AND 1=2--"),
        ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
        ("' AND 'a'='a'--", "' AND 'a'='b'--"),
        ("1 AND 1=1", "1 AND 1=2"),
    ]

    # 数据库错误特征模式
    ERROR_PATTERNS = [
        # MySQL
        r"sql syntax.*mysql", r"warning.*mysql_", r"mysqlclient", r"mysqli",
        r"mysql_fetch", r"mysql_num_rows", r"mysql_query",
        # PostgreSQL
        r"postgresql.*error", r"pg_query", r"pg_exec", r"pgsql",
        r"psql.*error", r"pg_connect",
        # Oracle
        r"ora-\d{5}", r"oracle.*driver", r"oracle.*error",
        r"quoted string not properly terminated",
        # SQL Server
        r"microsoft.*sql.*server", r"sqlserver", r"odbc.*driver",
        r"unclosed quotation mark", r"mssql",
        # SQLite
        r"sqlite.*error", r"sqlite3\.operationalerror", r"sqlite_",
        r"unable to open database",
        # 通用
        r"syntax error", r"sql syntax", r"query failed",
        r"unexpected end of sql", r"invalid query",
        r"sql command not properly ended",
    ]

    def get_payloads(self) -> Dict[str, List]:
        """获取 Payload 库"""
        return {
            "Error-based SQLi": self.ERROR_PAYLOADS,
            "Time-based Blind SQLi": self.TIME_PAYLOADS,
            "Boolean-based Blind SQLi": self.BOOLEAN_PAYLOADS,
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 SQL 注入"""
        if not response or not response.get("success"):
            return False

        resp_text = response.get("response_text", "").lower()

        # 检查错误型注入特征
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, resp_text, re.IGNORECASE):
                return True

        return False

    def detect_time_based(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测时间盲注"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params:
            for payload, expected_delay in self.TIME_PAYLOADS:
                # 发送请求并测量时间
                response = self.send_request(url, payload, test_param)

                if not response or not response.get("success"):
                    continue

                response_time = response.get("response_time", 0)

                # 检查响应时间是否显著延迟
                if response_time >= expected_delay * 0.85:
                    # 二次验证
                    verify_response = self.send_request(url, payload, test_param)
                    if verify_response and verify_response.get("response_time", 0) >= expected_delay * 0.8:
                        vulnerabilities.append(Vulnerability(
                            type="Time-based Blind SQLi",
                            severity="CRITICAL",
                            param=test_param,
                            payload=payload,
                            url=response.get("url", url),
                            evidence=f"响应延迟: {response_time:.2f}s / {verify_response.get('response_time', 0):.2f}s (预期: {expected_delay}s)",
                            verified=True,
                            confidence=0.85
                        ))
                        break  # 找到一个就停止该参数的测试

        return vulnerabilities

    def detect_boolean_based(
        self,
        url: str,
        param: Optional[str] = None,
        baseline: Dict[str, Any] = None
    ) -> List[Vulnerability]:
        """检测布尔盲注"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        if not baseline:
            baseline = self.get_baseline(url)

        baseline_length = baseline.get("response_length", 0) if baseline else 0

        for test_param in test_params:
            for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
                # 发送 TRUE 条件请求
                true_response = self.send_request(url, true_payload, test_param)
                if not true_response or not true_response.get("success"):
                    continue

                # 发送 FALSE 条件请求
                false_response = self.send_request(url, false_payload, test_param)
                if not false_response or not false_response.get("success"):
                    continue

                true_length = true_response.get("response_length", 0)
                false_length = false_response.get("response_length", 0)

                # 计算响应差异
                len_diff = abs(true_length - false_length)
                status_diff = true_response.get("status_code") != false_response.get("status_code")

                # 判断是否存在布尔盲注
                if len_diff > 50 or status_diff:
                    # 二次验证
                    verify_true = self.send_request(url, true_payload, test_param)
                    verify_false = self.send_request(url, false_payload, test_param)

                    if verify_true and verify_false:
                        verify_diff = abs(
                            verify_true.get("response_length", 0) -
                            verify_false.get("response_length", 0)
                        )

                        if verify_diff > 30:
                            vulnerabilities.append(Vulnerability(
                                type="Boolean-based Blind SQLi",
                                severity="HIGH",
                                param=test_param,
                                payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                                url=true_response.get("url", url),
                                evidence=f"响应长度差异: {len_diff} / {verify_diff} bytes",
                                verified=True,
                                confidence=0.8,
                                details={
                                    "true_length": true_length,
                                    "false_length": false_length,
                                    "baseline_length": baseline_length
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
        SQL 注入检测入口

        Args:
            url: 目标 URL
            param: 指定参数 (可选)
            deep_scan: 是否深度扫描 (包含时间盲注和布尔盲注)

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 获取基线
        baseline = self.get_baseline(url)

        # 1. 错误型注入检测 (使用基类方法)
        error_vulns = self.test_payloads(url, param, stop_on_first=not deep_scan)
        for vuln in error_vulns:
            vuln.type = "Error-based SQLi"
            vuln.severity = "CRITICAL"
        all_vulnerabilities.extend(error_vulns)

        if deep_scan:
            # 2. 时间盲注检测
            time_vulns = self.detect_time_based(url, param)
            all_vulnerabilities.extend(time_vulns)

            # 3. 布尔盲注检测
            boolean_vulns = self.detect_boolean_based(url, param, baseline)
            all_vulnerabilities.extend(boolean_vulns)

        # 二次验证
        verified_vulns = []
        for vuln in all_vulnerabilities:
            if not vuln.verified:
                if self.verify_vulnerability(vuln):
                    vuln.verified = True
                    vuln.confidence = min(1.0, vuln.confidence + 0.2)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "by_type": {
                "error_based": sum(1 for v in verified_vulns if "Error" in v.type),
                "time_based": sum(1 for v in verified_vulns if "Time" in v.type),
                "boolean_based": sum(1 for v in verified_vulns if "Boolean" in v.type),
            }
        }


# 便捷函数 - 兼容旧接口
def sqli_detect(url: str, param: str = None, deep_scan: bool = True) -> Dict[str, Any]:
    """SQL 注入检测 (兼容旧接口)"""
    with SQLiDetector() as detector:
        return detector.detect(url, param, deep_scan)