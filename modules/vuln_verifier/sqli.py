#!/usr/bin/env python3
"""
SQL注入验证模块

包含:
- SQLiVerifierMixin: SQLi 验证混入类
  - verify_sqli_time_based: 时间盲注验证
  - verify_sqli_boolean: 布尔盲注验证
  - verify_sqli_error: 报错注入验证
"""
import logging
import re
import time
from typing import Any, Dict, Optional

from .models import VerificationResult

logger = logging.getLogger(__name__)


class SQLiVerifierMixin:
    """SQL注入验证混入类"""

    def verify_sqli_time_based(
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
        """时间盲注验证 - 增强版，减少误报"""
        # 多次基准请求取平均值和标准差
        base_times = []
        base_url, base_body_data, base_headers = self._prepare_base_request(
            url=url,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data,
        )
        for _ in range(5):  # 5次基准测试
            _, _, bt, _ = self._request(
                base_url,
                method=method,
                data=base_body_data,
                headers=base_headers,
            )
            base_times.append(bt)

        base_time = sum(base_times) / len(base_times)
        # 计算标准差
        variance = sum((t - base_time) ** 2 for t in base_times) / len(base_times)
        std_dev = variance**0.5
        # 动态阈值：基准时间 + 延迟 + 2倍标准差
        dynamic_threshold = base_time + delay + (std_dev * 2)

        # Sleep payloads - 支持多种数据库
        payloads = [
            f"' AND SLEEP({delay})--",
            f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
            f"'; WAITFOR DELAY '0:0:{delay}'--",
            f"' AND pg_sleep({delay})--",
            f"' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",  # Oracle
            f"'; SELECT SLEEP({delay});--",  # SQLite
            f"' AND BENCHMARK({delay}000000,SHA1('test'))--",  # MySQL BENCHMARK
        ]

        # 第一轮检测
        first_pass_results = []
        for payload in payloads:
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
            _, code, elapsed, length = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            # 严格阈值
            if elapsed >= dynamic_threshold and elapsed >= delay * 0.9:
                first_pass_results.append(
                    (payload, elapsed, test_url, code, length, body_data, request_headers)
                )

        # 二次验证
        for (
            payload,
            first_elapsed,
            test_url,
            code,
            length,
            body_data,
            request_headers,
        ) in first_pass_results:
            _, _, second_elapsed, _ = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            # 两次都延迟才确认
            if second_elapsed >= delay * 0.85 and first_elapsed >= delay * 0.85:
                # 一致性检查
                diff_ratio = abs(first_elapsed - second_elapsed) / max(
                    first_elapsed, second_elapsed
                )
                if diff_ratio < 0.3:
                    return VerificationResult(
                        vuln_type="SQL Injection (Time-based Blind)",
                        payload=payload,
                        url=test_url,
                        is_vulnerable=True,
                        confidence="high",
                        evidence=f"Response delayed {first_elapsed:.2f}s (expected {delay}s)",
                        response_time=first_elapsed,
                        response_code=code,
                        response_length=length,
                        verification_method="time_delay",
                        recommendation="立即修复! 使用参数化查询替代字符串拼接",
                    )

        return VerificationResult(
            vuln_type="SQL Injection",
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

    def verify_sqli_boolean(
        self,
        url: str,
        param: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> VerificationResult:
        """布尔盲注验证 - 增强版"""
        # 获取原始响应基线
        base_url, base_body_data, base_headers = self._prepare_base_request(
            url=url,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data,
        )
        original_body, original_code, _, original_len = self._request(
            base_url,
            method=method,
            data=base_body_data,
            headers=base_headers,
        )

        # True/False 条件对
        true_payloads = [
            "' AND '1'='1",
            "' AND 1=1--",
            "') AND ('1'='1",
            "' AND 'a'='a",
            "1 AND 1=1",
            "' OR '1'='1' AND '1'='1",
        ]
        false_payloads = [
            "' AND '1'='2",
            "' AND 1=2--",
            "') AND ('1'='2",
            "' AND 'a'='b",
            "1 AND 1=2",
            "' OR '1'='1' AND '1'='2",
        ]
        # 错误条件 - 排除普通错误页
        error_payloads = ["'", "''", '"']

        # 获取错误响应特征
        error_lengths = []
        for ep in error_payloads:
            error_url, error_body_data, error_headers = self._prepare_request(
                url=url,
                param=param,
                payload=ep,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )
            error_body, _, _, error_len = self._request(
                error_url,
                method=method,
                data=error_body_data,
                headers=error_headers,
            )
            if error_body:
                error_lengths.append(error_len)

        for true_p, false_p in zip(true_payloads, false_payloads):
            true_url, true_body_data, true_headers = self._prepare_request(
                url=url,
                param=param,
                payload=true_p,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )
            false_url, false_body_data, false_headers = self._prepare_request(
                url=url,
                param=param,
                payload=false_p,
                method=method,
                headers=headers,
                params=params,
                data=data,
                json_data=json_data,
            )

            true_body, true_code, _, true_len = self._request(
                true_url,
                method=method,
                data=true_body_data,
                headers=true_headers,
            )
            false_body, false_code, _, false_len = self._request(
                false_url,
                method=method,
                data=false_body_data,
                headers=false_headers,
            )

            if true_body and false_body:
                # 排除：true响应与错误响应相似
                if error_lengths and any(
                    abs(true_len - el) < 50 for el in error_lengths
                ):
                    continue

                len_diff = abs(true_len - false_len)
                code_diff = true_code != false_code
                true_vs_original = abs(true_len - original_len)

                # 百分比差异
                min_len = min(len(true_body), len(false_body))
                max_len = max(len(true_body), len(false_body))
                len_diff_ratio = (max_len - min_len) / max_len if max_len > 0 else 0

                # 内容差异
                diff_count = sum(
                    1 for i in range(min_len) if true_body[i] != false_body[i]
                )
                content_diff_ratio = diff_count / min_len if min_len > 0 else 0

                # True与原始响应相似度
                true_vs_original_ratio = (
                    true_vs_original / original_len if original_len > 0 else 1
                )

                has_significant_diff = (
                    len_diff_ratio > 0.1 or code_diff or content_diff_ratio > 0.05
                )
                true_matches_original = true_vs_original_ratio < 0.15

                if has_significant_diff and true_matches_original:
                    # 二次验证
                    verify_true, _, _, verify_true_len = self._request(
                        true_url,
                        method=method,
                        data=true_body_data,
                        headers=true_headers,
                    )
                    verify_false, _, _, verify_false_len = self._request(
                        false_url,
                        method=method,
                        data=false_body_data,
                        headers=false_headers,
                    )

                    verify_diff = abs(verify_true_len - verify_false_len)
                    if verify_diff > min(verify_true_len, verify_false_len) * 0.05:
                        return VerificationResult(
                            vuln_type="SQL Injection (Boolean-based Blind)",
                            payload=f"True: {true_p} | False: {false_p}",
                            url=url,
                            is_vulnerable=True,
                            confidence="high",
                            evidence=f"Response diff: len_ratio={len_diff_ratio:.2%}, "
                            f"code={true_code}vs{false_code}, verified=True",
                            response_time=0,
                            response_code=true_code,
                            response_length=true_len,
                            verification_method="boolean_diff_verified",
                            recommendation="使用参数化查询, 实施输入验证",
                        )

        return VerificationResult(
            vuln_type="SQL Injection",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No boolean difference detected",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="boolean_diff",
        )

    def verify_sqli_error(
        self,
        url: str,
        param: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> VerificationResult:
        """报错注入验证"""
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySqlException",
            r"PostgreSQL.*ERROR",
            r"pg_query\(\)",
            r"pg_exec\(\)",
            r"ORA-[0-9]{5}",
            r"Oracle.*Driver",
            r"SQLServer.*Driver",
            r"ODBC.*Driver",
            r"SQLite.*error",
            r"sqlite3\.OperationalError",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
        ]

        payloads = ["'", '"', "' OR '", "'; --", "1'1", "1 AND 1=1"]

        for payload in payloads:
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
            body, code, elapsed, length = self._request(
                test_url,
                method=method,
                data=body_data,
                headers=request_headers,
            )

            if body:
                for pattern in error_patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        return VerificationResult(
                            vuln_type="SQL Injection (Error-based)",
                            payload=payload,
                            url=test_url,
                            is_vulnerable=True,
                            confidence="high",
                            evidence=f"SQL error found: {match.group()[:100]}",
                            response_time=elapsed,
                            response_code=code,
                            response_length=length,
                            verification_method="error_pattern",
                            recommendation="禁用详细错误信息, 使用参数化查询",
                        )

        return VerificationResult(
            vuln_type="SQL Injection",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No SQL error patterns found",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="error_pattern",
        )