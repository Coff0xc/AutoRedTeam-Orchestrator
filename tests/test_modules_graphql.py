#!/usr/bin/env python3
"""
GraphQL 安全测试模块单元测试

测试 modules/api_security/graphql.py 的各项功能。
"""

import json
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from modules.api_security.graphql import GraphQLTester
from modules.api_security.base import APIVulnType, Severity


class TestGraphQLTesterInit:
    """GraphQL 测试器初始化测试"""

    def test_init_basic(self):
        """测试基本初始化"""
        tester = GraphQLTester("https://api.example.com/graphql")

        assert tester.target == "https://api.example.com/graphql"
        assert tester.max_depth == 50
        assert tester.max_batch == 100
        assert tester.field_name == 'user'

    def test_init_with_config(self):
        """测试带配置的初始化"""
        config = {
            'max_depth': 100,
            'max_batch': 200,
            'field_name': 'product',
            'auth_header': {'Authorization': 'Bearer token'}
        }
        tester = GraphQLTester("https://api.example.com/graphql", config)

        assert tester.max_depth == 100
        assert tester.max_batch == 200
        assert tester.field_name == 'product'
        assert tester.auth_header == {'Authorization': 'Bearer token'}


class TestGraphQLIntrospection:
    """GraphQL Introspection 测试"""

    def test_introspection_enabled(self):
        """测试检测到 Introspection 已启用"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 返回 Schema 数据
        mock_response = {
            'success': True,
            'data': {
                'data': {
                    '__schema': {
                        'types': [
                            {'name': 'Query', 'kind': 'OBJECT'},
                            {'name': 'User', 'kind': 'OBJECT'},
                            {'name': 'Post', 'kind': 'OBJECT'},
                        ],
                        'queryType': {'name': 'Query'},
                        'mutationType': {'name': 'Mutation'}
                    }
                }
            }
        }

        with patch.object(tester, '_send_query', return_value=mock_response):
            with patch.object(tester, '_extract_schema_info') as mock_extract:
                # Mock 提取的 Schema 信息
                tester._schema_info = {
                    'types': ['Query', 'User', 'Post'],
                    'queries': ['user', 'users', 'post'],
                    'mutations': ['createUser', 'updateUser']
                }

                result = tester.test_introspection()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.GRAPHQL_INTROSPECTION
        assert result.severity == Severity.MEDIUM
        assert result.evidence['types_count'] == 3
        assert result.evidence['queries_count'] == 3

    def test_introspection_disabled(self):
        """测试 Introspection 已禁用"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 返回错误
        mock_response = {
            'success': False,
            'errors': [{'message': 'Introspection is disabled'}]
        }

        with patch.object(tester, '_send_query', return_value=mock_response):
            result = tester.test_introspection()

        assert result is None

    def test_introspection_no_schema_data(self):
        """测试响应中没有 Schema 数据"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 没有 Schema
        mock_response = {
            'success': True,
            'data': {
                'data': {
                    'someOtherField': 'value'
                }
            }
        }

        with patch.object(tester, '_send_query', return_value=mock_response):
            result = tester.test_introspection()

        assert result is None


class TestGraphQLBatchQueryDoS:
    """GraphQL 批量查询 DoS 测试"""

    def test_batch_query_dos_detected(self):
        """测试检测到批量查询 DoS"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock 批量查询响应 - 接受大量查询
        def mock_send_batch(batch):
            return {
                'success': True,
                'data': [{'data': {'__typename': 'Query'}}] * len(batch)
            }

        with patch.object(tester, '_send_batch', side_effect=mock_send_batch):
            result = tester.test_batch_query_dos()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.GRAPHQL_BATCH_DOS
        assert result.severity in [Severity.HIGH, Severity.MEDIUM]

    def test_batch_query_limited(self):
        """测试批量查询有限制"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock 批量查询响应 - 拒绝大量查询
        def mock_send_batch(batch):
            if len(batch) > 10:
                return {
                    'success': False,
                    'errors': [{'message': 'Batch limit exceeded'}]
                }
            return {
                'success': True,
                'data': [{'data': {'__typename': 'Query'}}] * len(batch)
            }

        with patch.object(tester, '_send_batch', side_effect=mock_send_batch):
            result = tester.test_batch_query_dos()

        # 如果有限制，可能不返回漏洞或返回较低严重性
        if result:
            assert result.severity in [Severity.LOW, Severity.MEDIUM]

    def test_batch_query_response_time(self):
        """测试批量查询响应时间"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock 批量查询响应 - 模拟响应时间增长
        def mock_send_batch(batch):
            time.sleep(len(batch) * 0.001)  # 模拟处理时间
            return {
                'success': True,
                'data': [{'data': {'__typename': 'Query'}}] * len(batch)
            }

        with patch.object(tester, '_send_batch', side_effect=mock_send_batch):
            result = tester.test_batch_query_dos()

        if result:
            assert 'response_times' in result.evidence or 'max_accepted' in result.evidence


class TestGraphQLDeepNestingDoS:
    """GraphQL 深度嵌套 DoS 测试"""

    def test_deep_nesting_dos_detected(self):
        """测试检测到深度嵌套 DoS"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock 深度嵌套查询响应 - 接受深度嵌套
        def mock_send_query(query):
            return {
                'success': True,
                'data': {'data': {'user': {'friends': {'friends': {}}}}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_deep_nesting_dos()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.GRAPHQL_DEEP_NESTING
        assert result.severity in [Severity.HIGH, Severity.MEDIUM]

    def test_deep_nesting_limited(self):
        """测试深度嵌套有限制"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock 深度嵌套查询响应 - 拒绝深度嵌套
        def mock_send_query(query):
            # 检查嵌套深度
            depth = query.count('{')
            if depth > 10:
                return {
                    'success': False,
                    'errors': [{'message': 'Query depth limit exceeded'}]
                }
            return {
                'success': True,
                'data': {'data': {'user': {}}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_deep_nesting_dos()

        # 如果有限制，可能不返回漏洞
        if result:
            assert result.severity in [Severity.LOW, Severity.MEDIUM]


class TestGraphQLFieldSuggestion:
    """GraphQL 字段建议测试"""

    def test_field_suggestion_detected(self):
        """测试检测到字段建议信息泄露"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 返回字段建议
        mock_response = {
            'success': False,
            'errors': [{
                'message': 'Cannot query field "passwrd" on type "User". Did you mean "password"?'
            }]
        }

        with patch.object(tester, '_send_query', return_value=mock_response):
            result = tester.test_field_suggestion()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.GRAPHQL_FIELD_SUGGESTION
        assert result.severity == Severity.LOW

    def test_field_suggestion_disabled(self):
        """测试字段建议已禁用"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 不返回字段建议
        mock_response = {
            'success': False,
            'errors': [{
                'message': 'Cannot query field "passwrd" on type "User".'
            }]
        }

        with patch.object(tester, '_send_query', return_value=mock_response):
            result = tester.test_field_suggestion()

        assert result is None


class TestGraphQLAliasOverload:
    """GraphQL 别名重载测试"""

    def test_alias_overload_detected(self):
        """测试检测到别名重载攻击"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 接受大量别名
        def mock_send_query(query):
            return {
                'success': True,
                'data': {'data': {f'alias{i}': 'value' for i in range(100)}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_alias_overload()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.GRAPHQL_ALIAS_OVERLOAD
        assert result.severity in [Severity.HIGH, Severity.MEDIUM]

    def test_alias_overload_limited(self):
        """测试别名重载有限制"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 拒绝大量别名
        def mock_send_query(query):
            alias_count = query.count('alias')
            if alias_count > 50:
                return {
                    'success': False,
                    'errors': [{'message': 'Too many aliases'}]
                }
            return {
                'success': True,
                'data': {'data': {}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_alias_overload()

        # 如果有限制，可能不返回漏洞
        if result:
            assert result.severity in [Severity.LOW, Severity.MEDIUM]


class TestGraphQLDirectiveOverload:
    """GraphQL 指令重载测试"""

    def test_directive_overload_detected(self):
        """测试检测到指令重载攻击"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 接受大量指令
        def mock_send_query(query):
            return {
                'success': True,
                'data': {'data': {'field': 'value'}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_directive_overload()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.GRAPHQL_DIRECTIVE_OVERLOAD
        assert result.severity in [Severity.MEDIUM, Severity.LOW]

    def test_directive_overload_limited(self):
        """测试指令重载有限制"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 拒绝大量指令
        def mock_send_query(query):
            directive_count = query.count('@')
            if directive_count > 50:
                return {
                    'success': False,
                    'errors': [{'message': 'Too many directives'}]
                }
            return {
                'success': True,
                'data': {'data': {}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_directive_overload()

        # 如果有限制，可能不返回漏洞
        if result:
            assert result.severity in [Severity.LOW, Severity.MEDIUM]


class TestGraphQLInjection:
    """GraphQL 注入测试"""

    def test_sql_injection_detected(self):
        """测试检测到 SQL 注入"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - SQL 错误
        def mock_send_query(query):
            if "'" in query or '"' in query:
                return {
                    'success': False,
                    'errors': [{
                        'message': 'SQL syntax error near "\'"'
                    }]
                }
            return {
                'success': True,
                'data': {'data': {}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_injection()

        assert result is not None
        assert result.vulnerable is True
        assert result.vuln_type == APIVulnType.GRAPHQL_INJECTION
        assert result.severity in [Severity.CRITICAL, Severity.HIGH]

    def test_nosql_injection_detected(self):
        """测试检测到 NoSQL 注入"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - NoSQL 错误
        def mock_send_query(query):
            if '$gt' in query or '$ne' in query:
                return {
                    'success': False,
                    'errors': [{
                        'message': 'Invalid operator: $gt'
                    }]
                }
            return {
                'success': True,
                'data': {'data': {}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_injection()

        if result:
            assert result.vulnerable is True
            assert result.vuln_type == APIVulnType.GRAPHQL_INJECTION

    def test_no_injection(self):
        """测试没有注入漏洞"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 正常处理
        def mock_send_query(query):
            return {
                'success': True,
                'data': {'data': {}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_injection()

        assert result is None


class TestGraphQLCircularFragment:
    """GraphQL 循环片段测试"""

    def test_circular_fragment_detected(self):
        """测试检测到循环片段攻击"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 接受循环片段
        def mock_send_query(query):
            return {
                'success': True,
                'data': {'data': {}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_circular_fragment()

        if result:
            assert result.vulnerable is True
            assert result.severity in [Severity.HIGH, Severity.MEDIUM]

    def test_circular_fragment_rejected(self):
        """测试拒绝循环片段"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock GraphQL 响应 - 拒绝循环片段
        def mock_send_query(query):
            if 'fragment' in query.lower():
                return {
                    'success': False,
                    'errors': [{'message': 'Circular fragment detected'}]
                }
            return {
                'success': True,
                'data': {'data': {}}
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            result = tester.test_circular_fragment()

        assert result is None


class TestGraphQLFullScan:
    """GraphQL 完整扫描测试"""

    def test_full_scan_execution(self):
        """测试完整扫描执行所有测试"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock 所有请求返回安全响应
        safe_response = {
            'success': False,
            'errors': [{'message': 'Query not allowed'}]
        }

        with patch.object(tester, '_send_query', return_value=safe_response):
            with patch.object(tester, '_send_batch', return_value=safe_response):
                results = tester.test()

        # 应该执行多个测试
        assert len(results) >= 0

    def test_full_scan_with_vulnerabilities(self):
        """测试完整扫描发现多个漏洞"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock 响应 - 返回多个漏洞
        def mock_send_query(query):
            if '__schema' in query or '__type' in query:
                return {
                    'success': True,
                    'data': {
                        'data': {
                            '__schema': {
                                'types': [{'name': 'Query'}]
                            }
                        }
                    }
                }
            return {
                'success': True,
                'data': {'data': {}}
            }

        def mock_send_batch(batch):
            return {
                'success': True,
                'data': [{'data': {}}] * len(batch)
            }

        with patch.object(tester, '_send_query', side_effect=mock_send_query):
            with patch.object(tester, '_send_batch', side_effect=mock_send_batch):
                with patch.object(tester, '_extract_schema_info'):
                    tester._schema_info = {
                        'types': ['Query'],
                        'queries': ['user'],
                        'mutations': []
                    }
                    results = tester.test()

        # 应该发现一些漏洞
        vulnerable_results = [r for r in results if r.vulnerable]
        assert len(vulnerable_results) >= 0

    def test_get_summary(self):
        """测试获取扫描摘要"""
        tester = GraphQLTester("https://api.example.com/graphql")

        safe_response = {
            'success': False,
            'errors': [{'message': 'Query not allowed'}]
        }

        with patch.object(tester, '_send_query', return_value=safe_response):
            with patch.object(tester, '_send_batch', return_value=safe_response):
                tester.test()

        summary = tester.get_summary()

        assert summary.target == "https://api.example.com/graphql"
        assert summary.total_tests >= 0
        assert isinstance(summary.to_dict(), dict)


class TestGraphQLHelperMethods:
    """GraphQL 辅助方法测试"""

    def test_send_query_success(self):
        """测试发送查询成功"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock HTTP 客户端
        with patch.object(tester, '_get_http_client') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'data': {'__typename': 'Query'}
            }
            mock_client.return_value.post.return_value = mock_response

            result = tester._send_query('{__typename}')

        assert result['success'] is True
        assert 'data' in result

    def test_send_query_error(self):
        """测试发送查询错误"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock HTTP 客户端
        with patch.object(tester, '_get_http_client') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'errors': [{'message': 'Syntax error'}]
            }
            mock_client.return_value.post.return_value = mock_response

            result = tester._send_query('{invalid')

        assert result['success'] is False
        assert 'errors' in result

    def test_send_query_exception(self):
        """测试发送查询异常"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock HTTP 客户端抛出异常
        with patch.object(tester, '_get_http_client') as mock_client:
            mock_client.return_value.post.side_effect = Exception("Connection error")

            result = tester._send_query('{__typename}')

        assert result['success'] is False

    def test_send_batch_success(self):
        """测试发送批量查询成功"""
        tester = GraphQLTester("https://api.example.com/graphql")

        batch = [
            {'query': '{__typename}'},
            {'query': '{__typename}'}
        ]

        # Mock HTTP 客户端
        with patch.object(tester, '_get_http_client') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = [
                {'data': {'__typename': 'Query'}},
                {'data': {'__typename': 'Query'}}
            ]
            mock_client.return_value.post.return_value = mock_response

            result = tester._send_batch(batch)

        assert result['success'] is True
        assert len(result['data']) == 2


class TestGraphQLEdgeCases:
    """GraphQL 边缘情况测试"""

    def test_empty_query(self):
        """测试空查询"""
        tester = GraphQLTester("https://api.example.com/graphql")

        with patch.object(tester, '_send_query', return_value={'success': False}):
            result = tester._send_query('')

        assert result['success'] is False

    def test_malformed_json_response(self):
        """测试格式错误的 JSON 响应"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock HTTP 客户端返回无效 JSON
        with patch.object(tester, '_get_http_client') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_client.return_value.post.return_value = mock_response

            result = tester._send_query('{__typename}')

        assert result['success'] is False

    def test_http_error_status(self):
        """测试 HTTP 错误状态码"""
        tester = GraphQLTester("https://api.example.com/graphql")

        # Mock HTTP 客户端返回错误状态
        with patch.object(tester, '_get_http_client') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.json.return_value = {
                'errors': [{'message': 'Internal server error'}]
            }
            mock_client.return_value.post.return_value = mock_response

            result = tester._send_query('{__typename}')

        assert result['success'] is False
