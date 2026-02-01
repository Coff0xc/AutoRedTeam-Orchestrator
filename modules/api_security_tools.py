#!/usr/bin/env python3
"""
API安全MCP工具注册模块
注册: GraphQL安全测试、WebSocket安全测试
"""

import logging

from utils.mcp_tooling import patch_mcp_tool

logger = logging.getLogger(__name__)


def register_api_security_tools(mcp):
    """注册API安全工具到MCP Server"""
    patch_mcp_tool(mcp)

    registered_tools = []

    # ========== GraphQL安全工具 ==========

    @mcp.tool()
    def graphql_introspection_test(url: str) -> dict:
        """GraphQL内省测试 - 检测Schema泄露风险

        检查GraphQL端点是否开启内省功能,可能泄露完整API Schema

        Args:
            url: GraphQL端点URL

        Returns:
            {
                "vulnerable": bool,
                "schema_extracted": bool,
                "types": [...],
                "queries": [...],
                "mutations": [...],
                "remediation": str
            }
        """
        try:
            from modules.api_security.graphql_security import GraphQLSecurityTester

            tester = GraphQLSecurityTester()
            return tester.test_introspection(url)

        except ImportError as e:
            return {"success": False, "error": f"模块导入失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("graphql_introspection_test")

    @mcp.tool()
    def graphql_batch_dos_test(url: str, max_queries: int = 100) -> dict:
        """GraphQL批量查询DoS测试 - 检测请求数量限制

        逐步增加批量查询数量,检测服务器是否有限制

        Args:
            url: GraphQL端点URL
            max_queries: 最大测试查询数量

        Returns:
            {
                "vulnerable": bool,
                "max_queries_accepted": int,
                "response_times": [...],
                "remediation": str
            }
        """
        try:
            from modules.api_security.graphql_security import GraphQLSecurityTester

            tester = GraphQLSecurityTester()
            return tester.test_batch_dos(url, max_queries, step=10)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("graphql_batch_dos_test")

    @mcp.tool()
    def graphql_deep_nesting_test(url: str, max_depth: int = 50) -> dict:
        """GraphQL深层嵌套DoS测试 - 检测嵌套深度限制

        测试服务器是否限制查询嵌套深度

        Args:
            url: GraphQL端点URL
            max_depth: 最大测试深度

        Returns:
            {
                "vulnerable": bool,
                "max_depth_accepted": int,
                "response_times": [...],
                "remediation": str
            }
        """
        try:
            from modules.api_security.graphql_security import GraphQLSecurityTester

            tester = GraphQLSecurityTester()
            return tester.test_deep_nesting(url, max_depth)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("graphql_deep_nesting_test")

    @mcp.tool()
    def graphql_field_suggestion_test(url: str) -> dict:
        """GraphQL字段建议测试 - 检测信息泄露

        发送错误字段名,检查服务器是否返回字段建议

        Args:
            url: GraphQL端点URL

        Returns:
            {
                "vulnerable": bool,
                "suggestions_found": [...],
                "remediation": str
            }
        """
        try:
            from modules.api_security.graphql_security import GraphQLSecurityTester

            tester = GraphQLSecurityTester()
            return tester.test_field_suggestion(url)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("graphql_field_suggestion_test")

    @mcp.tool()
    def graphql_alias_overload_test(url: str, max_aliases: int = 100) -> dict:
        """GraphQL别名重载测试 - 检测别名数量限制

        Args:
            url: GraphQL端点URL
            max_aliases: 最大测试别名数量
        """
        try:
            from modules.api_security.graphql_security import GraphQLSecurityTester

            tester = GraphQLSecurityTester()
            return tester.test_alias_overload(url, max_aliases)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("graphql_alias_overload_test")

    @mcp.tool()
    def graphql_full_scan(url: str) -> dict:
        """GraphQL完整安全扫描 - 执行所有GraphQL安全测试

        包含: 内省、批量DoS、深层嵌套、字段建议、别名重载

        Args:
            url: GraphQL端点URL

        Returns:
            {
                "vulnerabilities": [...],
                "tests": {...},
                "summary": {
                    "total_tests": int,
                    "vulnerable_count": int,
                    "highest_severity": str
                },
                "recommendations": [...]
            }
        """
        try:
            from modules.api_security.graphql_security import GraphQLSecurityTester

            tester = GraphQLSecurityTester()
            return tester.full_scan(url)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("graphql_full_scan")

    # ========== WebSocket安全工具 ==========

    @mcp.tool()
    def websocket_origin_bypass_test(ws_url: str, target_origin: str = "") -> dict:
        """WebSocket Origin绕过测试 - 检测Origin验证

        测试多种Origin绕过技术

        Args:
            ws_url: WebSocket URL (ws:// 或 wss://)
            target_origin: 目标网站Origin

        Returns:
            {
                "vulnerable": bool,
                "accepted_origins": [...],
                "tests": [...],
                "remediation": str
            }
        """
        try:
            from modules.api_security.websocket_security import WebSocketSecurityTester

            tester = WebSocketSecurityTester()
            return tester.test_origin_bypass(ws_url, target_origin)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("websocket_origin_bypass_test")

    @mcp.tool()
    def websocket_cswsh_test(ws_url: str, target_origin: str) -> dict:
        """WebSocket跨站劫持测试 - 检测CSWSH漏洞

        测试是否可以从攻击者域名建立WebSocket连接

        Args:
            ws_url: WebSocket URL
            target_origin: 目标网站Origin

        Returns:
            {
                "vulnerable": bool,
                "poc_html": str,
                "remediation": str
            }
        """
        try:
            from modules.api_security.websocket_security import WebSocketSecurityTester

            tester = WebSocketSecurityTester()
            return tester.test_cswsh(ws_url, target_origin)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("websocket_cswsh_test")

    @mcp.tool()
    def websocket_auth_bypass_test(ws_url: str) -> dict:
        """WebSocket认证绕过测试 - 检测是否需要认证

        测试无认证和无效Token是否能建立连接

        Args:
            ws_url: WebSocket URL

        Returns:
            {
                "vulnerable": bool,
                "tests": [...],
                "remediation": str
            }
        """
        try:
            from modules.api_security.websocket_security import WebSocketSecurityTester

            tester = WebSocketSecurityTester()
            return tester.test_auth_bypass(ws_url)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("websocket_auth_bypass_test")

    @mcp.tool()
    def websocket_compression_test(ws_url: str) -> dict:
        """WebSocket压缩攻击测试 - 检测CRIME漏洞

        检查是否启用permessage-deflate压缩

        Args:
            ws_url: WebSocket URL

        Returns:
            {
                "vulnerable": bool,
                "compression_enabled": bool,
                "extensions": [...],
                "remediation": str
            }
        """
        try:
            from modules.api_security.websocket_security import WebSocketSecurityTester

            tester = WebSocketSecurityTester()
            return tester.test_compression_oracle(ws_url)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("websocket_compression_test")

    @mcp.tool()
    def websocket_full_scan(ws_url: str, target_origin: str = "") -> dict:
        """WebSocket完整安全扫描 - 执行所有WebSocket安全测试

        包含: TLS检测、Origin绕过、CSWSH、认证绕过、压缩攻击

        Args:
            ws_url: WebSocket URL
            target_origin: 目标网站Origin

        Returns:
            {
                "vulnerabilities": [...],
                "tests": {...},
                "summary": {
                    "total_tests": int,
                    "vulnerable_count": int,
                    "highest_severity": str
                },
                "recommendations": [...]
            }
        """
        try:
            from modules.api_security.websocket_security import WebSocketSecurityTester

            tester = WebSocketSecurityTester()
            return tester.full_scan(ws_url, target_origin)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("websocket_full_scan")

    logger.info(f"已注册 {len(registered_tools)} 个API安全工具")
    return registered_tools
