"""
API安全工具处理器
包含: jwt_scan, cors_deep_scan, graphql_scan, websocket_scan, oauth_scan,
      security_headers_score, full_api_scan
"""

from typing import Any, Dict
from .tooling import tool


def register_api_security_tools(mcp, counter, logger):
    """注册API安全工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    async def jwt_scan(token: str, target: str = None) -> Dict[str, Any]:
        """JWT安全扫描 - 检测JWT令牌的安全问题

        检测: None算法、弱密钥、算法混淆、KID注入等

        Args:
            token: JWT令牌
            target: 目标URL (用于验证)

        Returns:
            JWT安全问题
        """
        try:
            from modules.api_security import JWTTester, quick_jwt_test, decode_jwt

            # 先解码查看基本信息
            decoded = decode_jwt(token)

            # 执行安全测试
            if target:
                tester = JWTTester(target, token)
                results = tester.test()

                vulns = [r.to_dict() for r in results if r.vulnerable]
            else:
                vulns = quick_jwt_test(token)

            return {
                'success': True,
                'decoded': decoded,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @tool(mcp)
    async def cors_deep_scan(url: str) -> Dict[str, Any]:
        """CORS深度扫描 - 全面检测CORS配置问题

        检测: Origin反射、子域名绕过、Null Origin、预检请求等

        Args:
            url: 目标URL

        Returns:
            CORS安全问题
        """
        try:
            from modules.api_security import CORSTester

            tester = CORSTester(url)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @tool(mcp)
    async def graphql_scan(url: str) -> Dict[str, Any]:
        """GraphQL安全扫描 - 检测GraphQL API安全问题

        检测: 内省查询、批量查询DoS、深层嵌套、字段建议、别名滥用

        Args:
            url: GraphQL端点URL

        Returns:
            GraphQL安全问题
        """
        try:
            from modules.api_security import GraphQLTester

            tester = GraphQLTester(url)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @tool(mcp)
    async def websocket_scan(url: str) -> Dict[str, Any]:
        """WebSocket安全扫描 - 检测WebSocket安全问题

        检测: Origin绕过、CSWSH、认证绕过、压缩攻击

        Args:
            url: WebSocket URL (ws:// 或 wss://)

        Returns:
            WebSocket安全问题
        """
        try:
            from modules.api_security import WebSocketTester

            tester = WebSocketTester(url)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @tool(mcp)
    async def oauth_scan(url: str, client_id: str = None) -> Dict[str, Any]:
        """OAuth安全扫描 - 检测OAuth 2.0实现问题

        检测: 开放重定向、CSRF、令牌泄露、PKCE缺失

        Args:
            url: OAuth端点URL
            client_id: 客户端ID (可选)

        Returns:
            OAuth安全问题
        """
        try:
            from modules.api_security import OAuthTester

            tester = OAuthTester(url, client_id=client_id)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @tool(mcp)
    async def security_headers_score(url: str) -> Dict[str, Any]:
        """安全头评分 - 评估网站的安全头配置

        评分标准: CSP, HSTS, X-Frame-Options等

        Args:
            url: 目标URL

        Returns:
            安全头评分和建议
        """
        try:
            from modules.api_security import SecurityHeadersTester

            tester = SecurityHeadersTester(url)
            results = tester.test()
            summary = tester.get_summary()

            return {
                'success': True,
                'url': url,
                'score': summary.score if hasattr(summary, 'score') else 0,
                'grade': summary.grade if hasattr(summary, 'grade') else 'N/A',
                'headers': summary.to_dict() if hasattr(summary, 'to_dict') else {},
                'recommendations': [r.to_dict() for r in results]
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @tool(mcp)
    async def full_api_scan(target: str, jwt_token: str = None) -> Dict[str, Any]:
        """完整API安全扫描 - 执行全面的API安全测试

        包含: JWT、CORS、安全头、GraphQL(如适用)

        Args:
            target: 目标URL
            jwt_token: JWT令牌 (可选)

        Returns:
            综合API安全报告
        """
        try:
            from modules.api_security import full_api_scan as _full_api_scan

            result = _full_api_scan(target, jwt_token=jwt_token)

            return {
                'success': True,
                'target': target,
                **result
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    counter.add('api_security', 7)
    logger.info("[API Security] 已注册 7 个API安全工具")