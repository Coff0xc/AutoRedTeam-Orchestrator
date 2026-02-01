#!/usr/bin/env python3
"""
增强检测器MCP工具注册模块
注册: JWT增强、CORS增强、安全头评分
"""

import logging

from utils.mcp_tooling import patch_mcp_tool

logger = logging.getLogger(__name__)


def register_enhanced_detector_tools(mcp):
    """注册增强检测器工具到MCP Server"""
    patch_mcp_tool(mcp)

    registered_tools = []

    # ========== JWT增强工具 ==========

    @mcp.tool()
    def jwt_none_algorithm_test(token: str, url: str = "") -> dict:
        """JWT None算法攻击测试 - 检测签名绕过漏洞

        Args:
            token: JWT字符串
            url: 验证端点URL (可选,用于实际验证)

        Returns:
            {
                "vulnerable": bool,
                "forged_tokens": [...],
                "proof": str,
                "remediation": str
            }
        """
        try:
            from modules.enhanced_detectors.jwt_enhanced import JWTSecurityTester

            tester = JWTSecurityTester()
            return tester.test_none_algorithm(token, url)

        except ImportError as e:
            return {"success": False, "error": f"模块导入失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("jwt_none_algorithm_test")

    @mcp.tool()
    def jwt_algorithm_confusion_test(token: str, url: str = "", public_key: str = "") -> dict:
        """JWT算法混淆攻击测试 - RS256->HS256绕过

        将RS256签名的Token改为HS256,使用公钥作为HMAC密钥

        Args:
            token: JWT字符串 (应为RS256签名)
            url: 验证端点URL
            public_key: RSA公钥 (PEM格式)
        """
        try:
            from modules.enhanced_detectors.jwt_enhanced import JWTSecurityTester

            tester = JWTSecurityTester()
            return tester.test_algorithm_confusion(token, url, public_key)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("jwt_algorithm_confusion_test")

    @mcp.tool()
    def jwt_weak_secret_test(token: str, custom_secrets: str = "") -> dict:
        """JWT弱密钥测试 - 尝试常见弱密钥

        Args:
            token: JWT字符串
            custom_secrets: 自定义密钥列表 (逗号分隔)

        Returns:
            {
                "vulnerable": bool,
                "found_secret": str,
                "attempts": int
            }
        """
        try:
            from modules.enhanced_detectors.jwt_enhanced import JWTSecurityTester

            tester = JWTSecurityTester()
            secrets = custom_secrets.split(",") if custom_secrets else None
            return tester.test_weak_secrets(token, secrets)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("jwt_weak_secret_test")

    @mcp.tool()
    def jwt_kid_injection_test(token: str, url: str = "") -> dict:
        """JWT KID参数注入测试 - 路径遍历/SQL注入

        Args:
            token: JWT字符串
            url: 验证端点URL
        """
        try:
            from modules.enhanced_detectors.jwt_enhanced import JWTSecurityTester

            tester = JWTSecurityTester()
            return tester.test_kid_injection(token, url)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("jwt_kid_injection_test")

    @mcp.tool()
    def jwt_full_scan(token: str, url: str = "", public_key: str = "") -> dict:
        """JWT完整安全扫描 - 执行所有JWT安全测试

        Args:
            token: JWT字符串
            url: 验证端点URL
            public_key: RSA公钥 (用于算法混淆测试)

        Returns:
            {
                "jwt_info": {...},
                "vulnerabilities": [...],
                "summary": {
                    "total_tests": int,
                    "vulnerable_count": int,
                    "highest_severity": str
                }
            }
        """
        try:
            from modules.enhanced_detectors.jwt_enhanced import JWTSecurityTester

            tester = JWTSecurityTester()
            return tester.full_scan(token, url, public_key)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("jwt_full_scan")

    # ========== CORS增强工具 ==========

    @mcp.tool()
    def cors_bypass_test(url: str, target_origin: str = "") -> dict:
        """CORS绕过测试 - 使用扩展Payloads测试Origin绕过

        测试30+种Origin绕过技术,包括:
        - 子域名欺骗
        - 协议混淆
        - URL编码绕过
        - Unicode绕过
        - 正则绕过

        Args:
            url: 目标URL
            target_origin: 目标网站Origin (用于构造绕过Payload)

        Returns:
            {
                "vulnerable": bool,
                "vulnerabilities": [...],
                "proof_of_concept": str,
                "recommendations": [...]
            }
        """
        try:
            from modules.enhanced_detectors.cors_enhanced import CORSEnhancedTester

            tester = CORSEnhancedTester()
            return tester.test_all_bypasses(url)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("cors_bypass_test")

    @mcp.tool()
    def cors_preflight_test(
        url: str, origin: str = "https://evil.com", method: str = "PUT"
    ) -> dict:
        """CORS预检请求测试 - 测试OPTIONS请求处理

        Args:
            url: 目标URL
            origin: Origin值
            method: Access-Control-Request-Method值
        """
        try:
            from modules.enhanced_detectors.cors_enhanced import CORSEnhancedTester

            tester = CORSEnhancedTester()
            return tester.test_preflight(url, origin, method)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("cors_preflight_test")

    # ========== 安全头评分工具 ==========

    @mcp.tool()
    def security_headers_score(url: str) -> dict:
        """安全头评分 - 基于OWASP指南的加权评分

        评估11个安全头的配置:
        - Strict-Transport-Security (HSTS)
        - Content-Security-Policy (CSP)
        - X-Content-Type-Options
        - X-Frame-Options
        - Referrer-Policy
        - Permissions-Policy
        - Cross-Origin-*-Policy

        Args:
            url: 目标URL

        Returns:
            {
                "score": int,
                "max_score": int,
                "percentage": float,
                "grade": str,  // A+, A, B, C, D, F
                "grade_description": str,
                "headers": [...],
                "recommendations": [...]
            }
        """
        try:
            from modules.enhanced_detectors.security_headers_scorer import SecurityHeadersScorer

            scorer = SecurityHeadersScorer()
            return scorer.analyze(url)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("security_headers_score")

    @mcp.tool()
    def security_headers_compare(url1: str, url2: str) -> dict:
        """安全头对比 - 比较两个URL的安全头配置

        Args:
            url1: 第一个URL
            url2: 第二个URL

        Returns:
            {
                "url1": {"score": int, "grade": str},
                "url2": {"score": int, "grade": str},
                "differences": [...]
            }
        """
        try:
            from modules.enhanced_detectors.security_headers_scorer import SecurityHeadersScorer

            scorer = SecurityHeadersScorer()
            return scorer.compare(url1, url2)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("security_headers_compare")

    @mcp.tool()
    def security_headers_report(url: str) -> dict:
        """安全头报告 - 生成文本格式的详细报告

        Args:
            url: 目标URL

        Returns:
            {"report": str}
        """
        try:
            from modules.enhanced_detectors.security_headers_scorer import SecurityHeadersScorer

            scorer = SecurityHeadersScorer()
            report = scorer.generate_report(url)
            return {"success": True, "report": report}

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("security_headers_report")

    logger.info(f"已注册 {len(registered_tools)} 个增强检测器工具")
    return registered_tools
