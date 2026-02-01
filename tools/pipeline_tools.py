#!/usr/bin/env python3
"""
流水线工具模块 - 指纹→POC→弱口令→攻击链联动
"""


def register_pipeline_tools(mcp):
    """注册所有流水线工具到 MCP 服务器"""

    @mcp.tool()
    def vulnerability_pipeline(target: str, verify_ssl: bool = True, timeout: int = 10) -> dict:
        """漏洞检测流水线 - 自动执行指纹→弱口令→漏洞→攻击链的完整流程

        Args:
            target: 目标URL
            verify_ssl: 是否验证SSL证书
            timeout: 请求超时时间(秒)

        Returns:
            {
                "target": str,
                "phases": {
                    "fingerprint": {...},
                    "weak_password": {...},
                    "vuln_scan": {...},
                    "attack_chain": {...}
                },
                "summary": {
                    "fingerprint_count": int,
                    "detected_cms": [...],
                    "weak_credentials_found": int,
                    "vulnerabilities_found": int,
                    "risk_level": str
                },
                "context": {...}
            }
        """
        from core.pipeline import VulnerabilityPipeline

        pipeline = VulnerabilityPipeline(target, verify_ssl, timeout)
        return pipeline.run_full_pipeline()

    @mcp.tool()
    def fingerprint_weak_password(
        url: str, cms_hint: str = None, verify_ssl: bool = True, timeout: int = 10
    ) -> dict:
        """基于指纹的弱口令检测 - 根据CMS/框架使用专用字典

        与通用weak_password_detect不同，此工具会：
        1. 先识别目标CMS/框架 (或使用提供的cms_hint)
        2. 使用针对该CMS的专用登录端点和凭证字典
        3. 使用正确的表单字段名进行测试

        支持的CMS/框架:
        - WordPress, Joomla, Drupal, Typecho, Discuz, DedeCMS
        - ThinkPHP, Laravel, Spring, Django
        - Tomcat, Weblogic, Jenkins, GitLab
        - phpMyAdmin, Nginx, Apache

        Args:
            url: 目标URL
            cms_hint: CMS提示，如 "WordPress" 或 "Tomcat"。不提供则自动识别
            verify_ssl: 是否验证SSL证书
            timeout: 请求超时时间(秒)

        Returns:
            {
                "success": bool,
                "tested_cms": [...],
                "weak_credentials": [
                    {
                        "cms": str,
                        "url": str,
                        "username": str,
                        "password": str,
                        "auth_type": "basic" | "form"
                    }
                ],
                "exposed_panels": [...],
                "fingerprint": {
                    "cms": [...],
                    "frameworks": [...]
                }
            }
        """
        from core.pipeline import fingerprint_weak_password_detect

        return fingerprint_weak_password_detect(url, cms_hint, verify_ssl, timeout)

    @mcp.tool()
    def targeted_vuln_scan(
        url: str, cms_list: str = None, verify_ssl: bool = True, timeout: int = 10
    ) -> dict:
        """基于指纹的针对性漏洞扫描 - 根据CMS执行特定漏洞检测

        支持的CMS专项检测:
        - WordPress: xmlrpc攻击、用户枚举
        - ThinkPHP: RCE漏洞
        - Spring: Actuator端点暴露、heapdump泄露
        - Laravel: 调试模式、.env泄露
        - Tomcat: Manager面板
        - Weblogic: 控制台路径穿越

        Args:
            url: 目标URL
            cms_list: CMS列表，逗号分隔 (如 "WordPress,ThinkPHP")。不提供则自动识别
            verify_ssl: 是否验证SSL证书
            timeout: 请求超时时间(秒)

        Returns:
            {
                "success": bool,
                "vulnerabilities": [...],
                "targeted_checks": [...],
                "fingerprint": {...}
            }
        """
        from core.pipeline import VulnerabilityPipeline

        pipeline = VulnerabilityPipeline(url, verify_ssl, timeout)

        # 如果提供了CMS列表，直接使用
        if cms_list:
            pipeline.context.detected_cms = [c.strip() for c in cms_list.split(",")]
        else:
            # 否则先运行指纹识别
            pipeline._run_fingerprint()

        # 运行针对性漏洞扫描
        result = pipeline._run_targeted_vuln_scan()
        result["fingerprint"] = {
            "cms": pipeline.context.detected_cms,
            "frameworks": pipeline.context.detected_frameworks,
        }

        return result

    @mcp.tool()
    def generate_attack_chain_from_context(
        url: str,
        detected_cms: str = None,
        weak_credentials: str = None,
        vulnerabilities: str = None,
    ) -> dict:
        """基于上下文生成攻击链 - 融合指纹、凭证、漏洞信息

        此工具用于手动构建攻击链，当你已经通过其他工具收集了信息时使用。
        会根据提供的上下文生成详细的攻击路径和建议。

        Args:
            url: 目标URL
            detected_cms: 检测到的CMS，逗号分隔 (如 "WordPress,Tomcat")
            weak_credentials: 发现的弱凭证JSON (如 '[{"cms":"WordPress","username":"admin","password":"123456"}]')
            vulnerabilities: 发现的漏洞JSON (如 '[{"type":"SQLi","url":"..."}]')

        Returns:
            {
                "success": bool,
                "attack_chain": {
                    "phases": [...],
                    "recommended_sequence": [...],
                    "exploitation_paths": [...]
                }
            }
        """
        import json as json_module

        from core.pipeline import VulnerabilityPipeline

        pipeline = VulnerabilityPipeline(url)

        # 填充上下文
        if detected_cms:
            pipeline.context.detected_cms = [c.strip() for c in detected_cms.split(",")]

        if weak_credentials:
            try:
                pipeline.context.weak_credentials = json_module.loads(weak_credentials)
            except json_module.JSONDecodeError:
                return {"success": False, "error": "weak_credentials JSON解析失败"}

        if vulnerabilities:
            try:
                pipeline.context.vulnerabilities = json_module.loads(vulnerabilities)
            except json_module.JSONDecodeError:
                return {"success": False, "error": "vulnerabilities JSON解析失败"}

        # 生成攻击链
        return pipeline._generate_attack_chain()

    @mcp.tool()
    def list_cms_credentials() -> dict:
        """列出所有支持的CMS默认凭证配置

        返回所有内置的CMS/框架专用凭证字典信息，
        用于了解支持哪些系统以及每个系统的测试端点。

        Returns:
            {
                "supported_cms": [...],
                "cms_configs": {
                    "WordPress": {
                        "endpoints": [...],
                        "credential_count": int,
                        "auth_type": "form" | "basic"
                    },
                    ...
                }
            }
        """
        from core.pipeline import CMS_DEFAULT_CREDENTIALS

        configs = {}
        for cms, config in CMS_DEFAULT_CREDENTIALS.items():
            configs[cms] = {
                "endpoints": config.get("endpoints", []),
                "credential_count": len(config.get("credentials", [])),
                "auth_type": config.get("auth_type", "form"),
                "check_only": config.get("check_only", False),
            }

        return {
            "supported_cms": list(CMS_DEFAULT_CREDENTIALS.keys()),
            "total_cms": len(CMS_DEFAULT_CREDENTIALS),
            "cms_configs": configs,
        }


# 导出
__all__ = ["register_pipeline_tools"]
