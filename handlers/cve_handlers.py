"""
CVE工具处理器
包含: cve_search, cve_sync, cve_stats, poc_execute, poc_list
"""

from typing import Any, Dict, List
from .tooling import tool
from .error_handling import handle_errors, ErrorCategory, extract_target, validate_inputs


def register_cve_tools(mcp, counter, logger):
    """注册CVE相关工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CVE)
    async def cve_search(
        keyword: str,
        severity: str = None,
        has_poc: bool = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """搜索CVE漏洞 - 在本地CVE数据库中搜索

        Args:
            keyword: 搜索关键词 (CVE ID或描述关键词)
            severity: 严重程度过滤 (CRITICAL, HIGH, MEDIUM, LOW)
            has_poc: 是否只返回有PoC的CVE
            limit: 最大返回数量

        Returns:
            CVE列表
        """
        from core.cve.update_manager import CVEUpdateManager

        manager = CVEUpdateManager()
        results = manager.search(
            keyword=keyword,
            severity=severity,
            poc_only=has_poc or False
        )

        cves = [
            {
                'cve_id': r.cve_id,
                'description': r.description[:200],
                'severity': r.severity,
                'cvss': r.cvss,
                'poc_available': r.poc_available,
                'poc_path': r.poc_path
            }
            for r in results[:limit]
        ]

        return {
            'success': True,
            'keyword': keyword,
            'cves': cves,
            'count': len(cves)
        }

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CVE)
    async def cve_sync(days: int = 7, sources: List[str] = None) -> Dict[str, Any]:
        """同步CVE数据 - 从多个数据源同步最新CVE

        数据源: NVD (官方), Nuclei Templates, Exploit-DB

        Args:
            days: 同步最近多少天的数据
            sources: 指定数据源 (默认全部)

        Returns:
            同步结果
        """
        from core.cve.update_manager import CVEUpdateManager

        manager = CVEUpdateManager()
        results = await manager.sync_all(days_back=days)

        return {
            'success': True,
            'days': days,
            'results': {
                source: {'new': new, 'updated': updated}
                for source, (new, updated) in results.items()
            }
        }

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CVE)
    async def cve_stats() -> Dict[str, Any]:
        """CVE数据库统计 - 获取本地CVE数据库统计信息

        Returns:
            统计信息
        """
        from core.cve.update_manager import CVEUpdateManager

        manager = CVEUpdateManager()
        stats = manager.get_stats()

        return {
            'success': True,
            'stats': stats
        }

    @tool(mcp)
    @validate_inputs(target='target')
    @handle_errors(logger, category=ErrorCategory.CVE, context_extractor=extract_target)
    async def poc_execute(target: str, template_id: str, variables: Dict[str, str] = None) -> Dict[str, Any]:
        """执行PoC验证 - 使用PoC模板验证目标漏洞

        Args:
            target: 目标URL
            template_id: PoC模板ID
            variables: 自定义变量

        Returns:
            执行结果
        """
        from core.cve.poc_engine import get_poc_engine

        engine = get_poc_engine()
        template = engine.get_template(template_id)

        if not template:
            return {
                'success': False,
                'error': f'模板不存在: {template_id}',
                'available_templates': engine.list_templates()[:10]
            }

        result = engine.execute(target, template, variables)

        return {
            'success': result.success,
            'vulnerable': result.vulnerable,
            'template_id': template_id,
            'target': target,
            'evidence': result.evidence,
            'extracted': result.extracted,
            'execution_time_ms': result.execution_time_ms
        }

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CVE)
    async def poc_list(keyword: str = None, limit: int = 50) -> Dict[str, Any]:
        """列出PoC模板 - 查看已加载的PoC模板

        Args:
            keyword: 过滤关键词
            limit: 最大返回数量

        Returns:
            PoC模板列表
        """
        from core.cve.poc_engine import get_poc_engine

        engine = get_poc_engine()
        templates = engine.list_templates()

        if keyword:
            templates = [t for t in templates if keyword.lower() in t.lower()]

        return {
            'success': True,
            'templates': templates[:limit],
            'count': len(templates[:limit])
        }

    # ==================== CVE 自动利用工具 ====================

    @tool(mcp)
    @validate_inputs(target='target')
    @handle_errors(logger, category=ErrorCategory.CVE, context_extractor=extract_target)
    async def cve_auto_exploit(
        target: str,
        cve_id: str,
        custom_vars: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """CVE自动利用 - 通过CVE ID自动生成PoC并利用

        完整流程: CVE搜索 → AI生成PoC → 验证 → 深度利用

        警告: 仅限授权渗透测试使用!

        Args:
            target: 目标URL
            cve_id: CVE编号 (如 CVE-2024-1234)
            custom_vars: 自定义变量 (传递给PoC模板)

        Returns:
            自动利用结果
        """
        from core.cve.auto_exploit import auto_exploit_cve

        result = await auto_exploit_cve(target, cve_id, custom_vars)

        return {
            'success': result.success,
            'status': result.status.value,
            'cve_id': cve_id,
            'target': target,
            'vulnerable': result.vulnerable,
            'vuln_type': result.vuln_type,
            'evidence': result.evidence,
            'poc_yaml': result.poc_yaml[:2000] if result.poc_yaml else None,
            'poc_template_path': result.poc_template_path,
            'exploit_data': result.exploit_data,
            'execution_time_ms': result.execution_time_ms,
            'steps': result.steps,
            'error': result.error,
        }

    @tool(mcp)
    @validate_inputs(target='target')
    @handle_errors(logger, category=ErrorCategory.CVE, context_extractor=extract_target)
    async def cve_exploit_with_desc(
        target: str,
        cve_id: str,
        description: str,
        severity: str = 'medium',
        custom_vars: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """通过CVE描述利用 - 已知描述时直接生成PoC并利用

        跳过CVE搜索步骤，直接从描述生成PoC

        警告: 仅限授权渗透测试使用!

        Args:
            target: 目标URL
            cve_id: CVE编号
            description: CVE描述
            severity: 严重性级别 (info/low/medium/high/critical)
            custom_vars: 自定义变量

        Returns:
            利用结果
        """
        from core.cve.auto_exploit import exploit_cve_with_description

        result = await exploit_cve_with_description(
            target, cve_id, description, severity, custom_vars
        )

        return {
            'success': result.success,
            'status': result.status.value,
            'cve_id': cve_id,
            'target': target,
            'vulnerable': result.vulnerable,
            'vuln_type': result.vuln_type,
            'evidence': result.evidence,
            'poc_yaml': result.poc_yaml[:2000] if result.poc_yaml else None,
            'exploit_data': result.exploit_data,
            'execution_time_ms': result.execution_time_ms,
            'steps': result.steps,
            'error': result.error,
        }

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CVE)
    async def cve_generate_poc(
        cve_id: str,
        description: str,
        severity: str = 'medium'
    ) -> Dict[str, Any]:
        """AI生成PoC - 根据CVE描述智能生成PoC模板

        仅生成PoC，不执行利用，适合人工审核场景

        Args:
            cve_id: CVE编号
            description: CVE描述
            severity: 严重性级别

        Returns:
            生成的PoC YAML模板
        """
        from core.cve.auto_exploit import generate_cve_poc

        poc_yaml = generate_cve_poc(cve_id, description, severity)

        if not poc_yaml:
            return {
                'success': False,
                'error': 'PoC生成失败'
            }

        return {
            'success': True,
            'cve_id': cve_id,
            'poc_yaml': poc_yaml,
            'poc_length': len(poc_yaml),
        }

    counter.add('cve', 8)  # 原有5个 + 新增3个
    logger.info("[CVE] 已注册 8 个CVE工具 (含3个自动利用工具)")

