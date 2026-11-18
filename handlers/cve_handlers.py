"""
CVE工具处理器
包含: cve_search, cve_sync, cve_stats, poc_execute, poc_list
"""

from typing import Any, Dict, List, Optional

from core.capability_manifest import surface_enabled_for_mcp

from .error_handling import ErrorCategory, handle_errors
from .tooling import tool


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
        severity: Optional[str] = None,
        has_poc: Optional[bool] = None,
        limit: int = 50,
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
        results = manager.search(keyword=keyword, severity=severity, poc_only=has_poc or False)

        cves = [
            {
                "cve_id": r.cve_id,
                "description": r.description[:200],
                "severity": r.severity,
                "cvss": r.cvss,
                "poc_available": r.poc_available,
                "poc_path": r.poc_path,
            }
            for r in results[:limit]
        ]

        return {"success": True, "keyword": keyword, "cves": cves, "count": len(cves)}

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CVE)
    async def cve_sync(days: int = 7, sources: Optional[List[str]] = None) -> Dict[str, Any]:
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
            "success": True,
            "days": days,
            "results": {
                source: {"new": new, "updated": updated}
                for source, (new, updated) in results.items()
            },
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

        return {"success": True, "stats": stats}

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CVE)
    async def poc_list(keyword: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
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

        return {"success": True, "templates": templates[:limit], "count": len(templates[:limit])}

    registered = 4
    if surface_enabled_for_mcp(mcp, "tool", "cve_auto_exploit"):
        from .cve_exploit_handlers import register_cve_exploit_tools

        registered += register_cve_exploit_tools(mcp, logger)

    counter.add("cve", registered)
    if registered == 8:
        logger.info("[CVE] 已注册 8 个CVE工具 (含3个自动利用工具)")
    else:
        logger.info("[CVE] 已注册 %s 个CVE工具", registered)
