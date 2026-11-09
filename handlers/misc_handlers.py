"""
杂项工具处理器
包含: registry_stats, health_check, tool_search, js_analyze
"""

import platform
from typing import Any, Dict, Optional

from core import __version__

from .error_handling import ErrorCategory, extract_url, handle_errors, validate_inputs
from .tooling import tool


def register_misc_tools(mcp, counter, logger):
    """注册杂项工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    async def registry_stats() -> Dict[str, Any]:
        """工具统计 - 获取已注册工具的统计信息

        Returns:
            工具统计
        """
        return {
            "success": True,
            "total": counter.total,
            "by_category": counter.counts,
            "version": __version__,
        }

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.MISC)
    async def tool_search(
        query: str = "",
        kind: Optional[str] = None,
        limit: int = 12,
    ) -> Dict[str, Any]:
        """Search the capability catalog for tools, prompts, and resources.

        Args:
            query: Name, category, handler, or effect tokens. Empty lists resident surfaces.
            kind: Optional filter: tool, prompt, or resource
            limit: Maximum cards to return (1-50)
        """
        from core.capability_manifest import resolve_profile, search_surfaces

        profile = getattr(mcp, "capability_profile", None)
        if not isinstance(profile, str) or not profile:
            profile = resolve_profile()
        payload = search_surfaces(query, profile=profile, kind=kind, limit=limit)
        payload["success"] = True
        return payload

    @tool(mcp)
    async def health_check() -> Dict[str, Any]:
        """健康检查 - 检查MCP服务器状态

        Returns:
            服务器状态
        """
        return {
            "success": True,
            "status": "healthy",
            "version": __version__,
            "python_version": platform.python_version(),
            "platform": platform.system(),
            "tools_registered": counter.total,
        }

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.MISC, context_extractor=extract_url)
    async def js_analyze(url: str) -> Dict[str, Any]:
        """JS代码分析 - 分析JavaScript代码中的敏感信息

        提取: API端点、密钥、令牌、内部路径

        Args:
            url: 目标URL或JS文件URL

        Returns:
            分析结果
        """
        from core.recon.js_analyzer import JSAnalyzer

        analyzer = JSAnalyzer()
        results = analyzer.analyze(url)

        return {"success": True, "url": url, "findings": results}

    counter.add("misc", 4)
    logger.info("[Misc] 已注册 4 个杂项工具")
