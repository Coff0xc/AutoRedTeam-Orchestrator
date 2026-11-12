"""
杂项工具处理器
包含: registry_stats, health_check, tool_search, tool_enable, js_analyze
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
    @handle_errors(logger, category=ErrorCategory.MISC)
    async def tool_enable(name: str, kind: str = "tool") -> Dict[str, Any]:
        """Enable a catalog-only surface on this server for the current profile.

        Args:
            name: Catalog surface name
            kind: tool, prompt, or resource
        """
        from core.capability_manifest import ProfileDenied, get_capability, resolve_profile

        profile = getattr(mcp, "capability_profile", None)
        if not isinstance(profile, str) or not profile:
            profile = resolve_profile()
        kind_name = str(kind).strip().lower()
        if kind_name not in {"tool", "prompt", "resource"}:
            return {
                "success": False,
                "error": "kind must be tool, prompt, or resource",
            }
        capability = get_capability(kind_name, name)
        if not capability.allowed_in(profile):
            raise ProfileDenied(
                name=capability.name,
                kind=capability.kind,
                profile=profile,
                required_profile=capability.minimum_profile,
            )
        invoke: Dict[str, Any] = {capability.kind: capability.name}
        if capability.kind == "resource" and capability.locator:
            invoke["locator"] = capability.locator
        if capability.resident:
            return {
                "success": True,
                "enabled": True,
                "resident": True,
                "invoke": invoke,
            }

        inner = getattr(mcp, "_mcp", mcp)
        catalog = getattr(inner, "_autort_catalog", None)
        if not isinstance(catalog, dict):
            catalog = {}
        key = (capability.kind, capability.name)
        func = catalog.get(key)
        enable_card: Dict[str, Any] = {"tool": "tool_enable", "name": capability.name}
        if capability.kind != "tool":
            enable_card["kind"] = capability.kind
        if func is None:
            return {
                "success": False,
                "error": f"{capability.name} is not loaded in this process",
                "invoke": enable_card,
            }
        enabled = getattr(inner, "_autort_enabled", None)
        if enabled is None:
            enabled = set()
            setattr(inner, "_autort_enabled", enabled)
        if key not in enabled:
            description = capability.public_description()
            if capability.kind == "tool":
                inner.tool(name=capability.name, description=description)(func)
            elif capability.kind == "prompt":
                inner.prompt(name=capability.name, description=description)(func)
            else:
                locator = capability.locator
                if not locator:
                    return {
                        "success": False,
                        "error": f"{capability.name} has no resource locator",
                        "invoke": enable_card,
                    }
                inner.resource(
                    locator,
                    name=capability.name,
                    description=description,
                    mime_type="application/json",
                )(func)
            enabled.add(key)
        return {
            "success": True,
            "enabled": True,
            "resident": False,
            "invoke": invoke,
        }

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

    counter.add("misc", 5)
    logger.info("[Misc] 已注册 5 个杂项工具")
