#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具注册层 - 公共接口

提供统一的工具注册、管理和MCP桥接功能。

Quick Start:
    from core.registry import (
        tool, ToolCategory, ToolResult,
        get_registry, MCPBridge
    )

    # 使用装饰器注册工具
    @tool(category=ToolCategory.RECON)
    def my_scanner(target: str) -> dict:
        '''我的扫描器'''
        return {'target': target, 'status': 'scanned'}

    # 执行工具
    registry = get_registry()
    result = registry.execute('my_scanner', target='192.168.1.1')

    # 与MCP集成
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("MyServer")
    bridge = MCPBridge(mcp)
    bridge.register_from_registry()
"""

from __future__ import annotations

# ============ 基类 ============
from .base import (  # 参数类型; 数据类; 基类
    PYTHON_TYPE_MAPPING,
    AsyncTool,
    BaseTool,
    FunctionTool,
    ParamType,
    ToolMetadata,
    ToolParameter,
    ToolResult,
)

# ============ 分类 ============
from .categories import (  # 枚举; 描述和映射; 辅助函数
    ATTCK_MAPPING,
    CATEGORY_DESCRIPTIONS,
    CATEGORY_HIERARCHY,
    CATEGORY_ICONS,
    ToolCategory,
    get_attck_tactics,
    get_categories_by_phase,
    get_category_description,
    get_category_icon,
    get_phase_for_category,
    list_all_categories,
    list_all_phases,
)

# ============ 装饰器 ============
from .decorator import (  # 主装饰器; 分类快捷装饰器; 参数装饰器; 属性装饰器; 批量操作
    ai_tool,
    api_tool,
    async_tool,
    c2_tool,
    cve_tool,
    deprecated,
    example,
    exploit_tool,
    lateral_tool,
    param,
    recon_tool,
    register_tools,
    report_tool,
    require_auth,
    require_root,
    tags,
    timeout,
    tool,
    unregister_tool,
    validate_params,
    vuln_tool,
)

# ============ MCP桥接 ============
from .mcp_bridge import (  # Schema; 桥接器; 便捷函数
    MCPBridge,
    MCPToolBuilder,
    MCPToolSchema,
    create_mcp_tool,
    get_global_bridge,
    mcp_tool,
    reset_global_bridge,
)

# ============ 注册表 ============
from .registry import (  # 异常; 注册表类; 全局访问; 快捷函数
    ToolAlreadyExistsError,
    ToolNotFoundError,
    ToolRegistry,
    ToolValidationError,
    async_execute_tool,
    execute_tool,
    get_registry,
    get_tool,
    list_all_tools,
    register_function,
    register_tool,
    reset_registry,
    search_tools,
)

# ============ 版本信息 ============
__version__ = "1.0.0"
__author__ = "AutoRedTeam"


# ============ 公开接口 ============
__all__ = [
    # 版本
    "__version__",
    "__author__",
    # === 分类 ===
    "ToolCategory",
    "CATEGORY_DESCRIPTIONS",
    "CATEGORY_HIERARCHY",
    "ATTCK_MAPPING",
    "CATEGORY_ICONS",
    "get_category_description",
    "get_categories_by_phase",
    "get_phase_for_category",
    "get_attck_tactics",
    "list_all_phases",
    "list_all_categories",
    "get_category_icon",
    # === 基类 ===
    "ParamType",
    "PYTHON_TYPE_MAPPING",
    "ToolParameter",
    "ToolResult",
    "ToolMetadata",
    "BaseTool",
    "FunctionTool",
    "AsyncTool",
    # === 注册表 ===
    "ToolNotFoundError",
    "ToolAlreadyExistsError",
    "ToolValidationError",
    "ToolRegistry",
    "get_registry",
    "reset_registry",
    "register_tool",
    "register_function",
    "get_tool",
    "execute_tool",
    "async_execute_tool",
    "list_all_tools",
    "search_tools",
    # === MCP桥接 ===
    "MCPToolSchema",
    "MCPBridge",
    "MCPToolBuilder",
    "create_mcp_tool",
    "mcp_tool",
    "get_global_bridge",
    "reset_global_bridge",
    # === 装饰器 ===
    "tool",
    "async_tool",
    "recon_tool",
    "vuln_tool",
    "api_tool",
    "exploit_tool",
    "c2_tool",
    "lateral_tool",
    "cve_tool",
    "report_tool",
    "ai_tool",
    "param",
    "validate_params",
    "deprecated",
    "require_auth",
    "require_root",
    "tags",
    "timeout",
    "example",
    "register_tools",
    "unregister_tool",
]


def __getattr__(name: str):
    """延迟导入支持"""
    if name == "get_registry":
        from .registry import get_registry

        return get_registry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
