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

# ============ 分类 ============
from .categories import (
    # 枚举
    ToolCategory,

    # 描述和映射
    CATEGORY_DESCRIPTIONS,
    CATEGORY_HIERARCHY,
    ATTCK_MAPPING,
    CATEGORY_ICONS,

    # 辅助函数
    get_category_description,
    get_categories_by_phase,
    get_phase_for_category,
    get_attck_tactics,
    list_all_phases,
    list_all_categories,
    get_category_icon,
)

# ============ 基类 ============
from .base import (
    # 参数类型
    ParamType,
    PYTHON_TYPE_MAPPING,

    # 数据类
    ToolParameter,
    ToolResult,
    ToolMetadata,

    # 基类
    BaseTool,
    FunctionTool,
    AsyncTool,
)

# ============ 注册表 ============
from .registry import (
    # 异常
    ToolNotFoundError,
    ToolAlreadyExistsError,
    ToolValidationError,

    # 注册表类
    ToolRegistry,

    # 全局访问
    get_registry,
    reset_registry,

    # 快捷函数
    register_tool,
    register_function,
    get_tool,
    execute_tool,
    async_execute_tool,
    list_all_tools,
    search_tools,
)

# ============ MCP桥接 ============
from .mcp_bridge import (
    # Schema
    MCPToolSchema,

    # 桥接器
    MCPBridge,
    MCPToolBuilder,

    # 便捷函数
    create_mcp_tool,
    mcp_tool,
    get_global_bridge,
    reset_global_bridge,
)

# ============ 装饰器 ============
from .decorator import (
    # 主装饰器
    tool,
    async_tool,

    # 分类快捷装饰器
    recon_tool,
    vuln_tool,
    api_tool,
    exploit_tool,
    c2_tool,
    lateral_tool,
    cve_tool,
    report_tool,
    ai_tool,

    # 参数装饰器
    param,
    validate_params,

    # 属性装饰器
    deprecated,
    require_auth,
    require_root,
    tags,
    timeout,
    example,

    # 批量操作
    register_tools,
    unregister_tool,
)


# ============ 版本信息 ============
__version__ = '1.0.0'
__author__ = 'AutoRedTeam'


# ============ 公开接口 ============
__all__ = [
    # 版本
    '__version__',
    '__author__',

    # === 分类 ===
    'ToolCategory',
    'CATEGORY_DESCRIPTIONS',
    'CATEGORY_HIERARCHY',
    'ATTCK_MAPPING',
    'CATEGORY_ICONS',
    'get_category_description',
    'get_categories_by_phase',
    'get_phase_for_category',
    'get_attck_tactics',
    'list_all_phases',
    'list_all_categories',
    'get_category_icon',

    # === 基类 ===
    'ParamType',
    'PYTHON_TYPE_MAPPING',
    'ToolParameter',
    'ToolResult',
    'ToolMetadata',
    'BaseTool',
    'FunctionTool',
    'AsyncTool',

    # === 注册表 ===
    'ToolNotFoundError',
    'ToolAlreadyExistsError',
    'ToolValidationError',
    'ToolRegistry',
    'get_registry',
    'reset_registry',
    'register_tool',
    'register_function',
    'get_tool',
    'execute_tool',
    'async_execute_tool',
    'list_all_tools',
    'search_tools',

    # === MCP桥接 ===
    'MCPToolSchema',
    'MCPBridge',
    'MCPToolBuilder',
    'create_mcp_tool',
    'mcp_tool',
    'get_global_bridge',
    'reset_global_bridge',

    # === 装饰器 ===
    'tool',
    'async_tool',
    'recon_tool',
    'vuln_tool',
    'api_tool',
    'exploit_tool',
    'c2_tool',
    'lateral_tool',
    'cve_tool',
    'report_tool',
    'ai_tool',
    'param',
    'validate_params',
    'deprecated',
    'require_auth',
    'require_root',
    'tags',
    'timeout',
    'example',
    'register_tools',
    'unregister_tool',
]


def __getattr__(name: str):
    """延迟导入支持"""
    if name == 'get_registry':
        from .registry import get_registry
        return get_registry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
