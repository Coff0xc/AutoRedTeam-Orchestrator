"""
AI Red Team MCP - Core Module

核心模块提供统一的工具返回值格式和基础组件。
"""

# 统一的工具返回值 Schema
from core.result import (
    ToolResult,
    ResultStatus,
    ToolResultType,
    ensure_tool_result,
)

# 注释有依赖问题的导入，使用时再单独导入
# from core.mcp_server import MCPServer, create_app
# from core.tool_registry import ToolRegistry, BaseTool
# from core.session_manager import SessionManager, Session
# from core.ai_engine import AIDecisionEngine

__all__ = [
    # 统一返回值
    "ToolResult",
    "ResultStatus",
    "ToolResultType",
    "ensure_tool_result",
    # 其他组件（暂时禁用）
    # "MCPServer",
    # "create_app",
    # "ToolRegistry",
    # "BaseTool",
    # "SessionManager",
    # "Session",
    # "AIDecisionEngine"
]
