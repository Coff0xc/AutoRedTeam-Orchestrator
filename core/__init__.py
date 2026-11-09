"""
AI Red Team MCP - Core Module

核心模块提供统一的工具返回值格式和基础组件。

导入约定:
- 轻量组件 (ToolResult) 直接导入
- AI 决策引擎与 session/http 通过 __getattr__ 懒加载，避免只读命令拉起 pydantic
- handlers/modules 中的导入应使用延迟导入模式
"""

from _version import __version__

# 统一的工具返回值 Schema (轻量，无重依赖)
from core.result import ResultStatus, ToolResult, ToolResultType, ensure_tool_result

__all__ = [
    # 统一返回值
    "ToolResult",
    "ResultStatus",
    "ToolResultType",
    "ensure_tool_result",
    # AI决策引擎
    "AIDecisionEngine",
    "RiskLevel",
    "AttackVector",
    # 会话管理 (懒加载)
    "Target",
    "TargetType",
    "TargetStatus",
    "ScanContext",
    "ScanPhase",
    "ContextStatus",
    "Vulnerability",
    "ScanResult",
    "Severity",
    "VulnType",
    "SessionManager",
    "get_session_manager",
    "reset_session_manager",
    "AuthContext",
    "HTTPSessionManager",
    "get_http_session_manager",
    "SessionStorage",
]

# 懒加载: AI 引擎依赖 pydantic，只读 CLI 不应在 import core 时拉起它
_AI_ATTRS = {
    "AIDecisionEngine",
    "AttackVector",
    "RiskLevel",
}

# 懒加载: session 相关组件（拉入 core.http.client ~400ms）
_SESSION_ATTRS = {
    "AuthContext",
    "ContextStatus",
    "HTTPSessionManager",
    "ScanContext",
    "ScanPhase",
    "ScanResult",
    "SessionManager",
    "SessionStorage",
    "Severity",
    "Target",
    "TargetStatus",
    "TargetType",
    "Vulnerability",
    "VulnType",
    "get_http_session_manager",
    "get_session_manager",
    "reset_session_manager",
}


def __getattr__(name: str):
    if name in _AI_ATTRS:
        from core import ai_engine as _ai_engine

        for attr in _AI_ATTRS:
            globals()[attr] = getattr(_ai_engine, attr)
        return globals()[name]
    if name in _SESSION_ATTRS:
        from core import session as _session

        # 一次性加载所有 session 属性到 globals
        for attr in _SESSION_ATTRS:
            globals()[attr] = getattr(_session, attr)
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
