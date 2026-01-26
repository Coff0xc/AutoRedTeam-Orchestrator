"""
AI Red Team MCP - Core Module

核心模块提供统一的工具返回值格式和基础组件。

导入约定:
- 所有 core 子模块均已验证无循环依赖风险
- 外部模块应优先使用此处导出的公共 API
- handlers/modules 中的导入应使用延迟导入模式
"""

# 统一的工具返回值 Schema
from core.result import (
    ToolResult,
    ResultStatus,
    ToolResultType,
    ensure_tool_result,
)

# 工具注册表 (无循环依赖 - 仅使用标准库)
from core.tool_registry import (
    ToolRegistry,
    BaseTool,
    FunctionTool,
    ToolCategory,
    ToolParameter,
    MCPBridge,
    get_registry,
    get_bridge,
)

# AI决策引擎 (无循环依赖 - 仅使用标准库+可选第三方)
from core.ai_engine import (
    AIDecisionEngine,
    RiskLevel,
    AttackVector,
)

# 会话管理 (无循环依赖 - 使用包内相对导入)
from core.session import (
    # Target
    Target,
    TargetType,
    TargetStatus,
    # Context
    ScanContext,
    ScanPhase,
    ContextStatus,
    # Result
    Vulnerability,
    ScanResult,
    Severity,
    VulnType,
    # Manager
    SessionManager,
    get_session_manager,
    reset_session_manager,
    # HTTP Manager
    AuthContext,
    HTTPSessionManager,
    get_http_session_manager,
    # Storage
    SessionStorage,
)

__all__ = [
    # 统一返回值
    "ToolResult",
    "ResultStatus",
    "ToolResultType",
    "ensure_tool_result",

    # 工具注册表
    "ToolRegistry",
    "BaseTool",
    "FunctionTool",
    "ToolCategory",
    "ToolParameter",
    "MCPBridge",
    "get_registry",
    "get_bridge",

    # AI决策引擎
    "AIDecisionEngine",
    "RiskLevel",
    "AttackVector",

    # 会话管理 - Target
    "Target",
    "TargetType",
    "TargetStatus",

    # 会话管理 - Context
    "ScanContext",
    "ScanPhase",
    "ContextStatus",

    # 会话管理 - Result
    "Vulnerability",
    "ScanResult",
    "Severity",
    "VulnType",

    # 会话管理 - Manager
    "SessionManager",
    "get_session_manager",
    "reset_session_manager",

    # 会话管理 - HTTP
    "AuthContext",
    "HTTPSessionManager",
    "get_http_session_manager",

    # 会话管理 - Storage
    "SessionStorage",
]

__version__ = '3.0.0'
