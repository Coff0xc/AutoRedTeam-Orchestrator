#!/usr/bin/env python3
"""
core/session - 会话管理层

提供扫描会话的完整生命周期管理，包括：
- Target: 目标定义和解析
- ScanContext: 扫描上下文状态管理
- Vulnerability/ScanResult: 结果定义
- SessionManager: 会话管理器（单例）
- SessionStorage: 持久化存储

使用示例:
    from core.session import (
        Target, ScanContext, SessionManager,
        get_session_manager, Vulnerability, Severity, VulnType
    )

    # 获取会话管理器
    manager = get_session_manager()

    # 创建会话
    context = manager.create_session("https://example.com")

    # 添加漏洞
    manager.add_vulnerability(
        context.session_id,
        vuln_type=VulnType.XSS,
        severity=Severity.HIGH,
        title="反射型XSS",
        url="https://example.com/search?q=<script>",
        param="q",
        payload="<script>alert(1)</script>"
    )

    # 完成会话
    result = manager.complete_session(context.session_id)
    print(result.to_json())
"""

from .target import (
    Target,
    TargetType,
    TargetStatus,
)

from .context import (
    ScanContext,
    ScanPhase,
    ContextStatus,
)

from .result import (
    Vulnerability,
    ScanResult,
    Severity,
    VulnType,
)

from .manager import (
    SessionManager,
    get_session_manager,
    reset_session_manager,
)

from .storage import (
    SessionStorage,
)

__all__ = [
    # Target
    'Target',
    'TargetType',
    'TargetStatus',

    # Context
    'ScanContext',
    'ScanPhase',
    'ContextStatus',

    # Result
    'Vulnerability',
    'ScanResult',
    'Severity',
    'VulnType',

    # Manager
    'SessionManager',
    'get_session_manager',
    'reset_session_manager',

    # Storage
    'SessionStorage',
]

__version__ = '1.0.0'
__author__ = 'AutoRedTeam'
