#!/usr/bin/env python3
"""
权限提升模块 - Privilege Escalation Module
ATT&CK Tactic: TA0004 - Privilege Escalation

提供 Windows 和 Linux 系统的权限提升功能，包括：
- Windows: UAC Bypass, Token Manipulation, Potato 系列
- Linux: SUID 提权, Sudo 绕过, Capability 提权
- macOS/Darwin: 复用 Linux 模块（类 Unix 系统）

仅用于授权渗透测试和安全研究
"""

from typing import Optional, List

from .base import (
    PrivilegeLevel,
    EscalationMethod,
    EscalationResult,
    EscalationConfig,
    BasePrivilegeEscalation,
)

from .common.enumeration import (
    PrivilegeEnumerator,
    EnumerationResult,
)

# 支持的平台列表
SUPPORTED_PLATFORMS: List[str] = ['windows', 'linux', 'darwin']

# 平台别名映射（用于兼容不同的平台标识）
PLATFORM_ALIASES: dict = {
    'win32': 'windows',
    'win64': 'windows',
    'cygwin': 'windows',
    'msys': 'windows',
    'darwin': 'darwin',
    'macos': 'darwin',
    'osx': 'darwin',
    'freebsd': 'linux',  # FreeBSD 可复用 Linux 模块
    'openbsd': 'linux',  # OpenBSD 可复用 Linux 模块
}


class UnsupportedPlatformError(Exception):
    """
    不支持的平台错误

    当尝试在不支持的操作系统上运行权限提升模块时抛出。
    提供详细的错误信息和支持的平台列表。

    Attributes:
        platform: 当前检测到的平台
        supported: 支持的平台列表
        message: 错误消息
    """

    def __init__(
        self,
        platform: str,
        supported: Optional[List[str]] = None,
        message: Optional[str] = None
    ):
        self.platform = platform
        self.supported = supported or SUPPORTED_PLATFORMS
        self.message = message or self._build_message()
        super().__init__(self.message)

    def _build_message(self) -> str:
        """构建详细的错误消息"""
        supported_str = ', '.join(self.supported)
        return (
            f"不支持的平台: '{self.platform}'\n"
            f"当前支持的平台: {supported_str}\n"
            f"如需支持其他平台，请提交 Issue 或 PR: "
            f"https://github.com/AutoRedTeam/Orchestrator/issues"
        )

    def to_dict(self) -> dict:
        """转换为字典格式，便于 JSON 序列化"""
        return {
            'error': 'UnsupportedPlatformError',
            'platform': self.platform,
            'supported_platforms': self.supported,
            'message': self.message,
        }


def _normalize_platform(system: str) -> str:
    """
    标准化平台名称

    Args:
        system: 原始平台名称（来自 platform.system()）

    Returns:
        标准化后的平台名称
    """
    system_lower = system.lower()

    # 检查别名映射
    if system_lower in PLATFORM_ALIASES:
        return PLATFORM_ALIASES[system_lower]

    return system_lower


def get_escalation_module(config: EscalationConfig = None) -> BasePrivilegeEscalation:
    """
    根据当前平台获取对应的权限提升模块

    支持的平台:
        - Windows: 完整支持 (UAC Bypass, Token Manipulation, Potato 等)
        - Linux: 完整支持 (SUID, Sudo, Capability, Kernel 等)
        - macOS/Darwin: 部分支持 (复用 Linux 模块的类 Unix 功能)

    Args:
        config: 提权配置，为 None 时使用默认配置

    Returns:
        对应平台的权限提升模块实例

    Raises:
        UnsupportedPlatformError: 当前平台不受支持时抛出，
            包含详细的错误信息和支持的平台列表

    Examples:
        >>> # 自动检测平台
        >>> module = get_escalation_module()
        >>> result = module.auto_escalate()

        >>> # 使用自定义配置
        >>> config = EscalationConfig(timeout=120, stealth=True)
        >>> module = get_escalation_module(config)
    """
    import platform

    config = config or EscalationConfig()
    raw_system = platform.system()
    system = _normalize_platform(raw_system)

    if system == 'windows':
        from .windows import WindowsPrivilegeEscalation
        return WindowsPrivilegeEscalation(config)

    elif system in ('linux', 'darwin'):
        # macOS/Darwin 复用 Linux 模块（类 Unix 系统）
        # 注意：某些 Linux 特有功能在 macOS 上可能不可用
        from .linux import LinuxPrivilegeEscalation
        module = LinuxPrivilegeEscalation(config)

        # 如果是 macOS，记录警告
        if system == 'darwin':
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "macOS/Darwin 平台使用 Linux 模块，"
                "部分功能（如 getcap、特定内核漏洞）可能不可用"
            )

        return module

    else:
        # 抛出自定义异常，提供详细信息
        raise UnsupportedPlatformError(
            platform=raw_system,
            supported=SUPPORTED_PLATFORMS
        )


__all__ = [
    # 枚举
    'PrivilegeLevel',
    'EscalationMethod',

    # 数据类
    'EscalationResult',
    'EscalationConfig',
    'EnumerationResult',

    # 基类
    'BasePrivilegeEscalation',
    'PrivilegeEnumerator',

    # 工厂函数
    'get_escalation_module',

    # 异常类
    'UnsupportedPlatformError',

    # 常量
    'SUPPORTED_PLATFORMS',
    'PLATFORM_ALIASES',
]
