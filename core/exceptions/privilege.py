"""
AutoRedTeam-Orchestrator 权限提升和数据外泄异常

权限提升、数据外泄相关的错误类型定义。
"""

from __future__ import annotations

from typing import Any, Optional

from .base import AutoRedTeamError

# ============================================================================
# 权限提升错误
# ============================================================================


class PrivilegeEscalationError(AutoRedTeamError):
    """
    权限提升错误基类

    权限提升过程中的错误。

    属性:
        method: 提权方法
        current_level: 当前权限级别
        target_level: 目标权限级别
    """

    def __init__(
        self,
        message: str,
        method: Optional[str] = None,
        current_level: Optional[str] = None,
        target_level: Optional[str] = None,
        **kwargs: Any,
    ):
        """
        初始化权限提升错误

        参数:
            message: 错误消息
            method: 提权方法 (uac_bypass, token_impersonation, suid, sudo等)
            current_level: 当前权限级别
            target_level: 目标权限级别
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.method = method
        self.current_level = current_level
        self.target_level = target_level
        if method:
            self.details["method"] = method
        if current_level:
            self.details["current_level"] = current_level
        if target_level:
            self.details["target_level"] = target_level


class EscalationVectorNotFound(PrivilegeEscalationError):
    """
    未找到可用的提权向量

    当系统中没有可利用的提权漏洞或配置错误时抛出。

    示例:
        >>> raise EscalationVectorNotFound("未找到SUID提权向量")
        >>> raise EscalationVectorNotFound("UAC绕过技术不适用", method="fodhelper")
    """


class InsufficientPrivilege(PrivilegeEscalationError):
    """
    权限不足以执行操作

    当当前权限级别无法执行所需操作时抛出。

    示例:
        >>> raise InsufficientPrivilege("需要管理员权限", current_level="user", target_level="admin")
        >>> raise InsufficientPrivilege("无法创建原始套接字", method="icmp_exfil")
    """


class UACBypassFailed(PrivilegeEscalationError):
    """
    UAC绕过失败

    当Windows UAC绕过技术执行失败时抛出。

    示例:
        >>> raise UACBypassFailed("fodhelper绕过失败", method="fodhelper")
        >>> raise UACBypassFailed("注册表写入被拒绝", details={"key": "HKCU\\...\\shell\\open\\command"})
    """


class TokenManipulationError(PrivilegeEscalationError):
    """
    Token操纵错误

    当Windows Token操纵失败时抛出。

    示例:
        >>> raise TokenManipulationError("无法打开目标进程", details={"pid": 4})
        >>> raise TokenManipulationError("Token复制失败", method="token_impersonation")
    """


# ============================================================================
# 数据外泄错误
# ============================================================================


class ExfiltrationError(AutoRedTeamError):
    """
    数据外泄错误基类

    数据外泄过程中的错误。

    属性:
        channel: 外泄通道类型
        destination: 目标地址
    """

    def __init__(
        self,
        message: str,
        channel: Optional[str] = None,
        destination: Optional[str] = None,
        **kwargs: Any,
    ):
        """
        初始化数据外泄错误

        参数:
            message: 错误消息
            channel: 外泄通道类型 (https, dns, icmp, smb等)
            destination: 目标地址
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.channel = channel
        self.destination = destination
        if channel:
            self.details["channel"] = channel
        if destination:
            self.details["destination"] = destination


class ChannelBlocked(ExfiltrationError):
    """
    外泄通道被阻断

    当外泄通道被防火墙、IDS/IPS或其他安全设备阻断时抛出。

    示例:
        >>> raise ChannelBlocked("DNS外泄被阻断", channel="dns")
        >>> raise ChannelBlocked("HTTPS出站被拦截", channel="https", destination="c2.example.com")
    """


class DataTooLarge(ExfiltrationError):
    """
    数据量超出通道限制

    当待外泄数据量超出通道容量或限制时抛出。

    属性:
        data_size: 数据大小 (字节)
        max_size: 通道最大限制 (字节)
    """

    def __init__(
        self,
        message: str,
        data_size: Optional[int] = None,
        max_size: Optional[int] = None,
        **kwargs: Any,
    ):
        """
        初始化数据过大错误

        参数:
            message: 错误消息
            data_size: 实际数据大小 (字节)
            max_size: 通道最大限制 (字节)
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.data_size = data_size
        self.max_size = max_size
        if data_size is not None:
            self.details["data_size"] = data_size
        if max_size is not None:
            self.details["max_size"] = max_size


class ChannelConnectionError(ExfiltrationError):
    """
    外泄通道连接错误

    当无法建立外泄通道连接时抛出。

    示例:
        >>> raise ChannelConnectionError("SMB连接失败", channel="smb")
        >>> raise ChannelConnectionError("DNS解析器不可用", channel="dns")
    """


class EncryptionRequired(ExfiltrationError):
    """
    需要加密

    当外泄操作需要加密但未配置加密时抛出。

    示例:
        >>> raise EncryptionRequired("该通道要求数据加密", channel="https")
    """


__all__ = [
    # 权限提升错误
    "PrivilegeEscalationError",
    "EscalationVectorNotFound",
    "InsufficientPrivilege",
    "UACBypassFailed",
    "TokenManipulationError",
    # 数据外泄错误
    "ExfiltrationError",
    "ChannelBlocked",
    "DataTooLarge",
    "ChannelConnectionError",
    "EncryptionRequired",
]
