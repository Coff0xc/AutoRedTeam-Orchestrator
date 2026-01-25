"""
AutoRedTeam-Orchestrator 认证异常

认证和权限相关的错误类型定义。
"""

from __future__ import annotations

from typing import Optional, Any

from .base import AutoRedTeamError


class AuthError(AutoRedTeamError):
    """
    认证错误基类

    所有认证相关错误的父类。

    示例:
        >>> raise AuthError("认证失败")
    """
    pass


class InvalidCredentials(AuthError):
    """
    无效凭证

    当用户名密码错误、API密钥无效时抛出。

    示例:
        >>> raise InvalidCredentials("用户名或密码错误")
        >>> raise InvalidCredentials("API密钥无效", details={"key_prefix": "sk-xxx..."})
    """
    pass


class TokenExpired(AuthError):
    """
    Token已过期

    当JWT、Session Token等认证令牌过期时抛出。

    属性:
        expired_at: 过期时间
    """

    def __init__(
        self,
        message: str = "认证令牌已过期",
        expired_at: Optional[str] = None,
        **kwargs: Any
    ):
        """
        初始化Token过期错误

        参数:
            message: 错误消息
            expired_at: Token过期时间
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.expired_at = expired_at
        if expired_at:
            self.details['expired_at'] = expired_at


class PermissionDenied(AuthError):
    """
    权限不足

    当当前用户/角色没有执行操作的权限时抛出。

    示例:
        >>> raise PermissionDenied("需要管理员权限")
        >>> raise PermissionDenied("无权访问该资源", details={"resource": "/admin/users", "required_role": "admin"})
    """
    pass


# 向后兼容别名
SecurityError = AuthError


__all__ = [
    'AuthError',
    'InvalidCredentials',
    'TokenExpired',
    'PermissionDenied',
    # 向后兼容
    'SecurityError',
]