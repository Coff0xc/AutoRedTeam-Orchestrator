"""
AutoRedTeam-Orchestrator 基础异常类

定义核心异常基类 AutoRedTeamError 和配置相关异常。
"""

from __future__ import annotations

import traceback
from typing import Optional, Any, Dict


class AutoRedTeamError(Exception):
    """
    AutoRedTeam 基础异常类

    所有自定义异常的父类，提供统一的异常格式和序列化支持。

    属性:
        message: 错误消息
        code: 错误代码，默认为异常类名
        details: 额外的错误详情字典
        cause: 原始异常（支持异常链）

    示例:
        >>> raise AutoRedTeamError("操作失败", code="OP_FAILED", details={"target": "192.168.1.1"})
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     raise AutoRedTeamError("包装后的异常", cause=e)
    """

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """
        初始化异常实例

        参数:
            message: 错误消息描述
            code: 错误代码，用于程序化处理。如果未指定，使用类名
            details: 附加的错误详情，如目标URL、参数等
            cause: 导致此异常的原始异常，用于异常链追踪
        """
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}
        self.cause = cause

        # 如果有原始异常，设置异常链
        if cause is not None:
            self.__cause__ = cause

    def __str__(self) -> str:
        """返回格式化的错误字符串"""
        parts = [f"[{self.code}] {self.message}"]
        if self.details:
            parts.append(f"Details: {self.details}")
        if self.cause:
            parts.append(f"Caused by: {type(self.cause).__name__}: {self.cause}")
        return " | ".join(parts)

    def __repr__(self) -> str:
        """返回可用于调试的表示形式"""
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"code={self.code!r}, "
            f"details={self.details!r})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        将异常转换为字典格式，便于JSON序列化

        返回:
            包含错误信息的字典
        """
        result = {
            'error': self.code,
            'message': self.message,
            'details': self.details,
            'type': self.__class__.__name__,
        }
        if self.cause:
            result['cause'] = {
                'type': type(self.cause).__name__,
                'message': str(self.cause)
            }
        return result

    def get_traceback(self) -> str:
        """获取完整的异常堆栈追踪"""
        return ''.join(traceback.format_exception(type(self), self, self.__traceback__))


class ConfigError(AutoRedTeamError):
    """
    配置错误

    当配置文件缺失、格式错误、参数无效时抛出。

    示例:
        >>> raise ConfigError("配置文件不存在", details={"path": "/etc/config.yaml"})
        >>> raise ConfigError("无效的配置项", code="INVALID_CONFIG", details={"key": "timeout", "value": -1})
    """
    pass


__all__ = [
    'AutoRedTeamError',
    'ConfigError',
]