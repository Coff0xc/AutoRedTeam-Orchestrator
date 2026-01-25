"""
AutoRedTeam-Orchestrator 异常辅助函数

提供异常包装、处理装饰器等辅助工具。
"""

from __future__ import annotations

import asyncio
import functools
import logging
from typing import Optional, Any, Dict, Callable, TypeVar, Union, Type

from .base import AutoRedTeamError, ConfigError
from .http import HTTPError, ConnectionError, TimeoutError, SSLError, ProxyError
from .auth import PermissionDenied
from .scan import ValidationError

T = TypeVar('T')


def wrap_exception(
    exc: Exception,
    wrapper_class: Type[AutoRedTeamError] = AutoRedTeamError,
    message: Optional[str] = None
) -> AutoRedTeamError:
    """
    将标准异常包装为自定义异常

    如果传入的异常已经是 AutoRedTeamError 类型，直接返回。
    否则创建一个新的包装异常。

    参数:
        exc: 原始异常
        wrapper_class: 包装使用的异常类，默认为 AutoRedTeamError
        message: 自定义错误消息，如果为None则使用原始异常的消息

    返回:
        AutoRedTeamError 类型的异常

    示例:
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     raise wrap_exception(e, HTTPError, "HTTP请求失败")
    """
    if isinstance(exc, AutoRedTeamError):
        return exc

    error_message = message or str(exc)
    return wrapper_class(
        error_message,
        cause=exc,
        details={'original_type': type(exc).__name__}
    )


def handle_exceptions(
    logger: Optional[logging.Logger] = None,
    default_return: Any = None,
    reraise: bool = False,
    error_mapping: Optional[Dict[Type[Exception], Type[AutoRedTeamError]]] = None
) -> Callable[[Callable[..., T]], Callable[..., Union[T, Any]]]:
    """
    统一异常处理装饰器

    自动捕获函数中的异常，根据配置进行日志记录、异常转换或返回默认值。
    支持同步和异步函数。

    参数:
        logger: 日志记录器，用于记录异常信息
        default_return: 异常发生时的默认返回值
        reraise: 是否重新抛出异常（转换后的异常）
        error_mapping: 异常类型映射字典，如 {requests.Timeout: TimeoutError}

    返回:
        装饰器函数

    示例:
        >>> @handle_exceptions(logger=logger, default_return=[])
        ... def scan_ports(target):
        ...     ...

        >>> @handle_exceptions(reraise=True, error_mapping={socket.timeout: TimeoutError})
        ... async def fetch_data(url):
        ...     ...
    """
    # 延迟导入 requests 以避免在未安装时报错
    try:
        import requests
        default_mapping: Dict[Type[Exception], Type[AutoRedTeamError]] = {
            requests.exceptions.Timeout: TimeoutError,
            requests.exceptions.ConnectionError: ConnectionError,
            requests.exceptions.SSLError: SSLError,
            requests.exceptions.ProxyError: ProxyError,
            requests.exceptions.RequestException: HTTPError,
        }
    except ImportError:
        default_mapping = {}

    # 添加标准库异常映射
    default_mapping.update({
        OSError: ConnectionError,
        ValueError: ValidationError,
        PermissionError: PermissionDenied,
        FileNotFoundError: ConfigError,
    })

    if error_mapping:
        default_mapping.update(error_mapping)

    def decorator(func: Callable[..., T]) -> Callable[..., Union[T, Any]]:
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Union[T, Any]:
            try:
                return func(*args, **kwargs)
            except AutoRedTeamError:
                # 自定义异常直接处理
                if reraise:
                    raise
                if logger:
                    logger.exception("捕获到已知异常")
                return default_return
            except Exception as e:
                # 尝试映射到自定义异常
                for exc_type, target_exc in default_mapping.items():
                    if isinstance(e, exc_type):
                        new_exc = wrap_exception(e, target_exc)
                        if logger:
                            logger.warning(f"{target_exc.__name__}: {e}")
                        if reraise:
                            raise new_exc from e
                        return default_return

                # 未映射的异常
                if logger:
                    logger.exception(f"未预期的错误: {e}")
                if reraise:
                    raise wrap_exception(e) from e
                return default_return

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Union[T, Any]:
            try:
                return await func(*args, **kwargs)
            except AutoRedTeamError:
                if reraise:
                    raise
                if logger:
                    logger.exception("捕获到已知异常")
                return default_return
            except Exception as e:
                for exc_type, target_exc in default_mapping.items():
                    if isinstance(e, exc_type):
                        new_exc = wrap_exception(e, target_exc)
                        if logger:
                            logger.warning(f"{target_exc.__name__}: {e}")
                        if reraise:
                            raise new_exc from e
                        return default_return

                if logger:
                    logger.exception(f"未预期的错误: {e}")
                if reraise:
                    raise wrap_exception(e) from e
                return default_return

        # 根据函数类型返回对应的包装器
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


__all__ = [
    'wrap_exception',
    'handle_exceptions',
]