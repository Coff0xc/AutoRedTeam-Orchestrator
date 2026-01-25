"""
统一异常处理机制

提供标准化的异常捕获、分类和响应生成，替代handlers中分散的try-except块。

设计原则:
    1. 异常分层：业务异常 vs 系统异常 vs 外部依赖异常
    2. 自动分类：根据异常类型自动设置 error_type
    3. 日志集中：统一日志级别和格式
    4. 便于维护：新增异常类型只需更新映射表

使用示例:
    from handlers.error_handling import handle_errors, ErrorCategory

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.RECON)
    async def my_tool(target: str) -> Dict[str, Any]:
        # 业务逻辑，无需手动 try-except
        result = do_something(target)
        return {'success': True, 'data': result}
"""

from __future__ import annotations

import functools
import inspect
import logging
from enum import Enum
from typing import Any, Callable, Dict, Optional, Tuple, Type


class ErrorCategory(Enum):
    """错误类别 - 用于日志分组和错误上下文"""
    RECON = "recon"              # 侦察类
    DETECTOR = "detector"        # 漏洞检测类
    CVE = "cve"                  # CVE相关
    REDTEAM = "redteam"          # 红队工具
    API_SECURITY = "api"         # API安全
    CLOUD = "cloud"              # 云安全
    SUPPLY_CHAIN = "supply"      # 供应链
    SESSION = "session"          # 会话管理
    REPORT = "report"            # 报告生成
    AI = "ai"                    # AI辅助
    MISC = "misc"                # 其他


class ErrorSeverity(Enum):
    """错误严重程度 - 决定日志级别"""
    DEBUG = "debug"       # 预期内的轻微问题
    INFO = "info"         # 业务层面的已知失败（如目标不可达）
    WARNING = "warning"   # 可恢复的异常（如超时重试后仍失败）
    ERROR = "error"       # 需要关注的错误（如模块导入失败）
    CRITICAL = "critical" # 严重错误（不应发生）


# 类型别名
ExceptionInfo = Tuple[str, ErrorSeverity, bool]
ExceptionMappingType = Dict[Type[Exception], ExceptionInfo]
ContextExtractor = Callable[[Tuple[Any, ...], Dict[str, Any]], Dict[str, Any]]


# ==================== 异常映射表 ====================

def _get_exception_mappings() -> ExceptionMappingType:
    """获取异常映射表（延迟加载）"""
    mappings: ExceptionMappingType = {
        # Python 内置异常
        ImportError: ("ImportError", ErrorSeverity.ERROR, False),
        ModuleNotFoundError: ("ModuleNotFound", ErrorSeverity.ERROR, False),
        FileNotFoundError: ("FileNotFound", ErrorSeverity.INFO, False),
        PermissionError: ("PermissionDenied", ErrorSeverity.WARNING, False),
        TimeoutError: ("Timeout", ErrorSeverity.WARNING, False),
        ConnectionError: ("ConnectionError", ErrorSeverity.WARNING, False),
        ConnectionRefusedError: ("ConnectionRefused", ErrorSeverity.INFO, False),
        ConnectionResetError: ("ConnectionReset", ErrorSeverity.WARNING, False),
        ValueError: ("ValueError", ErrorSeverity.INFO, False),
        TypeError: ("TypeError", ErrorSeverity.WARNING, True),
        KeyError: ("KeyError", ErrorSeverity.WARNING, True),
        AttributeError: ("AttributeError", ErrorSeverity.ERROR, True),
        RuntimeError: ("RuntimeError", ErrorSeverity.ERROR, True),
        OSError: ("OSError", ErrorSeverity.WARNING, False),
    }

    # 尝试导入项目自定义异常
    try:
        from core.exceptions import (
            AutoRedTeamError,
            ValidationError,
            ConfigError,
            # 横向移动
            LateralError,
            SMBError,
            SSHError,
            WMIError,
            # C2
            C2Error,
            BeaconError,
            TunnelError,
            # Payload
            PayloadError,
            # 认证
            AuthError,
            InvalidCredentials,
            # 权限提升
            PrivilegeEscalationError,
            EscalationVectorNotFound,
            InsufficientPrivilege,
            # 外泄
            ExfiltrationError,
            ChannelBlocked,
            ChannelConnectionError,
        )

        project_mappings: ExceptionMappingType = {
            # 基础异常
            AutoRedTeamError: ("AutoRedTeamError", ErrorSeverity.ERROR, False),
            ValidationError: ("ValidationError", ErrorSeverity.INFO, False),
            ConfigError: ("ConfigError", ErrorSeverity.WARNING, False),
            # 横向移动
            LateralError: ("LateralError", ErrorSeverity.WARNING, False),
            SMBError: ("SMBError", ErrorSeverity.WARNING, False),
            SSHError: ("SSHError", ErrorSeverity.WARNING, False),
            WMIError: ("WMIError", ErrorSeverity.WARNING, False),
            # C2
            C2Error: ("C2Error", ErrorSeverity.WARNING, False),
            BeaconError: ("BeaconError", ErrorSeverity.WARNING, False),
            TunnelError: ("TunnelError", ErrorSeverity.WARNING, False),
            # Payload
            PayloadError: ("PayloadError", ErrorSeverity.WARNING, False),
            # 认证
            AuthError: ("AuthError", ErrorSeverity.INFO, False),
            InvalidCredentials: ("InvalidCredentials", ErrorSeverity.INFO, False),
            # 权限提升
            PrivilegeEscalationError: ("PrivilegeEscalationError", ErrorSeverity.WARNING, False),
            EscalationVectorNotFound: ("EscalationVectorNotFound", ErrorSeverity.INFO, False),
            InsufficientPrivilege: ("InsufficientPrivilege", ErrorSeverity.INFO, False),
            # 外泄
            ExfiltrationError: ("ExfiltrationError", ErrorSeverity.WARNING, False),
            ChannelBlocked: ("ChannelBlocked", ErrorSeverity.WARNING, False),
            ChannelConnectionError: ("ChannelConnectionError", ErrorSeverity.WARNING, False),
        }
        mappings.update(project_mappings)
    except ImportError:
        pass  # 项目异常模块不可用时忽略

    return mappings


# 缓存映射表（模块级可变）
_exception_mappings_cache: Optional[ExceptionMappingType] = None


def get_exception_info(exc: Exception) -> ExceptionInfo:
    """
    获取异常的分类信息

    Args:
        exc: 异常实例

    Returns:
        (error_type, severity, need_traceback)
    """
    global _exception_mappings_cache
    if _exception_mappings_cache is None:
        _exception_mappings_cache = _get_exception_mappings()

    exc_type = type(exc)

    # 精确匹配
    if exc_type in _exception_mappings_cache:
        return _exception_mappings_cache[exc_type]

    # 继承链匹配（找最近的父类）
    for mapped_type, info in _exception_mappings_cache.items():
        if isinstance(exc, mapped_type):
            return info

    # 默认处理
    return (exc_type.__name__, ErrorSeverity.ERROR, True)


def format_error_response(
    error: str,
    error_type: str,
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    格式化错误响应

    Args:
        error: 错误消息
        error_type: 错误类型
        context: 上下文信息（如 target, url 等）

    Returns:
        标准化的错误响应字典
    """
    response: Dict[str, Any] = {
        'success': False,
        'error': error,
        'error_type': error_type,
    }
    if context:
        response.update(context)
    return response


def log_exception(
    logger: logging.Logger,
    exc: Exception,
    severity: ErrorSeverity,
    category: ErrorCategory,
    operation: str,
    need_traceback: bool = False
) -> None:
    """
    记录异常日志

    Args:
        logger: 日志记录器
        exc: 异常实例
        severity: 严重程度
        category: 错误类别
        operation: 操作名称
        need_traceback: 是否记录堆栈
    """
    msg = f"[{category.value}] {operation} 失败: {exc}"

    log_func = getattr(logger, severity.value, logger.error)
    if need_traceback and severity in (ErrorSeverity.ERROR, ErrorSeverity.CRITICAL):
        log_func(msg, exc_info=True)
    else:
        log_func(msg)


def handle_errors(
    logger: logging.Logger,
    category: ErrorCategory = ErrorCategory.MISC,
    context_extractor: Optional[ContextExtractor] = None,
    default_context: Optional[Dict[str, Any]] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    统一异常处理装饰器

    自动捕获异常、分类、记录日志、返回标准化错误响应。

    Args:
        logger: 日志记录器
        category: 错误类别（用于日志分组）
        context_extractor: 从函数参数提取上下文的函数，签名 (args, kwargs) -> dict
        default_context: 默认上下文字段

    Returns:
        装饰器函数

    Example:
        @handle_errors(logger, ErrorCategory.RECON, lambda a, kw: {'target': a[0] if a else kw.get('target')})
        async def port_scan(target: str, ports: str = "1-1000") -> Dict[str, Any]:
            ...
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        operation = func.__name__

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    return _handle_exception(
                        exc, logger, category, operation,
                        context_extractor, default_context, args, kwargs
                    )
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    return _handle_exception(
                        exc, logger, category, operation,
                        context_extractor, default_context, args, kwargs
                    )
            return sync_wrapper

    return decorator


def _handle_exception(
    exc: Exception,
    logger: logging.Logger,
    category: ErrorCategory,
    operation: str,
    context_extractor: Optional[ContextExtractor],
    default_context: Optional[Dict[str, Any]],
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    """内部异常处理逻辑"""
    error_type, severity, need_traceback = get_exception_info(exc)

    # 记录日志
    log_exception(logger, exc, severity, category, operation, need_traceback)

    # 提取上下文
    context: Dict[str, Any] = dict(default_context) if default_context else {}
    if context_extractor:
        try:
            extracted = context_extractor(args, kwargs)
            if extracted:
                context.update(extracted)
        except Exception:
            logger.warning("Suppressed exception in error handling", exc_info=True)

    return format_error_response(str(exc), error_type, context)


# ==================== 便捷上下文提取器 ====================

def extract_target(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """从参数中提取 target 字段"""
    if args:
        return {'target': args[0]}
    return {'target': kwargs.get('target', kwargs.get('url', kwargs.get('domain')))}


def extract_url(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """从参数中提取 url 字段"""
    if args:
        return {'url': args[0]}
    return {'url': kwargs.get('url', kwargs.get('target'))}


def extract_domain(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """从参数中提取 domain 字段"""
    if args:
        return {'domain': args[0]}
    return {'domain': kwargs.get('domain', kwargs.get('target'))}


def extract_file_path(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """从参数中提取 file_path 字段"""
    if args:
        return {'file_path': args[0]}
    return {'file_path': kwargs.get('file_path', kwargs.get('path'))}
