"""
统一异常处理与输入验证机制

提供标准化的异常捕获、分类、响应生成以及输入验证，替代handlers中分散的try-except块。

设计原则:
    1. 异常分层：业务异常 vs 系统异常 vs 外部依赖异常
    2. 自动分类：根据异常类型自动设置 error_type
    3. 日志集中：统一日志级别和格式
    4. 便于维护：新增异常类型只需更新映射表
    5. 输入验证：在处理前自动验证 URL/IP/域名等参数

使用示例:
    from handlers.error_handling import handle_errors, ErrorCategory, validate_inputs

    @tool(mcp)
    @validate_inputs(url='url', target='target')  # 指定参数的验证类型
    @handle_errors(logger, category=ErrorCategory.RECON)
    async def my_tool(url: str, target: str) -> Dict[str, Any]:
        # 业务逻辑，无需手动 try-except 或验证输入
        result = do_something(url, target)
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

    RECON = "recon"  # 侦察类
    DETECTOR = "detector"  # 漏洞检测类
    CVE = "cve"  # CVE相关
    REDTEAM = "redteam"  # 红队工具
    API_SECURITY = "api"  # API安全
    CLOUD = "cloud"  # 云安全
    SUPPLY_CHAIN = "supply"  # 供应链
    SESSION = "session"  # 会话管理
    REPORT = "report"  # 报告生成
    AI = "ai"  # AI辅助
    EXTERNAL_TOOLS = "external"  # 外部工具集成
    LATERAL = "lateral"  # 横向移动
    PERSISTENCE = "persistence"  # 持久化
    MISC = "misc"  # 其他


class ErrorSeverity(Enum):
    """错误严重程度 - 决定日志级别"""

    DEBUG = "debug"  # 预期内的轻微问题
    INFO = "info"  # 业务层面的已知失败（如目标不可达）
    WARNING = "warning"  # 可恢复的异常（如超时重试后仍失败）
    ERROR = "error"  # 需要关注的错误（如模块导入失败）
    CRITICAL = "critical"  # 严重错误（不应发生）


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
        from core.exceptions import (  # 横向移动; C2; Payload; 认证; 权限提升; 外泄
            AuthError,
            AutoRedTeamError,
            BeaconError,
            C2Error,
            ChannelBlocked,
            ChannelConnectionError,
            ConfigError,
            EscalationVectorNotFound,
            ExfiltrationError,
            InsufficientPrivilege,
            InvalidCredentials,
            LateralError,
            PayloadError,
            PrivilegeEscalationError,
            SMBError,
            SSHError,
            TunnelError,
            ValidationError,
            WMIError,
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
    error: str, error_type: str, context: Optional[Dict[str, Any]] = None
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
        "success": False,
        "error": error,
        "error_type": error_type,
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
    need_traceback: bool = False,
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
                        exc,
                        logger,
                        category,
                        operation,
                        context_extractor,
                        default_context,
                        args,
                        kwargs,
                    )

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    return _handle_exception(
                        exc,
                        logger,
                        category,
                        operation,
                        context_extractor,
                        default_context,
                        args,
                        kwargs,
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
        return {"target": args[0]}
    return {"target": kwargs.get("target", kwargs.get("url", kwargs.get("domain")))}


def extract_url(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """从参数中提取 url 字段"""
    if args:
        return {"url": args[0]}
    return {"url": kwargs.get("url", kwargs.get("target"))}


def extract_domain(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """从参数中提取 domain 字段"""
    if args:
        return {"domain": args[0]}
    return {"domain": kwargs.get("domain", kwargs.get("target"))}


def extract_file_path(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """从参数中提取 file_path 字段"""
    if args:
        return {"file_path": args[0]}
    return {"file_path": kwargs.get("file_path", kwargs.get("path"))}


# ==================== 输入验证装饰器 ====================

# 验证类型映射
_VALIDATION_TYPES = {
    "url": "validate_url",
    "ip": "validate_ip",
    "ipv4": "validate_ipv4",
    "ipv6": "validate_ipv6",
    "domain": "validate_domain",
    "cidr": "validate_cidr",
    "port": "validate_port",
    "port_range": "validate_port_range",
    "email": "validate_email",
    "target": "auto",  # 自动检测 (IP/URL/域名/CIDR)
    "session_id": "session_id",
    "path": "path",
}


def _get_validator(validation_type: str) -> Callable[[str], bool]:
    """获取验证函数"""
    try:
        from utils.validators import (
            InputValidator,
            validate_cidr,
            validate_domain,
            validate_email,
            validate_ip,
            validate_ipv4,
            validate_ipv6,
            validate_port,
            validate_port_range,
            validate_url,
        )

        validators = {
            "validate_url": validate_url,
            "validate_ip": validate_ip,
            "validate_ipv4": validate_ipv4,
            "validate_ipv6": validate_ipv6,
            "validate_domain": validate_domain,
            "validate_cidr": validate_cidr,
            "validate_port": validate_port,
            "validate_port_range": validate_port_range,
            "validate_email": validate_email,
            "auto": lambda x: _validate_target_auto(
                x, validate_url, validate_ip, validate_domain, validate_cidr
            ),
            "session_id": lambda x: InputValidator.validate_session_id(x)[0],
            "path": lambda x: InputValidator.validate_file_path(x, allow_absolute=True)[0],
        }

        return validators.get(validation_type, lambda x: True)

    except ImportError:
        # validators 模块不可用时返回始终通过的验证器
        return lambda x: True


def _validate_target_auto(
    target: str,
    validate_url: Callable,
    validate_ip: Callable,
    validate_domain: Callable,
    validate_cidr: Callable,
) -> bool:
    """自动验证目标（尝试多种类型）"""
    if not target or not isinstance(target, str):
        return False

    target = target.strip()

    # 尝试作为 URL
    if target.startswith(("http://", "https://")):
        return validate_url(target)

    # 尝试作为 CIDR
    if "/" in target:
        return validate_cidr(target)

    # 尝试作为 IP
    if validate_ip(target):
        return True

    # 尝试作为域名
    if validate_domain(target):
        return True

    # 如果都不匹配，检查是否包含危险字符
    # 同时阻止明显的内部网络目标
    dangerous_chars = [";", "|", "&", "$", "`", "\n", "\r", ">", "<", '"', "'"]
    for char in dangerous_chars:
        if char in target:
            return False

    # 阻止常见的内部/云元数据主机名
    internal_patterns = [
        "localhost", "metadata.google", "169.254.169.254",
        "metadata.aws", "metadata.azure",
        "internal", ".local", "127.0.0.1",
    ]
    target_lower = target.lower()
    for pattern in internal_patterns:
        if pattern in target_lower:
            logger = logging.getLogger(__name__)
            logger.warning(f"目标可能指向内部网络: {target}")
            return False

    return True


def validate_inputs(**param_validators: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    输入验证装饰器

    在函数执行前验证指定参数，验证失败时返回标准化错误响应。

    Args:
        **param_validators: 参数名到验证类型的映射
            支持的验证类型:
            - 'url': URL格式验证
            - 'ip': IP地址验证 (IPv4或IPv6)
            - 'ipv4': IPv4地址验证
            - 'ipv6': IPv6地址验证
            - 'domain': 域名格式验证
            - 'cidr': CIDR网段验证
            - 'port': 端口号验证 (1-65535)
            - 'port_range': 端口范围验证 (如 "80,443,8000-9000")
            - 'email': 邮箱格式验证
            - 'target': 自动检测 (URL/IP/域名/CIDR)
            - 'session_id': 会话ID格式验证
            - 'path': 文件路径安全验证

    Returns:
        装饰器函数

    Example:
        @validate_inputs(url='url', port='port')
        async def scan(url: str, port: int = 80) -> Dict[str, Any]:
            ...

        @validate_inputs(target='target')
        async def recon(target: str) -> Dict[str, Any]:
            ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        # 获取函数签名以支持位置参数映射
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                validation_error = _do_validation(param_validators, param_names, args, kwargs)
                if validation_error:
                    return validation_error
                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                validation_error = _do_validation(param_validators, param_names, args, kwargs)
                if validation_error:
                    return validation_error
                return func(*args, **kwargs)

            return sync_wrapper

    return decorator


def _do_validation(
    param_validators: Dict[str, str],
    param_names: list,
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    执行参数验证

    Returns:
        验证失败时返回错误响应字典，成功时返回 None
    """
    for param_name, validation_type in param_validators.items():
        # 获取参数值
        value = None

        # 先检查 kwargs
        if param_name in kwargs:
            value = kwargs[param_name]
        # 再检查位置参数
        elif param_name in param_names:
            idx = param_names.index(param_name)
            if idx < len(args):
                value = args[idx]

        # 跳过 None 或空值（由业务逻辑处理）
        if value is None or value == "":
            continue

        # 端口特殊处理（可能是整数）
        if validation_type in ("port", "validate_port"):
            if isinstance(value, int):
                if not (1 <= value <= 65535):
                    return format_error_response(
                        f"端口 '{param_name}' 无效: {value} (有效范围: 1-65535)",
                        "ValidationError",
                        {param_name: value},
                    )
                continue
            value = str(value)

        # 字符串类型验证
        if isinstance(value, str):
            validator_name = _VALIDATION_TYPES.get(validation_type, validation_type)
            validator = _get_validator(validator_name)

            if not validator(value):
                return format_error_response(
                    f"参数 '{param_name}' 验证失败: '{value}' 不是有效的 {validation_type}",
                    "ValidationError",
                    {param_name: value},
                )

    return None


def require_non_empty(*param_names: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    非空参数验证装饰器

    确保指定参数不为空（非 None、非空字符串、非空列表/字典）

    Args:
        *param_names: 必须非空的参数名列表

    Example:
        @require_non_empty('url', 'target')
        async def scan(url: str, target: str) -> Dict[str, Any]:
            ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        sig = inspect.signature(func)
        all_param_names = list(sig.parameters.keys())

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                error = _check_non_empty(param_names, all_param_names, args, kwargs)
                if error:
                    return error
                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                error = _check_non_empty(param_names, all_param_names, args, kwargs)
                if error:
                    return error
                return func(*args, **kwargs)

            return sync_wrapper

    return decorator


def _check_non_empty(
    required_params: Tuple[str, ...],
    all_param_names: list,
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """检查参数是否为空"""
    for param_name in required_params:
        value = None

        if param_name in kwargs:
            value = kwargs[param_name]
        elif param_name in all_param_names:
            idx = all_param_names.index(param_name)
            if idx < len(args):
                value = args[idx]

        # 检查空值
        if value is None:
            return format_error_response(
                f"参数 '{param_name}' 不能为空", "ValidationError", {param_name: None}
            )

        if isinstance(value, str) and not value.strip():
            return format_error_response(
                f"参数 '{param_name}' 不能为空字符串", "ValidationError", {param_name: value}
            )

        if isinstance(value, (list, dict)) and len(value) == 0:
            return format_error_response(
                f"参数 '{param_name}' 不能为空", "ValidationError", {param_name: value}
            )

    return None


# ==================== 外部工具专用异常处理 ====================

# 外部工具错误提示映射
_EXTERNAL_TOOL_HINTS: Dict[Type[Exception], str] = {
    ImportError: "请确保 core.tools 模块已正确安装",
    ModuleNotFoundError: "请确保 core.tools 模块已正确安装",
    FileNotFoundError: "请检查 config/external_tools.yaml 中的工具路径配置",
    PermissionError: "某些扫描功能可能需要管理员/root权限",
}


def handle_external_tool_errors(
    logger: logging.Logger,
    tool_name: str,
    context_extractor: Optional[ContextExtractor] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    外部工具专用异常处理装饰器

    与 handle_errors 类似，但为外部工具错误提供更有针对性的 hint。

    Args:
        logger: 日志记录器
        tool_name: 工具名称 (用于日志和错误消息)
        context_extractor: 上下文提取函数

    Example:
        @handle_external_tool_errors(logger, "ext_nmap_scan", extract_target)
        async def ext_nmap_scan(target: str) -> Dict[str, Any]:
            ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    return _handle_external_tool_exception(
                        exc, logger, tool_name, context_extractor, args, kwargs
                    )

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    return _handle_external_tool_exception(
                        exc, logger, tool_name, context_extractor, args, kwargs
                    )

            return sync_wrapper

    return decorator


def _handle_external_tool_exception(
    exc: Exception,
    logger: logging.Logger,
    tool_name: str,
    context_extractor: Optional[ContextExtractor],
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    """处理外部工具异常，提供针对性的错误信息和提示"""
    import asyncio
    import subprocess

    error_type = type(exc).__name__
    error_msg = str(exc)

    # 获取提示信息
    hint = _EXTERNAL_TOOL_HINTS.get(type(exc))

    # 特殊异常类型的处理
    if isinstance(exc, subprocess.TimeoutExpired):
        error_msg = "工具执行超时"
        hint = "可尝试减少扫描范围或增加超时时间"
        logger.warning(f"{tool_name}: {error_msg}")
    elif isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        error_msg = "操作超时"
        logger.warning(f"{tool_name}: {error_msg}")
    elif isinstance(exc, (ConnectionError, OSError)):
        logger.warning(f"{tool_name}: 连接/IO错误 - {error_msg}")
    elif isinstance(exc, (ImportError, ModuleNotFoundError)):
        logger.warning(f"{tool_name}: 模块导入失败 - {error_msg}")
    elif isinstance(exc, FileNotFoundError):
        logger.warning(f"{tool_name}: 工具未找到 - {error_msg}")
    elif isinstance(exc, PermissionError):
        logger.warning(f"{tool_name}: 权限不足 - {error_msg}")
    else:
        logger.error(f"{tool_name}: 执行失败 - [{error_type}] {error_msg}")

    # 提取上下文
    context: Dict[str, Any] = {}
    if context_extractor:
        try:
            extracted = context_extractor(args, kwargs)
            if extracted:
                context.update(extracted)
        except Exception as ctx_err:
            logger.debug(f"Context extraction failed: {ctx_err}")

    # 构建响应
    response: Dict[str, Any] = {
        "success": False,
        "error": error_msg,
        "error_type": error_type,
    }
    if hint:
        response["hint"] = hint
    if context:
        response.update(context)

    return response
