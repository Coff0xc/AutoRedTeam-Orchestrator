#!/usr/bin/env python3
"""
输入验证模块 - AutoRedTeam-Orchestrator

统一的输入验证框架，提供：
- URL/IP/域名验证
- 端口验证
- 路径安全验证（防止路径遍历）
- 命令安全验证（防止命令注入）
- 文件名验证
- HTML清理（防XSS）
- 通用输入清理
- 参数验证装饰器

使用示例:
    from utils.validators import validate_url, validate_ip, InputValidator

    # 快捷函数
    if validate_url("https://example.com"):
        print("URL有效")

    # 验证器类
    validator = InputValidator()
    target_type, normalized = validator.validate_target("192.168.1.1")

    # 使用装饰器
    @validate_params(url=lambda x: InputValidator.validate_url_strict(x))
    def scan(url: str):
        pass

注意:
    此模块合并了以下旧模块的功能：
    - utils/input_validator.py (已废弃)
    - core/security/input_validator.py (已废弃)

    请使用此模块的函数，旧模块将在未来版本移除。
"""

import inspect
import ipaddress
import logging
import os
import re
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """验证错误异常"""

    def __init__(self, message: str, field: Optional[str] = None):
        self.message = message
        self.field = field
        super().__init__(message)


# =============================================================================
# 预定义正则模式
# =============================================================================
VALIDATION_PATTERNS = {
    "alphanumeric": re.compile(r"^[a-zA-Z0-9]+$"),
    "alphanumeric_dash": re.compile(r"^[a-zA-Z0-9_-]+$"),
    "domain": re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"),
    "email": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    "ipv4": re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ),
    "port": re.compile(
        r"^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
    ),
    "filename": re.compile(r"^[a-zA-Z0-9_.-]+$"),
    "session_id": re.compile(r"^[a-zA-Z0-9_-]{8,64}$"),
    "cve_id": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
}

# =============================================================================
# 危险字符分类
# =============================================================================
DANGEROUS_CHARS = {
    "path": ["..", "~", "\\", "\x00"],
    "command": [
        ";",
        "|",
        "&",
        "$",
        "`",
        "\n",
        "\r",
        ">",
        "<",
        "'",
        '"',
        "\\",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        "\x00",
        "\t",
        "\x0b",
        "\x0c",
    ],
    "sql": ["'", '"', "--", "/*", "*/", "xp_", "sp_"],
}


def validate_url(url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
    """
    验证URL格式

    Args:
        url: 要验证的URL
        allowed_schemes: 允许的协议列表，默认 ['http', 'https']

    Returns:
        URL是否有效
    """
    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    try:
        result = urlparse(url)

        # 必须有scheme和netloc
        if not result.scheme or not result.netloc:
            return False

        # 检查协议
        if result.scheme.lower() not in allowed_schemes:
            return False

        # 基本格式检查
        if ".." in url or "\\" in url:
            return False

        return True

    except (ValueError, TypeError):
        return False


def validate_ip(ip: str) -> bool:
    """
    验证IP地址（IPv4或IPv6）

    Args:
        ip: 要验证的IP地址

    Returns:
        IP是否有效
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ipv4(ip: str) -> bool:
    """
    验证IPv4地址

    Args:
        ip: 要验证的IP地址

    Returns:
        是否为有效的IPv4地址
    """
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv4Address)
    except ValueError:
        return False


def validate_ipv6(ip: str) -> bool:
    """
    验证IPv6地址

    Args:
        ip: 要验证的IP地址

    Returns:
        是否为有效的IPv6地址
    """
    try:
        addr = ipaddress.ip_address(ip)
        return isinstance(addr, ipaddress.IPv6Address)
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    验证CIDR网段

    Args:
        cidr: 要验证的CIDR（如 192.168.1.0/24）

    Returns:
        CIDR是否有效
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port: Union[int, str]) -> bool:
    """
    验证端口号

    Args:
        port: 要验证的端口号

    Returns:
        端口是否有效（1-65535）
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def validate_port_range(port_range: str) -> bool:
    """
    验证端口范围字符串

    支持格式：
    - 单个端口: "80"
    - 端口列表: "80,443,8080"
    - 端口范围: "80-100"
    - 混合格式: "80,443,8000-9000"

    Args:
        port_range: 端口范围字符串

    Returns:
        端口范围是否有效
    """
    try:
        parts = port_range.replace(" ", "").split(",")

        for part in parts:
            if "-" in part:
                start, end = part.split("-")
                start_port = int(start)
                end_port = int(end)

                if not (validate_port(start_port) and validate_port(end_port)):
                    return False

                if start_port > end_port:
                    return False
            else:
                if not validate_port(int(part)):
                    return False

        return True

    except (ValueError, TypeError):
        return False


def validate_domain(domain: str) -> bool:
    """
    验证域名

    Args:
        domain: 要验证的域名

    Returns:
        域名是否有效
    """
    # 域名正则表达式
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if not re.match(domain_pattern, domain):
        return False

    # 检查总长度
    if len(domain) > 253:
        return False

    # 检查每个标签长度
    labels = domain.split(".")
    for label in labels:
        if len(label) > 63:
            return False

    return True


def validate_email(email: str) -> bool:
    """
    验证邮箱地址

    Args:
        email: 要验证的邮箱

    Returns:
        邮箱是否有效
    """
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, email))


def sanitize_path(path: str) -> str:
    """
    清理路径，移除路径遍历攻击载荷

    Args:
        path: 原始路径

    Returns:
        清理后的路径
    """
    if not path:
        return ""

    # URL解码
    decoded = unquote(unquote(path))

    # 移除路径遍历序列
    traversal_patterns = ["../", "..\\", "%2e%2e/", "%2e%2e\\"]
    for pattern in traversal_patterns:
        while pattern.lower() in decoded.lower():
            decoded = re.sub(re.escape(pattern), "", decoded, flags=re.IGNORECASE)

    # 移除双斜杠
    while "//" in decoded:
        decoded = decoded.replace("//", "/")
    while "\\\\" in decoded:
        decoded = decoded.replace("\\\\", "\\")

    # 移除开头的斜杠（相对路径）
    decoded = decoded.lstrip("/\\")

    return decoded


def sanitize_command(cmd: str, strict: bool = True) -> str:
    """
    清理命令字符串，防止命令注入

    Args:
        cmd: 原始命令
        strict: 严格模式 (默认True)
                - True: 如果包含危险字符则抛出 ValidationError
                - False: 移除危险字符 (不推荐，可能被绕过)

    Returns:
        清理后的命令

    Raises:
        ValidationError: 严格模式下检测到危险字符

    安全警告:
        此函数不能完全防止命令注入。最佳实践是:
        1. 使用参数化命令 (subprocess 的列表形式)
        2. 使用白名单验证允许的命令
        3. 避免将用户输入直接用于命令
    """
    if not cmd:
        return ""

    # 危险字符列表
    dangerous_chars = [
        ";",
        "|",
        "&",
        "$",
        "`",
        "\n",
        "\r",
        ">",
        "<",
        "'",
        '"',
        "\\",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        "\x00",
        "\t",
        "\x0b",
        "\x0c",
    ]

    if strict:
        # 严格模式：检测到危险字符则拒绝
        for char in dangerous_chars:
            if char in cmd:
                raise ValidationError(f"命令包含危险字符: {repr(char)}", field="command")
        return cmd.strip()
    else:
        # 宽松模式：移除危险字符 (不推荐)
        logger.warning("sanitize_command 使用宽松模式 - 可能存在绕过风险")
        result = cmd
        for char in dangerous_chars:
            result = result.replace(char, "")
        return result.strip()


def sanitize_filename(filename: str) -> str:
    """
    清理文件名，移除不安全字符

    Args:
        filename: 原始文件名

    Returns:
        清理后的文件名
    """
    if not filename:
        return "unnamed"

    # 移除路径分隔符
    filename = filename.replace("/", "_").replace("\\", "_")

    # 移除其他不安全字符
    unsafe_chars = ["<", ">", ":", '"', "|", "?", "*", "\x00"]
    for char in unsafe_chars:
        filename = filename.replace(char, "_")

    # 移除开头的点（隐藏文件）
    filename = filename.lstrip(".")

    # 限制长度
    if len(filename) > 255:
        name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
        max_name_len = 255 - len(ext) - 1 if ext else 255
        filename = f"{name[:max_name_len]}.{ext}" if ext else name[:255]

    return filename or "unnamed"


class InputValidator:
    """
    输入验证器类

    提供更详细的验证结果和错误信息。
    """

    # 危险命令列表
    DANGEROUS_COMMANDS = [
        "rm",
        "dd",
        "mkfs",
        "format",
        ":(){:|:&};:",
        "chmod",
        "chown",
        "shutdown",
        "reboot",
        "init",
        "del",
        "rmdir",
        "rd",
        "deltree",
    ]

    # 危险系统路径
    DANGEROUS_PATHS = [
        "/etc/",
        "/sys/",
        "/proc/",
        "/dev/",
        "/root/",
        "/boot/",
        "C:\\Windows",
        "C:\\System32",
        "C:\\Program Files",
    ]

    # Session ID 正则
    SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{8,64}$")

    @staticmethod
    def validate_target(target: str) -> Tuple[str, str]:
        """
        验证并解析目标

        自动识别目标类型（IP、CIDR、URL、域名）并返回规范化值。

        Args:
            target: 目标字符串

        Returns:
            (目标类型, 规范化值) - 类型为 'ip', 'cidr', 'url', 'domain'

        Raises:
            ValidationError: 无法识别目标类型
        """
        if not target or not target.strip():
            raise ValidationError("目标不能为空", "target")

        target = target.strip()

        # 尝试作为IP地址
        if validate_ip(target):
            return "ip", target

        # 尝试作为CIDR
        if validate_cidr(target):
            return "cidr", target

        # 尝试作为URL
        if validate_url(target):
            return "url", target

        # 尝试作为域名
        if validate_domain(target):
            return "domain", target

        raise ValidationError(f"无法识别目标类型: {target}", "target")

    @staticmethod
    def validate_file_path(
        path: str,
        allow_absolute: bool = False,
        base_dir: Optional[str] = None,
        must_exist: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """
        验证文件路径安全性

        Args:
            path: 文件路径
            allow_absolute: 是否允许绝对路径
            base_dir: 限制的基础目录
            must_exist: 是否必须存在

        Returns:
            (是否有效, 错误消息)
        """
        if not path or not isinstance(path, str):
            return False, "路径不能为空"

        # URL解码
        decoded_path = unquote(unquote(path))

        # 检查路径遍历
        traversal_patterns = ["..", "%2e%2e", "%252e%252e", "...."]
        for pattern in traversal_patterns:
            if pattern.lower() in decoded_path.lower():
                return False, f"路径包含非法字符: {pattern}"

        # 规范化路径
        try:
            import os

            normalized = os.path.normpath(decoded_path)
        except (TypeError, ValueError):
            return False, "路径格式无效"

        # 检查绝对路径
        if not allow_absolute:
            # Unix 绝对路径
            if normalized.startswith("/"):
                return False, "不允许绝对路径"
            # Windows 盘符路径
            if re.match(r"^[A-Za-z]:", normalized):
                return False, "不允许 Windows 绝对路径"
            # UNC 路径
            if normalized.startswith("\\\\") or normalized.startswith("//"):
                return False, "不允许 UNC 路径"

        # 检查危险系统路径
        normalized_lower = normalized.lower().replace("\\", "/")
        for dangerous in InputValidator.DANGEROUS_PATHS:
            if normalized_lower.startswith(dangerous.lower().replace("\\", "/")):
                return False, f"不允许访问系统路径: {dangerous}"

        # 检查基础目录限制
        if base_dir:
            try:
                base_resolved = Path(base_dir).resolve()
                path_resolved = (base_resolved / normalized).resolve()
                if not str(path_resolved).startswith(str(base_resolved)):
                    return False, "路径超出允许范围"
            except (OSError, ValueError, RuntimeError):
                return False, "路径解析失败"

        # 检查是否存在
        if must_exist:
            if not Path(normalized).exists():
                return False, f"路径不存在: {path}"

        return True, None

    @staticmethod
    def validate_session_id(session_id: str) -> Tuple[bool, Optional[str]]:
        """
        验证Session ID格式

        Args:
            session_id: Session ID

        Returns:
            (是否有效, 错误消息)
        """
        if not session_id:
            return False, "Session ID 不能为空"

        if not InputValidator.SESSION_ID_PATTERN.match(session_id):
            return False, "Session ID 格式无效 (仅允许字母数字下划线连字符, 8-64字符)"

        # 检查危险字符
        if ".." in session_id or "/" in session_id or "\\" in session_id:
            return False, "Session ID 包含非法字符"

        return True, None

    @staticmethod
    def check_dangerous_command(cmd: Union[str, List[str]]) -> Tuple[bool, Optional[str]]:
        """
        检查命令是否包含危险操作

        Args:
            cmd: 命令字符串或参数列表

        Returns:
            (是否安全, 错误消息)
        """
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        cmd_lower = cmd_str.lower()

        for dangerous in InputValidator.DANGEROUS_COMMANDS:
            # 使用单词边界匹配
            pattern = r"\b" + re.escape(dangerous) + r"\b"
            if re.search(pattern, cmd_lower):
                return False, f"检测到危险命令: {dangerous}"

        return True, None

    @staticmethod
    def validate_json(data: str) -> Tuple[bool, Optional[str]]:
        """
        验证JSON格式

        Args:
            data: JSON字符串

        Returns:
            (是否有效, 错误消息)
        """
        import json

        try:
            json.loads(data)
            return True, None
        except json.JSONDecodeError as e:
            return False, f"JSON格式无效: {e}"

    @staticmethod
    def validate_base64(data: str) -> Tuple[bool, Optional[str]]:
        """
        验证Base64格式

        Args:
            data: Base64字符串

        Returns:
            (是否有效, 错误消息)
        """
        import base64

        try:
            # 尝试解码
            decoded = base64.b64decode(data, validate=True)
            # 重新编码检查
            if base64.b64encode(decoded).decode() == data:
                return True, None
            return False, "Base64编码不规范"
        except Exception as e:
            return False, f"Base64格式无效: {e}"

    @staticmethod
    def validate_string(
        value: str,
        min_length: int = 0,
        max_length: int = 1000,
        pattern: str = None,
        allow_empty: bool = False,
    ) -> str:
        """
        验证字符串

        Args:
            value: 待验证的字符串
            min_length: 最小长度
            max_length: 最大长度
            pattern: 正则模式名称（对应 VALIDATION_PATTERNS）
            allow_empty: 是否允许空字符串

        Returns:
            验证后的字符串

        Raises:
            ValidationError: 验证失败
        """
        if not isinstance(value, str):
            raise ValidationError(f"期望字符串类型，实际为 {type(value)}")

        if not allow_empty and not value:
            raise ValidationError("字符串不能为空")

        if len(value) < min_length:
            raise ValidationError(f"字符串长度不能小于 {min_length}")

        if len(value) > max_length:
            raise ValidationError(f"字符串长度不能大于 {max_length}")

        if pattern and pattern in VALIDATION_PATTERNS:
            if not VALIDATION_PATTERNS[pattern].match(value):
                raise ValidationError(f"字符串格式不符合 {pattern} 规则")

        return value

    @staticmethod
    def validate_command_args(args: List[str], whitelist: Optional[List[str]] = None) -> List[str]:
        """
        验证命令参数（防止命令注入）

        Args:
            args: 命令参数列表
            whitelist: 允许的命令白名单

        Returns:
            验证后的参数列表

        Raises:
            ValidationError: 验证失败
        """
        if not args:
            raise ValidationError("命令参数不能为空")

        # 检查命令是否在白名单中
        if whitelist and args[0] not in whitelist:
            raise ValidationError(f"命令 {args[0]} 不在白名单中")

        # 检查每个参数
        for arg in args:
            if not isinstance(arg, str):
                raise ValidationError(f"参数必须是字符串类型: {type(arg)}")

            # 检查危险字符
            for dangerous in DANGEROUS_CHARS["command"]:
                if dangerous in arg:
                    raise ValidationError(f"参数包含危险字符: {dangerous}")

        return args

    @staticmethod
    def sanitize_html(html: str) -> str:
        """
        清理HTML（防止XSS）

        Args:
            html: 待清理的HTML

        Returns:
            清理后的HTML（HTML实体转义）
        """
        html = html.replace("&", "&amp;")
        html = html.replace("<", "&lt;")
        html = html.replace(">", "&gt;")
        html = html.replace('"', "&quot;")
        html = html.replace("'", "&#x27;")
        html = html.replace("/", "&#x2F;")
        return html


# 便捷验证函数
def validate_and_raise(value: str, validator_func, field_name: str, **kwargs) -> str:
    """
    验证值并在失败时抛出异常

    Args:
        value: 要验证的值
        validator_func: 验证函数
        field_name: 字段名称
        **kwargs: 传递给验证函数的额外参数

    Returns:
        原始值

    Raises:
        ValidationError: 验证失败
    """
    if not validator_func(value, **kwargs):
        raise ValidationError(f"{field_name} 验证失败: {value}", field_name)
    return value


# =============================================================================
# 装饰器
# =============================================================================


def validate_params(**validators):
    """
    参数验证装饰器

    用法:
        @validate_params(
            url=lambda x: InputValidator.validate_url(x),
            port=lambda x: InputValidator.validate_port(x)
        )
        def scan(url: str, port: int):
            pass
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 获取函数参数名
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()

            # 验证每个参数
            for param_name, validator in validators.items():
                if param_name in bound.arguments:
                    value = bound.arguments[param_name]
                    try:
                        validated = validator(value)
                        bound.arguments[param_name] = validated
                    except ValidationError as e:
                        logger.error(f"参数验证失败 [{param_name}]: {e}")
                        raise

            return func(**bound.arguments)

        return wrapper

    return decorator


def require_auth(func: Callable) -> Callable:
    """
    认证装饰器

    需要配合 core.security.auth_manager 使用。
    支持同步和异步函数。
    """

    def _get_auth_manager():
        from core.security.auth_manager import AuthManager

        if not hasattr(_get_auth_manager, "_instance"):
            _get_auth_manager._instance = AuthManager()
        return _get_auth_manager._instance

    def _extract_api_key(kwargs: Dict[str, Any]) -> Optional[str]:
        return kwargs.get("api_key") or os.environ.get("AUTOREDTEAM_API_KEY")

    @wraps(func)
    def wrapper(*args, **kwargs):
        api_key = _extract_api_key(kwargs)
        if not api_key:
            raise ValidationError("缺少 API Key（请设置 AUTOREDTEAM_API_KEY 或传入 api_key）")

        manager = _get_auth_manager()
        key_obj = manager.verify_key(api_key)
        if not key_obj:
            raise ValidationError("API Key 无效或已过期")
        if not manager.check_permission(key_obj, func.__name__):
            raise ValidationError("API Key 权限不足")

        return func(*args, **kwargs)

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        api_key = _extract_api_key(kwargs)
        if not api_key:
            raise ValidationError("缺少 API Key（请设置 AUTOREDTEAM_API_KEY 或传入 api_key）")

        manager = _get_auth_manager()
        key_obj = manager.verify_key(api_key)
        if not key_obj:
            raise ValidationError("API Key 无效或已过期")
        if not manager.check_permission(key_obj, func.__name__):
            raise ValidationError("API Key 权限不足")

        return await func(*args, **kwargs)

    if inspect.iscoroutinefunction(func):
        return async_wrapper
    return wrapper


# =============================================================================
# 便捷函数
# =============================================================================


def safe_path_join(base: str, *paths: str) -> str:
    """
    安全的路径拼接（防止路径遍历）

    Args:
        base: 基础目录
        *paths: 要拼接的路径部分

    Returns:
        安全的绝对路径

    Raises:
        ValidationError: 路径遍历检测
    """
    result = Path(base).resolve()

    for part in paths:
        # 验证每个部分
        if ".." in part or part.startswith("/") or part.startswith("\\"):
            raise ValidationError(f"路径部分包含危险字符: {part}")

        result = result / part

    # 确保最终路径在基础目录内
    try:
        result.resolve().relative_to(Path(base).resolve())
    except ValueError:
        raise ValidationError("路径遍历攻击检测")

    return str(result.resolve())


def validate_target(target: str) -> Dict[str, str]:
    """
    验证扫描目标（URL、IP或域名）

    Args:
        target: 目标字符串

    Returns:
        包含 type 和 value 的字典

    Raises:
        ValidationError: 验证失败
    """
    target = target.strip()

    # 尝试作为URL验证
    if target.startswith(("http://", "https://")):
        if validate_url(target):
            return {"type": "url", "value": target}

    # 尝试作为IP验证
    if validate_ip(target):
        return {"type": "ip", "value": target}

    # 尝试作为CIDR验证
    if validate_cidr(target):
        return {"type": "cidr", "value": target}

    # 尝试作为域名验证
    if validate_domain(target):
        return {"type": "domain", "value": target}

    raise ValidationError(f"无效的目标格式: {target}")


__all__ = [
    # 异常类
    "ValidationError",
    # 快捷验证函数
    "validate_url",
    "validate_ip",
    "validate_ipv4",
    "validate_ipv6",
    "validate_cidr",
    "validate_port",
    "validate_port_range",
    "validate_domain",
    "validate_email",
    # 清理函数
    "sanitize_path",
    "sanitize_command",
    "sanitize_filename",
    # 验证器类
    "InputValidator",
    # 便捷函数
    "validate_and_raise",
    "validate_target",
    "safe_path_join",
    # 装饰器
    "validate_params",
    "require_auth",
    # 常量
    "VALIDATION_PATTERNS",
    "DANGEROUS_CHARS",
]
