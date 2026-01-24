#!/usr/bin/env python3
"""
输入验证模块 - AutoRedTeam-Orchestrator

提供各种输入验证功能，包括：
- URL/IP/域名验证
- 端口验证
- 路径安全验证（防止路径遍历）
- 命令安全验证（防止命令注入）
- 通用输入清理

使用示例:
    from utils.validators import validate_url, validate_ip, InputValidator

    # 快捷函数
    if validate_url("https://example.com"):
        print("URL有效")

    # 验证器类
    validator = InputValidator()
    target_type, normalized = validator.validate_target("192.168.1.1")
"""

import re
import ipaddress
from typing import Optional, List, Tuple, Union
from urllib.parse import urlparse, unquote
from pathlib import Path


class ValidationError(Exception):
    """验证错误异常"""

    def __init__(self, message: str, field: Optional[str] = None):
        self.message = message
        self.field = field
        super().__init__(message)


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
        allowed_schemes = ['http', 'https']

    try:
        result = urlparse(url)

        # 必须有scheme和netloc
        if not result.scheme or not result.netloc:
            return False

        # 检查协议
        if result.scheme.lower() not in allowed_schemes:
            return False

        # 基本格式检查
        if '..' in url or '\\' in url:
            return False

        return True

    except Exception:
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
        parts = port_range.replace(' ', '').split(',')

        for part in parts:
            if '-' in part:
                start, end = part.split('-')
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
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    if not re.match(domain_pattern, domain):
        return False

    # 检查总长度
    if len(domain) > 253:
        return False

    # 检查每个标签长度
    labels = domain.split('.')
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
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
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
        return ''

    # URL解码
    decoded = unquote(unquote(path))

    # 移除路径遍历序列
    traversal_patterns = ['../', '..\\', '%2e%2e/', '%2e%2e\\']
    for pattern in traversal_patterns:
        while pattern.lower() in decoded.lower():
            decoded = re.sub(re.escape(pattern), '', decoded, flags=re.IGNORECASE)

    # 移除双斜杠
    while '//' in decoded:
        decoded = decoded.replace('//', '/')
    while '\\\\' in decoded:
        decoded = decoded.replace('\\\\', '\\')

    # 移除开头的斜杠（相对路径）
    decoded = decoded.lstrip('/\\')

    return decoded


def sanitize_command(cmd: str) -> str:
    """
    清理命令字符串，移除危险字符

    注意：这不能完全防止命令注入，最好使用参数化命令

    Args:
        cmd: 原始命令

    Returns:
        清理后的命令
    """
    if not cmd:
        return ''

    # 危险字符列表
    dangerous_chars = [
        ';', '|', '&', '$', '`', '\n', '\r', '>', '<',
        "'", '"', '\\', '(', ')', '{', '}', '[', ']',
        '\x00', '\t', '\x0b', '\x0c',
    ]

    result = cmd
    for char in dangerous_chars:
        result = result.replace(char, '')

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
        return 'unnamed'

    # 移除路径分隔符
    filename = filename.replace('/', '_').replace('\\', '_')

    # 移除其他不安全字符
    unsafe_chars = ['<', '>', ':', '"', '|', '?', '*', '\x00']
    for char in unsafe_chars:
        filename = filename.replace(char, '_')

    # 移除开头的点（隐藏文件）
    filename = filename.lstrip('.')

    # 限制长度
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        max_name_len = 255 - len(ext) - 1 if ext else 255
        filename = f"{name[:max_name_len]}.{ext}" if ext else name[:255]

    return filename or 'unnamed'


class InputValidator:
    """
    输入验证器类

    提供更详细的验证结果和错误信息。
    """

    # 危险命令列表
    DANGEROUS_COMMANDS = [
        'rm', 'dd', 'mkfs', 'format', ':(){:|:&};:',
        'chmod', 'chown', 'shutdown', 'reboot', 'init',
        'del', 'rmdir', 'rd', 'deltree'
    ]

    # 危险系统路径
    DANGEROUS_PATHS = [
        '/etc/', '/sys/', '/proc/', '/dev/', '/root/', '/boot/',
        'C:\\Windows', 'C:\\System32', 'C:\\Program Files'
    ]

    # Session ID 正则
    SESSION_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{8,64}$')

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
            return 'ip', target

        # 尝试作为CIDR
        if validate_cidr(target):
            return 'cidr', target

        # 尝试作为URL
        if validate_url(target):
            return 'url', target

        # 尝试作为域名
        if validate_domain(target):
            return 'domain', target

        raise ValidationError(f"无法识别目标类型: {target}", "target")

    @staticmethod
    def validate_file_path(
        path: str,
        allow_absolute: bool = False,
        base_dir: Optional[str] = None,
        must_exist: bool = False
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
        traversal_patterns = ['..', '%2e%2e', '%252e%252e', '....']
        for pattern in traversal_patterns:
            if pattern.lower() in decoded_path.lower():
                return False, f"路径包含非法字符: {pattern}"

        # 规范化路径
        try:
            import os
            normalized = os.path.normpath(decoded_path)
        except Exception:
            return False, "路径格式无效"

        # 检查绝对路径
        if not allow_absolute:
            # Unix 绝对路径
            if normalized.startswith('/'):
                return False, "不允许绝对路径"
            # Windows 盘符路径
            if re.match(r'^[A-Za-z]:', normalized):
                return False, "不允许 Windows 绝对路径"
            # UNC 路径
            if normalized.startswith('\\\\') or normalized.startswith('//'):
                return False, "不允许 UNC 路径"

        # 检查危险系统路径
        normalized_lower = normalized.lower().replace('\\', '/')
        for dangerous in InputValidator.DANGEROUS_PATHS:
            if normalized_lower.startswith(dangerous.lower().replace('\\', '/')):
                return False, f"不允许访问系统路径: {dangerous}"

        # 检查基础目录限制
        if base_dir:
            try:
                base_resolved = Path(base_dir).resolve()
                path_resolved = (base_resolved / normalized).resolve()
                if not str(path_resolved).startswith(str(base_resolved)):
                    return False, "路径超出允许范围"
            except Exception:
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
        if '..' in session_id or '/' in session_id or '\\' in session_id:
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
            cmd_str = ' '.join(cmd)
        else:
            cmd_str = cmd

        cmd_lower = cmd_str.lower()

        for dangerous in InputValidator.DANGEROUS_COMMANDS:
            # 使用单词边界匹配
            pattern = r'\b' + re.escape(dangerous) + r'\b'
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


# 便捷验证函数
def validate_and_raise(
    value: str,
    validator_func,
    field_name: str,
    **kwargs
) -> str:
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


__all__ = [
    'ValidationError',
    'validate_url',
    'validate_ip',
    'validate_ipv4',
    'validate_ipv6',
    'validate_cidr',
    'validate_port',
    'validate_port_range',
    'validate_domain',
    'validate_email',
    'sanitize_path',
    'sanitize_command',
    'sanitize_filename',
    'InputValidator',
    'validate_and_raise',
]
