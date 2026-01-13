#!/usr/bin/env python3
"""
输入验证框架 - 统一的输入校验机制
防止注入攻击、路径遍历、XSS等安全问题
"""

import re
import ipaddress
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from functools import wraps
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """验证错误异常"""
    pass


class InputValidator:
    """输入验证器"""

    # 安全正则模式
    PATTERNS = {
        "alphanumeric": re.compile(r'^[a-zA-Z0-9]+$'),
        "alphanumeric_dash": re.compile(r'^[a-zA-Z0-9_-]+$'),
        "domain": re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
        "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        "ipv4": re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
        "port": re.compile(r'^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'),
        "filename": re.compile(r'^[a-zA-Z0-9_.-]+$'),
        "session_id": re.compile(r'^[a-zA-Z0-9_-]{8,64}$'),
        "cve_id": re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE),
    }

    # 危险字符黑名单
    DANGEROUS_CHARS = {
        "path": ['..', '~', '\\', '\x00'],
        "command": [';', '|', '&', '$', '`', '\n', '\r'],
        "sql": ["'", '"', '--', '/*', '*/', 'xp_', 'sp_'],
    }

    @staticmethod
    def validate_string(value: str, min_length: int = 0, max_length: int = 1000,
                       pattern: str = None, allow_empty: bool = False) -> str:
        """
        验证字符串

        Args:
            value: 待验证的字符串
            min_length: 最小长度
            max_length: 最大长度
            pattern: 正则模式名称
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

        if pattern and pattern in InputValidator.PATTERNS:
            if not InputValidator.PATTERNS[pattern].match(value):
                raise ValidationError(f"字符串格式不符合 {pattern} 规则")

        return value

    @staticmethod
    def validate_url(url: str, allowed_schemes: List[str] = None,
                    require_scheme: bool = True) -> str:
        """
        验证URL

        Args:
            url: 待验证的URL
            allowed_schemes: 允许的协议列表
            require_scheme: 是否必须包含协议

        Returns:
            验证后的URL

        Raises:
            ValidationError: 验证失败
        """
        if not url:
            raise ValidationError("URL不能为空")

        if len(url) > 2048:
            raise ValidationError("URL长度不能超过2048字符")

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"URL解析失败: {e}")

        if require_scheme and not parsed.scheme:
            raise ValidationError("URL必须包含协议 (http/https)")

        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']

        if parsed.scheme and parsed.scheme not in allowed_schemes:
            raise ValidationError(f"不支持的协议: {parsed.scheme}，仅允许 {allowed_schemes}")

        # 检查危险字符
        dangerous_patterns = ['javascript:', 'data:', 'file:', 'vbscript:']
        url_lower = url.lower()
        for pattern in dangerous_patterns:
            if pattern in url_lower:
                raise ValidationError(f"URL包含危险协议: {pattern}")

        return url

    @staticmethod
    def validate_ip(ip: str, allow_private: bool = True) -> str:
        """
        验证IP地址

        Args:
            ip: 待验证的IP地址
            allow_private: 是否允许私有IP

        Returns:
            验证后的IP地址

        Raises:
            ValidationError: 验证失败
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValidationError(f"无效的IP地址: {e}")

        if not allow_private and ip_obj.is_private:
            raise ValidationError("不允许使用私有IP地址")

        # 禁止回环地址和保留地址
        if ip_obj.is_loopback:
            raise ValidationError("不允许使用回环地址")

        if ip_obj.is_reserved:
            raise ValidationError("不允许使用保留地址")

        return str(ip_obj)

    @staticmethod
    def validate_port(port: Union[int, str]) -> int:
        """
        验证端口号

        Args:
            port: 待验证的端口号

        Returns:
            验证后的端口号

        Raises:
            ValidationError: 验证失败
        """
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            raise ValidationError(f"无效的端口号: {port}")

        if not (1 <= port_int <= 65535):
            raise ValidationError(f"端口号必须在1-65535之间，实际为 {port_int}")

        return port_int

    @staticmethod
    def validate_path(path: str, base_dir: str = None,
                     must_exist: bool = False, allow_create: bool = False) -> str:
        """
        验证文件路径（防止路径遍历）

        Args:
            path: 待验证的路径
            base_dir: 基础目录（路径必须在此目录内）
            must_exist: 路径必须存在
            allow_create: 是否允许创建不存在的路径

        Returns:
            规范化后的绝对路径

        Raises:
            ValidationError: 验证失败
        """
        if not path:
            raise ValidationError("路径不能为空")

        # 检查危险字符
        for dangerous in InputValidator.DANGEROUS_CHARS["path"]:
            if dangerous in path:
                raise ValidationError(f"路径包含危险字符: {dangerous}")

        # 转换为Path对象并规范化
        try:
            path_obj = Path(path).resolve()
        except Exception as e:
            raise ValidationError(f"路径解析失败: {e}")

        # 检查是否在基础目录内
        if base_dir:
            try:
                base_obj = Path(base_dir).resolve()
                # 确保路径在基础目录内
                path_obj.relative_to(base_obj)
            except ValueError:
                raise ValidationError(f"路径遍历攻击检测: 路径必须在 {base_dir} 内")

        # 检查路径是否存在
        if must_exist and not path_obj.exists():
            raise ValidationError(f"路径不存在: {path_obj}")

        # 如果不存在且不允许创建
        if not path_obj.exists() and not allow_create:
            raise ValidationError(f"路径不存在且不允许创建: {path_obj}")

        return str(path_obj)

    @staticmethod
    def validate_filename(filename: str, allowed_extensions: List[str] = None) -> str:
        """
        验证文件名

        Args:
            filename: 待验证的文件名
            allowed_extensions: 允许的扩展名列表

        Returns:
            验证后的文件名

        Raises:
            ValidationError: 验证失败
        """
        if not filename:
            raise ValidationError("文件名不能为空")

        # 检查文件名格式
        if not InputValidator.PATTERNS["filename"].match(filename):
            raise ValidationError("文件名包含非法字符")

        # 检查路径遍历
        if '..' in filename or '/' in filename or '\\' in filename:
            raise ValidationError("文件名不能包含路径分隔符")

        # 检查扩展名
        if allowed_extensions:
            ext = Path(filename).suffix.lower()
            if ext not in allowed_extensions:
                raise ValidationError(f"不支持的文件扩展名: {ext}，仅允许 {allowed_extensions}")

        return filename

    @staticmethod
    def validate_command_args(args: List[str], whitelist: List[str] = None) -> List[str]:
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
            for dangerous in InputValidator.DANGEROUS_CHARS["command"]:
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
            清理后的HTML
        """
        # 简单的HTML转义
        html = html.replace('&', '&amp;')
        html = html.replace('<', '&lt;')
        html = html.replace('>', '&gt;')
        html = html.replace('"', '&quot;')
        html = html.replace("'", '&#x27;')
        html = html.replace('/', '&#x2F;')
        return html

    @staticmethod
    def validate_json(data: str, max_size: int = 1024 * 1024) -> Dict:
        """
        验证JSON数据

        Args:
            data: JSON字符串
            max_size: 最大大小（字节）

        Returns:
            解析后的字典

        Raises:
            ValidationError: 验证失败
        """
        if len(data) > max_size:
            raise ValidationError(f"JSON数据过大: {len(data)} > {max_size}")

        try:
            import json
            return json.loads(data)
        except json.JSONDecodeError as e:
            raise ValidationError(f"JSON解析失败: {e}")


# ========== 装饰器 ==========

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
            import inspect
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
    认证装饰器（占位，需要配合认证系统使用）
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # TODO: 实现认证检查
        return func(*args, **kwargs)
    return wrapper


# ========== 便捷函数 ==========

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
        if '..' in part or part.startswith('/') or part.startswith('\\'):
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
        包含type和value的字典

    Raises:
        ValidationError: 验证失败
    """
    target = target.strip()

    # 尝试作为URL验证
    if target.startswith(('http://', 'https://')):
        validated = InputValidator.validate_url(target)
        return {"type": "url", "value": validated}

    # 尝试作为IP验证
    try:
        validated = InputValidator.validate_ip(target)
        return {"type": "ip", "value": validated}
    except ValidationError:
        pass

    # 尝试作为域名验证
    if InputValidator.PATTERNS["domain"].match(target):
        return {"type": "domain", "value": target}

    raise ValidationError(f"无效的目标格式: {target}")


# ========== 测试 ==========

if __name__ == "__main__":
    # 测试用例
    validator = InputValidator()

    # 测试URL验证
    try:
        print(validator.validate_url("http://example.com"))
        print(validator.validate_url("javascript:alert(1)"))  # 应该失败
    except ValidationError as e:
        print(f"预期的错误: {e}")

    # 测试路径验证
    try:
        print(validator.validate_path("test.txt", base_dir="."))
        print(validator.validate_path("../etc/passwd", base_dir="."))  # 应该失败
    except ValidationError as e:
        print(f"预期的错误: {e}")

    # 测试命令参数验证
    try:
        print(validator.validate_command_args(["nmap", "-sV", "127.0.0.1"]))
        print(validator.validate_command_args(["nmap", "-sV; rm -rf /"]))  # 应该失败
    except ValidationError as e:
        print(f"预期的错误: {e}")
