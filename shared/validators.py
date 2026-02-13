"""
跨模块共享验证器 - 委托给 utils.validators 的完整实现

保持 Tuple[bool, Optional[str]] 的 API 签名，内部复用 utils.validators 逻辑。
sanitize_command_arg 无对应实现，保留原地定义。
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from utils.validators import (
    validate_domain as _validate_domain,
    validate_ip as _validate_ip,
    validate_port as _validate_port,
    validate_url as _validate_url,
)

# 危险字符: 命令分隔符、重定向、子shell、引号、换行、空字节
_DANGEROUS_CHARS = re.compile(r'[;\|\$\`\&\>\<\(\)\{\}\[\]\\\'\"\n\r\x00\t\x0b\x0c]')


def validate_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """验证域名格式"""
    if not domain:
        return False, "域名不能为空"
    if _DANGEROUS_CHARS.search(domain):
        return False, "域名包含危险字符"
    if not _validate_domain(domain):
        return False, "域名格式无效"
    return True, None


def validate_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """验证IP地址格式"""
    if not ip:
        return False, "IP不能为空"
    if not _validate_ip(ip):
        return False, "无效的IP地址: %s" % ip
    return True, None


def validate_url(url: str, require_https: bool = False) -> Tuple[bool, Optional[str]]:
    """验证URL格式"""
    if not url:
        return False, "URL不能为空"
    if len(url) > 2048:
        return False, "URL长度超过2048字符"
    parsed = urlparse(url)
    if not parsed.scheme:
        return False, "URL缺少协议"
    schemes = ["https"] if require_https else ["http", "https"]
    if not _validate_url(url, allowed_schemes=schemes):
        if require_https:
            return False, "需要有效的HTTPS URL"
        return False, "URL格式无效"
    return True, None


def validate_port(port: int) -> Tuple[bool, Optional[str]]:
    """验证端口号"""
    if not isinstance(port, int):
        return False, "端口必须是整数"
    if not _validate_port(port):
        return False, "端口必须在1-65535之间"
    return True, None


def sanitize_command_arg(arg: str) -> str:
    """清理命令行参数，防止注入"""
    if not arg:
        return ""
    return _DANGEROUS_CHARS.sub("", arg).strip()
