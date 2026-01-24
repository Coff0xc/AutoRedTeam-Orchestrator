#!/usr/bin/env python3
"""
编码工具模块 - AutoRedTeam-Orchestrator

提供各种编码/解码功能，包括：
- Base64编码/解码
- 十六进制编码/解码
- URL编码/解码
- HTML实体编码/解码
- Unicode编码/解码
- 多重编码

使用示例:
    from utils.encoding import base64_encode, url_encode, hex_encode

    # Base64
    encoded = base64_encode("Hello, World!")
    decoded = base64_decode(encoded)

    # URL编码
    encoded = url_encode("param=value&key=test")
"""

import base64
import binascii
import html
import codecs
from typing import Union, Optional
from urllib.parse import quote, unquote, quote_plus, unquote_plus


def _ensure_bytes(data: Union[str, bytes], encoding: str = 'utf-8') -> bytes:
    """确保数据为bytes类型"""
    if isinstance(data, str):
        return data.encode(encoding)
    return data


def _ensure_str(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """确保数据为str类型"""
    if isinstance(data, bytes):
        return data.decode(encoding)
    return data


# ==================== Base64 编码 ====================

def base64_encode(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    Base64编码

    Args:
        data: 要编码的数据（字符串或字节）
        encoding: 字符串编码方式

    Returns:
        Base64编码后的字符串
    """
    data_bytes = _ensure_bytes(data, encoding)
    return base64.b64encode(data_bytes).decode('ascii')


def base64_decode(data: str, encoding: str = 'utf-8') -> bytes:
    """
    Base64解码

    Args:
        data: Base64编码的字符串
        encoding: 不使用，保留参数以保持接口一致

    Returns:
        解码后的字节数据
    """
    # 处理URL安全的Base64
    data = data.replace('-', '+').replace('_', '/')

    # 补齐padding
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding

    return base64.b64decode(data)


def base64_decode_str(data: str, encoding: str = 'utf-8') -> str:
    """
    Base64解码为字符串

    Args:
        data: Base64编码的字符串
        encoding: 输出字符串编码

    Returns:
        解码后的字符串
    """
    return base64_decode(data).decode(encoding)


def base64_url_encode(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    URL安全的Base64编码

    使用 - 和 _ 替代 + 和 /，移除 = 填充

    Args:
        data: 要编码的数据
        encoding: 字符串编码方式

    Returns:
        URL安全的Base64字符串
    """
    data_bytes = _ensure_bytes(data, encoding)
    encoded = base64.urlsafe_b64encode(data_bytes).decode('ascii')
    return encoded.rstrip('=')


def base64_url_decode(data: str) -> bytes:
    """
    URL安全的Base64解码

    Args:
        data: URL安全的Base64字符串

    Returns:
        解码后的字节数据
    """
    # 补齐padding
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding

    return base64.urlsafe_b64decode(data)


# ==================== 十六进制编码 ====================

def hex_encode(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    十六进制编码

    Args:
        data: 要编码的数据
        encoding: 字符串编码方式

    Returns:
        十六进制字符串
    """
    data_bytes = _ensure_bytes(data, encoding)
    return binascii.hexlify(data_bytes).decode('ascii')


def hex_decode(data: str) -> bytes:
    """
    十六进制解码

    Args:
        data: 十六进制字符串

    Returns:
        解码后的字节数据
    """
    # 移除可能的0x前缀
    if data.lower().startswith('0x'):
        data = data[2:]

    # 移除空格
    data = data.replace(' ', '').replace('\n', '')

    return binascii.unhexlify(data)


def hex_decode_str(data: str, encoding: str = 'utf-8') -> str:
    """
    十六进制解码为字符串

    Args:
        data: 十六进制字符串
        encoding: 输出字符串编码

    Returns:
        解码后的字符串
    """
    return hex_decode(data).decode(encoding)


# ==================== URL编码 ====================

def url_encode(data: str, safe: str = '') -> str:
    """
    URL编码

    Args:
        data: 要编码的字符串
        safe: 不进行编码的字符

    Returns:
        URL编码后的字符串
    """
    return quote(data, safe=safe)


def url_decode(data: str) -> str:
    """
    URL解码

    Args:
        data: URL编码的字符串

    Returns:
        解码后的字符串
    """
    return unquote(data)


def url_encode_plus(data: str) -> str:
    """
    URL编码（空格编码为+）

    用于表单数据编码

    Args:
        data: 要编码的字符串

    Returns:
        URL编码后的字符串
    """
    return quote_plus(data)


def url_decode_plus(data: str) -> str:
    """
    URL解码（+解码为空格）

    Args:
        data: URL编码的字符串

    Returns:
        解码后的字符串
    """
    return unquote_plus(data)


def url_encode_all(data: str) -> str:
    """
    URL编码所有字符（包括字母数字）

    Args:
        data: 要编码的字符串

    Returns:
        完全URL编码的字符串
    """
    return ''.join(f'%{ord(c):02X}' for c in data)


def double_url_encode(data: str) -> str:
    """
    双重URL编码

    用于某些WAF绕过场景

    Args:
        data: 要编码的字符串

    Returns:
        双重URL编码的字符串
    """
    return url_encode(url_encode(data))


# ==================== HTML实体编码 ====================

def html_encode(data: str) -> str:
    """
    HTML实体编码

    编码 < > & " ' 等特殊字符

    Args:
        data: 要编码的字符串

    Returns:
        HTML编码后的字符串
    """
    return html.escape(data, quote=True)


def html_decode(data: str) -> str:
    """
    HTML实体解码

    Args:
        data: HTML编码的字符串

    Returns:
        解码后的字符串
    """
    return html.unescape(data)


def html_encode_all(data: str) -> str:
    """
    HTML编码所有字符为数字实体

    Args:
        data: 要编码的字符串

    Returns:
        HTML数字实体编码的字符串
    """
    return ''.join(f'&#{ord(c)};' for c in data)


def html_encode_hex(data: str) -> str:
    """
    HTML编码所有字符为十六进制实体

    Args:
        data: 要编码的字符串

    Returns:
        HTML十六进制实体编码的字符串
    """
    return ''.join(f'&#x{ord(c):x};' for c in data)


# ==================== Unicode编码 ====================

def unicode_encode(data: str) -> str:
    """
    Unicode编码（\\uXXXX格式）

    Args:
        data: 要编码的字符串

    Returns:
        Unicode编码的字符串
    """
    return ''.join(f'\\u{ord(c):04x}' for c in data)


def unicode_decode(data: str) -> str:
    """
    Unicode解码

    支持 \\uXXXX 和 \\UXXXXXXXX 格式

    Args:
        data: Unicode编码的字符串

    Returns:
        解码后的字符串
    """
    return codecs.decode(data, 'unicode_escape')


def unicode_encode_wide(data: str) -> str:
    """
    Unicode宽字符编码（\\u00XX格式）

    主要用于ASCII字符的Unicode表示

    Args:
        data: 要编码的字符串

    Returns:
        Unicode宽字符编码的字符串
    """
    return ''.join(f'\\u00{ord(c):02x}' if ord(c) < 256 else f'\\u{ord(c):04x}' for c in data)


# ==================== 其他编码 ====================

def rot13(data: str) -> str:
    """
    ROT13编码/解码

    ROT13是自反的，编码和解码使用同一函数

    Args:
        data: 要编码/解码的字符串

    Returns:
        ROT13处理后的字符串
    """
    return codecs.encode(data, 'rot_13')


def binary_encode(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    二进制编码

    Args:
        data: 要编码的数据
        encoding: 字符串编码方式

    Returns:
        二进制字符串（空格分隔的8位二进制）
    """
    data_bytes = _ensure_bytes(data, encoding)
    return ' '.join(f'{b:08b}' for b in data_bytes)


def binary_decode(data: str) -> bytes:
    """
    二进制解码

    Args:
        data: 二进制字符串

    Returns:
        解码后的字节数据
    """
    # 移除空格和换行
    data = data.replace(' ', '').replace('\n', '')

    # 按8位分组
    bytes_list = [data[i:i+8] for i in range(0, len(data), 8)]

    return bytes(int(b, 2) for b in bytes_list)


def octal_encode(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    八进制编码

    Args:
        data: 要编码的数据
        encoding: 字符串编码方式

    Returns:
        八进制字符串
    """
    data_bytes = _ensure_bytes(data, encoding)
    return ''.join(f'\\{b:03o}' for b in data_bytes)


def ascii_encode(data: str) -> str:
    """
    ASCII码编码

    Args:
        data: 要编码的字符串

    Returns:
        ASCII码字符串（逗号分隔的十进制）
    """
    return ','.join(str(ord(c)) for c in data)


def ascii_decode(data: str) -> str:
    """
    ASCII码解码

    Args:
        data: ASCII码字符串（逗号或空格分隔）

    Returns:
        解码后的字符串
    """
    # 处理不同分隔符
    if ',' in data:
        codes = data.split(',')
    else:
        codes = data.split()

    return ''.join(chr(int(code.strip())) for code in codes if code.strip())


# ==================== 多重编码 ====================

class MultiEncoder:
    """
    多重编码器

    支持链式编码操作
    """

    def __init__(self, data: Union[str, bytes]):
        """
        初始化编码器

        Args:
            data: 初始数据
        """
        self._data = data

    @property
    def data(self) -> Union[str, bytes]:
        """获取当前数据"""
        return self._data

    def base64(self) -> 'MultiEncoder':
        """Base64编码"""
        self._data = base64_encode(self._data)
        return self

    def url(self) -> 'MultiEncoder':
        """URL编码"""
        self._data = url_encode(_ensure_str(self._data))
        return self

    def hex(self) -> 'MultiEncoder':
        """十六进制编码"""
        self._data = hex_encode(self._data)
        return self

    def html(self) -> 'MultiEncoder':
        """HTML编码"""
        self._data = html_encode(_ensure_str(self._data))
        return self

    def unicode(self) -> 'MultiEncoder':
        """Unicode编码"""
        self._data = unicode_encode(_ensure_str(self._data))
        return self

    def result(self) -> str:
        """获取最终结果"""
        return _ensure_str(self._data)


def multi_encode(data: Union[str, bytes]) -> MultiEncoder:
    """
    创建多重编码器

    使用示例:
        result = multi_encode("test").base64().url().result()

    Args:
        data: 初始数据

    Returns:
        MultiEncoder实例
    """
    return MultiEncoder(data)


__all__ = [
    # Base64
    'base64_encode',
    'base64_decode',
    'base64_decode_str',
    'base64_url_encode',
    'base64_url_decode',
    # Hex
    'hex_encode',
    'hex_decode',
    'hex_decode_str',
    # URL
    'url_encode',
    'url_decode',
    'url_encode_plus',
    'url_decode_plus',
    'url_encode_all',
    'double_url_encode',
    # HTML
    'html_encode',
    'html_decode',
    'html_encode_all',
    'html_encode_hex',
    # Unicode
    'unicode_encode',
    'unicode_decode',
    'unicode_encode_wide',
    # 其他
    'rot13',
    'binary_encode',
    'binary_decode',
    'octal_encode',
    'ascii_encode',
    'ascii_decode',
    # 多重编码
    'MultiEncoder',
    'multi_encode',
]
