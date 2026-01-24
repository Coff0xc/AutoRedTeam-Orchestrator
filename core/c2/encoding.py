#!/usr/bin/env python3
"""
C2 编码模块 - C2 Encoding Module

提供 C2 通信的数据编码功能
仅用于授权渗透测试和安全研究

支持的编码:
    - Base64 (标准/URL安全)
    - Base32 (DNS 安全)
    - Hex
    - XOR
    - 自定义字符表
"""

import base64
import zlib
import json
import struct
import logging
from typing import Optional, Union, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class EncodingType(Enum):
    """编码类型"""
    NONE = 'none'
    BASE64 = 'base64'
    BASE64_URL = 'base64_url'
    BASE32 = 'base32'
    HEX = 'hex'
    XOR = 'xor'
    CUSTOM = 'custom'


@dataclass
class EncodedData:
    """编码后的数据"""
    data: Union[bytes, str]
    encoding: EncodingType
    compressed: bool = False
    checksum: Optional[bytes] = None


class C2Encoder:
    """
    C2 编码器

    提供多种编码方式，用于数据传输和隐蔽

    Usage:
        encoder = C2Encoder()

        # 编码
        encoded = encoder.encode(b"secret data", encoding='base64')

        # 解码
        decoded = encoder.decode(encoded)

        # 带压缩
        encoded = encoder.encode(large_data, compress=True)
    """

    # 自定义 Base64 字符表 (用于绕过检测)
    CUSTOM_B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    STANDARD_B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    def __init__(self, xor_key: Optional[bytes] = None):
        """
        初始化编码器

        Args:
            xor_key: XOR 编码密钥
        """
        self.xor_key = xor_key or b'c2_encoder_key'

    def encode(
        self,
        data: Union[bytes, str],
        encoding: str = 'base64',
        compress: bool = False,
        add_checksum: bool = False
    ) -> EncodedData:
        """
        编码数据

        Args:
            data: 要编码的数据
            encoding: 编码类型
            compress: 是否压缩
            add_checksum: 是否添加校验和

        Returns:
            EncodedData 对象
        """
        # 转换为 bytes
        if isinstance(data, str):
            data = data.encode('utf-8')

        # 压缩
        if compress:
            data = zlib.compress(data, level=9)

        # 计算校验和
        checksum = None
        if add_checksum:
            checksum = self._calculate_checksum(data)

        # 编码
        encoding_type = EncodingType(encoding.lower())
        encoded = self._encode(data, encoding_type)

        return EncodedData(
            data=encoded,
            encoding=encoding_type,
            compressed=compress,
            checksum=checksum
        )

    def decode(
        self,
        data: Union[bytes, str, EncodedData],
        encoding: Optional[str] = None,
        decompress: bool = False,
        verify_checksum: Optional[bytes] = None
    ) -> bytes:
        """
        解码数据

        Args:
            data: 编码后的数据
            encoding: 编码类型（如果 data 是 EncodedData 则自动检测）
            decompress: 是否解压
            verify_checksum: 校验和验证

        Returns:
            解码后的数据
        """
        # 处理 EncodedData
        if isinstance(data, EncodedData):
            encoding = data.encoding.value
            decompress = data.compressed
            verify_checksum = data.checksum
            data = data.data

        # 转换为 bytes
        if isinstance(data, str):
            data = data.encode('utf-8')

        # 解码
        encoding_type = EncodingType(encoding.lower()) if encoding else EncodingType.BASE64
        decoded = self._decode(data, encoding_type)

        # 验证校验和
        if verify_checksum:
            calculated = self._calculate_checksum(decoded)
            if calculated != verify_checksum:
                raise ValueError("Checksum verification failed")

        # 解压
        if decompress:
            decoded = zlib.decompress(decoded)

        return decoded

    def _encode(self, data: bytes, encoding: EncodingType) -> Union[bytes, str]:
        """内部编码方法"""
        if encoding == EncodingType.NONE:
            return data

        if encoding == EncodingType.BASE64:
            return base64.b64encode(data).decode('ascii')

        if encoding == EncodingType.BASE64_URL:
            return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

        if encoding == EncodingType.BASE32:
            return base64.b32encode(data).decode('ascii').lower().rstrip('=')

        if encoding == EncodingType.HEX:
            return data.hex()

        if encoding == EncodingType.XOR:
            return self._xor_encode(data)

        if encoding == EncodingType.CUSTOM:
            return self._custom_encode(data)

        raise ValueError(f"Unknown encoding: {encoding}")

    def _decode(self, data: Union[bytes, str], encoding: EncodingType) -> bytes:
        """内部解码方法"""
        if isinstance(data, bytes):
            data_str = data.decode('ascii')
        else:
            data_str = data

        if encoding == EncodingType.NONE:
            return data if isinstance(data, bytes) else data.encode('utf-8')

        if encoding == EncodingType.BASE64:
            return base64.b64decode(data_str)

        if encoding == EncodingType.BASE64_URL:
            # 添加填充
            padding = 4 - (len(data_str) % 4)
            if padding != 4:
                data_str += '=' * padding
            return base64.urlsafe_b64decode(data_str)

        if encoding == EncodingType.BASE32:
            # 添加填充
            data_str = data_str.upper()
            padding = 8 - (len(data_str) % 8)
            if padding != 8:
                data_str += '=' * padding
            return base64.b32decode(data_str)

        if encoding == EncodingType.HEX:
            return bytes.fromhex(data_str)

        if encoding == EncodingType.XOR:
            return self._xor_decode(data if isinstance(data, bytes) else data.encode('latin-1'))

        if encoding == EncodingType.CUSTOM:
            return self._custom_decode(data_str)

        raise ValueError(f"Unknown encoding: {encoding}")

    def _xor_encode(self, data: bytes) -> bytes:
        """XOR 编码"""
        key_len = len(self.xor_key)
        return bytes([data[i] ^ self.xor_key[i % key_len] for i in range(len(data))])

    def _xor_decode(self, data: bytes) -> bytes:
        """XOR 解码（对称）"""
        return self._xor_encode(data)

    def _custom_encode(self, data: bytes) -> str:
        """自定义字符表 Base64 编码"""
        standard = base64.b64encode(data).decode('ascii')
        # 替换字符
        table = str.maketrans(self.STANDARD_B64_CHARS + '+/', self.CUSTOM_B64_CHARS)
        return standard.translate(table)

    def _custom_decode(self, data: str) -> bytes:
        """自定义字符表 Base64 解码"""
        # 恢复标准字符
        table = str.maketrans(self.CUSTOM_B64_CHARS, self.STANDARD_B64_CHARS + '+/')
        standard = data.translate(table)
        return base64.b64decode(standard)

    def _calculate_checksum(self, data: bytes) -> bytes:
        """计算 CRC32 校验和"""
        checksum = zlib.crc32(data) & 0xffffffff
        return struct.pack('>I', checksum)

    # ==================== 便捷方法 ====================

    def base64_encode(self, data: Union[bytes, str]) -> str:
        """Base64 编码"""
        result = self.encode(data, 'base64')
        return result.data if isinstance(result.data, str) else result.data.decode()

    def base64_decode(self, data: str) -> bytes:
        """Base64 解码"""
        return self.decode(data, 'base64')

    def base32_encode(self, data: Union[bytes, str]) -> str:
        """Base32 编码（DNS 安全）"""
        result = self.encode(data, 'base32')
        return result.data if isinstance(result.data, str) else result.data.decode()

    def base32_decode(self, data: str) -> bytes:
        """Base32 解码"""
        return self.decode(data, 'base32')

    def hex_encode(self, data: Union[bytes, str]) -> str:
        """Hex 编码"""
        result = self.encode(data, 'hex')
        return result.data if isinstance(result.data, str) else result.data.decode()

    def hex_decode(self, data: str) -> bytes:
        """Hex 解码"""
        return self.decode(data, 'hex')

    def url_safe_encode(self, data: Union[bytes, str]) -> str:
        """URL 安全编码"""
        result = self.encode(data, 'base64_url')
        return result.data if isinstance(result.data, str) else result.data.decode()

    def url_safe_decode(self, data: str) -> bytes:
        """URL 安全解码"""
        return self.decode(data, 'base64_url')


class ChunkEncoder:
    """
    分块编码器

    用于将大数据分块编码，适合 DNS 隧道等有大小限制的场景
    """

    def __init__(self, chunk_size: int = 63):
        """
        初始化分块编码器

        Args:
            chunk_size: 每个块的最大大小
        """
        self.chunk_size = chunk_size
        self.encoder = C2Encoder()

    def encode_chunks(self, data: Union[bytes, str], encoding: str = 'base32') -> List[str]:
        """
        分块编码

        Args:
            data: 要编码的数据
            encoding: 编码类型

        Returns:
            编码后的块列表
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        # 编码整体数据
        encoded = self.encoder.encode(data, encoding)
        encoded_str = encoded.data if isinstance(encoded.data, str) else encoded.data.decode()

        # 分块
        chunks = []
        for i in range(0, len(encoded_str), self.chunk_size):
            chunks.append(encoded_str[i:i + self.chunk_size])

        return chunks

    def decode_chunks(self, chunks: List[str], encoding: str = 'base32') -> bytes:
        """
        合并并解码分块

        Args:
            chunks: 编码后的块列表
            encoding: 编码类型

        Returns:
            解码后的数据
        """
        # 合并所有块
        combined = ''.join(chunks)

        # 解码
        return self.encoder.decode(combined, encoding)


class JSONEncoder:
    """
    JSON 编码器

    用于序列化和反序列化复杂数据结构
    """

    def __init__(self, encoder: Optional[C2Encoder] = None):
        """
        初始化 JSON 编码器

        Args:
            encoder: C2Encoder 实例
        """
        self.encoder = encoder or C2Encoder()

    def encode(
        self,
        data: Dict[str, Any],
        encoding: str = 'base64',
        compress: bool = False
    ) -> str:
        """
        编码 JSON 数据

        Args:
            data: 要编码的字典
            encoding: 编码类型
            compress: 是否压缩

        Returns:
            编码后的字符串
        """
        json_str = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        result = self.encoder.encode(json_str, encoding, compress=compress)
        return result.data if isinstance(result.data, str) else result.data.decode()

    def decode(
        self,
        data: str,
        encoding: str = 'base64',
        decompress: bool = False
    ) -> Dict[str, Any]:
        """
        解码 JSON 数据

        Args:
            data: 编码后的字符串
            encoding: 编码类型
            decompress: 是否解压

        Returns:
            解码后的字典
        """
        decoded = self.encoder.decode(data, encoding, decompress=decompress)
        return json.loads(decoded.decode('utf-8'))


# ==================== 流量混淆 ====================

class TrafficObfuscator:
    """
    流量混淆器

    用于混淆 C2 流量，使其看起来像正常流量
    """

    def __init__(self):
        self.encoder = C2Encoder()

    def as_image_data(self, data: bytes) -> bytes:
        """
        将数据伪装成图片数据

        添加 PNG 文件头
        """
        png_header = bytes([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG 签名
            0x00, 0x00, 0x00, 0x0D,  # IHDR 长度
            0x49, 0x48, 0x44, 0x52,  # "IHDR"
        ])
        # 添加长度标记
        length = len(data)
        length_bytes = struct.pack('>I', length)

        return png_header + length_bytes + data

    def from_image_data(self, data: bytes) -> bytes:
        """从伪装的图片数据中提取原始数据"""
        # 跳过 PNG 头部 (8 + 4 + 4 = 16 bytes)
        length_bytes = data[16:20]
        length = struct.unpack('>I', length_bytes)[0]
        return data[20:20 + length]

    def as_html_comment(self, data: bytes) -> str:
        """
        将数据隐藏在 HTML 注释中
        """
        encoded = self.encoder.base64_encode(data)
        return f'<!-- {encoded} -->'

    def from_html_comment(self, html: str) -> bytes:
        """从 HTML 注释中提取数据"""
        import re
        match = re.search(r'<!--\s*([A-Za-z0-9+/=]+)\s*-->', html)
        if match:
            return self.encoder.base64_decode(match.group(1))
        raise ValueError("No encoded data found in HTML comment")

    def as_cookie_value(self, data: bytes, name: str = 'session') -> str:
        """
        将数据编码为 Cookie 值
        """
        encoded = self.encoder.url_safe_encode(data)
        return f'{name}={encoded}'

    def as_header_value(self, data: bytes) -> str:
        """
        将数据编码为 HTTP 头部值
        """
        return self.encoder.base64_encode(data)

    def split_into_params(self, data: bytes, max_len: int = 100) -> Dict[str, str]:
        """
        将数据分割成多个 URL 参数
        """
        encoded = self.encoder.url_safe_encode(data)
        params = {}
        chunk_index = 0

        for i in range(0, len(encoded), max_len):
            chunk = encoded[i:i + max_len]
            params[f'p{chunk_index}'] = chunk
            chunk_index += 1

        # 添加块数量
        params['n'] = str(chunk_index)
        return params

    def merge_from_params(self, params: Dict[str, str]) -> bytes:
        """
        从 URL 参数中合并数据
        """
        count = int(params.get('n', 0))
        chunks = []
        for i in range(count):
            chunk = params.get(f'p{i}', '')
            chunks.append(chunk)

        combined = ''.join(chunks)
        return self.encoder.url_safe_decode(combined)


# ==================== 便捷函数 ====================

def base64_encode(data: Union[bytes, str]) -> str:
    """快速 Base64 编码"""
    return C2Encoder().base64_encode(data)


def base64_decode(data: str) -> bytes:
    """快速 Base64 解码"""
    return C2Encoder().base64_decode(data)


def base32_encode(data: Union[bytes, str]) -> str:
    """快速 Base32 编码"""
    return C2Encoder().base32_encode(data)


def base32_decode(data: str) -> bytes:
    """快速 Base32 解码"""
    return C2Encoder().base32_decode(data)


def url_safe_encode(data: Union[bytes, str]) -> str:
    """快速 URL 安全编码"""
    return C2Encoder().url_safe_encode(data)


def url_safe_decode(data: str) -> bytes:
    """快速 URL 安全解码"""
    return C2Encoder().url_safe_decode(data)


__all__ = [
    'EncodingType',
    'EncodedData',
    'C2Encoder',
    'ChunkEncoder',
    'JSONEncoder',
    'TrafficObfuscator',
    'base64_encode',
    'base64_decode',
    'base32_encode',
    'base32_decode',
    'url_safe_encode',
    'url_safe_decode',
]
