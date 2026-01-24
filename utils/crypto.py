#!/usr/bin/env python3
"""
加密工具模块 - AutoRedTeam-Orchestrator

提供常用的加密/哈希功能，包括：
- 哈希计算（MD5, SHA1, SHA256, SHA512等）
- 随机数/字符串生成
- XOR加密
- 简单的对称加密

注意：此模块仅用于安全测试和数据处理，
不适合用于生产环境的加密需求。

使用示例:
    from utils.crypto import md5, sha256, random_string

    # 计算哈希
    hash_value = md5("password")
    hash_value = sha256(b"binary data")

    # 生成随机字符串
    token = random_string(32)
"""

import hashlib
import hmac
import secrets
import string
from typing import Union, Optional


def _ensure_bytes(data: Union[str, bytes], encoding: str = 'utf-8') -> bytes:
    """确保数据为bytes类型"""
    if isinstance(data, str):
        return data.encode(encoding)
    return data


# ==================== 哈希函数 ====================

def md5(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算MD5哈希

    注意：MD5已不安全，仅用于兼容性场景

    Args:
        data: 要哈希的数据
        encoding: 字符串编码方式

    Returns:
        MD5哈希值（32位十六进制字符串）
    """
    data_bytes = _ensure_bytes(data, encoding)
    return hashlib.md5(data_bytes).hexdigest()


def sha1(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算SHA1哈希

    注意：SHA1已不推荐用于安全场景

    Args:
        data: 要哈希的数据
        encoding: 字符串编码方式

    Returns:
        SHA1哈希值（40位十六进制字符串）
    """
    data_bytes = _ensure_bytes(data, encoding)
    return hashlib.sha1(data_bytes).hexdigest()


def sha256(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算SHA256哈希

    Args:
        data: 要哈希的数据
        encoding: 字符串编码方式

    Returns:
        SHA256哈希值（64位十六进制字符串）
    """
    data_bytes = _ensure_bytes(data, encoding)
    return hashlib.sha256(data_bytes).hexdigest()


def sha384(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算SHA384哈希

    Args:
        data: 要哈希的数据
        encoding: 字符串编码方式

    Returns:
        SHA384哈希值（96位十六进制字符串）
    """
    data_bytes = _ensure_bytes(data, encoding)
    return hashlib.sha384(data_bytes).hexdigest()


def sha512(data: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算SHA512哈希

    Args:
        data: 要哈希的数据
        encoding: 字符串编码方式

    Returns:
        SHA512哈希值（128位十六进制字符串）
    """
    data_bytes = _ensure_bytes(data, encoding)
    return hashlib.sha512(data_bytes).hexdigest()


def blake2b(data: Union[str, bytes], digest_size: int = 64, encoding: str = 'utf-8') -> str:
    """
    计算BLAKE2b哈希

    Args:
        data: 要哈希的数据
        digest_size: 输出长度（字节），最大64
        encoding: 字符串编码方式

    Returns:
        BLAKE2b哈希值
    """
    data_bytes = _ensure_bytes(data, encoding)
    return hashlib.blake2b(data_bytes, digest_size=digest_size).hexdigest()


def blake2s(data: Union[str, bytes], digest_size: int = 32, encoding: str = 'utf-8') -> str:
    """
    计算BLAKE2s哈希

    Args:
        data: 要哈希的数据
        digest_size: 输出长度（字节），最大32
        encoding: 字符串编码方式

    Returns:
        BLAKE2s哈希值
    """
    data_bytes = _ensure_bytes(data, encoding)
    return hashlib.blake2s(data_bytes, digest_size=digest_size).hexdigest()


def hash_file(filepath: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
    """
    计算文件哈希

    Args:
        filepath: 文件路径
        algorithm: 哈希算法（md5, sha1, sha256, sha512等）
        chunk_size: 读取块大小

    Returns:
        文件哈希值
    """
    hasher = hashlib.new(algorithm)

    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


# ==================== HMAC函数 ====================

def hmac_md5(data: Union[str, bytes], key: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算HMAC-MD5

    Args:
        data: 要签名的数据
        key: 密钥
        encoding: 字符串编码方式

    Returns:
        HMAC-MD5签名
    """
    data_bytes = _ensure_bytes(data, encoding)
    key_bytes = _ensure_bytes(key, encoding)
    return hmac.new(key_bytes, data_bytes, hashlib.md5).hexdigest()


def hmac_sha1(data: Union[str, bytes], key: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算HMAC-SHA1

    Args:
        data: 要签名的数据
        key: 密钥
        encoding: 字符串编码方式

    Returns:
        HMAC-SHA1签名
    """
    data_bytes = _ensure_bytes(data, encoding)
    key_bytes = _ensure_bytes(key, encoding)
    return hmac.new(key_bytes, data_bytes, hashlib.sha1).hexdigest()


def hmac_sha256(data: Union[str, bytes], key: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算HMAC-SHA256

    Args:
        data: 要签名的数据
        key: 密钥
        encoding: 字符串编码方式

    Returns:
        HMAC-SHA256签名
    """
    data_bytes = _ensure_bytes(data, encoding)
    key_bytes = _ensure_bytes(key, encoding)
    return hmac.new(key_bytes, data_bytes, hashlib.sha256).hexdigest()


def hmac_sha512(data: Union[str, bytes], key: Union[str, bytes], encoding: str = 'utf-8') -> str:
    """
    计算HMAC-SHA512

    Args:
        data: 要签名的数据
        key: 密钥
        encoding: 字符串编码方式

    Returns:
        HMAC-SHA512签名
    """
    data_bytes = _ensure_bytes(data, encoding)
    key_bytes = _ensure_bytes(key, encoding)
    return hmac.new(key_bytes, data_bytes, hashlib.sha512).hexdigest()


def verify_hmac(
    data: Union[str, bytes],
    key: Union[str, bytes],
    signature: str,
    algorithm: str = 'sha256'
) -> bool:
    """
    验证HMAC签名

    使用常数时间比较，防止时序攻击

    Args:
        data: 原始数据
        key: 密钥
        signature: 待验证的签名
        algorithm: 哈希算法

    Returns:
        签名是否有效
    """
    data_bytes = _ensure_bytes(data)
    key_bytes = _ensure_bytes(key)

    expected = hmac.new(key_bytes, data_bytes, algorithm).hexdigest()
    return hmac.compare_digest(expected, signature)


# ==================== 随机数生成 ====================

def random_string(
    length: int = 16,
    charset: Optional[str] = None,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_special: bool = False
) -> str:
    """
    生成随机字符串

    使用密码学安全的随机数生成器

    Args:
        length: 字符串长度
        charset: 自定义字符集（指定后忽略其他选项）
        include_upper: 包含大写字母
        include_lower: 包含小写字母
        include_digits: 包含数字
        include_special: 包含特殊字符

    Returns:
        随机字符串
    """
    if charset:
        chars = charset
    else:
        chars = ''
        if include_upper:
            chars += string.ascii_uppercase
        if include_lower:
            chars += string.ascii_lowercase
        if include_digits:
            chars += string.digits
        if include_special:
            chars += string.punctuation

        if not chars:
            chars = string.ascii_letters + string.digits

    return ''.join(secrets.choice(chars) for _ in range(length))


def random_bytes(length: int = 16) -> bytes:
    """
    生成随机字节

    使用密码学安全的随机数生成器

    Args:
        length: 字节长度

    Returns:
        随机字节
    """
    return secrets.token_bytes(length)


def random_hex(length: int = 32) -> str:
    """
    生成随机十六进制字符串

    Args:
        length: 十六进制字符串长度（字节数的2倍）

    Returns:
        随机十六进制字符串
    """
    byte_length = (length + 1) // 2
    return secrets.token_hex(byte_length)[:length]


def random_int(min_value: int = 0, max_value: int = 2**32 - 1) -> int:
    """
    生成随机整数

    Args:
        min_value: 最小值（包含）
        max_value: 最大值（包含）

    Returns:
        随机整数
    """
    return secrets.randbelow(max_value - min_value + 1) + min_value


def random_uuid() -> str:
    """
    生成随机UUID（版本4）

    Returns:
        UUID字符串
    """
    import uuid
    return str(uuid.uuid4())


def random_token(length: int = 32) -> str:
    """
    生成URL安全的随机令牌

    Args:
        length: 令牌长度

    Returns:
        URL安全的随机令牌
    """
    return secrets.token_urlsafe(length)[:length]


# ==================== XOR加密 ====================

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR加密/解密

    XOR是自反的，加密和解密使用同一函数

    Args:
        data: 要加密的数据
        key: 密钥

    Returns:
        加密/解密后的数据
    """
    key_len = len(key)
    return bytes(d ^ key[i % key_len] for i, d in enumerate(data))


def xor_encrypt_str(data: str, key: str, encoding: str = 'utf-8') -> bytes:
    """
    XOR加密字符串

    Args:
        data: 要加密的字符串
        key: 密钥字符串
        encoding: 字符串编码

    Returns:
        加密后的字节数据
    """
    return xor_encrypt(data.encode(encoding), key.encode(encoding))


def single_byte_xor(data: bytes, key_byte: int) -> bytes:
    """
    单字节XOR

    Args:
        data: 要加密的数据
        key_byte: 密钥字节（0-255）

    Returns:
        加密后的数据
    """
    return bytes(b ^ key_byte for b in data)


def rolling_xor(data: bytes, initial_key: int = 0) -> bytes:
    """
    滚动XOR加密

    每个字节与前一个字节XOR结果进行XOR

    Args:
        data: 要加密的数据
        initial_key: 初始密钥

    Returns:
        加密后的数据
    """
    result = []
    prev = initial_key

    for b in data:
        encrypted = b ^ prev
        result.append(encrypted)
        prev = encrypted

    return bytes(result)


# ==================== 简单加密工具 ====================

def caesar_cipher(text: str, shift: int = 3, decrypt: bool = False) -> str:
    """
    凯撒密码加密/解密

    Args:
        text: 要处理的文本
        shift: 位移量
        decrypt: 是否解密

    Returns:
        处理后的文本
    """
    if decrypt:
        shift = -shift

    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)

    return ''.join(result)


def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
    """
    维吉尼亚密码加密/解密

    Args:
        text: 要处理的文本
        key: 密钥
        decrypt: 是否解密

    Returns:
        处理后的文本
    """
    result = []
    key = key.upper()
    key_idx = 0

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')

            if decrypt:
                shift = -shift

            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)

    return ''.join(result)


# ==================== 密码强度评估 ====================

def password_strength(password: str) -> dict:
    """
    评估密码强度

    Args:
        password: 要评估的密码

    Returns:
        包含强度评分和建议的字典
    """
    score = 0
    feedback = []

    # 长度检查
    length = len(password)
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if length >= 16:
        score += 1

    if length < 8:
        feedback.append("密码太短，建议至少8个字符")

    # 字符类型检查
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    if has_lower:
        score += 1
    else:
        feedback.append("建议包含小写字母")

    if has_upper:
        score += 1
    else:
        feedback.append("建议包含大写字母")

    if has_digit:
        score += 1
    else:
        feedback.append("建议包含数字")

    if has_special:
        score += 2
    else:
        feedback.append("建议包含特殊字符")

    # 常见弱密码检查
    common_passwords = [
        'password', '123456', 'qwerty', 'admin', 'letmein',
        'welcome', 'monkey', 'dragon', 'master', 'login'
    ]
    if password.lower() in common_passwords:
        score = max(0, score - 3)
        feedback.append("这是常见的弱密码")

    # 连续字符检查
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 1)
        feedback.append("避免连续重复字符")

    # 强度等级
    if score <= 2:
        strength = 'weak'
    elif score <= 4:
        strength = 'fair'
    elif score <= 6:
        strength = 'good'
    else:
        strength = 'strong'

    return {
        'score': score,
        'max_score': 9,
        'strength': strength,
        'feedback': feedback
    }


# 导入re模块用于密码强度评估
import re


__all__ = [
    # 哈希
    'md5',
    'sha1',
    'sha256',
    'sha384',
    'sha512',
    'blake2b',
    'blake2s',
    'hash_file',
    # HMAC
    'hmac_md5',
    'hmac_sha1',
    'hmac_sha256',
    'hmac_sha512',
    'verify_hmac',
    # 随机数
    'random_string',
    'random_bytes',
    'random_hex',
    'random_int',
    'random_uuid',
    'random_token',
    # XOR
    'xor_encrypt',
    'xor_encrypt_str',
    'single_byte_xor',
    'rolling_xor',
    # 简单加密
    'caesar_cipher',
    'vigenere_cipher',
    # 工具
    'password_strength',
]
