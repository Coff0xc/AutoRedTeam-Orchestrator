#!/usr/bin/env python3
"""
C2 加密模块 - C2 Crypto Module

提供 C2 通信的加密功能，支持多种加密算法
仅用于授权渗透测试和安全研究

支持的算法:
    - AES-256-GCM (推荐，带认证)
    - AES-256-CBC
    - ChaCha20-Poly1305 (推荐，带认证)
    - XOR (简单，仅用于混淆)
"""

import os
import hashlib
import hmac
import logging
from typing import Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# 尝试导入加密库
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


class CryptoAlgorithm(Enum):
    """加密算法"""
    NONE = 'none'
    XOR = 'xor'
    AES256_CBC = 'aes256_cbc'
    AES256_GCM = 'aes256_gcm'
    CHACHA20 = 'chacha20'
    CHACHA20_POLY1305 = 'chacha20_poly1305'


@dataclass
class CryptoResult:
    """加密结果"""
    ciphertext: bytes
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None     # AEAD 认证标签


class C2Crypto:
    """
    C2 加密类

    提供对称加密功能，支持多种算法

    Usage:
        # 创建加密器
        crypto = C2Crypto(algorithm='aes256_gcm')

        # 加密
        result = crypto.encrypt(b"secret data")
        ciphertext = result.ciphertext

        # 解密
        plaintext = crypto.decrypt(result.ciphertext, iv=result.iv, tag=result.tag)
    """

    # AES 块大小
    AES_BLOCK_SIZE = 16
    # 密钥长度
    KEY_SIZE = 32       # 256 bits
    # IV/Nonce 长度
    IV_SIZE = 16        # AES CBC
    NONCE_SIZE = 12     # GCM/ChaCha20

    def __init__(
        self,
        algorithm: str = 'aes256_gcm',
        key: Optional[bytes] = None,
        derive_key: bool = True
    ):
        """
        初始化加密器

        Args:
            algorithm: 加密算法
            key: 加密密钥（32字节），如果为 None 则自动生成
            derive_key: 是否从密钥派生（用于短密钥/密码）
        """
        self.algorithm = CryptoAlgorithm(algorithm.lower().replace('-', '_'))
        self._derive_key = derive_key

        # 初始化或派生密钥
        if key is None:
            self.key = self._generate_key()
        elif derive_key and len(key) != self.KEY_SIZE:
            self.key = self._derive_key_from_password(key)
        else:
            self.key = key[:self.KEY_SIZE] if len(key) > self.KEY_SIZE else key.ljust(self.KEY_SIZE, b'\x00')

        # 检查加密库可用性
        self._check_crypto_available()

    def _check_crypto_available(self) -> None:
        """检查加密库是否可用"""
        if self.algorithm == CryptoAlgorithm.NONE:
            return

        if self.algorithm == CryptoAlgorithm.XOR:
            return  # XOR 不需要库

        if not HAS_CRYPTOGRAPHY and not HAS_PYCRYPTODOME:
            raise ImportError(
                "需要安装加密库: pip install cryptography 或 pip install pycryptodome"
            )

    def _generate_key(self) -> bytes:
        """生成随机密钥"""
        return os.urandom(self.KEY_SIZE)

    def _derive_key_from_password(self, password: bytes) -> bytes:
        """
        从密码派生密钥（PBKDF2）

        Args:
            password: 密码

        Returns:
            派生的密钥
        """
        # 使用固定盐值（实际应用中应该使用随机盐）
        salt = b'c2_crypto_salt_v1'

        if HAS_CRYPTOGRAPHY:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_SIZE,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            return kdf.derive(password)
        else:
            # 回退到简单 SHA256 派生
            return hashlib.pbkdf2_hmac('sha256', password, salt, 100000, self.KEY_SIZE)

    def _generate_iv(self, size: int = None) -> bytes:
        """生成随机 IV/Nonce"""
        if size is None:
            size = self.NONCE_SIZE if 'gcm' in self.algorithm.value or 'poly1305' in self.algorithm.value else self.IV_SIZE
        return os.urandom(size)

    def encrypt(self, plaintext: bytes) -> CryptoResult:
        """
        加密数据

        Args:
            plaintext: 明文

        Returns:
            CryptoResult 包含密文和必要的元数据
        """
        if self.algorithm == CryptoAlgorithm.NONE:
            return CryptoResult(ciphertext=plaintext)

        if self.algorithm == CryptoAlgorithm.XOR:
            return CryptoResult(ciphertext=self._xor_encrypt(plaintext))

        if self.algorithm == CryptoAlgorithm.AES256_CBC:
            return self._aes_cbc_encrypt(plaintext)

        if self.algorithm == CryptoAlgorithm.AES256_GCM:
            return self._aes_gcm_encrypt(plaintext)

        if self.algorithm in (CryptoAlgorithm.CHACHA20, CryptoAlgorithm.CHACHA20_POLY1305):
            return self._chacha20_encrypt(plaintext)

        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def decrypt(
        self,
        ciphertext: bytes,
        iv: Optional[bytes] = None,
        tag: Optional[bytes] = None
    ) -> bytes:
        """
        解密数据

        Args:
            ciphertext: 密文
            iv: 初始化向量
            tag: AEAD 认证标签

        Returns:
            明文
        """
        if self.algorithm == CryptoAlgorithm.NONE:
            return ciphertext

        if self.algorithm == CryptoAlgorithm.XOR:
            return self._xor_decrypt(ciphertext)

        if self.algorithm == CryptoAlgorithm.AES256_CBC:
            return self._aes_cbc_decrypt(ciphertext, iv)

        if self.algorithm == CryptoAlgorithm.AES256_GCM:
            return self._aes_gcm_decrypt(ciphertext, iv, tag)

        if self.algorithm in (CryptoAlgorithm.CHACHA20, CryptoAlgorithm.CHACHA20_POLY1305):
            return self._chacha20_decrypt(ciphertext, iv, tag)

        raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    # ==================== XOR ====================

    def _xor_encrypt(self, plaintext: bytes) -> bytes:
        """XOR 加密"""
        key_len = len(self.key)
        return bytes([plaintext[i] ^ self.key[i % key_len] for i in range(len(plaintext))])

    def _xor_decrypt(self, ciphertext: bytes) -> bytes:
        """XOR 解密（对称）"""
        return self._xor_encrypt(ciphertext)

    # ==================== AES-CBC ====================

    def _aes_cbc_encrypt(self, plaintext: bytes) -> CryptoResult:
        """AES-256-CBC 加密"""
        iv = self._generate_iv(self.IV_SIZE)

        if HAS_CRYPTOGRAPHY:
            # 使用 cryptography
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()

            # PKCS7 填充
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()

            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        elif HAS_PYCRYPTODOME:
            # 使用 pycryptodome
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_data = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)

        else:
            raise ImportError("No crypto library available")

        return CryptoResult(ciphertext=ciphertext, iv=iv)

    def _aes_cbc_decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """AES-256-CBC 解密"""
        if iv is None:
            raise ValueError("IV required for AES-CBC decryption")

        if HAS_CRYPTOGRAPHY:
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # 去除 PKCS7 填充
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        elif HAS_PYCRYPTODOME:
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)

        else:
            raise ImportError("No crypto library available")

        return plaintext

    # ==================== AES-GCM ====================

    def _aes_gcm_encrypt(self, plaintext: bytes) -> CryptoResult:
        """AES-256-GCM 加密（带认证）"""
        nonce = self._generate_iv(self.NONCE_SIZE)

        if HAS_CRYPTOGRAPHY:
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag

        elif HAS_PYCRYPTODOME:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        else:
            raise ImportError("No crypto library available")

        return CryptoResult(ciphertext=ciphertext, iv=nonce, tag=tag)

    def _aes_gcm_decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """AES-256-GCM 解密"""
        if nonce is None or tag is None:
            raise ValueError("Nonce and tag required for AES-GCM decryption")

        if HAS_CRYPTOGRAPHY:
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        elif HAS_PYCRYPTODOME:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        else:
            raise ImportError("No crypto library available")

        return plaintext

    # ==================== ChaCha20 ====================

    def _chacha20_encrypt(self, plaintext: bytes) -> CryptoResult:
        """ChaCha20-Poly1305 加密"""
        nonce = self._generate_iv(self.NONCE_SIZE)

        if HAS_CRYPTOGRAPHY:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            cipher = ChaCha20Poly1305(self.key)
            # ChaCha20Poly1305 将 tag 附加到密文
            ciphertext_with_tag = cipher.encrypt(nonce, plaintext, None)
            # 提取 tag (最后 16 字节)
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]

        elif HAS_PYCRYPTODOME:
            cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        else:
            raise ImportError("No crypto library available")

        return CryptoResult(ciphertext=ciphertext, iv=nonce, tag=tag)

    def _chacha20_decrypt(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """ChaCha20-Poly1305 解密"""
        if nonce is None or tag is None:
            raise ValueError("Nonce and tag required for ChaCha20 decryption")

        if HAS_CRYPTOGRAPHY:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            cipher = ChaCha20Poly1305(self.key)
            # 重新组合密文和 tag
            ciphertext_with_tag = ciphertext + tag
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, None)

        elif HAS_PYCRYPTODOME:
            cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        else:
            raise ImportError("No crypto library available")

        return plaintext

    # ==================== 实用方法 ====================

    def encrypt_with_header(self, plaintext: bytes) -> bytes:
        """
        加密并添加头部（包含 IV 和 tag）

        格式: [1 byte algo][12 bytes nonce][16 bytes tag][ciphertext]

        Args:
            plaintext: 明文

        Returns:
            带头部的密文
        """
        result = self.encrypt(plaintext)

        # 构建头部
        algo_byte = list(CryptoAlgorithm).index(self.algorithm).to_bytes(1, 'big')

        if self.algorithm == CryptoAlgorithm.NONE:
            return algo_byte + result.ciphertext

        if self.algorithm == CryptoAlgorithm.XOR:
            return algo_byte + result.ciphertext

        # AEAD 算法
        nonce = result.iv or b'\x00' * self.NONCE_SIZE
        tag = result.tag or b'\x00' * 16

        return algo_byte + nonce + tag + result.ciphertext

    def decrypt_with_header(self, data: bytes) -> bytes:
        """
        解密带头部的数据

        Args:
            data: 带头部的密文

        Returns:
            明文
        """
        algo_index = data[0]
        algorithm = list(CryptoAlgorithm)[algo_index]

        if algorithm == CryptoAlgorithm.NONE:
            return data[1:]

        if algorithm == CryptoAlgorithm.XOR:
            return self._xor_decrypt(data[1:])

        # AEAD 算法
        nonce = data[1:13]
        tag = data[13:29]
        ciphertext = data[29:]

        return self.decrypt(ciphertext, iv=nonce, tag=tag)

    @classmethod
    def generate_key_pair(cls) -> Tuple[bytes, bytes]:
        """
        生成密钥对（用于密钥交换）

        Returns:
            (私钥, 公钥) 元组
        """
        if HAS_CRYPTOGRAPHY:
            from cryptography.hazmat.primitives.asymmetric import x25519
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()
            return (
                private_key.private_bytes_raw(),
                public_key.public_bytes_raw()
            )
        else:
            # 回退到简单随机密钥
            private_key = os.urandom(32)
            public_key = hashlib.sha256(private_key).digest()
            return private_key, public_key

    def compute_hmac(self, data: bytes) -> bytes:
        """计算 HMAC"""
        return hmac.new(self.key, data, hashlib.sha256).digest()

    def verify_hmac(self, data: bytes, expected_hmac: bytes) -> bool:
        """验证 HMAC"""
        computed = self.compute_hmac(data)
        return hmac.compare_digest(computed, expected_hmac)


# ==================== 便捷函数 ====================

def create_crypto(
    algorithm: str = 'aes256_gcm',
    key: Optional[bytes] = None,
    password: Optional[str] = None
) -> C2Crypto:
    """
    创建加密器

    Args:
        algorithm: 加密算法
        key: 密钥（32字节）
        password: 密码（将派生为密钥）

    Returns:
        C2Crypto 实例
    """
    if password:
        key = password.encode()
        return C2Crypto(algorithm, key, derive_key=True)

    return C2Crypto(algorithm, key, derive_key=False)


def quick_encrypt(plaintext: bytes, key: bytes, algorithm: str = 'aes256_gcm') -> bytes:
    """快速加密"""
    crypto = C2Crypto(algorithm, key)
    return crypto.encrypt_with_header(plaintext)


def quick_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """快速解密"""
    # 从头部获取算法
    algo_index = ciphertext[0]
    algorithm = list(CryptoAlgorithm)[algo_index]
    crypto = C2Crypto(algorithm.value, key)
    return crypto.decrypt_with_header(ciphertext)


__all__ = [
    'CryptoAlgorithm',
    'CryptoResult',
    'C2Crypto',
    'create_crypto',
    'quick_encrypt',
    'quick_decrypt',
    'HAS_CRYPTOGRAPHY',
    'HAS_PYCRYPTODOME',
]
