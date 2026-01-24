"""
凭证安全存储 - 轻量级凭证加密存储

解决明文密码传递问题，提供简单的凭证加密/解密接口
与 secrets_manager.py 配合使用

使用示例:
    from core.security.credential_vault import CredentialVault

    vault = CredentialVault()

    # 存储凭证
    encrypted = vault.store("db_password", "my_secret_password")

    # 检索凭证
    password = vault.retrieve("db_password", encrypted)
"""

import os
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class CredentialVault:
    """凭证安全存储

    提供简单的凭证加密/解密功能，支持：
    - 使用 Fernet 对称加密（如果有密钥）
    - 回退到 Base64 编码（无密钥时）
    """

    ENV_KEY_NAME = "ART_ENCRYPTION_KEY"

    def __init__(self, key: Optional[bytes] = None):
        """初始化凭证存储

        Args:
            key: 加密密钥（Fernet 格式），如果不提供则从环境变量读取
        """
        self._key = key or self._get_key_from_env()
        self._cipher = None

        if self._key:
            try:
                from cryptography.fernet import Fernet
                self._cipher = Fernet(self._key)
                logger.debug("凭证存储使用 Fernet 加密")
            except Exception as e:
                logger.warning(f"Fernet 初始化失败，回退到 Base64: {e}")
                self._cipher = None

    def _get_key_from_env(self) -> Optional[bytes]:
        """从环境变量获取密钥"""
        key_str = os.getenv(self.ENV_KEY_NAME)
        if key_str:
            return key_str.encode() if isinstance(key_str, str) else key_str
        return None

    def store(self, name: str, credential: str) -> str:
        """加密存储凭证

        Args:
            name: 凭证名称（用于日志）
            credential: 明文凭证

        Returns:
            加密后的凭证字符串
        """
        if self._cipher:
            encrypted = self._cipher.encrypt(credential.encode()).decode()
            logger.debug(f"凭证 '{name}' 已加密存储")
            return encrypted

        # 回退到 Base64（不安全，仅用于开发环境）
        encoded = base64.b64encode(credential.encode()).decode()
        logger.warning(f"凭证 '{name}' 使用 Base64 编码（建议设置 {self.ENV_KEY_NAME}）")
        return encoded

    def retrieve(self, name: str, encrypted: str) -> str:
        """解密获取凭证

        Args:
            name: 凭证名称（用于日志）
            encrypted: 加密的凭证字符串

        Returns:
            明文凭证
        """
        if self._cipher:
            try:
                decrypted = self._cipher.decrypt(encrypted.encode()).decode()
                logger.debug(f"凭证 '{name}' 已解密")
                return decrypted
            except Exception as e:
                logger.error(f"凭证 '{name}' 解密失败: {e}")
                raise ValueError(f"凭证解密失败: {name}")

        # 回退到 Base64 解码
        return base64.b64decode(encrypted.encode()).decode()

    @staticmethod
    def generate_key() -> bytes:
        """生成新的加密密钥

        Returns:
            Fernet 格式的密钥
        """
        from cryptography.fernet import Fernet
        return Fernet.generate_key()

    @property
    def is_secure(self) -> bool:
        """检查是否使用安全加密"""
        return self._cipher is not None


# 全局实例
_vault: Optional[CredentialVault] = None


def get_vault() -> CredentialVault:
    """获取全局凭证存储实例"""
    global _vault
    if _vault is None:
        _vault = CredentialVault()
    return _vault
