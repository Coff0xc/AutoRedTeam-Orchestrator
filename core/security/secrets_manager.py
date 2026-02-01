#!/usr/bin/env python3
"""
敏感信息管理器 - 配置加密、密钥管理、环境变量
防止硬编码敏感信息泄露
"""

import base64
import binascii
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Dict, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class SecretsManager:
    """敏感信息管理器"""

    def __init__(self, master_key: str = None, storage_path: str = None):
        """
        初始化敏感信息管理器

        Args:
            master_key: 主密钥（从环境变量或密钥文件读取）
            storage_path: 存储路径
        """
        self.storage_path = storage_path or "data/secrets"
        Path(self.storage_path).mkdir(parents=True, exist_ok=True)

        # 获取或生成主密钥
        self.master_key = master_key or self._get_master_key()
        self.cipher = self._create_cipher(self.master_key)

        self.secrets: Dict[str, str] = {}
        self._load_secrets()

        logger.info("敏感信息管理器初始化完成")

    def _get_master_key(self) -> str:
        """
        获取主密钥
        优先级: 环境变量 > 密钥文件 > 生成新密钥
        """
        # 1. 从环境变量读取
        env_key = os.getenv("REDTEAM_MASTER_KEY")
        if env_key:
            logger.info("从环境变量加载主密钥")
            return env_key

        # 2. 从密钥文件读取
        key_file = Path(self.storage_path) / ".master_key"
        if key_file.exists():
            try:
                with open(key_file, "r", encoding="utf-8") as f:
                    key = f.read().strip()
                logger.info("从密钥文件加载主密钥")
                return key
            except Exception as e:
                logger.error(f"读取密钥文件失败: {e}")

        # 3. 生成新密钥
        logger.warning("生成新的主密钥")
        new_key = Fernet.generate_key().decode()

        # 保存到文件
        try:
            with open(key_file, "w", encoding="utf-8") as f:
                f.write(new_key)
            # 设置文件权限（仅所有者可读写）
            if os.name != "nt":  # Unix-like系统
                os.chmod(key_file, 0o600)
            logger.info(f"主密钥已保存到: {key_file}")
        except Exception as e:
            logger.error(f"保存密钥文件失败: {e}")

        return new_key

    def _create_cipher(self, master_key: str) -> Fernet:
        """创建加密器"""
        try:
            # 如果是Fernet格式的密钥，直接使用
            return Fernet(master_key.encode())
        except (ValueError, binascii.Error, TypeError):
            # 否则使用PBKDF2派生密钥，使用随机盐值
            salt = self._get_or_create_salt()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
            return Fernet(key)

    def _get_or_create_salt(self) -> bytes:
        """
        获取或创建KDF盐值

        盐值存储在文件中，首次运行时随机生成
        """
        salt_file = Path(self.storage_path) / ".kdf_salt"

        if salt_file.exists():
            try:
                with open(salt_file, "rb") as f:
                    salt = f.read()
                if len(salt) == 16:  # 有效的盐值
                    return salt
            except Exception as e:
                logger.warning(f"读取盐值文件失败: {e}")

        # 生成新的随机盐值
        salt = secrets.token_bytes(16)

        # 保存到文件
        try:
            with open(salt_file, "wb") as f:
                f.write(salt)
            # 设置文件权限（仅所有者可读写）
            if os.name != "nt":
                os.chmod(salt_file, 0o600)
            else:
                # Windows: 尝试设置权限
                try:
                    import stat

                    os.chmod(salt_file, stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
            logger.info(f"KDF盐值已保存到: {salt_file}")
        except Exception as e:
            logger.error(f"保存盐值文件失败: {e}")

        return salt

    def set_secret(self, key: str, value: str):
        """
        设置敏感信息

        Args:
            key: 密钥名称
            value: 密钥值
        """
        self.secrets[key] = value
        self._save_secrets()
        logger.info(f"设置敏感信息: {key}")

    def get_secret(self, key: str, default: str = None) -> Optional[str]:
        """
        获取敏感信息

        Args:
            key: 密钥名称
            default: 默认值

        Returns:
            密钥值
        """
        # 优先从环境变量读取
        env_value = os.getenv(key)
        if env_value:
            return env_value

        # 从存储中读取
        return self.secrets.get(key, default)

    def delete_secret(self, key: str):
        """删除敏感信息"""
        if key in self.secrets:
            del self.secrets[key]
            self._save_secrets()
            logger.info(f"删除敏感信息: {key}")

    def list_secrets(self) -> list:
        """列出所有密钥名称（不包含值）"""
        return list(self.secrets.keys())

    def rotate_master_key(self, new_master_key: str):
        """
        轮换主密钥

        Args:
            new_master_key: 新的主密钥
        """
        # 使用旧密钥解密所有数据
        old_secrets = self.secrets.copy()

        # 更新密钥和加密器
        self.master_key = new_master_key
        self.cipher = self._create_cipher(new_master_key)

        # 使用新密钥重新加密
        self.secrets = old_secrets
        self._save_secrets()

        # 更新密钥文件
        key_file = Path(self.storage_path) / ".master_key"
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(new_master_key)

        logger.info("主密钥已轮换")

    def _load_secrets(self):
        """加载加密的敏感信息"""
        secrets_file = Path(self.storage_path) / "secrets.enc"
        if not secrets_file.exists():
            return

        try:
            with open(secrets_file, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = self.cipher.decrypt(encrypted_data)
            self.secrets = json.loads(decrypted_data.decode())

            logger.info(f"加载了 {len(self.secrets)} 个敏感信息")

        except Exception as e:
            logger.error(f"加载敏感信息失败: {e}")

    def _save_secrets(self):
        """保存加密的敏感信息"""
        secrets_file = Path(self.storage_path) / "secrets.enc"

        try:
            data = json.dumps(self.secrets, ensure_ascii=False)
            encrypted_data = self.cipher.encrypt(data.encode())

            with open(secrets_file, "wb") as f:
                f.write(encrypted_data)

            # 设置文件权限
            if os.name != "nt":
                os.chmod(secrets_file, 0o600)

        except Exception as e:
            logger.error(f"保存敏感信息失败: {e}")


class ConfigEncryptor:
    """配置文件加密器"""

    @staticmethod
    def encrypt_config(config_path: str, output_path: str, master_key: str):
        """
        加密配置文件

        Args:
            config_path: 原始配置文件路径
            output_path: 加密后的输出路径
            master_key: 主密钥
        """
        cipher = Fernet(master_key.encode())

        with open(config_path, "rb") as f:
            data = f.read()

        encrypted = cipher.encrypt(data)

        with open(output_path, "wb") as f:
            f.write(encrypted)

        logger.info(f"配置文件已加密: {output_path}")

    @staticmethod
    def decrypt_config(encrypted_path: str, output_path: str, master_key: str):
        """
        解密配置文件

        Args:
            encrypted_path: 加密的配置文件路径
            output_path: 解密后的输出路径
            master_key: 主密钥
        """
        cipher = Fernet(master_key.encode())

        with open(encrypted_path, "rb") as f:
            encrypted = f.read()

        decrypted = cipher.decrypt(encrypted)

        with open(output_path, "wb") as f:
            f.write(decrypted)

        logger.info(f"配置文件已解密: {output_path}")


class EnvironmentManager:
    """环境变量管理器"""

    # 敏感信息的环境变量名称
    SENSITIVE_VARS = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "VT_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "NVD_API_KEY",
        "GITHUB_TOKEN",
        "REDTEAM_MASTER_KEY",
        "AUTOREDTEAM_API_KEY",
        "DATABASE_PASSWORD",
        "JWT_SECRET",
    ]

    @staticmethod
    def load_env_file(env_file: str = ".env"):
        """
        加载.env文件

        Args:
            env_file: .env文件路径
        """
        env_path = Path(env_file)
        if not env_path.exists():
            logger.warning(f".env文件不存在: {env_file}")
            return

        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        os.environ[key] = value

            logger.info(f"已加载环境变量: {env_file}")

        except Exception as e:
            logger.error(f"加载.env文件失败: {e}")

    @staticmethod
    def check_sensitive_vars() -> Dict[str, bool]:
        """
        检查敏感环境变量是否设置

        Returns:
            变量名到是否设置的映射
        """
        return {var: os.getenv(var) is not None for var in EnvironmentManager.SENSITIVE_VARS}

    @staticmethod
    def mask_value(value: str, show_chars: int = 4) -> str:
        """
        遮蔽敏感值

        Args:
            value: 原始值
            show_chars: 显示的字符数

        Returns:
            遮蔽后的值
        """
        if not value or len(value) <= show_chars:
            return "***"

        return value[:show_chars] + "*" * (len(value) - show_chars)


# 全局实例
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """获取全局敏感信息管理器"""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# 便捷函数
def get_secret(key: str, default: str = None) -> Optional[str]:
    """获取敏感信息"""
    return get_secrets_manager().get_secret(key, default)


def set_secret(key: str, value: str):
    """设置敏感信息"""
    get_secrets_manager().set_secret(key, value)
