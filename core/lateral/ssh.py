#!/usr/bin/env python3
"""
SSH 横向移动模块 - SSH Lateral Movement
功能: SSH 命令执行、端口转发、SOCKS 代理、密钥认证

用于授权安全测试，仅限合法渗透测试使用
"""

import io
import logging
import os
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .base import (
    AuthMethod,
    BaseLateralModule,
    Credentials,
    ExecutionMethod,
    ExecutionResult,
    FileTransferResult,
    LateralConfig,
    LateralStatus,
)

logger = logging.getLogger(__name__)

# 尝试导入 paramiko
try:
    import paramiko
    from paramiko import (
        AuthenticationException,
        Channel,
        DSSKey,
        ECDSAKey,
        Ed25519Key,
        RSAKey,
        SFTPClient,
        SSHClient,
        SSHException,
        Transport,
    )

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    logger.debug("paramiko 未安装，SSH 功能受限")


@dataclass
class TunnelConfig:
    """SSH 隧道配置"""

    local_port: int
    remote_host: str
    remote_port: int
    bind_address: str = "127.0.0.1"
    tunnel_type: str = "local"  # local, remote, dynamic


@dataclass
class TunnelInfo:
    """隧道信息"""

    tunnel_type: str
    local_bind: str
    remote_target: str
    is_active: bool = True
    thread: Optional[threading.Thread] = None


class SSHLateral(BaseLateralModule):
    """
    SSH 横向移动模块

    支持:
    - 密码认证
    - 私钥认证
    - SSH Agent
    - 命令执行
    - SFTP 文件传输
    - 端口转发 (Local/Remote/Dynamic)
    - SOCKS 代理

    Usage:
        creds = Credentials(
            username='root',
            password='password123'
        )

        with SSHLateral('192.168.1.100', creds) as ssh:
            # 执行命令
            result = ssh.execute('whoami')
            print(result.output)

            # 上传文件
            ssh.upload('/local/script.sh', '/tmp/script.sh')

            # 创建隧道
            tunnel = ssh.create_tunnel(
                TunnelConfig(local_port=8080, remote_host='10.0.0.1', remote_port=80)
            )
    """

    name = "ssh"
    description = "SSH 横向移动，支持密钥认证和端口转发"
    default_port = 22
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.KEY, AuthMethod.AGENT]
    supports_file_transfer = True  # 支持 SFTP 文件传输

    def __init__(
        self, target: str, credentials: Credentials, config: Optional[LateralConfig] = None
    ):
        super().__init__(target, credentials, config)
        self._client: Optional["SSHClient"] = None
        self._transport: Optional["Transport"] = None
        self._sftp: Optional["SFTPClient"] = None
        self._tunnels: List[TunnelInfo] = []
        self._tunnels_lock = threading.Lock()  # 保护 _tunnels 列表

    @property
    def port(self) -> int:
        """获取 SSH 端口"""
        return self.config.port or self.config.ssh_port or self.default_port

    def connect(self) -> bool:
        """建立 SSH 连接"""
        if not HAS_PARAMIKO:
            self.logger.error("paramiko 未安装，无法建立 SSH 连接")
            self._set_status(LateralStatus.FAILED)
            return False

        self._set_status(LateralStatus.CONNECTING)

        try:
            self._client = paramiko.SSHClient()

            # 根据配置设置主机密钥策略
            host_key_policy = self.config.ssh_host_key_policy
            if host_key_policy == "reject":
                # 严格模式：仅接受已知主机
                self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
            elif host_key_policy == "warning":
                # 警告模式：接受但记录警告
                self._client.set_missing_host_key_policy(paramiko.WarningPolicy())
            else:
                # 自动模式：自动接受（不推荐，仅用于测试环境）
                self.logger.warning(
                    "SSH 使用 AutoAddPolicy，存在中间人攻击风险。"
                    "生产环境请设置 ssh_host_key_policy='reject' 或 'warning'"
                )
                self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # 加载已知主机文件
            if self.config.ssh_known_hosts_file:
                try:
                    self._client.load_host_keys(self.config.ssh_known_hosts_file)
                except FileNotFoundError:
                    self.logger.warning(f"已知主机文件不存在: {self.config.ssh_known_hosts_file}")
            else:
                # 尝试加载系统默认的 known_hosts
                try:
                    self._client.load_system_host_keys()
                except (IOError, OSError):
                    pass  # 忽略加载失败（文件不存在或权限问题）

            connect_kwargs = {
                "hostname": self.target,
                "port": self.port,
                "username": self.credentials.username,
                "timeout": self.config.ssh_timeout,
                "banner_timeout": self.config.ssh_banner_timeout,
                "auth_timeout": self.config.ssh_auth_timeout,
                "allow_agent": self.config.ssh_allow_agent,
                "look_for_keys": self.config.ssh_look_for_keys,
            }

            # 根据认证方式设置参数
            if self.credentials.method == AuthMethod.KEY:
                key = self._load_private_key()
                if key:
                    connect_kwargs["pkey"] = key
                elif self.credentials.ssh_key:
                    connect_kwargs["key_filename"] = self.credentials.ssh_key
                    if self.credentials.ssh_passphrase:
                        connect_kwargs["passphrase"] = self.credentials.ssh_passphrase
            elif self.credentials.method == AuthMethod.AGENT:
                connect_kwargs["allow_agent"] = True
            else:
                # 密码认证
                connect_kwargs["password"] = self.credentials.password

            self._client.connect(**connect_kwargs)
            self._transport = self._client.get_transport()
            self._connect_time = time.time()

            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"SSH 连接成功: {self.credentials.username}@{self.target}")
            return True

        except AuthenticationException as e:
            self.logger.error(f"SSH 认证失败: {e}")
            self._set_status(LateralStatus.FAILED)
            return False
        except SSHException as e:
            self.logger.error(f"SSH 连接失败: {e}")
            self._set_status(LateralStatus.FAILED)
            return False
        except socket.error as e:
            self.logger.error(f"网络错误: {e}")
            self._set_status(LateralStatus.FAILED)
            return False
        except Exception as e:
            self.logger.error(f"SSH 错误: {e}")
            self._set_status(LateralStatus.FAILED)
            return False

    def _load_private_key(self) -> Optional["paramiko.PKey"]:
        """加载私钥"""
        if not HAS_PARAMIKO:
            return None

        key_classes = [RSAKey, DSSKey, ECDSAKey, Ed25519Key]
        passphrase = self.credentials.ssh_passphrase

        # 从文件加载
        if self.credentials.ssh_key:
            for key_class in key_classes:
                try:
                    return key_class.from_private_key_file(
                        self.credentials.ssh_key, password=passphrase
                    )
                except (IOError, OSError, SSHException):
                    continue  # 尝试下一个密钥类型

        # 从字符串加载
        if self.credentials.ssh_key_data:
            key_file = io.StringIO(self.credentials.ssh_key_data)
            for key_class in key_classes:
                try:
                    key_file.seek(0)
                    return key_class.from_private_key(key_file, password=passphrase)
                except (ValueError, SSHException):
                    continue  # 尝试下一个密钥类型

        return None

    def disconnect(self) -> None:
        """断开 SSH 连接"""
        self._set_status(LateralStatus.DISCONNECTING)

        # 关闭隧道（线程安全）
        with self._tunnels_lock:
            for tunnel in self._tunnels:
                tunnel.is_active = False

        # 关闭 SFTP
        if self._sftp:
            try:
                self._sftp.close()
            except (SSHException, socket.error, OSError) as e:
                self.logger.debug(f"关闭 SFTP 时出错: {e}")
            finally:
                self._sftp = None

        # 关闭 SSH 客户端
        if self._client:
            try:
                self._client.close()
            except (SSHException, socket.error, OSError) as e:
                self.logger.debug(f"关闭 SSH 客户端时出错: {e}")
            finally:
                self._client = None

        self._transport = None
        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行 SSH 命令

        Args:
            command: 要执行的命令
            timeout: 超时时间

        Returns:
            ExecutionResult 对象
        """
        if not self._client:
            return ExecutionResult(success=False, error="未连接", method=ExecutionMethod.SSH.value)

        self._set_status(LateralStatus.EXECUTING)
        self._update_activity()
        start_time = time.time()
        timeout = timeout or self.config.timeout

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)

            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode("utf-8", errors="ignore")
            stderr_text = stderr.read().decode("utf-8", errors="ignore")

            self._set_status(LateralStatus.CONNECTED)

            return ExecutionResult(
                success=exit_code == 0,
                output=stdout_text,
                error=stderr_text,
                exit_code=exit_code,
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )

        except socket.timeout:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error="命令执行超时",
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )
        except SSHException as e:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error=f"SSH 错误: {e}",
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )
        except socket.error as e:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error=f"网络错误: {e}",
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )

    def execute_interactive(
        self, command: str, input_data: Optional[str] = None, timeout: float = 60.0
    ) -> ExecutionResult:
        """
        交互式命令执行

        用于需要输入的命令 (如 sudo)

        Args:
            command: 命令
            input_data: 要发送的输入
            timeout: 超时时间
        """
        if not self._transport:
            return ExecutionResult(success=False, error="未连接")

        start_time = time.time()

        try:
            channel = self._transport.open_session()
            channel.settimeout(timeout)
            channel.get_pty()
            channel.exec_command(command)

            if input_data:
                time.sleep(0.5)  # 等待提示
                channel.send(input_data + "\n")

            output = ""
            while True:
                if channel.recv_ready():
                    data = channel.recv(4096)
                    if not data:
                        break
                    output += data.decode("utf-8", errors="ignore")

                if channel.exit_status_ready():
                    break

                if time.time() - start_time > timeout:
                    break

                time.sleep(0.1)

            exit_code = channel.recv_exit_status()
            channel.close()

            return ExecutionResult(
                success=exit_code == 0,
                output=output,
                exit_code=exit_code,
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )

        except (SSHException, socket.error, socket.timeout) as e:
            return ExecutionResult(
                success=False,
                error=f"SSH/网络错误: {e}",
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )

    def execute_sudo(self, command: str, sudo_password: Optional[str] = None) -> ExecutionResult:
        """
        以 sudo 执行命令 (安全方式: 通过 stdin 传递密码)

        Args:
            command: 命令
            sudo_password: sudo 密码 (默认使用连接密码)
        """
        password = sudo_password or self.credentials.password
        if not password:
            return ExecutionResult(success=False, error="需要 sudo 密码")

        if not self._client:
            return ExecutionResult(success=False, error="未连接")

        start_time = time.time()
        try:
            # 安全方式: 使用 -S 从 stdin 读取密码，避免在进程列表中暴露
            # -p '' 设置空提示符避免干扰输出
            sudo_command = f"sudo -S -p '' {command}"
            stdin, stdout, stderr = self._client.exec_command(sudo_command, get_pty=True)

            # 通过 stdin 安全地发送密码
            stdin.write(f"{password}\n")
            stdin.flush()

            # 读取输出
            output = stdout.read().decode("utf-8", errors="replace")
            error_output = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()

            # 组合输出，过滤掉可能的密码回显
            combined_output = output
            if error_output and "password" not in error_output.lower():
                combined_output += f"\n{error_output}"

            return ExecutionResult(
                success=exit_code == 0,
                output=combined_output.strip(),
                exit_code=exit_code,
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )

        except (SSHException, socket.error, socket.timeout) as e:
            return ExecutionResult(
                success=False,
                error=f"SSH sudo 执行错误: {e}",
                duration=time.time() - start_time,
                method=ExecutionMethod.SSH.value,
            )

    def _get_sftp(self) -> Optional["SFTPClient"]:
        """获取或创建 SFTP 客户端"""
        if self._sftp is None and self._client:
            try:
                self._sftp = self._client.open_sftp()
            except (SSHException, socket.error) as e:
                self.logger.error(f"创建 SFTP 失败: {e}")
                return None
        return self._sftp

    def upload(self, local_path: str, remote_path: str) -> FileTransferResult:
        """
        SFTP 上传文件

        Args:
            local_path: 本地文件路径
            remote_path: 远程文件路径
        """
        if not self._client:
            return FileTransferResult(
                success=False, source=local_path, destination=remote_path, error="未连接"
            )

        sftp = self._get_sftp()
        if not sftp:
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error="无法创建 SFTP 连接",
            )

        self._set_status(LateralStatus.UPLOADING)
        self._update_activity()
        start_time = time.time()

        try:
            file_size = os.path.getsize(local_path)
            sftp.put(local_path, remote_path)

            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"上传成功: {local_path} -> {remote_path}")

            return FileTransferResult(
                success=True,
                source=local_path,
                destination=remote_path,
                size=file_size,
                duration=time.time() - start_time,
            )

        except FileNotFoundError as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=f"文件不存在: {e}",
                duration=time.time() - start_time,
            )
        except (IOError, OSError) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=f"文件操作错误: {e}",
                duration=time.time() - start_time,
            )
        except SSHException as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=f"SFTP 错误: {e}",
                duration=time.time() - start_time,
            )

    def download(self, remote_path: str, local_path: str) -> FileTransferResult:
        """
        SFTP 下载文件

        Args:
            remote_path: 远程文件路径
            local_path: 本地文件路径
        """
        if not self._client:
            return FileTransferResult(
                success=False, source=remote_path, destination=local_path, error="未连接"
            )

        sftp = self._get_sftp()
        if not sftp:
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error="无法创建 SFTP 连接",
            )

        self._set_status(LateralStatus.DOWNLOADING)
        self._update_activity()
        start_time = time.time()

        try:
            sftp.get(remote_path, local_path)
            file_size = os.path.getsize(local_path)

            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"下载成功: {remote_path} -> {local_path}")

            return FileTransferResult(
                success=True,
                source=remote_path,
                destination=local_path,
                size=file_size,
                duration=time.time() - start_time,
            )

        except FileNotFoundError as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error=f"远程文件不存在: {e}",
                duration=time.time() - start_time,
            )
        except (IOError, OSError) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error=f"文件操作错误: {e}",
                duration=time.time() - start_time,
            )
        except SSHException as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error=f"SFTP 错误: {e}",
                duration=time.time() - start_time,
            )

    def list_dir(self, path: str = ".") -> List[str]:
        """列出目录内容"""
        sftp = self._get_sftp()
        if not sftp:
            return []

        try:
            return sftp.listdir(path)
        except (IOError, OSError, SSHException) as e:
            self.logger.error(f"列出目录失败: {e}")
            return []

    def create_tunnel(self, config: TunnelConfig) -> Optional[TunnelInfo]:
        """
        创建 SSH 隧道

        Args:
            config: 隧道配置

        Returns:
            TunnelInfo 对象
        """
        if not self._transport:
            return None

        if config.tunnel_type == "local":
            return self._create_local_forward(config)
        elif config.tunnel_type == "remote":
            return self._create_remote_forward(config)
        elif config.tunnel_type == "dynamic":
            return self._create_socks_proxy(config)

        return None

    def _create_local_forward(self, config: TunnelConfig) -> Optional[TunnelInfo]:
        """创建本地端口转发 (SSH -L)"""
        tunnel_info = TunnelInfo(
            tunnel_type="local",
            local_bind=f"{config.bind_address}:{config.local_port}",
            remote_target=f"{config.remote_host}:{config.remote_port}",
        )

        def forward_handler():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((config.bind_address, config.local_port))
                server.listen(5)
                server.settimeout(1.0)

                self.logger.info(
                    f"本地转发: {config.bind_address}:{config.local_port} -> "
                    f"{config.remote_host}:{config.remote_port}"
                )

                while tunnel_info.is_active:
                    try:
                        client_sock, addr = server.accept()
                    except socket.timeout:
                        continue

                    try:
                        channel = self._transport.open_channel(
                            "direct-tcpip", (config.remote_host, config.remote_port), addr
                        )

                        if channel is None:
                            client_sock.close()
                            continue

                        # 启动双向转发
                        forward_thread = threading.Thread(
                            target=self._forward_data, args=(client_sock, channel, tunnel_info)
                        )
                        forward_thread.daemon = True
                        forward_thread.start()

                    except SSHException as e:
                        self.logger.debug(f"转发错误: {e}")
                        client_sock.close()

                server.close()

            except (socket.error, OSError) as e:
                self.logger.error(f"本地转发错误: {e}")

        thread = threading.Thread(target=forward_handler)
        thread.daemon = True
        thread.start()

        tunnel_info.thread = thread
        with self._tunnels_lock:
            self._tunnels.append(tunnel_info)
        return tunnel_info

    def _create_remote_forward(self, config: TunnelConfig) -> Optional[TunnelInfo]:
        """创建远程端口转发 (SSH -R)"""
        if not self._transport:
            return None

        tunnel_info = TunnelInfo(
            tunnel_type="remote",
            local_bind=f"{config.bind_address}:{config.local_port}",
            remote_target=f"localhost:{config.remote_port}",
        )

        try:
            self._transport.request_port_forward(config.bind_address, config.local_port)

            self.logger.info(
                f"远程转发: {config.bind_address}:{config.local_port} -> "
                f"localhost:{config.remote_port}"
            )

            with self._tunnels_lock:
                self._tunnels.append(tunnel_info)
            return tunnel_info

        except (SSHException, socket.error) as e:
            self.logger.error(f"远程转发失败: {e}")
            return None

    def _create_socks_proxy(self, config: TunnelConfig) -> Optional[TunnelInfo]:
        """创建 SOCKS5 代理 (SSH -D)"""
        tunnel_info = TunnelInfo(
            tunnel_type="dynamic",
            local_bind=f"{config.bind_address}:{config.local_port}",
            remote_target="SOCKS5",
        )

        def socks_handler():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((config.bind_address, config.local_port))
                server.listen(5)
                server.settimeout(1.0)

                self.logger.info(f"SOCKS5 代理: {config.bind_address}:{config.local_port}")

                while tunnel_info.is_active:
                    try:
                        client_sock, addr = server.accept()
                    except socket.timeout:
                        continue

                    handler_thread = threading.Thread(
                        target=self._handle_socks_client, args=(client_sock, tunnel_info)
                    )
                    handler_thread.daemon = True
                    handler_thread.start()

                server.close()

            except (socket.error, OSError) as e:
                self.logger.error(f"SOCKS 代理错误: {e}")

        thread = threading.Thread(target=socks_handler)
        thread.daemon = True
        thread.start()

        tunnel_info.thread = thread
        with self._tunnels_lock:
            self._tunnels.append(tunnel_info)
        return tunnel_info

    def _handle_socks_client(self, client_sock: socket.socket, tunnel_info: TunnelInfo):
        """处理 SOCKS5 客户端"""
        try:
            # SOCKS5 握手
            data = client_sock.recv(2)
            if len(data) < 2 or data[0] != 0x05:
                client_sock.close()
                return

            nmethods = data[1]
            methods = client_sock.recv(nmethods)

            # 无认证
            client_sock.send(b"\x05\x00")

            # 获取请求
            data = client_sock.recv(4)
            if len(data) < 4 or data[0] != 0x05 or data[1] != 0x01:
                client_sock.close()
                return

            addr_type = data[3]

            if addr_type == 0x01:  # IPv4
                addr = socket.inet_ntoa(client_sock.recv(4))
            elif addr_type == 0x03:  # 域名
                addr_len = client_sock.recv(1)[0]
                addr = client_sock.recv(addr_len).decode()
            elif addr_type == 0x04:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
            else:
                client_sock.close()
                return

            port = int.from_bytes(client_sock.recv(2), "big")

            # 打开 SSH 通道
            try:
                channel = self._transport.open_channel(
                    "direct-tcpip", (addr, port), client_sock.getpeername()
                )
            except SSHException:
                client_sock.send(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            if channel is None:
                client_sock.send(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                return

            # 发送成功响应
            client_sock.send(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            # 转发数据
            self._forward_data(client_sock, channel, tunnel_info)

        except (socket.error, socket.timeout, struct.error) as e:
            self.logger.debug(f"SOCKS 客户端错误: {e}")
        finally:
            try:
                client_sock.close()
            except (socket.error, OSError):
                pass  # 清理时忽略错误

    def _forward_data(self, sock: socket.socket, channel: "Channel", tunnel_info: TunnelInfo):
        """双向数据转发"""
        try:
            while tunnel_info.is_active:
                r, w, x = select.select([sock, channel], [], [], 1.0)

                if sock in r:
                    data = sock.recv(4096)
                    if len(data) == 0:
                        break
                    channel.send(data)

                if channel in r:
                    data = channel.recv(4096)
                    if len(data) == 0:
                        break
                    sock.send(data)

        except (socket.error, socket.timeout, SSHException) as e:
            self.logger.debug(f"转发错误: {e}")
        finally:
            try:
                channel.close()
            except (SSHException, socket.error, OSError):
                pass  # 清理时忽略错误
            try:
                sock.close()
            except (socket.error, OSError):
                pass  # 清理时忽略错误

    def close_tunnel(self, tunnel: TunnelInfo) -> bool:
        """关闭隧道（线程安全）"""
        tunnel.is_active = False
        with self._tunnels_lock:
            if tunnel in self._tunnels:
                self._tunnels.remove(tunnel)
        return True

    def get_tunnels(self) -> List[TunnelInfo]:
        """获取活跃隧道列表（线程安全）"""
        with self._tunnels_lock:
            return [t for t in self._tunnels if t.is_active]


# 便捷函数
def ssh_exec(
    target: str,
    username: str,
    password: str = "",
    key_file: str = "",
    command: str = "whoami",
    port: int = 22,
) -> Dict[str, Any]:
    """
    SSH 命令执行 (便捷函数)

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        key_file: 密钥文件路径
        command: 命令
        port: SSH 端口
    """
    creds = Credentials(
        username=username,
        password=password if password else None,
        ssh_key=key_file if key_file else None,
    )

    config = LateralConfig(ssh_port=port)
    ssh = SSHLateral(target, creds, config)

    if not ssh.connect():
        return {"success": False, "error": "连接失败", "target": target, "command": command}

    result = ssh.execute(command)
    ssh.disconnect()

    return {
        "success": result.success,
        "output": result.output,
        "error": result.error,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "target": target,
        "command": command,
        "method": result.method,
    }


def ssh_tunnel(
    target: str,
    username: str,
    password: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    port: int = 22,
) -> Dict[str, Any]:
    """
    创建 SSH 隧道 (便捷函数)

    Args:
        target: SSH 服务器
        username: 用户名
        password: 密码
        local_port: 本地端口
        remote_host: 远程目标主机
        remote_port: 远程目标端口
        port: SSH 端口
    """
    creds = Credentials(username=username, password=password)
    config = LateralConfig(ssh_port=port)

    ssh = SSHLateral(target, creds, config)

    if not ssh.connect():
        return {"success": False, "error": "连接失败"}

    tunnel_config = TunnelConfig(
        local_port=local_port, remote_host=remote_host, remote_port=remote_port
    )

    tunnel = ssh.create_tunnel(tunnel_config)

    if tunnel:
        return {
            "success": True,
            "local_bind": tunnel.local_bind,
            "remote_target": tunnel.remote_target,
            "tunnel_type": tunnel.tunnel_type,
            "ssh_server": target,
        }
    else:
        ssh.disconnect()
        return {"success": False, "error": "隧道创建失败"}


def ssh_upload(
    target: str, username: str, password: str, local_path: str, remote_path: str, port: int = 22
) -> Dict[str, Any]:
    """SSH 文件上传"""
    creds = Credentials(username=username, password=password)
    config = LateralConfig(ssh_port=port)

    ssh = SSHLateral(target, creds, config)

    if not ssh.connect():
        return {"success": False, "error": "连接失败"}

    result = ssh.upload(local_path, remote_path)
    ssh.disconnect()

    return result.to_dict()


def ssh_download(
    target: str, username: str, password: str, remote_path: str, local_path: str, port: int = 22
) -> Dict[str, Any]:
    """SSH 文件下载"""
    creds = Credentials(username=username, password=password)
    config = LateralConfig(ssh_port=port)

    ssh = SSHLateral(target, creds, config)

    if not ssh.connect():
        return {"success": False, "error": "连接失败"}

    result = ssh.download(remote_path, local_path)
    ssh.disconnect()

    return result.to_dict()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("=== SSH Lateral Movement Module ===")
    logger.info(f"paramiko 可用: {HAS_PARAMIKO}")
    logger.info("使用示例:")
    logger.info("  from core.lateral import SSHLateral, Credentials, ssh_exec")
    logger.info("  result = ssh_exec('192.168.1.100', 'root', 'password', command='id')")
