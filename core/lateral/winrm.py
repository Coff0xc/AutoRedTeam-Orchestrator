#!/usr/bin/env python3
"""
WinRM 横向移动模块 - WinRM Lateral Movement
功能: WinRM 远程命令执行、PowerShell 远程管理

用于授权安全测试，仅限合法渗透测试使用
"""

import socket
import time
import logging
import base64
from typing import Optional, List, Dict, Any
from xml.etree import ElementTree

from .base import (
    BaseLateralModule,
    Credentials,
    ExecutionResult,
    FileTransferResult,
    LateralConfig,
    LateralStatus,
    AuthMethod,
    ExecutionMethod,
    LateralModuleError,
)

logger = logging.getLogger(__name__)

# 尝试导入 pywinrm
try:
    import winrm
    from winrm import Session
    from winrm.protocol import Protocol
    HAS_WINRM = True
except ImportError:
    HAS_WINRM = False
    logger.debug("pywinrm 未安装，WinRM 功能受限")

# 尝试导入 requests-ntlm (用于 NTLM 认证)
try:
    from requests_ntlm import HttpNtlmAuth
    HAS_NTLM = True
except ImportError:
    HAS_NTLM = False

# 尝试导入 requests-kerberos (用于 Kerberos 认证)
try:
    from requests_kerberos import HTTPKerberosAuth
    HAS_KERBEROS = True
except ImportError:
    HAS_KERBEROS = False


class WinRMLateral(BaseLateralModule):
    """
    WinRM 横向移动模块

    支持:
    - 基本认证 (Basic)
    - NTLM 认证
    - Kerberos 认证
    - PowerShell 远程执行
    - 文件传输

    Usage:
        creds = Credentials(
            username='administrator',
            password='password123',
            domain='WORKGROUP'
        )

        with WinRMLateral('192.168.1.100', creds) as winrm_client:
            # 执行 CMD 命令
            result = winrm_client.execute('whoami')

            # 执行 PowerShell
            result = winrm_client.execute_ps('Get-Process')
    """

    name = 'winrm'
    description = 'WinRM 横向移动，支持 NTLM 和 Kerberos 认证'
    default_port = 5985
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.HASH, AuthMethod.TICKET]
    supports_file_transfer = True  # 支持 PowerShell Base64 文件传输

    def __init__(
        self,
        target: str,
        credentials: Credentials,
        config: Optional[LateralConfig] = None
    ):
        super().__init__(target, credentials, config)
        self._session: Optional['Session'] = None
        self._protocol: Optional['Protocol'] = None

    @property
    def port(self) -> int:
        """获取 WinRM 端口"""
        if self.config.port:
            return self.config.port
        if self.config.winrm_use_ssl:
            return self.config.winrm_ssl_port
        return self.config.winrm_port

    @property
    def endpoint(self) -> str:
        """获取 WinRM 端点 URL"""
        scheme = 'https' if self.config.winrm_use_ssl else 'http'
        return f'{scheme}://{self.target}:{self.port}/wsman'

    def connect(self) -> bool:
        """建立 WinRM 连接"""
        if not HAS_WINRM:
            self.logger.error("pywinrm 未安装，无法建立 WinRM 连接")
            self._set_status(LateralStatus.FAILED)
            return False

        self._set_status(LateralStatus.CONNECTING)

        try:
            # 构建认证参数
            transport = self._get_transport()
            auth_params = self._get_auth_params()

            # 创建会话
            self._session = Session(
                target=self.endpoint,
                auth=(
                    self.credentials.full_username,
                    self.credentials.password or ''
                ),
                transport=transport,
                read_timeout_sec=self.config.winrm_read_timeout,
                operation_timeout_sec=self.config.winrm_operation_timeout,
                **auth_params
            )

            # 测试连接
            test_result = self._session.run_cmd('echo test')
            if test_result.status_code != 0:
                self.logger.error("WinRM 连接测试失败")
                self._set_status(LateralStatus.FAILED)
                return False

            self._connect_time = time.time()
            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"WinRM 连接成功: {self.credentials.username}@{self.target}")
            return True

        except (socket.error, socket.timeout, OSError) as e:
            self.logger.error(f"WinRM 连接失败: {e}")
            self._set_status(LateralStatus.FAILED)
            return False

    def _get_transport(self) -> str:
        """获取传输方式"""
        transport = self.config.winrm_transport.lower()

        if transport == 'kerberos':
            if not HAS_KERBEROS:
                self.logger.warning("requests-kerberos 未安装，回退到 NTLM")
                return 'ntlm'
            return 'kerberos'

        if transport == 'ntlm':
            if not HAS_NTLM:
                self.logger.warning("requests-ntlm 未安装，回退到 basic")
                return 'basic'
            return 'ntlm'

        return 'basic'

    def _get_auth_params(self) -> Dict[str, Any]:
        """获取认证参数"""
        params: Dict[str, Any] = {}

        if self.config.winrm_use_ssl:
            cert_validation = self.config.winrm_cert_validation
            if cert_validation == 'ignore':
                self.logger.warning(
                    "WinRM SSL 证书验证已禁用，存在中间人攻击风险。"
                    "生产环境请设置 winrm_cert_validation='validate'"
                )
                params['server_cert_validation'] = 'ignore'
            else:
                params['server_cert_validation'] = 'validate'
                if self.config.winrm_ca_trust_path:
                    params['ca_trust_path'] = self.config.winrm_ca_trust_path

        return params

    def disconnect(self) -> None:
        """断开 WinRM 连接"""
        self._set_status(LateralStatus.DISCONNECTING)

        # WinRM Session 不需要显式关闭
        self._session = None
        self._protocol = None

        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行 CMD 命令

        Args:
            command: CMD 命令
            timeout: 超时时间
        """
        if not self._session:
            return ExecutionResult(
                success=False,
                error="未连接",
                method=ExecutionMethod.WINRM.value
            )

        self._set_status(LateralStatus.EXECUTING)
        self._update_activity()
        start_time = time.time()

        try:
            result = self._session.run_cmd(command)

            self._set_status(LateralStatus.CONNECTED)

            stdout = result.std_out.decode('utf-8', errors='ignore') if result.std_out else ''
            stderr = result.std_err.decode('utf-8', errors='ignore') if result.std_err else ''

            return ExecutionResult(
                success=result.status_code == 0,
                output=stdout,
                error=stderr,
                exit_code=result.status_code,
                duration=time.time() - start_time,
                method=ExecutionMethod.WINRM.value
            )

        except (socket.error, socket.timeout, OSError) as e:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error=f"网络错误: {e}",
                duration=time.time() - start_time,
                method=ExecutionMethod.WINRM.value
            )

    def execute_ps(self, script: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行 PowerShell 脚本

        Args:
            script: PowerShell 脚本
            timeout: 超时时间
        """
        if not self._session:
            return ExecutionResult(
                success=False,
                error="未连接",
                method=ExecutionMethod.WINRM.value
            )

        self._set_status(LateralStatus.EXECUTING)
        self._update_activity()
        start_time = time.time()

        try:
            result = self._session.run_ps(script)

            self._set_status(LateralStatus.CONNECTED)

            stdout = result.std_out.decode('utf-8', errors='ignore') if result.std_out else ''
            stderr = result.std_err.decode('utf-8', errors='ignore') if result.std_err else ''

            return ExecutionResult(
                success=result.status_code == 0,
                output=stdout,
                error=stderr,
                exit_code=result.status_code,
                duration=time.time() - start_time,
                method=ExecutionMethod.WINRM.value
            )

        except (socket.error, socket.timeout, OSError) as e:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error=f"网络错误: {e}",
                duration=time.time() - start_time,
                method=ExecutionMethod.WINRM.value
            )

    def execute_ps_encoded(self, script: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行 Base64 编码的 PowerShell 脚本

        用于执行包含特殊字符的脚本

        Args:
            script: PowerShell 脚本
            timeout: 超时时间
        """
        # UTF-16LE 编码后 Base64
        encoded = base64.b64encode(script.encode('utf-16-le')).decode()
        command = f'powershell -EncodedCommand {encoded}'
        return self.execute(command, timeout)

    def get_system_info(self) -> Dict[str, Any]:
        """获取系统信息"""
        ps_script = '''
        $info = @{
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Username = $env:USERNAME
            OSVersion = [Environment]::OSVersion.VersionString
            Architecture = $env:PROCESSOR_ARCHITECTURE
            ProcessorCount = $env:NUMBER_OF_PROCESSORS
        }
        $info | ConvertTo-Json
        '''

        result = self.execute_ps(ps_script)
        if result.success and result.output:
            try:
                import json
                return json.loads(result.output)
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.debug(f"JSON 解析失败: {e}")

        return {'error': result.error or '获取失败'}

    def get_processes(self) -> List[Dict[str, Any]]:
        """获取进程列表"""
        ps_script = '''
        Get-Process | Select-Object Id, ProcessName, CPU, WS | ConvertTo-Json
        '''

        result = self.execute_ps(ps_script)
        if result.success and result.output:
            try:
                import json
                data = json.loads(result.output)
                return data if isinstance(data, list) else [data]
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.debug(f"JSON 解析失败: {e}")

        return []

    def get_services(self) -> List[Dict[str, Any]]:
        """获取服务列表"""
        ps_script = '''
        Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json
        '''

        result = self.execute_ps(ps_script)
        if result.success and result.output:
            try:
                import json
                data = json.loads(result.output)
                return data if isinstance(data, list) else [data]
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.debug(f"JSON 解析失败: {e}")

        return []

    def get_users(self) -> List[Dict[str, Any]]:
        """获取本地用户"""
        ps_script = '''
        Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description | ConvertTo-Json
        '''

        result = self.execute_ps(ps_script)
        if result.success and result.output:
            try:
                import json
                data = json.loads(result.output)
                return data if isinstance(data, list) else [data]
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.debug(f"JSON 解析失败: {e}")

        return []

    def get_network_config(self) -> List[Dict[str, Any]]:
        """获取网络配置"""
        ps_script = '''
        Get-NetIPAddress -AddressFamily IPv4 |
        Select-Object InterfaceAlias, IPAddress, PrefixLength |
        ConvertTo-Json
        '''

        result = self.execute_ps(ps_script)
        if result.success and result.output:
            try:
                import json
                data = json.loads(result.output)
                return data if isinstance(data, list) else [data]
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.debug(f"JSON 解析失败: {e}")

        return []

    def upload(self, local_path: str, remote_path: str) -> FileTransferResult:
        """
        上传文件

        通过 PowerShell 和 Base64 编码传输

        Args:
            local_path: 本地文件路径
            remote_path: 远程文件路径
        """
        if not self._session:
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error="未连接"
            )

        self._set_status(LateralStatus.UPLOADING)
        self._update_activity()
        start_time = time.time()

        try:
            import os

            # 读取文件并编码
            with open(local_path, 'rb') as f:
                content = f.read()

            file_size = len(content)
            encoded = base64.b64encode(content).decode()

            # 分块传输 (每块 50KB)
            chunk_size = 50 * 1024
            chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

            # 第一个块创建文件
            ps_script = f'''
            $bytes = [Convert]::FromBase64String("{chunks[0]}")
            [IO.File]::WriteAllBytes("{remote_path}", $bytes)
            '''
            result = self.execute_ps(ps_script)

            if not result.success:
                self._set_status(LateralStatus.CONNECTED)
                return FileTransferResult(
                    success=False,
                    source=local_path,
                    destination=remote_path,
                    error=result.error,
                    duration=time.time() - start_time
                )

            # 追加剩余块
            for chunk in chunks[1:]:
                ps_script = f'''
                $bytes = [Convert]::FromBase64String("{chunk}")
                [IO.File]::AppendAllBytes("{remote_path}", $bytes)
                '''
                result = self.execute_ps(ps_script)

                if not result.success:
                    self._set_status(LateralStatus.CONNECTED)
                    return FileTransferResult(
                        success=False,
                        source=local_path,
                        destination=remote_path,
                        error=result.error,
                        duration=time.time() - start_time
                    )

            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"上传成功: {local_path} -> {remote_path}")

            return FileTransferResult(
                success=True,
                source=local_path,
                destination=remote_path,
                size=file_size,
                duration=time.time() - start_time
            )

        except FileNotFoundError as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=f"文件不存在: {e}",
                duration=time.time() - start_time
            )
        except (IOError, OSError) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=f"文件操作错误: {e}",
                duration=time.time() - start_time
            )
        except (socket.error, socket.timeout) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=local_path,
                destination=remote_path,
                error=f"网络错误: {e}",
                duration=time.time() - start_time
            )

    def download(self, remote_path: str, local_path: str) -> FileTransferResult:
        """
        下载文件

        通过 PowerShell 和 Base64 编码传输

        Args:
            remote_path: 远程文件路径
            local_path: 本地文件路径
        """
        if not self._session:
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error="未连接"
            )

        self._set_status(LateralStatus.DOWNLOADING)
        self._update_activity()
        start_time = time.time()

        try:
            # 读取远程文件并编码
            ps_script = f'''
            $bytes = [IO.File]::ReadAllBytes("{remote_path}")
            [Convert]::ToBase64String($bytes)
            '''
            result = self.execute_ps(ps_script)

            if not result.success:
                self._set_status(LateralStatus.CONNECTED)
                return FileTransferResult(
                    success=False,
                    source=remote_path,
                    destination=local_path,
                    error=result.error,
                    duration=time.time() - start_time
                )

            # 解码并写入本地文件
            encoded = result.output.strip()
            content = base64.b64decode(encoded)

            import os
            with open(local_path, 'wb') as f:
                f.write(content)

            file_size = len(content)
            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"下载成功: {remote_path} -> {local_path}")

            return FileTransferResult(
                success=True,
                source=remote_path,
                destination=local_path,
                size=file_size,
                duration=time.time() - start_time
            )

        except (IOError, OSError) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error=f"文件操作错误: {e}",
                duration=time.time() - start_time
            )
        except (socket.error, socket.timeout) as e:
            self._set_status(LateralStatus.CONNECTED)
            return FileTransferResult(
                success=False,
                source=remote_path,
                destination=local_path,
                error=f"网络错误: {e}",
                duration=time.time() - start_time
            )

    def recon(self) -> Dict[str, Any]:
        """系统侦察"""
        if not self._session:
            return {'success': False, 'error': '未连接'}

        try:
            return {
                'success': True,
                'target': self.target,
                'system_info': self.get_system_info(),
                'users': self.get_users(),
                'network': self.get_network_config(),
                'process_count': len(self.get_processes()),
                'services': len(self.get_services()),
            }
        except (socket.error, socket.timeout, OSError) as e:
            return {'success': False, 'error': f"网络错误: {e}"}


# 便捷函数
def winrm_exec(
    target: str,
    username: str,
    password: str,
    command: str,
    domain: str = '',
    use_ssl: bool = False,
    transport: str = 'ntlm'
) -> Dict[str, Any]:
    """
    WinRM 命令执行 (便捷函数)

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        command: 命令
        domain: 域名
        use_ssl: 是否使用 SSL
        transport: 传输方式 (basic, ntlm, kerberos)
    """
    if not HAS_WINRM:
        return {'success': False, 'error': 'pywinrm 未安装'}

    creds = Credentials(
        username=username,
        password=password,
        domain=domain
    )

    config = LateralConfig(
        winrm_use_ssl=use_ssl,
        winrm_transport=transport
    )

    client = WinRMLateral(target, creds, config)

    if not client.connect():
        return {
            'success': False,
            'error': '连接失败',
            'target': target,
            'command': command
        }

    result = client.execute(command)
    client.disconnect()

    return {
        'success': result.success,
        'output': result.output,
        'error': result.error,
        'exit_code': result.exit_code,
        'duration': result.duration,
        'target': target,
        'command': command,
        'method': result.method
    }


def winrm_ps(
    target: str,
    username: str,
    password: str,
    script: str,
    domain: str = '',
    use_ssl: bool = False,
    transport: str = 'ntlm'
) -> Dict[str, Any]:
    """
    WinRM PowerShell 执行 (便捷函数)
    """
    if not HAS_WINRM:
        return {'success': False, 'error': 'pywinrm 未安装'}

    creds = Credentials(
        username=username,
        password=password,
        domain=domain
    )

    config = LateralConfig(
        winrm_use_ssl=use_ssl,
        winrm_transport=transport
    )

    client = WinRMLateral(target, creds, config)

    if not client.connect():
        return {
            'success': False,
            'error': '连接失败',
            'target': target,
            'script': script[:100]
        }

    result = client.execute_ps(script)
    client.disconnect()

    return {
        'success': result.success,
        'output': result.output,
        'error': result.error,
        'exit_code': result.exit_code,
        'duration': result.duration,
        'target': target,
        'method': result.method
    }


if __name__ == '__main__':
    print("=== WinRM Lateral Movement Module ===")
    print(f"pywinrm 可用: {HAS_WINRM}")
    print(f"NTLM 认证可用: {HAS_NTLM}")
    print(f"Kerberos 认证可用: {HAS_KERBEROS}")
    print("\n使用示例:")
    print("  from core.lateral import WinRMLateral, Credentials, winrm_exec")
    print("  result = winrm_exec('192.168.1.100', 'admin', 'password', 'whoami')")
