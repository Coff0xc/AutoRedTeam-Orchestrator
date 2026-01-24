#!/usr/bin/env python3
"""
横向移动基类 - Lateral Movement Base Module
定义所有横向移动模块的基础接口和数据结构

用于授权安全测试，仅限合法渗透测试使用
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Union
from enum import Enum
import uuid
import time
import logging

logger = logging.getLogger(__name__)


class LateralStatus(Enum):
    """横向移动状态枚举"""
    IDLE = 'idle'                    # 空闲
    CONNECTING = 'connecting'        # 连接中
    CONNECTED = 'connected'          # 已连接
    AUTHENTICATING = 'authenticating'  # 认证中
    AUTHENTICATED = 'authenticated'  # 已认证
    EXECUTING = 'executing'          # 执行中
    UPLOADING = 'uploading'          # 上传中
    DOWNLOADING = 'downloading'      # 下载中
    DISCONNECTING = 'disconnecting'  # 断开中
    DISCONNECTED = 'disconnected'    # 已断开
    FAILED = 'failed'                # 失败
    ERROR = 'error'                  # 错误


class AuthMethod(Enum):
    """认证方式枚举"""
    PASSWORD = 'password'            # 密码认证
    HASH = 'hash'                    # NTLM Hash (Pass-the-Hash)
    TICKET = 'ticket'                # Kerberos 票据 (Pass-the-Ticket)
    KEY = 'key'                      # SSH 私钥
    CERTIFICATE = 'certificate'      # 证书认证
    TOKEN = 'token'                  # 令牌认证
    AGENT = 'agent'                  # SSH Agent


class ExecutionMethod(Enum):
    """命令执行方式"""
    SMBEXEC = 'smbexec'              # SMBExec
    PSEXEC = 'psexec'                # PsExec
    WMIEXEC = 'wmiexec'              # WMIExec
    ATEXEC = 'atexec'                # AtExec (计划任务)
    DCOMEXEC = 'dcomexec'            # DCOM Exec
    WINRM = 'winrm'                  # WinRM
    SSH = 'ssh'                      # SSH


@dataclass
class Credentials:
    """
    凭证信息

    支持多种认证方式:
    - 密码认证
    - Pass-the-Hash (NTLM Hash)
    - Pass-the-Ticket (Kerberos)
    - SSH 私钥
    - 证书认证
    """
    username: str
    password: Optional[str] = None
    domain: Optional[str] = None
    ntlm_hash: Optional[str] = None       # 格式: LM:NT 或仅 NT
    aes_key: Optional[str] = None         # Kerberos AES Key
    ticket: Optional[str] = None          # Kerberos 票据 (ccache 文件路径)
    ssh_key: Optional[str] = None         # SSH 私钥路径
    ssh_key_data: Optional[str] = None    # SSH 私钥内容
    ssh_passphrase: Optional[str] = None  # SSH 私钥密码
    certificate: Optional[str] = None     # 证书路径
    method: AuthMethod = AuthMethod.PASSWORD

    def __post_init__(self):
        """根据提供的凭据自动推断认证方式"""
        if self.method == AuthMethod.PASSWORD:
            if self.ntlm_hash:
                self.method = AuthMethod.HASH
            elif self.ticket:
                self.method = AuthMethod.TICKET
            elif self.ssh_key or self.ssh_key_data:
                self.method = AuthMethod.KEY
            elif self.certificate:
                self.method = AuthMethod.CERTIFICATE

    @property
    def lm_hash(self) -> str:
        """获取 LM Hash"""
        if self.ntlm_hash and ':' in self.ntlm_hash:
            return self.ntlm_hash.split(':')[0]
        # 空 LM Hash
        return "aad3b435b51404eeaad3b435b51404ee"

    @property
    def nt_hash(self) -> str:
        """获取 NT Hash"""
        if self.ntlm_hash and ':' in self.ntlm_hash:
            return self.ntlm_hash.split(':')[1]
        elif self.ntlm_hash:
            return self.ntlm_hash
        return ""

    @property
    def full_username(self) -> str:
        """获取完整用户名 (domain\\username)"""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'username': self.username,
            'domain': self.domain,
            'method': self.method.value,
            'has_password': self.password is not None,
            'has_hash': self.ntlm_hash is not None,
            'has_ticket': self.ticket is not None,
            'has_ssh_key': self.ssh_key is not None or self.ssh_key_data is not None,
        }

    def __repr__(self) -> str:
        return f"Credentials(user={self.full_username}, method={self.method.value})"


@dataclass
class ExecutionResult:
    """
    命令执行结果
    """
    success: bool
    output: str = ''
    error: str = ''
    exit_code: int = 0
    duration: float = 0.0
    process_id: Optional[int] = None
    method: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'success': self.success,
            'output': self.output,
            'error': self.error,
            'exit_code': self.exit_code,
            'duration': self.duration,
            'process_id': self.process_id,
            'method': self.method,
        }

    def __bool__(self) -> bool:
        return self.success


@dataclass
class FileTransferResult:
    """
    文件传输结果
    """
    success: bool
    source: str = ''
    destination: str = ''
    size: int = 0
    duration: float = 0.0
    error: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'source': self.source,
            'destination': self.destination,
            'size': self.size,
            'duration': self.duration,
            'error': self.error,
        }


@dataclass
class LateralConfig:
    """
    横向移动配置
    """
    # 通用配置
    timeout: float = 30.0
    port: Optional[int] = None
    retry_count: int = 3
    retry_delay: float = 1.0

    # SMB 配置
    smb_port: int = 445
    smb_share: str = 'ADMIN$'
    smb_service_name: str = 'AutoRedTeam'
    smb_service_prefix: str = 'ART'

    # SSH 配置
    ssh_port: int = 22
    ssh_timeout: float = 10.0
    ssh_banner_timeout: float = 5.0
    ssh_auth_timeout: float = 10.0
    ssh_allow_agent: bool = False
    ssh_look_for_keys: bool = False

    # WMI 配置
    wmi_namespace: str = 'root/cimv2'
    wmi_timeout: float = 60.0

    # WinRM 配置
    winrm_port: int = 5985
    winrm_ssl_port: int = 5986
    winrm_use_ssl: bool = False
    winrm_transport: str = 'ntlm'  # ntlm, kerberos, basic
    winrm_read_timeout: float = 30.0
    winrm_operation_timeout: float = 20.0

    # PsExec 配置
    psexec_share: str = 'ADMIN$'
    psexec_service_name: Optional[str] = None
    psexec_copy_file: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'timeout': self.timeout,
            'port': self.port,
            'smb_port': self.smb_port,
            'smb_share': self.smb_share,
            'ssh_port': self.ssh_port,
            'wmi_namespace': self.wmi_namespace,
            'winrm_port': self.winrm_port,
            'winrm_use_ssl': self.winrm_use_ssl,
        }


class BaseLateralModule(ABC):
    """
    横向移动基类

    所有横向移动模块必须继承此类并实现抽象方法

    Usage:
        class MyLateral(BaseLateralModule):
            name = 'mylateral'
            description = 'My Lateral Movement'
            default_port = 12345

            def connect(self) -> bool:
                ...

            def disconnect(self) -> None:
                ...

            def execute(self, command: str) -> ExecutionResult:
                ...

    Context Manager:
        with MyLateral(target, creds) as lateral:
            result = lateral.execute('whoami')
    """

    # 模块元信息 (子类必须覆盖)
    name: str = 'base'
    description: str = 'Base Lateral Movement Module'
    default_port: int = 0
    supported_auth: List[AuthMethod] = [AuthMethod.PASSWORD]

    def __init__(
        self,
        target: str,
        credentials: Credentials,
        config: Optional[LateralConfig] = None
    ):
        """
        初始化横向移动模块

        Args:
            target: 目标主机 IP 或主机名
            credentials: 凭证信息
            config: 配置选项
        """
        self.target = target
        self.credentials = credentials
        self.config = config or LateralConfig()

        # 状态管理
        self.status = LateralStatus.IDLE
        self._session_id = str(uuid.uuid4())[:8]
        self._connect_time: Optional[float] = None
        self._last_activity: Optional[float] = None

        # 日志
        self.logger = logging.getLogger(f"{__name__}.{self.name}")

    @property
    def port(self) -> int:
        """获取端口 (配置优先)"""
        return self.config.port or self.default_port

    @property
    def session_id(self) -> str:
        """获取会话 ID"""
        return self._session_id

    @property
    def is_connected(self) -> bool:
        """是否已连接"""
        return self.status in (
            LateralStatus.CONNECTED,
            LateralStatus.AUTHENTICATED,
            LateralStatus.EXECUTING,
            LateralStatus.UPLOADING,
            LateralStatus.DOWNLOADING,
        )

    @property
    def connection_duration(self) -> float:
        """连接持续时间"""
        if self._connect_time:
            return time.time() - self._connect_time
        return 0.0

    def _update_activity(self) -> None:
        """更新最后活动时间"""
        self._last_activity = time.time()

    def _set_status(self, status: LateralStatus) -> None:
        """设置状态"""
        old_status = self.status
        self.status = status
        self.logger.debug(f"Status: {old_status.value} -> {status.value}")

    @abstractmethod
    def connect(self) -> bool:
        """
        建立连接

        Returns:
            成功返回 True，失败返回 False
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """断开连接"""
        pass

    @abstractmethod
    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        执行命令

        Args:
            command: 要执行的命令
            timeout: 超时时间 (秒)

        Returns:
            ExecutionResult 对象
        """
        pass

    def upload(self, local_path: str, remote_path: str) -> FileTransferResult:
        """
        上传文件

        Args:
            local_path: 本地文件路径
            remote_path: 远程文件路径

        Returns:
            FileTransferResult 对象
        """
        raise NotImplementedError(f"{self.name} 不支持文件上传")

    def download(self, remote_path: str, local_path: str) -> FileTransferResult:
        """
        下载文件

        Args:
            remote_path: 远程文件路径
            local_path: 本地文件路径

        Returns:
            FileTransferResult 对象
        """
        raise NotImplementedError(f"{self.name} 不支持文件下载")

    def test_connection(self) -> bool:
        """
        测试连接

        尝试连接并执行简单命令验证
        """
        try:
            if not self.connect():
                return False

            # 尝试执行简单命令
            result = self.execute('echo test')
            self.disconnect()

            return result.success
        except Exception as e:
            self.logger.error(f"连接测试失败: {e}")
            return False

    def get_info(self) -> Dict[str, Any]:
        """获取模块信息"""
        return {
            'name': self.name,
            'description': self.description,
            'target': self.target,
            'port': self.port,
            'status': self.status.value,
            'session_id': self.session_id,
            'is_connected': self.is_connected,
            'connection_duration': self.connection_duration,
            'auth_method': self.credentials.method.value,
            'supported_auth': [m.value for m in self.supported_auth],
        }

    def __enter__(self) -> 'BaseLateralModule':
        """上下文管理器入口"""
        if not self.connect():
            raise ConnectionError(
                f"无法连接到 {self.target}:{self.port} "
                f"({self.name})"
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器出口"""
        self.disconnect()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"target={self.target}, "
            f"port={self.port}, "
            f"status={self.status.value})"
        )


class LateralModuleError(Exception):
    """横向移动模块异常基类"""
    pass


class ConnectionError(LateralModuleError):
    """连接错误"""
    pass


class AuthenticationError(LateralModuleError):
    """认证错误"""
    pass


class ExecutionError(LateralModuleError):
    """执行错误"""
    pass


class TransferError(LateralModuleError):
    """传输错误"""
    pass


# 类型别名
CredentialsType = Union[Credentials, Dict[str, Any]]


def ensure_credentials(creds: CredentialsType) -> Credentials:
    """确保凭据为 Credentials 对象"""
    if isinstance(creds, Credentials):
        return creds
    elif isinstance(creds, dict):
        return Credentials(**creds)
    else:
        raise ValueError(f"无效的凭据类型: {type(creds)}")


if __name__ == '__main__':
    # 测试数据结构
    print("=== Lateral Movement Base Module ===")

    # 测试 Credentials
    creds = Credentials(
        username='administrator',
        ntlm_hash='aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
        domain='WORKGROUP'
    )
    print(f"\nCredentials: {creds}")
    print(f"  Method: {creds.method.value}")
    print(f"  LM Hash: {creds.lm_hash}")
    print(f"  NT Hash: {creds.nt_hash}")

    # 测试 ExecutionResult
    result = ExecutionResult(
        success=True,
        output='NT AUTHORITY\\SYSTEM',
        exit_code=0,
        duration=0.5
    )
    print(f"\nExecutionResult: {result.to_dict()}")

    # 测试 LateralConfig
    config = LateralConfig(timeout=60.0, smb_share='C$')
    print(f"\nLateralConfig: {config.to_dict()}")
