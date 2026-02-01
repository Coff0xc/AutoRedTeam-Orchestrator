#!/usr/bin/env python3
"""
命令执行器 - 统一的命令执行接口
优化点: 统一命令执行逻辑，减少重复代码

安全特性:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- shell=False 强制禁用 (防止命令注入)
- 命令白名单验证
- 危险命令检测与警告
- 执行日志审计
- 超时保护

使用示例:
    from utils.command_executor import execute_command, safe_execute

    # 推荐: 使用列表形式的命令
    result = execute_command(["nmap", "-sV", "192.168.1.1"])

    # 安全执行 (带验证)
    result = safe_execute(["ls", "-la"], allowed_commands=["ls", "cat", "grep"])
"""

import logging
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ============================================================================
# 安全配置
# ============================================================================

# 危险命令列表 (执行时会记录警告)
DANGEROUS_COMMANDS: Set[str] = {
    "rm",
    "rmdir",
    "del",
    "format",
    "mkfs",
    "dd",
    "shred",
    "wipefs",
    "chmod",
    "chown",
    "chattr",
    "kill",
    "killall",
    "pkill",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "iptables",
    "firewall-cmd",
    "ufw",
    "passwd",
    "useradd",
    "userdel",
    "usermod",
    "visudo",
    "sudoers",
}

# 禁止的命令 (完全阻止执行)
BLOCKED_COMMANDS: Set[str] = {
    ":(){ :|:& };:",  # Fork bomb
    ">/dev/sda",
    "mkfs.ext4",
}

# Shell 元字符 (用于检测潜在的命令注入)
SHELL_METACHARACTERS = re.compile(r'[;&|`$(){}[\]<>\\\'"]')


class ExecutionMode(Enum):
    """执行模式"""

    SYNC = "sync"  # 同步执行
    ASYNC = "async"  # 异步执行
    PROGRESS = "progress"  # 带进度条执行


@dataclass
class CommandResult:
    """命令执行结果"""

    success: bool
    stdout: str
    stderr: str
    returncode: int
    command: str
    execution_time: float
    error: Optional[str] = None
    # 安全审计字段
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    warnings: List[str] = field(default_factory=list)
    shell_used: bool = False  # 是否使用了 shell=True (应始终为 False)


class ProgressBar:
    """
    实时进度条 - 诚实版

    进度模式:
    - progress > 0: 显示真实百分比进度条
    - progress = 0: 显示旋转指示器 (表示"进行中，进度未知")
    """

    SPINNERS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, tool_name: str, target: str, enable: bool = True):
        self.tool_name = tool_name
        self.target = target
        self.progress = 0
        self.status = "初始化"
        self.running = False
        self._thread = None
        self.enable = enable

    def start(self):
        if not self.enable:
            return self
        self.running = True
        self.progress = 0
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()
        return self

    def _animate(self):
        idx = 0
        while self.running:
            spinner = self.SPINNERS[idx % len(self.SPINNERS)]
            bar = self._make_bar()
            msg = f"\r{spinner} [{self.tool_name}] {self.target} {bar} - {self.status}"
            sys.stderr.write(msg + " " * 10)
            sys.stderr.flush()
            idx += 1
            time.sleep(0.1)

    def _make_bar(self) -> str:
        """生成进度条 (诚实模式)"""
        if self.progress == 0:
            # 进度未知时显示旋转动画而非假进度
            return "[····进行中····]"
        else:
            # 有真实进度时显示百分比
            filled = int(self.progress / 5)
            empty = 20 - filled
            return f"[{'█' * filled}{'░' * empty}] {self.progress}%"

    def update(self, progress: int, status: str = None):
        self.progress = min(progress, 100)
        if status:
            self.status = status

    def complete(self, success: bool = True):
        if not self.enable:
            return
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=0.5)
        self.progress = 100
        icon = "✓" if success else "✗"
        bar = self._make_bar()
        msg = f"\r{icon} [{self.tool_name}] {self.target} {bar} 100% - {'完成' if success else '失败'}\n"
        sys.stderr.write(msg)
        sys.stderr.flush()


class CommandExecutor:
    """统一命令执行器"""

    def __init__(self, default_timeout: int = 300, enable_progress: bool = True):
        self.default_timeout = default_timeout
        self.enable_progress = enable_progress

    def execute(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        mode: ExecutionMode = ExecutionMode.SYNC,
        tool_name: str = "command",
        target: str = "",
        use_sudo: bool = False,
        cwd: Optional[str] = None,
        env: Optional[Dict] = None,
    ) -> CommandResult:
        """
        执行命令

        Args:
            cmd: 命令列表
            timeout: 超时时间(秒)
            mode: 执行模式
            tool_name: 工具名称(用于进度显示)
            target: 目标(用于进度显示)
            use_sudo: 是否使用sudo
            cwd: 工作目录
            env: 环境变量

        Returns:
            CommandResult: 执行结果
        """
        timeout = timeout or self.default_timeout

        if use_sudo and cmd[0] != "sudo":
            cmd = ["sudo"] + cmd

        if mode == ExecutionMode.PROGRESS:
            return self._execute_with_progress(cmd, timeout, tool_name, target, cwd, env)
        elif mode == ExecutionMode.ASYNC:
            return self._execute_async(cmd, timeout, cwd, env)
        else:
            return self._execute_sync(cmd, timeout, cwd, env)

    def _execute_sync(
        self, cmd: List[str], timeout: int, cwd: Optional[str] = None, env: Optional[Dict] = None
    ) -> CommandResult:
        """同步执行"""
        start_time = time.time()

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env
            )

            execution_time = time.time() - start_time

            return CommandResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                command=" ".join(cmd),
                execution_time=execution_time,
            )

        except subprocess.TimeoutExpired:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=timeout,
                error="命令执行超时",
            )

        except FileNotFoundError:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=0,
                error=f"命令未找到: {cmd[0]}",
            )

        except Exception as e:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def _execute_with_progress(
        self,
        cmd: List[str],
        timeout: int,
        tool_name: str,
        target: str,
        cwd: Optional[str] = None,
        env: Optional[Dict] = None,
    ) -> CommandResult:
        """带进度条执行"""
        progress = ProgressBar(tool_name, target, self.enable_progress)
        progress.start()
        start_time = time.time()

        try:
            progress.update(0, "启动中...")

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd, env=env
            )

            progress.update(0, "执行中...")

            # 诚实进度: 不模拟百分比，只显示状态和已用时间
            while proc.poll() is None:
                elapsed = time.time() - start_time
                # 显示已用时间而非假进度
                progress.update(0, f"运行中... ({elapsed:.0f}s)")
                time.sleep(0.5)

                if elapsed > timeout:
                    proc.kill()
                    progress.complete(False)
                    return CommandResult(
                        success=False,
                        stdout="",
                        stderr="",
                        returncode=-1,
                        command=" ".join(cmd),
                        execution_time=elapsed,
                        error="命令执行超时",
                    )

            stdout, stderr = proc.communicate()
            progress.update(95, "处理结果...")

            execution_time = time.time() - start_time
            success = proc.returncode == 0
            progress.complete(success)

            return CommandResult(
                success=success,
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode,
                command=" ".join(cmd),
                execution_time=execution_time,
            )

        except FileNotFoundError:
            progress.complete(False)
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=0,
                error=f"命令未找到: {cmd[0]}",
            )

        except Exception as e:
            progress.complete(False)
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def _execute_async(
        self, cmd: List[str], timeout: int, cwd: Optional[str] = None, env: Optional[Dict] = None
    ) -> CommandResult:
        """异步执行 - 返回立即结果"""
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd, env=env
            )

            return CommandResult(
                success=True,
                stdout=f"进程已启动 (PID: {proc.pid})",
                stderr="",
                returncode=0,
                command=" ".join(cmd),
                execution_time=0,
            )

        except Exception as e:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=0,
                error=str(e),
            )


# 全局执行器实例
_executor = None


def get_executor() -> CommandExecutor:
    """获取全局执行器实例"""
    global _executor
    if _executor is None:
        _executor = CommandExecutor()
    return _executor


def execute_command(
    cmd: List[str],
    timeout: int = 300,
    with_progress: bool = False,
    tool_name: str = "command",
    target: str = "",
    use_sudo: bool = False,
) -> Dict:
    """
    便捷函数: 执行命令并返回字典格式结果

    Args:
        cmd: 命令列表
        timeout: 超时时间
        with_progress: 是否显示进度条
        tool_name: 工具名称
        target: 目标
        use_sudo: 是否使用sudo

    Returns:
        Dict: 包含success, stdout, stderr, command等字段的字典
    """
    executor = get_executor()
    mode = ExecutionMode.PROGRESS if with_progress else ExecutionMode.SYNC

    result = executor.execute(
        cmd=cmd, timeout=timeout, mode=mode, tool_name=tool_name, target=target, use_sudo=use_sudo
    )

    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "command": result.command,
        "execution_time": result.execution_time,
        "error": result.error,
        "warnings": result.warnings,
        "timestamp": result.timestamp,
    }


# ============================================================================
# 安全验证函数
# ============================================================================


def validate_command(cmd: List[str]) -> tuple[bool, List[str]]:
    """
    验证命令安全性

    Args:
        cmd: 命令列表

    Returns:
        tuple: (是否安全, 警告列表)
    """
    warnings = []

    if not cmd:
        return False, ["空命令"]

    base_cmd = cmd[0].split("/")[-1].split("\\")[-1]  # 获取命令名

    # 检查是否为阻止的命令
    cmd_str = " ".join(cmd)
    for blocked in BLOCKED_COMMANDS:
        if blocked in cmd_str:
            return False, [f"命令被阻止: 包含危险模式 '{blocked}'"]

    # 检查是否为危险命令
    if base_cmd in DANGEROUS_COMMANDS:
        warnings.append(f"危险命令警告: '{base_cmd}' 可能造成系统损坏")
        logger.warning(f"执行危险命令: {cmd_str}")

    # 检查参数中的 shell 元字符
    for arg in cmd[1:]:
        if SHELL_METACHARACTERS.search(arg):
            warnings.append(f"参数包含 shell 元字符: '{arg}'")

    return True, warnings


def check_command_exists(cmd: str) -> bool:
    """检查命令是否存在"""
    return shutil.which(cmd) is not None


def safe_execute(
    cmd: List[str],
    allowed_commands: Optional[List[str]] = None,
    timeout: int = 300,
    validate: bool = True,
) -> Dict:
    """
    安全执行命令 (带验证)

    Args:
        cmd: 命令列表 (禁止字符串形式)
        allowed_commands: 允许的命令白名单
        timeout: 超时时间
        validate: 是否进行安全验证

    Returns:
        Dict: 执行结果
    """
    warnings = []

    # 类型检查
    if isinstance(cmd, str):
        return {
            "success": False,
            "error": "安全错误: 禁止使用字符串形式的命令，请使用列表",
            "warnings": ["shell=True 已被禁用"],
        }

    if not cmd:
        return {"success": False, "error": "空命令", "warnings": []}

    base_cmd = cmd[0].split("/")[-1].split("\\")[-1]

    # 白名单检查
    if allowed_commands and base_cmd not in allowed_commands:
        return {
            "success": False,
            "error": f"命令 '{base_cmd}' 不在白名单中",
            "warnings": [f"允许的命令: {allowed_commands}"],
        }

    # 安全验证
    if validate:
        is_safe, val_warnings = validate_command(cmd)
        warnings.extend(val_warnings)
        if not is_safe:
            return {
                "success": False,
                "error": val_warnings[0] if val_warnings else "命令验证失败",
                "warnings": warnings,
            }

    # 检查命令是否存在
    if not check_command_exists(cmd[0]):
        return {
            "success": False,
            "error": f"命令未找到: {cmd[0]}",
            "warnings": warnings,
        }

    # 执行命令
    result = execute_command(cmd, timeout=timeout)
    result["warnings"] = warnings + result.get("warnings", [])

    # 记录审计日志
    logger.info(f"命令执行: {' '.join(cmd)} -> {'成功' if result['success'] else '失败'}")

    return result
