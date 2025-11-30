#!/usr/bin/env python3
"""
命令执行器 - 统一的命令执行接口
优化点: 统一命令执行逻辑，减少重复代码
"""

import subprocess
import threading
import time
import sys
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum


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


class ProgressBar:
    """实时进度条 - 优化版"""
    
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
            msg = f"\r{spinner} [{self.tool_name}] {self.target} {bar} {self.progress}% - {self.status}"
            sys.stderr.write(msg + " " * 10)
            sys.stderr.flush()
            idx += 1
            time.sleep(0.1)
    
    def _make_bar(self) -> str:
        filled = int(self.progress / 5)
        empty = 20 - filled
        return f"[{'█' * filled}{'░' * empty}]"
    
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
        env: Optional[Dict] = None
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
        self,
        cmd: List[str],
        timeout: int,
        cwd: Optional[str] = None,
        env: Optional[Dict] = None
    ) -> CommandResult:
        """同步执行"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env
            )
            
            execution_time = time.time() - start_time
            
            return CommandResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                command=" ".join(cmd),
                execution_time=execution_time
            )
        
        except subprocess.TimeoutExpired:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=timeout,
                error="命令执行超时"
            )
        
        except FileNotFoundError:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=0,
                error=f"命令未找到: {cmd[0]}"
            )
        
        except Exception as e:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=time.time() - start_time,
                error=str(e)
            )
    
    def _execute_with_progress(
        self,
        cmd: List[str],
        timeout: int,
        tool_name: str,
        target: str,
        cwd: Optional[str] = None,
        env: Optional[Dict] = None
    ) -> CommandResult:
        """带进度条执行"""
        progress = ProgressBar(tool_name, target, self.enable_progress)
        progress.start()
        start_time = time.time()
        
        try:
            progress.update(10, "启动中...")
            
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env
            )
            
            progress.update(20, "执行中...")
            
            # 模拟进度
            while proc.poll() is None:
                elapsed = time.time() - start_time
                estimated = min(20 + int(elapsed * 70 / timeout), 90)
                progress.update(estimated, "扫描中...")
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
                        error="命令执行超时"
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
                execution_time=execution_time
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
                error=f"命令未找到: {cmd[0]}"
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
                error=str(e)
            )
    
    def _execute_async(
        self,
        cmd: List[str],
        timeout: int,
        cwd: Optional[str] = None,
        env: Optional[Dict] = None
    ) -> CommandResult:
        """异步执行 - 返回立即结果"""
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                env=env
            )
            
            return CommandResult(
                success=True,
                stdout=f"进程已启动 (PID: {proc.pid})",
                stderr="",
                returncode=0,
                command=" ".join(cmd),
                execution_time=0
            )
        
        except Exception as e:
            return CommandResult(
                success=False,
                stdout="",
                stderr="",
                returncode=-1,
                command=" ".join(cmd),
                execution_time=0,
                error=str(e)
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
    use_sudo: bool = False
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
        cmd=cmd,
        timeout=timeout,
        mode=mode,
        tool_name=tool_name,
        target=target,
        use_sudo=use_sudo
    )
    
    return {
        "success": result.success,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "command": result.command,
        "execution_time": result.execution_time,
        "error": result.error
    }
