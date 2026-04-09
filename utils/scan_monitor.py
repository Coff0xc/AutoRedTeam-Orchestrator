#!/usr/bin/env python3
"""
扫描监控模块
- 防止超时
- 实时进度监控
- 任务状态管理
- 超时自动终止
"""

import logging

logger = logging.getLogger(__name__)

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional

# 导入终端输出
try:
    from utils.terminal_output import terminal
except ImportError:
    from terminal_output import terminal  # type: ignore[no-redef]


class ScanStatus(Enum):
    """扫描状态"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"
    CANCELLED = "cancelled"


@dataclass
class ScanTask:
    """扫描任务"""

    task_id: str
    tool_name: str
    target: str
    command: List[str]
    timeout: int
    status: ScanStatus = ScanStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    process: Optional[subprocess.Popen] = None
    result: Optional[Dict] = None
    stdout_lines: List[str] = field(default_factory=list)
    stderr_lines: List[str] = field(default_factory=list)
    progress: int = 0  # 0-100
    last_activity: Optional[datetime] = None


class ScanMonitor:
    """扫描监控器 - 管理所有扫描任务"""

    # 默认超时配置 (秒)
    DEFAULT_TIMEOUTS = {
        "nmap": 300,
        "nuclei": 600,
        "nikto": 600,
        "sqlmap": 900,
        "gobuster": 900,
        "subfinder": 120,
        "whatweb": 60,
        "wafw00f": 60,
        "httpx": 120,
        "default": 300,
    }

    # 无活动超时 (秒) - 如果工具在这段时间内没有输出，认为它卡住了
    INACTIVITY_TIMEOUT = 120

    def __init__(self):
        self.tasks: Dict[str, ScanTask] = {}
        self.lock = threading.Lock()
        self.monitor_thread: Optional[threading.Thread] = None
        self.running = False
        self._task_counter = 0

        # 启动监控线程
        self._start_monitor()

    def _start_monitor(self):
        """启动后台监控线程"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _monitor_loop(self):
        """监控循环 - 检查所有任务状态"""
        while self.running:
            try:
                self._check_tasks()
                time.sleep(1)  # 每秒检查一次
            except Exception as e:
                terminal.error(f"监控循环错误: {e}")

    def _check_tasks(self):
        """检查所有运行中的任务"""
        with self.lock:
            for task_id, task in list(self.tasks.items()):
                if task.status != ScanStatus.RUNNING:
                    continue

                now = datetime.now()

                # 检查总超时
                if task.start_time:
                    elapsed = (now - task.start_time).total_seconds()
                    if elapsed > task.timeout:
                        self._timeout_task(task, f"总超时 ({task.timeout}s)")
                        continue

                # 检查无活动超时
                if task.last_activity:
                    inactive = (now - task.last_activity).total_seconds()
                    if inactive > self.INACTIVITY_TIMEOUT:
                        self._timeout_task(task, f"无活动超时 ({self.INACTIVITY_TIMEOUT}s)")
                        continue

                # 更新进度估算
                if task.start_time:
                    elapsed = (now - task.start_time).total_seconds()
                    task.progress = min(int((elapsed / task.timeout) * 100), 99)

    def _timeout_task(self, task: ScanTask, reason: str):
        """超时终止任务"""
        terminal.warning(f"⏰ [{task.tool_name}] {reason} - 终止任务")

        if task.process:
            try:
                task.process.kill()
                task.process.wait(timeout=5)
            except Exception:
                try:
                    os.kill(task.process.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                except Exception:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        task.status = ScanStatus.TIMEOUT
        task.end_time = datetime.now()
        task.result = {
            "success": False,
            "error": reason,
            "partial_stdout": "\n".join(task.stdout_lines[-100:]),  # 最后100行
            "partial_stderr": "\n".join(task.stderr_lines[-100:]),
            "command": " ".join(task.command),
        }

    def _generate_task_id(self) -> str:
        """生成任务ID"""
        self._task_counter += 1
        return f"scan_{self._task_counter}_{int(time.time())}"

    def get_timeout(self, tool_name: str) -> int:
        """获取工具的默认超时时间"""
        return self.DEFAULT_TIMEOUTS.get(tool_name.lower(), self.DEFAULT_TIMEOUTS["default"])

    def create_task(
        self, tool_name: str, target: str, command: List[str], timeout: Optional[int] = None
    ) -> ScanTask:
        """创建扫描任务"""
        task_id = self._generate_task_id()

        if timeout is None:
            timeout = self.get_timeout(tool_name)

        task = ScanTask(
            task_id=task_id, tool_name=tool_name, target=target, command=command, timeout=timeout
        )

        with self.lock:
            self.tasks[task_id] = task

        return task

    def run_task(self, task: ScanTask, show_output: bool = True) -> Dict:
        """运行扫描任务（带监控）"""
        task.status = ScanStatus.RUNNING
        task.start_time = datetime.now()
        task.last_activity = datetime.now()

        # 打印任务开始信息
        terminal.tool_start(task.tool_name, task.target, task.command)
        terminal.info(f"任务ID: {task.task_id} | 超时: {task.timeout}s")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        try:
            task.process = subprocess.Popen(
                task.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
            )

            output_count = [0]  # 使用列表以便在闭包中修改

            def read_output(stream, lines_list, is_stderr):
                try:
                    for line in iter(stream.readline, ""):
                        if not line:
                            break

                        s_line = line.rstrip()
                        lines_list.append(s_line)
                        task.last_activity = datetime.now()

                        if show_output and output_count[0] < 1000:
                            terminal.tool_output(s_line, is_stderr)
                            output_count[0] += 1
                        elif output_count[0] == 1000:
                            terminal.warning("... 输出过多，后续隐藏")
                            output_count[0] += 1
                except Exception:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            stdout_thread = threading.Thread(
                target=read_output,
                args=(task.process.stdout, task.stdout_lines, False),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=read_output, args=(task.process.stderr, task.stderr_lines, True), daemon=True
            )

            stdout_thread.start()
            stderr_thread.start()

            # 等待进程完成
            try:
                task.process.wait(timeout=task.timeout)
            except subprocess.TimeoutExpired:
                self._timeout_task(task, f"执行超时 ({task.timeout}s)")
                assert task.result is not None  # _timeout_task 总是设置 result
                return task.result

            # 等待IO线程
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

            task.status = ScanStatus.COMPLETED
            task.end_time = datetime.now()
            task.progress = 100

            duration = (task.end_time - task.start_time).total_seconds()
            success = task.process.returncode == 0

            terminal.tool_complete(task.tool_name, success, duration)

            task.result = {
                "success": success,
                "stdout": "\n".join(task.stdout_lines),
                "stderr": "\n".join(task.stderr_lines),
                "returncode": task.process.returncode,
                "command": " ".join(task.command),
                "duration": duration,
                "task_id": task.task_id,
            }
            return task.result

        except FileNotFoundError:
            task.status = ScanStatus.ERROR
            task.end_time = datetime.now()
            terminal.error(f"🔧 工具未找到: {task.command[0]}")
            task.result = {
                "success": False,
                "error": f"工具未找到: {task.command[0]}",
                "command": " ".join(task.command),
            }
            return task.result

        except Exception as e:
            task.status = ScanStatus.ERROR
            task.end_time = datetime.now()
            terminal.error(f"❌ 执行错误: {str(e)}")
            task.result = {"success": False, "error": str(e), "command": " ".join(task.command)}
            return task.result

    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                return False

            if task.status != ScanStatus.RUNNING:
                return False

            if task.process:
                try:
                    task.process.kill()
                except Exception:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            task.status = ScanStatus.CANCELLED
            task.end_time = datetime.now()
            terminal.warning(f"任务已取消: {task_id}")
            return True

    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """获取任务状态"""
        task = self.tasks.get(task_id)
        if not task:
            return None

        elapsed: float = 0
        if task.start_time:
            end = task.end_time or datetime.now()
            elapsed = (end - task.start_time).total_seconds()

        return {
            "task_id": task.task_id,
            "tool_name": task.tool_name,
            "target": task.target,
            "status": task.status.value,
            "progress": task.progress,
            "elapsed_seconds": elapsed,
            "timeout": task.timeout,
            "output_lines": len(task.stdout_lines) + len(task.stderr_lines),
        }

    def get_running_tasks(self) -> List[Dict]:
        """获取所有运行中的任务"""
        running = []
        for task_id, task in self.tasks.items():
            if task.status == ScanStatus.RUNNING:
                status = self.get_task_status(task_id)
                if status is not None:
                    running.append(status)
        return running

    def cleanup_old_tasks(self, max_age_hours: int = 24):
        """清理旧任务"""
        cutoff = datetime.now() - timedelta(hours=max_age_hours)
        with self.lock:
            to_remove = []
            for task_id, task in self.tasks.items():
                if task.end_time and task.end_time < cutoff:
                    to_remove.append(task_id)
            for task_id in to_remove:
                del self.tasks[task_id]

        if to_remove:
            terminal.info(f"已清理 {len(to_remove)} 个旧任务")


# 全局监控器实例
scan_monitor = ScanMonitor()


def run_monitored_scan(
    cmd: List[str],
    tool_name: str,
    target: str,
    timeout: Optional[int] = None,
    show_output: bool = True,
) -> Dict:
    """
    运行带监控的扫描 - 替代 run_with_realtime_output

    特性:
    - 自动超时管理
    - 无活动检测
    - 任务状态追踪
    - 实时输出显示
    """
    task = scan_monitor.create_task(tool_name, target, cmd, timeout)
    return scan_monitor.run_task(task, show_output)


def get_scan_status(task_id: str) -> Optional[Dict]:
    """获取扫描状态"""
    return scan_monitor.get_task_status(task_id)


def cancel_scan(task_id: str) -> bool:
    """取消扫描"""
    return scan_monitor.cancel_task(task_id)


def list_running_scans() -> List[Dict]:
    """列出运行中的扫描"""
    return scan_monitor.get_running_tasks()


# 快速测试
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    terminal.header("扫描监控模块测试")

    # 测试正常执行
    result = run_monitored_scan(["echo", "Hello from monitored scan!"], "echo", "test", timeout=10)
    logger.info("结果: %s", result["success"])

    # 测试超时
    terminal.info("测试超时场景...")
    result = run_monitored_scan(["sleep", "100"], "sleep", "test", timeout=3)
    logger.info("超时测试结果: %s", result)
