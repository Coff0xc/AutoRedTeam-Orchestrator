#!/usr/bin/env python3
"""
终端实时显示工具 - 用于MCP工具执行时的进度展示
"""

import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional


class Colors:
    """终端颜色定义"""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


class TerminalDisplay:
    """终端实时显示器"""

    def __init__(self, title: str = "AI Red Team MCP"):
        self.title = title
        self.tasks = []
        self.current_task = None
        self.running = False
        self._lock = threading.Lock()

    def start(self):
        """启动显示器"""
        self.running = True
        self._clear_screen()
        self._print_header()

    def stop(self):
        """停止显示器"""
        self.running = False

    def _clear_screen(self):
        """清屏"""
        os.system("clear" if os.name == "posix" else "cls")

    def _print_header(self):
        """打印头部"""
        print(f"{Colors.CYAN}{'=' * 70}")
        print(f"  {Colors.BOLD}🔥 {self.title}{Colors.END}")
        print(f"{Colors.CYAN}  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 70}{Colors.END}\n")

    def add_task(self, name: str, status: str = "pending"):
        """添加任务"""
        with self._lock:
            self.tasks.append(
                {
                    "name": name,
                    "status": status,
                    "start_time": None,
                    "end_time": None,
                    "result": None,
                }
            )

    def start_task(self, name: str):
        """开始任务"""
        with self._lock:
            for task in self.tasks:
                if task["name"] == name:
                    task["status"] = "running"
                    task["start_time"] = time.time()
                    self.current_task = task
                    break
        self._update_display()

    def complete_task(self, name: str, success: bool = True, result: str = ""):
        """完成任务"""
        with self._lock:
            for task in self.tasks:
                if task["name"] == name:
                    task["status"] = "success" if success else "failed"
                    task["end_time"] = time.time()
                    task["result"] = result
                    break
            self.current_task = None
        self._update_display()

    def _update_display(self):
        """更新显示"""
        status_icons = {
            "pending": f"{Colors.DIM}○{Colors.END}",
            "running": f"{Colors.YELLOW}◉{Colors.END}",
            "success": f"{Colors.GREEN}✓{Colors.END}",
            "failed": f"{Colors.RED}✗{Colors.END}",
        }

        print(f"\n{Colors.BOLD}任务进度:{Colors.END}")
        for task in self.tasks:
            icon = status_icons.get(task["status"], "?")
            duration = ""
            if task["start_time"]:
                if task["end_time"]:
                    duration = f" ({task['end_time'] - task['start_time']:.1f}s)"
                else:
                    duration = f" ({time.time() - task['start_time']:.1f}s...)"

            color = Colors.WHITE
            if task["status"] == "running":
                color = Colors.YELLOW
            elif task["status"] == "success":
                color = Colors.GREEN
            elif task["status"] == "failed":
                color = Colors.RED

            print(f"  {icon} {color}{task['name']}{duration}{Colors.END}")


class LiveProgressBar:
    """实时进度条 - 支持多任务"""

    def __init__(self):
        self.tasks: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """启动进度显示"""
        self._running = True
        self._thread = threading.Thread(target=self._display_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """停止进度显示"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=1)

    def add_task(self, task_id: str, name: str, total: int = 100):
        """添加任务"""
        with self._lock:
            self.tasks[task_id] = {
                "name": name,
                "progress": 0,
                "total": total,
                "status": "pending",
                "message": "",
            }

    def update(self, task_id: str, progress: int, message: str = ""):
        """更新进度"""
        with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id]["progress"] = min(progress, self.tasks[task_id]["total"])
                self.tasks[task_id]["status"] = "running"
                if message:
                    self.tasks[task_id]["message"] = message

    def complete(self, task_id: str, success: bool = True):
        """完成任务"""
        with self._lock:
            if task_id in self.tasks:
                self.tasks[task_id]["progress"] = self.tasks[task_id]["total"]
                self.tasks[task_id]["status"] = "success" if success else "failed"

    def _display_loop(self):
        """显示循环"""
        spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        idx = 0

        while self._running:
            with self._lock:
                lines = []
                for task_id, task in self.tasks.items():
                    if task["status"] == "pending":
                        continue

                    # 构建进度条
                    pct = int(task["progress"] / task["total"] * 100)
                    filled = int(pct / 5)
                    bar = f"[{'█' * filled}{'░' * (20 - filled)}]"

                    # 状态图标
                    if task["status"] == "running":
                        icon = spinners[idx % len(spinners)]
                        color = Colors.YELLOW
                    elif task["status"] == "success":
                        icon = "✓"
                        color = Colors.GREEN
                    else:
                        icon = "✗"
                        color = Colors.RED

                    line = (
                        f"\r{color}{icon} [{task['name']}] {bar}"
                        f" {pct}% - {task['message']}{Colors.END}"
                    )
                    lines.append(line)

                if lines:
                    # 移动光标并打印
                    sys.stderr.write("\033[2K")  # 清除当前行
                    sys.stderr.write(lines[-1] + " " * 10)
                    sys.stderr.flush()

            idx += 1
            time.sleep(0.1)


def run_with_terminal_display(cmd: List[str], task_name: str, timeout: int = 300) -> Dict:
    """带终端显示运行命令"""
    progress = LiveProgressBar()
    task_id = f"task_{time.time()}"

    progress.add_task(task_id, task_name)
    progress.start()

    try:
        progress.update(task_id, 10, "启动中...")

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        progress.update(task_id, 20, "执行中...")

        start_time = time.time()
        while proc.poll() is None:
            elapsed = time.time() - start_time
            estimated = min(20 + int(elapsed * 70 / timeout), 90)
            progress.update(task_id, estimated, "扫描中...")
            time.sleep(0.5)

            if elapsed > timeout:
                proc.kill()
                progress.complete(task_id, False)
                progress.stop()
                return {"success": False, "error": "超时"}

        stdout, stderr = proc.communicate()
        progress.update(task_id, 95, "处理结果...")

        success = proc.returncode == 0
        progress.complete(task_id, success)
        progress.stop()

        # 打印完成状态
        icon = "✓" if success else "✗"
        color = Colors.GREEN if success else Colors.RED
        sys.stderr.write(
            f"\r{color}{icon} [{task_name}] [████████████████████] 100% - 完成{Colors.END}\n"
        )
        sys.stderr.flush()

        return {"success": success, "stdout": stdout, "stderr": stderr, "command": " ".join(cmd)}

    except FileNotFoundError:
        progress.complete(task_id, False)
        progress.stop()
        return {"success": False, "error": f"未找到: {cmd[0]}"}
    except Exception as e:
        progress.complete(task_id, False)
        progress.stop()
        return {"success": False, "error": str(e)}


def check_tool_availability(tools: List[str]) -> Dict[str, bool]:
    """检查工具可用性"""
    results = {}
    for tool in tools:
        try:
            result = subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
            results[tool] = result.returncode == 0
        except Exception:
            results[tool] = False
    return results


def print_tool_status(tools: Dict[str, bool]):
    """打印工具状态"""
    print(f"\n{Colors.BOLD}工具可用性检查:{Colors.END}")
    for tool, available in tools.items():
        if available:
            print(f"  {Colors.GREEN}✓ {tool}{Colors.END}")
        else:
            print(f"  {Colors.RED}✗ {tool} (未安装){Colors.END}")


if __name__ == "__main__":
    # 测试
    print("测试终端显示功能...")

    # 检查常用工具
    tools = ["nmap", "subfinder", "whatweb", "wafw00f", "httpx", "nuclei", "gobuster"]
    status = check_tool_availability(tools)
    print_tool_status(status)
