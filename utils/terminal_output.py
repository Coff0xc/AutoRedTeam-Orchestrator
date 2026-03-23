#!/usr/bin/env python3
"""
终端实时输出模块
在MCP工具执行时显示实时进度和输出到终端
"""

import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

# 日志文件路径
LOG_FILE = os.path.join(tempfile.gettempdir(), "mcp_redteam_live.log")

logger = logging.getLogger(__name__)


class TerminalLogger:
    """终端日志输出器 - 绕过MCP的stdout通信

    支持上下文管理器协议，确保资源正确释放。
    """

    # ANSI颜色
    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }

    def __init__(self):
        self.log_file = None
        self.real_tty = None
        self.lock = threading.Lock()
        self.enabled = True

        # 尝试打开日志文件
        try:
            self.log_file = open(LOG_FILE, "a", buffering=1, encoding="utf-8")
        except OSError as e:
            logger.debug("无法打开日志文件: %s", e)

        # 跨平台：仅在 Unix 系统尝试获取真实 TTY
        if sys.platform != "win32":
            try:
                self.real_tty = open("/dev/tty", "w", encoding="utf-8")
            except OSError as e:
                logger.debug("无法打开 /dev/tty: %s", e)

    def __enter__(self):
        """上下文管理器入口"""
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        """上下文管理器出口 - 确保资源释放"""
        self.close()
        return False  # 不抑制异常

    def __del__(self):
        """析构时关闭文件句柄，作为后备清理"""
        self.close()

    def close(self):
        """显式关闭所有文件句柄"""
        with self.lock:
            if self.log_file is not None:
                try:
                    self.log_file.close()
                except OSError:
                    pass
                self.log_file = None

            if self.real_tty is not None:
                try:
                    self.real_tty.close()
                except OSError:
                    pass
                self.real_tty = None

    def _write(self, msg: str):
        """线程安全写入"""
        if not self.enabled:
            return
        with self.lock:
            # 1. 写入日志文件
            if self.log_file:
                try:
                    self.log_file.write(msg)
                    self.log_file.flush()
                except Exception:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            # 2. 写入标准错误 (MCP兼容方式)
            try:
                sys.stderr.write(msg)
                sys.stderr.flush()
            except Exception:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            # 3. 写入真实终端 (如果可用)
            if self.real_tty:
                try:
                    self.real_tty.write(msg)
                    self.real_tty.flush()
                except Exception:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def print(self, msg: str, color: Optional[str] = None, bold: bool = False):
        """打印带颜色的消息"""
        prefix = ""
        suffix = self.COLORS["reset"]
        if bold:
            prefix += self.COLORS["bold"]
        if color and color in self.COLORS:
            prefix += self.COLORS[color]
        self._write(f"{prefix}{msg}{suffix}\n")

    def header(self, title: str):
        """打印标题头"""
        line = "=" * 60
        self._write(f"\n{self.COLORS['cyan']}{line}\n")
        self._write(f"  🔧 {title}\n")
        self._write(f"{line}{self.COLORS['reset']}\n\n")

    def tool_start(self, tool_name: str, target: str, cmd: List[str]):
        """工具开始执行"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._write(
            f"\n{self.COLORS['yellow']}"
            "┌──────────────────────────────────────────────────────────\n"
        )
        self._write(
            f"│ [{timestamp}] 🚀 {self.COLORS['bold']}{tool_name}"
            f"{self.COLORS['reset']}{self.COLORS['yellow']}\n"
        )
        self._write(f"│ 目标: {self.COLORS['cyan']}{target}{self.COLORS['yellow']}\n")
        self._write(f"│ 命令: {self.COLORS['white']}{' '.join(cmd)}{self.COLORS['yellow']}\n")
        self._write(
            f"└──────────────────────────────────────────────────────────{self.COLORS['reset']}\n"
        )

    def tool_progress(self, msg: str):
        """工具进度更新"""
        self._write(f"  {self.COLORS['blue']}⟳{self.COLORS['reset']} {msg}\n")

    def tool_output(self, line: str, is_stderr: bool = False):
        """实时输出"""
        color = self.COLORS["red"] if is_stderr else self.COLORS["white"]
        # 限制行长度 - 增加长度以减少截断感
        if len(line) > 200:
            line = line[:197] + "..."

        # 构造带颜色的行，减少多次 write 调用
        formatted = f"  {color}│{self.COLORS['reset']} {line}\n"
        self._write(formatted)

    def tool_complete(self, tool_name: str, success: bool, duration: float):
        """工具完成"""
        status = f"{self.COLORS['green']}✓ 成功" if success else f"{self.COLORS['red']}✗ 失败"
        self._write(
            f"\n{self.COLORS['yellow']}"
            "┌──────────────────────────────────────────────────────────\n"
        )
        self._write(f"│ {status}{self.COLORS['yellow']} | {tool_name} | 耗时: {duration:.1f}s\n")
        self._write(
            f"└──────────────────────────────────────────────────────────{self.COLORS['reset']}\n\n"
        )

    def info(self, msg: str):
        """信息消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._write(f"{self.COLORS['blue']}[{timestamp}] ℹ {self.COLORS['reset']}{msg}\n")

    def warning(self, msg: str):
        """警告消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._write(f"{self.COLORS['yellow']}[{timestamp}] ⚠ {msg}{self.COLORS['reset']}\n")

    def error(self, msg: str):
        """错误消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._write(f"{self.COLORS['red']}[{timestamp}] ✗ {msg}{self.COLORS['reset']}\n")

    def success(self, msg: str):
        """成功消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._write(f"{self.COLORS['green']}[{timestamp}] ✓ {msg}{self.COLORS['reset']}\n")

    def finding(self, title: str, details: Optional[str] = None):
        """发现/结果消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if details:
            self._write(
                f"{self.COLORS['magenta']}[{timestamp}] 🎯 {title}: "
                f"{self.COLORS['cyan']}{details}{self.COLORS['reset']}\n"
            )
        else:
            self._write(f"{self.COLORS['magenta']}[{timestamp}] 🎯 {title}{self.COLORS['reset']}\n")


# 线程安全的单例模式
_terminal_instance: Optional[TerminalLogger] = None
_terminal_lock = threading.Lock()


def get_terminal() -> TerminalLogger:
    """获取全局终端日志实例（线程安全）"""
    global _terminal_instance
    if _terminal_instance is None:
        with _terminal_lock:
            if _terminal_instance is None:
                _terminal_instance = TerminalLogger()
    return _terminal_instance


# 兼容性别名
terminal = get_terminal()


def run_with_realtime_output(
    cmd: List[str],
    tool_name: str,
    target: str,
    timeout: int = 300,
    show_output: bool = True,
    max_output_lines: int = 1000,  # 增加默认显示行数
) -> Dict:
    """
    运行命令并实时显示输出到终端 (优化版)
    """
    terminal.tool_start(tool_name, target, cmd)
    start_time = time.time()

    # 准备环境变量，强制禁用缓冲
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["NSUnbufferedIO"] = "YES"  # 部分工具支持

    try:
        # 启动进程
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # 行缓冲
            env=env,
        )

        stdout_lines: List[str] = []
        stderr_lines: List[str] = []

        # 使用列表作为简单的计数器引用
        state = {"output_count": 0, "killed": False}

        # 优化的读取函数
        def read_stream(stream, lines_list, is_stderr):
            try:
                for line in iter(stream.readline, ""):
                    if not line:
                        break

                    s_line = line.rstrip()
                    lines_list.append(s_line)

                    if show_output:
                        if state["output_count"] < max_output_lines:
                            terminal.tool_output(s_line, is_stderr)
                            state["output_count"] += 1
                        elif state["output_count"] == max_output_lines:
                            terminal.warning("... 输出过多，后续内容已隐藏 (仍在后台记录)")
                            state["output_count"] += 1
            except ValueError:
                pass  # 文件已关闭
            except Exception:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        stdout_thread = threading.Thread(
            target=read_stream, args=(proc.stdout, stdout_lines, False)
        )
        stderr_thread = threading.Thread(target=read_stream, args=(proc.stderr, stderr_lines, True))

        # 设为守护线程，防止主进程退出时卡住
        stdout_thread.daemon = True
        stderr_thread.daemon = True

        stdout_thread.start()
        stderr_thread.start()

        # 等待完成或超时
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            state["killed"] = True
            proc.kill()
            terminal.error(f"⏰ 命令超时 ({timeout}s) - 进程已终止")

            # 即使超时也尝试等待线程结束(给一点点时间)
            stdout_thread.join(timeout=0.1)
            stderr_thread.join(timeout=0.1)

            return {"success": False, "error": f"超时 ({timeout}s)", "command": " ".join(cmd)}

        # 等待IO线程完成
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)

        duration = time.time() - start_time
        success = proc.returncode == 0

        terminal.tool_complete(tool_name, success, duration)

        return {
            "success": success,
            "stdout": "\n".join(stdout_lines),
            "stderr": "\n".join(stderr_lines),
            "returncode": proc.returncode,
            "command": " ".join(cmd),
            "duration": duration,
        }

    except FileNotFoundError:
        duration = time.time() - start_time
        terminal.tool_complete(tool_name, False, duration)
        terminal.error(f"🔧 工具未找到: {cmd[0]}")
        return {"success": False, "error": f"工具未找到: {cmd[0]}", "command": " ".join(cmd)}
    except Exception as e:
        duration = time.time() - start_time
        terminal.tool_complete(tool_name, False, duration)
        terminal.error(f"❌ 执行错误: {str(e)}")
        return {"success": False, "error": str(e), "command": " ".join(cmd)}


def print_scan_summary(results: Dict):
    """打印扫描摘要"""
    terminal.header("扫描结果摘要")

    if "subdomains" in results:
        terminal.finding(f"子域名: {len(results['subdomains'])} 个")

    if "ports" in results:
        terminal.finding(f"开放端口: {len(results['ports'])} 个")

    if "vulnerabilities" in results:
        terminal.finding(f"潜在漏洞: {len(results['vulnerabilities'])} 个", "需要验证")


# 快速测试
if __name__ == "__main__":
    terminal.header("终端输出测试")
    terminal.info("这是信息消息")
    terminal.warning("这是警告消息")
    terminal.error("这是错误消息")
    terminal.finding("发现漏洞", "SQL注入 @ /api/login")

    # 测试命令执行
    result = run_with_realtime_output(["echo", "Hello World"], "echo", "test", timeout=10)
    print(f"\n结果: {result}")
