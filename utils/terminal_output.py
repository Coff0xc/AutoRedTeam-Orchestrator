#!/usr/bin/env python3
"""
终端实时输出模块
在MCP工具执行时显示实时进度和输出到终端
"""

import sys
import os
import time
import threading
import subprocess
from typing import Dict, List, Optional, Callable
from datetime import datetime

# 日志文件路径
LOG_FILE = "/tmp/mcp_redteam_live.log"

# 尝试打开真正的终端或日志文件
def get_tty():
    """获取输出目标 - 优先日志文件，方便tail -f查看"""
    try:
        # 始终写入日志文件，方便用户用 tail -f 查看
        log_file = open(LOG_FILE, 'a', buffering=1)  # 行缓冲
        return log_file
    except:
        try:
            return open('/dev/tty', 'w')
        except:
            return sys.stderr


class TerminalLogger:
    """终端日志输出器 - 绕过MCP的stdout通信"""
    
    # ANSI颜色
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    
    def __init__(self):
        # 尝试打开日志文件
        try:
            self.log_file = open(LOG_FILE, 'a', buffering=1)
        except:
            self.log_file = None
            
        self.lock = threading.Lock()
        self.enabled = True
        
        # 尝试获取真实的 TTY (直接控制台输出)
        self.real_tty = None
        try:
            self.real_tty = open('/dev/tty', 'w')
        except:
            pass
    
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
                except:
                    pass
            
            # 2. 写入标准错误 (MCP兼容方式)
            try:
                sys.stderr.write(msg)
                sys.stderr.flush()
            except:
                pass
                
            # 3. 写入真实终端 (如果可用)
            if self.real_tty:
                try:
                    self.real_tty.write(msg)
                    self.real_tty.flush()
                except:
                    pass
    
    def print(self, msg: str, color: str = None, bold: bool = False):
        """打印带颜色的消息"""
        prefix = ""
        suffix = self.COLORS['reset']
        if bold:
            prefix += self.COLORS['bold']
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
        self._write(f"\n{self.COLORS['yellow']}┌──────────────────────────────────────────────────────────\n")
        self._write(f"│ [{timestamp}] 🚀 {self.COLORS['bold']}{tool_name}{self.COLORS['reset']}{self.COLORS['yellow']}\n")
        self._write(f"│ 目标: {self.COLORS['cyan']}{target}{self.COLORS['yellow']}\n")
        self._write(f"│ 命令: {self.COLORS['white']}{' '.join(cmd)}{self.COLORS['yellow']}\n")
        self._write(f"└──────────────────────────────────────────────────────────{self.COLORS['reset']}\n")
    
    def tool_progress(self, msg: str):
        """工具进度更新"""
        self._write(f"  {self.COLORS['blue']}⟳{self.COLORS['reset']} {msg}\n")
    
    def tool_output(self, line: str, is_stderr: bool = False):
        """实时输出"""
        color = self.COLORS['red'] if is_stderr else self.COLORS['white']
        # 限制行长度 - 增加长度以减少截断感
        if len(line) > 200:
            line = line[:197] + "..."
        
        # 构造带颜色的行，减少多次 write 调用
        formatted = f"  {color}│{self.COLORS['reset']} {line}\n"
        self._write(formatted)
    
    def tool_complete(self, tool_name: str, success: bool, duration: float):
        """工具完成"""
        status = f"{self.COLORS['green']}✓ 成功" if success else f"{self.COLORS['red']}✗ 失败"
        self._write(f"\n{self.COLORS['yellow']}┌──────────────────────────────────────────────────────────\n")
        self._write(f"│ {status}{self.COLORS['yellow']} | {tool_name} | 耗时: {duration:.1f}s\n")
        self._write(f"└──────────────────────────────────────────────────────────{self.COLORS['reset']}\n\n")
    
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
    
    def finding(self, title: str, details: str = None):
        """发现/结果消息"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if details:
            self._write(f"{self.COLORS['magenta']}[{timestamp}] 🎯 {title}: {self.COLORS['cyan']}{details}{self.COLORS['reset']}\n")
        else:
            self._write(f"{self.COLORS['magenta']}[{timestamp}] 🎯 {title}{self.COLORS['reset']}\n")


# 全局实例
terminal = TerminalLogger()


def run_with_realtime_output(
    cmd: List[str], 
    tool_name: str, 
    target: str, 
    timeout: int = 300,
    show_output: bool = True,
    max_output_lines: int = 1000  # 增加默认显示行数
) -> Dict:
    """
    运行命令并实时显示输出到终端 (优化版)
    """
    terminal.tool_start(tool_name, target, cmd)
    start_time = time.time()
    
    # 准备环境变量，强制禁用缓冲
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    env['NSUnbufferedIO'] = 'YES'  # 部分工具支持
    
    try:
        # 启动进程
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # 行缓冲
            env=env
        )
        
        stdout_lines = []
        stderr_lines = []
        
        # 使用列表作为简单的计数器引用
        state = {"output_count": 0, "killed": False}
        
        # 优化的读取函数
        def read_stream(stream, lines_list, is_stderr):
            try:
                for line in iter(stream.readline, ''):
                    if not line: break
                    
                    s_line = line.rstrip()
                    lines_list.append(s_line)
                    
                    if show_output:
                        if state["output_count"] < max_output_lines:
                            terminal.tool_output(s_line, is_stderr)
                            state["output_count"] += 1
                        elif state["output_count"] == max_output_lines:
                            terminal.warning(f"... 输出过多，后续内容已隐藏 (仍在后台记录)")
                            state["output_count"] += 1
            except ValueError:
                pass  # 文件已关闭
            except Exception:
                pass
        
        stdout_thread = threading.Thread(target=read_stream, args=(proc.stdout, stdout_lines, False))
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
            
            return {
                "success": False,
                "error": f"超时 ({timeout}s)",
                "command": " ".join(cmd)
            }
        
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
            "duration": duration
        }
        
    except FileNotFoundError:
        duration = time.time() - start_time
        terminal.tool_complete(tool_name, False, duration)
        terminal.error(f"🔧 工具未找到: {cmd[0]}")
        return {
            "success": False,
            "error": f"工具未找到: {cmd[0]}",
            "command": " ".join(cmd)
        }
    except Exception as e:
        duration = time.time() - start_time
        terminal.tool_complete(tool_name, False, duration)
        terminal.error(f"❌ 执行错误: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "command": " ".join(cmd)
        }


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
    result = run_with_realtime_output(
        ["echo", "Hello World"],
        "echo",
        "test",
        timeout=10
    )
    print(f"\n结果: {result}")
