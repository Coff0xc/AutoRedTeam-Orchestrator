#!/usr/bin/env python3
"""
C2 协议模块 - C2 Protocol Module

定义 C2 通信协议，包括消息格式、心跳、任务和结果编码
仅用于授权渗透测试和安全研究

协议格式:
    Message = Header(16 bytes) + Payload

    Header:
        - magic (4 bytes): 0xC2C2C2C2
        - version (1 byte): 协议版本
        - type (1 byte): 消息类型
        - flags (2 bytes): 标志位
        - length (4 bytes): 载荷长度
        - checksum (4 bytes): CRC32 校验
"""

import struct
import json
import time
import zlib
import uuid
import logging
from typing import Optional, Dict, Any, List, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import IntEnum

from .base import Task, TaskResult, BeaconInfo
from .encoding import C2Encoder, JSONEncoder
from .crypto import C2Crypto, CryptoAlgorithm

logger = logging.getLogger(__name__)


# ==================== 协议常量 ====================

# 协议魔数
PROTOCOL_MAGIC = 0xC2C2C2C2

# 协议版本
PROTOCOL_VERSION = 0x01

# 消息头大小
HEADER_SIZE = 16

# 最大消息大小 (10 MB)
MAX_MESSAGE_SIZE = 10 * 1024 * 1024


class MessageType(IntEnum):
    """消息类型"""
    HEARTBEAT = 0x01        # 心跳
    HEARTBEAT_ACK = 0x02    # 心跳响应
    CHECKIN = 0x03          # 签到
    CHECKIN_ACK = 0x04      # 签到响应
    TASK = 0x05             # 任务下发
    TASK_RESULT = 0x06      # 任务结果
    DATA = 0x07             # 数据传输
    DATA_ACK = 0x08         # 数据确认
    ERROR = 0x09            # 错误
    CLOSE = 0x0A            # 关闭连接
    KEEPALIVE = 0x0B        # 保活


class MessageFlags(IntEnum):
    """消息标志位"""
    NONE = 0x0000
    ENCRYPTED = 0x0001      # 已加密
    COMPRESSED = 0x0002     # 已压缩
    CHUNKED = 0x0004        # 分块传输
    ACK_REQUIRED = 0x0008   # 需要确认
    PRIORITY = 0x0010       # 高优先级


@dataclass
class MessageHeader:
    """消息头"""
    magic: int = PROTOCOL_MAGIC
    version: int = PROTOCOL_VERSION
    msg_type: MessageType = MessageType.DATA
    flags: int = MessageFlags.NONE
    length: int = 0
    checksum: int = 0

    def pack(self) -> bytes:
        """打包为字节"""
        return struct.pack(
            '>IBBHII',
            self.magic,
            self.version,
            self.msg_type,
            self.flags,
            self.length,
            self.checksum
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'MessageHeader':
        """从字节解包"""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} < {HEADER_SIZE}")

        magic, version, msg_type, flags, length, checksum = struct.unpack(
            '>IBBHII', data[:HEADER_SIZE]
        )

        if magic != PROTOCOL_MAGIC:
            raise ValueError(f"Invalid magic: {hex(magic)}")

        return cls(
            magic=magic,
            version=version,
            msg_type=MessageType(msg_type),
            flags=flags,
            length=length,
            checksum=checksum
        )


@dataclass
class Message:
    """协议消息"""
    header: MessageHeader
    payload: bytes

    @classmethod
    def create(
        cls,
        msg_type: MessageType,
        payload: bytes,
        flags: int = MessageFlags.NONE
    ) -> 'Message':
        """创建消息"""
        checksum = zlib.crc32(payload) & 0xffffffff

        header = MessageHeader(
            msg_type=msg_type,
            flags=flags,
            length=len(payload),
            checksum=checksum
        )

        return cls(header=header, payload=payload)

    def pack(self) -> bytes:
        """打包完整消息"""
        return self.header.pack() + self.payload

    @classmethod
    def unpack(cls, data: bytes) -> 'Message':
        """解包消息"""
        header = MessageHeader.unpack(data[:HEADER_SIZE])
        payload = data[HEADER_SIZE:HEADER_SIZE + header.length]

        # 验证校验和
        calculated_checksum = zlib.crc32(payload) & 0xffffffff
        if calculated_checksum != header.checksum:
            raise ValueError("Checksum mismatch")

        return cls(header=header, payload=payload)

    def verify(self) -> bool:
        """验证消息完整性"""
        calculated = zlib.crc32(self.payload) & 0xffffffff
        return calculated == self.header.checksum


# ==================== 协议编解码器 ====================

class ProtocolCodec:
    """
    协议编解码器

    提供消息的序列化和反序列化功能

    Usage:
        codec = ProtocolCodec()

        # 编码心跳
        data = codec.encode_heartbeat(beacon_id)

        # 解码任务
        tasks = codec.decode_tasks(data)
    """

    def __init__(
        self,
        crypto: Optional[C2Crypto] = None,
        compress: bool = True
    ):
        """
        初始化编解码器

        Args:
            crypto: 加密器（可选）
            compress: 是否压缩数据
        """
        self.crypto = crypto
        self.compress = compress
        self.encoder = C2Encoder()
        self.json_encoder = JSONEncoder(self.encoder)

    def _prepare_payload(self, data: Dict[str, Any]) -> Tuple[bytes, int]:
        """
        准备载荷（压缩和加密）

        Returns:
            (处理后的载荷, 标志位)
        """
        flags = MessageFlags.NONE

        # JSON 序列化
        json_data = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
        payload = json_data.encode('utf-8')

        # 压缩
        if self.compress and len(payload) > 100:
            compressed = zlib.compress(payload, level=6)
            if len(compressed) < len(payload):
                payload = compressed
                flags |= MessageFlags.COMPRESSED

        # 加密
        if self.crypto and self.crypto.algorithm != CryptoAlgorithm.NONE:
            payload = self.crypto.encrypt_with_header(payload)
            flags |= MessageFlags.ENCRYPTED

        return payload, flags

    def _extract_payload(self, payload: bytes, flags: int) -> Dict[str, Any]:
        """
        提取载荷（解密和解压）

        Returns:
            解析后的字典
        """
        data = payload

        # 解密
        if flags & MessageFlags.ENCRYPTED:
            if not self.crypto:
                raise ValueError("Encrypted message but no crypto configured")
            data = self.crypto.decrypt_with_header(data)

        # 解压
        if flags & MessageFlags.COMPRESSED:
            data = zlib.decompress(data)

        # JSON 反序列化
        return json.loads(data.decode('utf-8'))

    # ==================== 心跳 ====================

    def encode_heartbeat(
        self,
        beacon_id: str,
        timestamp: Optional[float] = None
    ) -> bytes:
        """
        编码心跳消息

        Args:
            beacon_id: Beacon ID
            timestamp: 时间戳

        Returns:
            编码后的消息
        """
        data = {
            'beacon_id': beacon_id,
            'timestamp': timestamp or time.time(),
            'type': 'heartbeat'
        }

        payload, flags = self._prepare_payload(data)
        message = Message.create(MessageType.HEARTBEAT, payload, flags)
        return message.pack()

    def decode_heartbeat(self, data: bytes) -> Dict[str, Any]:
        """
        解码心跳消息

        Args:
            data: 编码后的消息

        Returns:
            心跳数据
        """
        message = Message.unpack(data)

        if message.header.msg_type != MessageType.HEARTBEAT:
            raise ValueError(f"Expected HEARTBEAT, got {message.header.msg_type}")

        return self._extract_payload(message.payload, message.header.flags)

    # ==================== 签到 ====================

    def encode_checkin(self, info: BeaconInfo) -> bytes:
        """
        编码签到消息

        Args:
            info: Beacon 信息

        Returns:
            编码后的消息
        """
        data = info.to_dict()
        data['type'] = 'checkin'
        data['timestamp'] = time.time()

        payload, flags = self._prepare_payload(data)
        message = Message.create(MessageType.CHECKIN, payload, flags)
        return message.pack()

    def decode_checkin(self, data: bytes) -> BeaconInfo:
        """
        解码签到消息

        Args:
            data: 编码后的消息

        Returns:
            Beacon 信息
        """
        message = Message.unpack(data)

        if message.header.msg_type != MessageType.CHECKIN:
            raise ValueError(f"Expected CHECKIN, got {message.header.msg_type}")

        payload_data = self._extract_payload(message.payload, message.header.flags)

        return BeaconInfo(
            beacon_id=payload_data.get('beacon_id', ''),
            hostname=payload_data.get('hostname', ''),
            username=payload_data.get('username', ''),
            os_info=payload_data.get('os_info', ''),
            arch=payload_data.get('arch', ''),
            ip_address=payload_data.get('ip_address', ''),
            pid=payload_data.get('pid', 0),
            integrity=payload_data.get('integrity', 'medium'),
        )

    # ==================== 任务 ====================

    def encode_task(self, task: Task) -> bytes:
        """
        编码任务消息

        Args:
            task: 任务对象

        Returns:
            编码后的消息
        """
        data = {
            'id': task.id,
            'type': task.type,
            'payload': task.payload,
            'timeout': task.timeout,
            'priority': task.priority,
            'created_at': task.created_at,
        }

        payload, flags = self._prepare_payload(data)
        message = Message.create(MessageType.TASK, payload, flags)
        return message.pack()

    def encode_tasks(self, tasks: List[Task]) -> bytes:
        """
        编码多个任务

        Args:
            tasks: 任务列表

        Returns:
            编码后的消息
        """
        data = {
            'tasks': [
                {
                    'id': t.id,
                    'type': t.type,
                    'payload': t.payload,
                    'timeout': t.timeout,
                    'priority': t.priority,
                }
                for t in tasks
            ],
            'count': len(tasks),
        }

        payload, flags = self._prepare_payload(data)
        message = Message.create(MessageType.TASK, payload, flags)
        return message.pack()

    def decode_tasks(self, data: bytes) -> List[Task]:
        """
        解码任务消息

        Args:
            data: 编码后的消息

        Returns:
            任务列表
        """
        message = Message.unpack(data)

        if message.header.msg_type != MessageType.TASK:
            raise ValueError(f"Expected TASK, got {message.header.msg_type}")

        payload_data = self._extract_payload(message.payload, message.header.flags)

        tasks = []
        task_list = payload_data.get('tasks', [payload_data])

        for task_data in task_list:
            task = Task(
                id=task_data.get('id', str(uuid.uuid4())[:8]),
                type=task_data.get('type', 'unknown'),
                payload=task_data.get('payload'),
                timeout=task_data.get('timeout', 300.0),
                priority=task_data.get('priority', 5),
                created_at=task_data.get('created_at', time.time()),
            )
            tasks.append(task)

        return tasks

    # ==================== 任务结果 ====================

    def encode_result(self, result: TaskResult) -> bytes:
        """
        编码任务结果

        Args:
            result: 任务结果

        Returns:
            编码后的消息
        """
        data = result.to_dict()
        data['timestamp'] = time.time()

        payload, flags = self._prepare_payload(data)
        message = Message.create(MessageType.TASK_RESULT, payload, flags)
        return message.pack()

    def decode_result(self, data: bytes) -> TaskResult:
        """
        解码任务结果

        Args:
            data: 编码后的消息

        Returns:
            任务结果
        """
        message = Message.unpack(data)

        if message.header.msg_type != MessageType.TASK_RESULT:
            raise ValueError(f"Expected TASK_RESULT, got {message.header.msg_type}")

        payload_data = self._extract_payload(message.payload, message.header.flags)
        return TaskResult.from_dict(payload_data)

    # ==================== 通用数据 ====================

    def encode_data(self, data: Union[bytes, Dict[str, Any]]) -> bytes:
        """
        编码通用数据

        Args:
            data: 数据（字节或字典）

        Returns:
            编码后的消息
        """
        if isinstance(data, bytes):
            payload = data
            flags = MessageFlags.NONE

            if self.compress and len(payload) > 100:
                compressed = zlib.compress(payload, level=6)
                if len(compressed) < len(payload):
                    payload = compressed
                    flags |= MessageFlags.COMPRESSED

            if self.crypto and self.crypto.algorithm != CryptoAlgorithm.NONE:
                payload = self.crypto.encrypt_with_header(payload)
                flags |= MessageFlags.ENCRYPTED

        else:
            payload, flags = self._prepare_payload(data)

        message = Message.create(MessageType.DATA, payload, flags)
        return message.pack()

    def decode_data(self, data: bytes, as_dict: bool = True) -> Union[bytes, Dict[str, Any]]:
        """
        解码通用数据

        Args:
            data: 编码后的消息
            as_dict: 是否解析为字典

        Returns:
            解码后的数据
        """
        message = Message.unpack(data)
        flags = message.header.flags
        payload = message.payload

        # 解密
        if flags & MessageFlags.ENCRYPTED:
            if not self.crypto:
                raise ValueError("Encrypted message but no crypto configured")
            payload = self.crypto.decrypt_with_header(payload)

        # 解压
        if flags & MessageFlags.COMPRESSED:
            payload = zlib.decompress(payload)

        if as_dict:
            return json.loads(payload.decode('utf-8'))

        return payload

    # ==================== 错误 ====================

    def encode_error(self, error_code: int, message: str) -> bytes:
        """
        编码错误消息

        Args:
            error_code: 错误码
            message: 错误信息

        Returns:
            编码后的消息
        """
        data = {
            'error_code': error_code,
            'message': message,
            'timestamp': time.time(),
        }

        payload, flags = self._prepare_payload(data)
        msg = Message.create(MessageType.ERROR, payload, flags)
        return msg.pack()


# ==================== HTTP 协议适配 ====================

class HTTPProtocolAdapter:
    """
    HTTP 协议适配器

    将 C2 协议适配为 HTTP 请求/响应格式
    """

    def __init__(self, codec: Optional[ProtocolCodec] = None):
        """
        初始化适配器

        Args:
            codec: 协议编解码器
        """
        self.codec = codec or ProtocolCodec()
        self.encoder = C2Encoder()

    def encode_request(
        self,
        data: bytes,
        method: str = 'POST'
    ) -> Tuple[Dict[str, str], Union[str, Dict[str, Any]]]:
        """
        编码为 HTTP 请求

        Args:
            data: 原始数据
            method: HTTP 方法

        Returns:
            (headers, body) 元组
        """
        # Base64 编码
        encoded = self.encoder.base64_encode(data)

        if method.upper() == 'GET':
            # GET 请求放在参数中
            return {}, {'d': encoded, 't': str(int(time.time()))}
        else:
            # POST 请求放在 body 中
            headers = {
                'Content-Type': 'application/json',
            }
            body = {
                'data': encoded,
                'timestamp': int(time.time()),
            }
            return headers, body

    def decode_request(
        self,
        body: Union[str, Dict[str, Any]]
    ) -> bytes:
        """
        解码 HTTP 请求

        Args:
            body: 请求体

        Returns:
            原始数据
        """
        if isinstance(body, str):
            body = json.loads(body)

        encoded = body.get('data') or body.get('d', '')
        return self.encoder.base64_decode(encoded)

    def encode_response(self, data: bytes) -> Dict[str, Any]:
        """
        编码为 HTTP 响应

        Args:
            data: 原始数据

        Returns:
            响应体
        """
        encoded = self.encoder.base64_encode(data)
        return {
            'data': encoded,
            'timestamp': int(time.time()),
            'status': 'ok',
        }

    def decode_response(self, body: Union[str, Dict[str, Any]]) -> bytes:
        """
        解码 HTTP 响应

        Args:
            body: 响应体

        Returns:
            原始数据
        """
        if isinstance(body, str):
            body = json.loads(body)

        encoded = body.get('data', '')
        if not encoded:
            return b''

        return self.encoder.base64_decode(encoded)


# ==================== 便捷函数 ====================

def encode_heartbeat(beacon_id: str, timestamp: Optional[float] = None) -> bytes:
    """编码心跳消息"""
    codec = ProtocolCodec(compress=False)
    return codec.encode_heartbeat(beacon_id, timestamp)


def decode_heartbeat(data: bytes) -> Dict[str, Any]:
    """解码心跳消息"""
    codec = ProtocolCodec(compress=False)
    return codec.decode_heartbeat(data)


def encode_tasks(tasks: List[Task]) -> bytes:
    """编码任务列表"""
    codec = ProtocolCodec()
    return codec.encode_tasks(tasks)


def decode_tasks(data: bytes) -> List[Task]:
    """解码任务列表"""
    codec = ProtocolCodec()
    return codec.decode_tasks(data)


def encode_result(result: TaskResult) -> bytes:
    """编码任务结果"""
    codec = ProtocolCodec()
    return codec.encode_result(result)


def decode_result(data: bytes) -> TaskResult:
    """解码任务结果"""
    codec = ProtocolCodec()
    return codec.decode_result(data)


__all__ = [
    'PROTOCOL_MAGIC',
    'PROTOCOL_VERSION',
    'HEADER_SIZE',
    'MessageType',
    'MessageFlags',
    'MessageHeader',
    'Message',
    'ProtocolCodec',
    'HTTPProtocolAdapter',
    'encode_heartbeat',
    'decode_heartbeat',
    'encode_tasks',
    'decode_tasks',
    'encode_result',
    'decode_result',
]
