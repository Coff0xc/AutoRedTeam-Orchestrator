#!/usr/bin/env python3
"""
C2 隧道模块 - C2 Tunnels Module

提供多种隧道实现和工厂函数
仅用于授权渗透测试和安全研究

支持的隧道类型:
    - HTTP/HTTPS 隧道
    - DNS 隧道
    - WebSocket 隧道
"""

from typing import Optional, Union, Type
import logging

from ..base import BaseTunnel, C2Config, TunnelType
from .http import HTTPTunnel
from .dns import DNSTunnel
from .websocket import WebSocketTunnel

logger = logging.getLogger(__name__)

# 隧道类型映射
TUNNEL_REGISTRY: dict[str, Type[BaseTunnel]] = {
    'http': HTTPTunnel,
    'https': HTTPTunnel,
    'dns': DNSTunnel,
    'ws': WebSocketTunnel,
    'wss': WebSocketTunnel,
    'websocket': WebSocketTunnel,
}


def create_tunnel(
    protocol: str,
    server: str,
    port: int,
    config: Optional[C2Config] = None,
    **kwargs
) -> BaseTunnel:
    """
    创建隧道实例

    Args:
        protocol: 协议类型 (http, https, dns, ws, wss, websocket)
        server: 服务器地址
        port: 端口号
        config: C2 配置
        **kwargs: 额外参数

    Returns:
        BaseTunnel 子类实例

    Raises:
        ValueError: 不支持的协议类型
    """
    protocol = protocol.lower()

    if protocol not in TUNNEL_REGISTRY:
        raise ValueError(
            f"Unsupported protocol: {protocol}. "
            f"Available: {list(TUNNEL_REGISTRY.keys())}"
        )

    # 创建或更新配置
    if config is None:
        config = C2Config(server=server, port=port, protocol=protocol)
    else:
        config.server = server
        config.port = port
        config.protocol = protocol

    # 合并额外参数
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

    # 创建隧道
    tunnel_class = TUNNEL_REGISTRY[protocol]
    return tunnel_class(config)


def get_tunnel_class(protocol: str) -> Type[BaseTunnel]:
    """
    获取隧道类

    Args:
        protocol: 协议类型

    Returns:
        隧道类
    """
    protocol = protocol.lower()

    if protocol not in TUNNEL_REGISTRY:
        raise ValueError(f"Unsupported protocol: {protocol}")

    return TUNNEL_REGISTRY[protocol]


def register_tunnel(protocol: str, tunnel_class: Type[BaseTunnel]) -> None:
    """
    注册自定义隧道

    Args:
        protocol: 协议类型
        tunnel_class: 隧道类
    """
    TUNNEL_REGISTRY[protocol.lower()] = tunnel_class
    logger.info(f"Registered tunnel type: {protocol}")


def list_available_tunnels() -> list[str]:
    """获取可用的隧道类型列表"""
    return list(TUNNEL_REGISTRY.keys())


__all__ = [
    # 隧道类
    'HTTPTunnel',
    'DNSTunnel',
    'WebSocketTunnel',
    # 工厂函数
    'create_tunnel',
    'get_tunnel_class',
    'register_tunnel',
    'list_available_tunnels',
    # 注册表
    'TUNNEL_REGISTRY',
]
