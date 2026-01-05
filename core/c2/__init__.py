#!/usr/bin/env python3
"""
C2 通信模块 - Command and Control Module
提供 Beacon、DNS隧道、ICMP隧道等通信能力
仅用于授权渗透测试
"""

from .beacon import (
    LightBeacon,
    BeaconConfig,
    BeaconTask,
    TaskType,
    create_beacon,
    start_beacon_server,
)
from .tunnels import (
    DNSTunnel,
    ICMPTunnel,
    HTTPTunnel,
    TunnelConfig,
    create_dns_tunnel,
    create_icmp_tunnel,
)

__all__ = [
    # Beacon
    'LightBeacon',
    'BeaconConfig',
    'BeaconTask',
    'TaskType',
    'create_beacon',
    'start_beacon_server',
    # Tunnels
    'DNSTunnel',
    'ICMPTunnel',
    'HTTPTunnel',
    'TunnelConfig',
    'create_dns_tunnel',
    'create_icmp_tunnel',
]
