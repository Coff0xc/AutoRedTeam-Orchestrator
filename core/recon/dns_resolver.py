#!/usr/bin/env python3
"""
dns_resolver.py - DNS解析模块

提供DNS记录查询功能，支持A/AAAA/MX/NS/TXT/CNAME/SOA等记录类型。

使用方式:
    from core.recon.dns_resolver import DNSResolver, DNSRecord

    # 基础解析
    resolver = DNSResolver()
    ips = resolver.resolve("example.com")

    # 获取所有记录
    records = resolver.get_all_records("example.com")

    # 异步解析
    ips = await resolver.async_resolve("example.com")
"""

import socket
import asyncio
import logging
import struct
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Set
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger(__name__)


class DNSRecordType(Enum):
    """DNS记录类型"""
    A = 1       # IPv4地址
    AAAA = 28   # IPv6地址
    CNAME = 5   # 别名
    MX = 15     # 邮件交换
    NS = 2      # 名称服务器
    TXT = 16    # 文本记录
    SOA = 6     # 起始授权
    PTR = 12    # 指针记录
    SRV = 33    # 服务记录


@dataclass
class DNSRecord:
    """DNS记录

    Attributes:
        type: 记录类型
        name: 域名
        value: 记录值
        ttl: 生存时间
        priority: 优先级(MX/SRV)
        metadata: 额外元数据
    """
    type: str
    name: str
    value: str
    ttl: int = 0
    priority: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "type": self.type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
        }
        if self.priority is not None:
            result["priority"] = self.priority
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class DNSResult:
    """DNS查询结果

    Attributes:
        domain: 查询的域名
        records: 所有记录
        ip_addresses: IPv4地址列表
        ipv6_addresses: IPv6地址列表
        nameservers: NS记录
        mail_servers: MX记录
        txt_records: TXT记录
        cname_records: CNAME记录
        errors: 错误列表
    """
    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    mail_servers: List[Tuple[int, str]] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "domain": self.domain,
            "records": [r.to_dict() for r in self.records],
            "ip_addresses": self.ip_addresses,
            "ipv6_addresses": self.ipv6_addresses,
            "nameservers": self.nameservers,
            "mail_servers": [{"priority": p, "server": s} for p, s in self.mail_servers],
            "txt_records": self.txt_records,
            "cname_records": self.cname_records,
            "errors": self.errors,
        }


class DNSResolver:
    """DNS解析器

    提供多种DNS记录类型的查询功能。

    Attributes:
        timeout: 查询超时时间(秒)
        nameservers: 自定义DNS服务器列表
        use_tcp: 是否使用TCP查询
    """

    # 公共DNS服务器
    PUBLIC_DNS_SERVERS: List[str] = [
        "8.8.8.8",          # Google
        "8.8.4.4",          # Google
        "1.1.1.1",          # Cloudflare
        "1.0.0.1",          # Cloudflare
        "9.9.9.9",          # Quad9
        "208.67.222.222",   # OpenDNS
        "114.114.114.114",  # 114DNS (中国)
        "223.5.5.5",        # 阿里DNS
    ]

    def __init__(
        self,
        timeout: float = 5.0,
        nameservers: Optional[List[str]] = None,
        use_tcp: bool = False
    ):
        """初始化DNS解析器

        Args:
            timeout: 查询超时时间
            nameservers: 自定义DNS服务器
            use_tcp: 是否使用TCP查询
        """
        self.timeout = timeout
        self.nameservers = nameservers or []
        self.use_tcp = use_tcp

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def resolve(self, hostname: str) -> List[str]:
        """解析域名到IP地址（A记录）

        Args:
            hostname: 域名

        Returns:
            IP地址列表
        """
        try:
            # 使用系统DNS解析
            result = socket.gethostbyname_ex(hostname)
            return list(result[2])
        except socket.gaierror as e:
            self._logger.debug(f"DNS resolution failed for {hostname}: {e}")
            return []
        except Exception as e:
            self._logger.debug(f"DNS error for {hostname}: {e}")
            return []

    async def async_resolve(self, hostname: str) -> List[str]:
        """异步解析域名到IP地址

        Args:
            hostname: 域名

        Returns:
            IP地址列表
        """
        loop = asyncio.get_event_loop()
        try:
            # 使用线程池执行阻塞的DNS查询
            result = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyname_ex(hostname)
            )
            return list(result[2])
        except socket.gaierror:
            return []
        except Exception:
            return []

    def resolve_ipv6(self, hostname: str) -> List[str]:
        """解析域名到IPv6地址（AAAA记录）

        Args:
            hostname: 域名

        Returns:
            IPv6地址列表
        """
        try:
            results = socket.getaddrinfo(
                hostname, None, socket.AF_INET6, socket.SOCK_STREAM
            )
            return list(set(r[4][0] for r in results))
        except socket.gaierror:
            return []
        except Exception:
            return []

    async def async_resolve_ipv6(self, hostname: str) -> List[str]:
        """异步解析IPv6地址"""
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, self.resolve_ipv6, hostname)
            return result
        except Exception:
            return []

    def get_all_records(self, domain: str) -> DNSResult:
        """获取域名的所有DNS记录

        Args:
            domain: 域名

        Returns:
            DNSResult 对象
        """
        result = DNSResult(domain=domain)

        # A记录
        ips = self.resolve(domain)
        result.ip_addresses = ips
        for ip in ips:
            result.records.append(DNSRecord(
                type="A",
                name=domain,
                value=ip
            ))

        # AAAA记录
        ipv6s = self.resolve_ipv6(domain)
        result.ipv6_addresses = ipv6s
        for ip in ipv6s:
            result.records.append(DNSRecord(
                type="AAAA",
                name=domain,
                value=ip
            ))

        # MX记录
        try:
            mx_records = self._query_mx(domain)
            result.mail_servers = mx_records
            for priority, server in mx_records:
                result.records.append(DNSRecord(
                    type="MX",
                    name=domain,
                    value=server,
                    priority=priority
                ))
        except Exception as e:
            result.errors.append(f"MX query failed: {e}")

        # NS记录
        try:
            ns_records = self._query_ns(domain)
            result.nameservers = ns_records
            for ns in ns_records:
                result.records.append(DNSRecord(
                    type="NS",
                    name=domain,
                    value=ns
                ))
        except Exception as e:
            result.errors.append(f"NS query failed: {e}")

        # TXT记录
        try:
            txt_records = self._query_txt(domain)
            result.txt_records = txt_records
            for txt in txt_records:
                result.records.append(DNSRecord(
                    type="TXT",
                    name=domain,
                    value=txt
                ))
        except Exception as e:
            result.errors.append(f"TXT query failed: {e}")

        # CNAME记录
        try:
            cname = self._query_cname(domain)
            if cname:
                result.cname_records = [cname]
                result.records.append(DNSRecord(
                    type="CNAME",
                    name=domain,
                    value=cname
                ))
        except Exception as e:
            result.errors.append(f"CNAME query failed: {e}")

        return result

    async def async_get_all_records(self, domain: str) -> DNSResult:
        """异步获取所有DNS记录"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.get_all_records, domain)

    def _query_mx(self, domain: str) -> List[Tuple[int, str]]:
        """查询MX记录

        使用简单的DNS查询实现，不依赖外部库。

        Args:
            domain: 域名

        Returns:
            (优先级, 服务器) 元组列表
        """
        # 尝试使用nslookup命令（跨平台兼容）
        import subprocess
        import platform

        results: List[Tuple[int, str]] = []

        try:
            if platform.system() == "Windows":
                cmd = ["nslookup", "-type=mx", domain]
            else:
                cmd = ["nslookup", "-type=mx", domain]

            output = subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout
            ).decode("utf-8", errors="replace")

            # 解析输出
            for line in output.split("\n"):
                line = line.strip()
                if "mail exchanger" in line.lower() or "mx preference" in line.lower():
                    # 尝试解析优先级和服务器
                    parts = line.split("=")
                    if len(parts) >= 2:
                        mx_part = parts[-1].strip()
                        # 格式: "10 mail.example.com"
                        mx_parts = mx_part.split()
                        if len(mx_parts) >= 2:
                            try:
                                priority = int(mx_parts[0])
                                server = mx_parts[1].rstrip(".")
                                results.append((priority, server))
                            except ValueError:
                                pass

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        except Exception as e:
            self._logger.debug(f"MX query error: {e}")

        return sorted(results, key=lambda x: x[0])

    def _query_ns(self, domain: str) -> List[str]:
        """查询NS记录"""
        import subprocess
        import platform

        results: List[str] = []

        try:
            if platform.system() == "Windows":
                cmd = ["nslookup", "-type=ns", domain]
            else:
                cmd = ["nslookup", "-type=ns", domain]

            output = subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout
            ).decode("utf-8", errors="replace")

            for line in output.split("\n"):
                line = line.strip()
                if "nameserver" in line.lower():
                    parts = line.split("=")
                    if len(parts) >= 2:
                        ns = parts[-1].strip().rstrip(".")
                        if ns and ns not in results:
                            results.append(ns)

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        except Exception as e:
            self._logger.debug(f"NS query error: {e}")

        return results

    def _query_txt(self, domain: str) -> List[str]:
        """查询TXT记录"""
        import subprocess
        import platform

        results: List[str] = []

        try:
            if platform.system() == "Windows":
                cmd = ["nslookup", "-type=txt", domain]
            else:
                cmd = ["nslookup", "-type=txt", domain]

            output = subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout
            ).decode("utf-8", errors="replace")

            for line in output.split("\n"):
                line = line.strip()
                if "text" in line.lower() or line.startswith('"'):
                    # 提取TXT值
                    if "=" in line:
                        txt = line.split("=", 1)[-1].strip().strip('"')
                    else:
                        txt = line.strip('"')
                    if txt and txt not in results:
                        results.append(txt)

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
        except Exception as e:
            self._logger.debug(f"TXT query error: {e}")

        return results

    def _query_cname(self, domain: str) -> Optional[str]:
        """查询CNAME记录"""
        try:
            # 尝试获取CNAME
            result = socket.gethostbyname_ex(domain)
            # gethostbyname_ex 返回 (hostname, aliaslist, ipaddrlist)
            # 如果有别名，说明存在CNAME
            if result[0] != domain:
                return result[0]
            if result[1]:
                return result[1][0]
        except Exception:
            pass
        return None

    def reverse_lookup(self, ip: str) -> Optional[str]:
        """反向DNS查询

        Args:
            ip: IP地址

        Returns:
            主机名，失败返回 None
        """
        try:
            result = socket.gethostbyaddr(ip)
            return result[0]
        except socket.herror:
            return None
        except Exception:
            return None

    async def async_reverse_lookup(self, ip: str) -> Optional[str]:
        """异步反向DNS查询"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.reverse_lookup, ip)

    def batch_resolve(
        self,
        hostnames: List[str],
        threads: int = 10
    ) -> Dict[str, List[str]]:
        """批量解析域名

        Args:
            hostnames: 域名列表
            threads: 并发线程数

        Returns:
            {域名: [IP地址]} 字典
        """
        results: Dict[str, List[str]] = {}

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self.resolve, hostname): hostname
                for hostname in hostnames
            }

            for future in as_completed(futures):
                hostname = futures[future]
                try:
                    ips = future.result()
                    results[hostname] = ips
                except Exception:
                    results[hostname] = []

        return results

    async def async_batch_resolve(
        self,
        hostnames: List[str],
        concurrency: int = 50
    ) -> Dict[str, List[str]]:
        """异步批量解析域名

        Args:
            hostnames: 域名列表
            concurrency: 并发数

        Returns:
            {域名: [IP地址]} 字典
        """
        semaphore = asyncio.Semaphore(concurrency)
        results: Dict[str, List[str]] = {}

        async def resolve_with_limit(hostname: str):
            async with semaphore:
                return hostname, await self.async_resolve(hostname)

        tasks = [resolve_with_limit(h) for h in hostnames]
        for hostname, ips in await asyncio.gather(*tasks):
            results[hostname] = ips

        return results

    def check_domain_exists(self, domain: str) -> bool:
        """检查域名是否存在

        Args:
            domain: 域名

        Returns:
            是否存在
        """
        ips = self.resolve(domain)
        return len(ips) > 0

    async def async_check_domain_exists(self, domain: str) -> bool:
        """异步检查域名是否存在"""
        ips = await self.async_resolve(domain)
        return len(ips) > 0


# 便捷函数
def resolve_domain(hostname: str, timeout: float = 5.0) -> List[str]:
    """便捷函数：解析域名到IP

    Args:
        hostname: 域名
        timeout: 超时时间

    Returns:
        IP地址列表
    """
    resolver = DNSResolver(timeout=timeout)
    return resolver.resolve(hostname)


async def async_resolve_domain(hostname: str, timeout: float = 5.0) -> List[str]:
    """便捷函数：异步解析域名"""
    resolver = DNSResolver(timeout=timeout)
    return await resolver.async_resolve(hostname)


def get_dns_records(domain: str, timeout: float = 5.0) -> DNSResult:
    """便捷函数：获取所有DNS记录

    Args:
        domain: 域名
        timeout: 超时时间

    Returns:
        DNSResult 对象
    """
    resolver = DNSResolver(timeout=timeout)
    return resolver.get_all_records(domain)


# 导出
__all__ = [
    "DNSRecordType",
    "DNSRecord",
    "DNSResult",
    "DNSResolver",
    "resolve_domain",
    "async_resolve_domain",
    "get_dns_records",
]
