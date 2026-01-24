#!/usr/bin/env python3
"""
port_scanner.py - 纯Python端口扫描器

提供同步和异步的端口扫描功能，无需外部工具依赖。

使用方式:
    from core.recon.port_scanner import PortScanner, PortInfo

    # 同步扫描
    scanner = PortScanner()
    results = scanner.scan("192.168.1.1", ports="1-1000")

    # 异步扫描
    results = await scanner.async_scan("192.168.1.1", ports="22,80,443,8080")

    # 扫描Top端口
    results = scanner.scan_top_ports("192.168.1.1", top=100)
"""

import socket
import asyncio
import logging
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    """端口信息

    Attributes:
        port: 端口号
        state: 状态 (open, closed, filtered)
        service: 服务名称
        banner: Banner信息
        protocol: 协议 (tcp/udp)
        version: 版本信息
        metadata: 额外元数据
    """
    port: int
    state: str = "unknown"  # open, closed, filtered, unknown
    service: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "tcp"
    version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_open(self) -> bool:
        """判断端口是否开放"""
        return self.state == "open"

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "protocol": self.protocol,
            "version": self.version,
            "metadata": self.metadata,
        }


class PortScanner:
    """纯Python端口扫描器

    支持TCP Connect扫描，提供同步和异步接口。

    Attributes:
        timeout: 连接超时时间(秒)
        max_threads: 最大并发线程数
        grab_banner: 是否尝试获取Banner
        resolve_service: 是否解析服务名称
    """

    # 常见端口服务映射
    COMMON_PORTS: Dict[int, str] = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        69: "tftp",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        119: "nntp",
        123: "ntp",
        135: "msrpc",
        137: "netbios-ns",
        138: "netbios-dgm",
        139: "netbios-ssn",
        143: "imap",
        161: "snmp",
        162: "snmptrap",
        179: "bgp",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        464: "kpasswd5",
        465: "smtps",
        500: "isakmp",
        514: "syslog",
        515: "printer",
        520: "rip",
        521: "ripng",
        543: "klogin",
        544: "kshell",
        548: "afp",
        554: "rtsp",
        587: "submission",
        593: "http-rpc-epmap",
        631: "ipp",
        636: "ldaps",
        873: "rsync",
        902: "vmware-auth",
        989: "ftps-data",
        990: "ftps",
        993: "imaps",
        995: "pop3s",
        1080: "socks",
        1194: "openvpn",
        1433: "ms-sql-s",
        1434: "ms-sql-m",
        1521: "oracle",
        1723: "pptp",
        1883: "mqtt",
        2049: "nfs",
        2082: "cpanel",
        2083: "cpanel-ssl",
        2181: "zookeeper",
        2375: "docker",
        2376: "docker-ssl",
        2379: "etcd-client",
        2380: "etcd-server",
        3000: "grafana",
        3128: "squid",
        3268: "globalcatLDAP",
        3269: "globalcatLDAPssl",
        3306: "mysql",
        3389: "ms-wbt-server",
        3690: "svn",
        4369: "epmd",
        5000: "upnp",
        5432: "postgresql",
        5601: "kibana",
        5672: "amqp",
        5900: "vnc",
        5984: "couchdb",
        6000: "x11",
        6379: "redis",
        6443: "k8s-api",
        6666: "irc",
        6667: "irc",
        7001: "weblogic",
        7002: "weblogic-ssl",
        8000: "http-alt",
        8008: "http-alt",
        8009: "ajp13",
        8080: "http-proxy",
        8081: "http-alt",
        8088: "http-alt",
        8443: "https-alt",
        8500: "consul",
        8834: "nessus",
        8888: "http-alt",
        9000: "cslistener",
        9001: "tor-orport",
        9042: "cassandra",
        9090: "prometheus",
        9092: "kafka",
        9200: "elasticsearch",
        9300: "elasticsearch-cluster",
        9418: "git",
        9999: "abyss",
        10000: "webmin",
        10250: "kubelet",
        10255: "kubelet-readonly",
        11211: "memcached",
        15672: "rabbitmq-management",
        27017: "mongodb",
        27018: "mongodb",
        28017: "mongodb-web",
        50000: "jenkins",
        50070: "hadoop-namenode",
        50075: "hadoop-datanode",
    }

    # Top 100 常用端口
    TOP_100_PORTS: List[int] = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
        143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389,
        5432, 5900, 6379, 8080, 8443, 8888, 27017,
        20, 69, 123, 137, 138, 161, 389, 464, 500, 514,
        548, 587, 631, 636, 873, 902, 989, 990, 1080, 1194,
        1434, 1883, 2049, 2082, 2083, 2181, 2375, 2376, 2379, 3000,
        3128, 3268, 3690, 4369, 5000, 5601, 5672, 5984, 6000, 6443,
        6666, 7001, 7002, 8000, 8008, 8009, 8081, 8088, 8500, 8834,
        9000, 9042, 9090, 9092, 9200, 9300, 9418, 10000, 10250, 11211,
        15672, 27018, 50000, 50070, 50075, 179, 119, 162, 543, 544,
    ]

    def __init__(
        self,
        timeout: float = 3.0,
        max_threads: int = 100,
        grab_banner: bool = True,
        resolve_service: bool = True
    ):
        """初始化端口扫描器

        Args:
            timeout: 连接超时时间(秒)
            max_threads: 最大并发线程数
            grab_banner: 是否尝试获取Banner
            resolve_service: 是否解析服务名称
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.grab_banner = grab_banner
        self.resolve_service = resolve_service

        # 线程安全
        self._lock = threading.Lock()
        self._stop_flag = threading.Event()

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def scan(
        self,
        host: str,
        ports: str = "1-1000",
        threads: Optional[int] = None
    ) -> List[PortInfo]:
        """同步扫描端口

        Args:
            host: 目标主机IP或域名
            ports: 端口范围，支持格式: "80", "80,443", "1-1000", "22,80,443,8000-9000"
            threads: 并发线程数，默认使用 self.max_threads

        Returns:
            开放端口的 PortInfo 列表
        """
        threads = threads or self.max_threads
        port_list = self._parse_ports(ports)
        results: List[PortInfo] = []

        self._logger.info(f"Scanning {host} ports: {len(port_list)} ports with {threads} threads")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._scan_port, host, port): port
                for port in port_list
            }

            for future in as_completed(futures):
                if self._stop_flag.is_set():
                    break

                try:
                    result = future.result()
                    if result and result.is_open():
                        with self._lock:
                            results.append(result)
                except Exception as e:
                    self._logger.debug(f"Port scan error: {e}")

        return sorted(results, key=lambda x: x.port)

    async def async_scan(
        self,
        host: str,
        ports: str = "1-1000",
        concurrency: int = 100
    ) -> List[PortInfo]:
        """异步扫描端口

        Args:
            host: 目标主机IP或域名
            ports: 端口范围
            concurrency: 并发数量

        Returns:
            开放端口的 PortInfo 列表
        """
        port_list = self._parse_ports(ports)
        semaphore = asyncio.Semaphore(concurrency)
        results: List[PortInfo] = []

        self._logger.info(f"Async scanning {host} ports: {len(port_list)} ports")

        async def scan_with_limit(port: int) -> Optional[PortInfo]:
            async with semaphore:
                if self._stop_flag.is_set():
                    return None
                return await self._async_scan_port(host, port)

        tasks = [scan_with_limit(port) for port in port_list]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in scan_results:
            if isinstance(result, PortInfo) and result.is_open():
                results.append(result)

        return sorted(results, key=lambda x: x.port)

    def scan_top_ports(
        self,
        host: str,
        top: int = 100,
        threads: Optional[int] = None
    ) -> List[PortInfo]:
        """扫描Top常用端口

        Args:
            host: 目标主机
            top: Top N 端口数量 (最大100)
            threads: 并发线程数

        Returns:
            开放端口列表
        """
        top = min(top, len(self.TOP_100_PORTS))
        ports = ",".join(str(p) for p in self.TOP_100_PORTS[:top])
        return self.scan(host, ports, threads)

    async def async_scan_top_ports(
        self,
        host: str,
        top: int = 100,
        concurrency: int = 100
    ) -> List[PortInfo]:
        """异步扫描Top常用端口"""
        top = min(top, len(self.TOP_100_PORTS))
        ports = ",".join(str(p) for p in self.TOP_100_PORTS[:top])
        return await self.async_scan(host, ports, concurrency)

    def scan_single(self, host: str, port: int) -> PortInfo:
        """扫描单个端口

        Args:
            host: 目标主机
            port: 端口号

        Returns:
            PortInfo 对象
        """
        result = self._scan_port(host, port)
        return result or PortInfo(port=port, state="unknown")

    async def async_scan_single(self, host: str, port: int) -> PortInfo:
        """异步扫描单个端口"""
        result = await self._async_scan_port(host, port)
        return result or PortInfo(port=port, state="unknown")

    def _scan_port(self, host: str, port: int) -> Optional[PortInfo]:
        """扫描单个端口（内部方法）

        Args:
            host: 目标主机
            port: 端口号

        Returns:
            PortInfo 对象，失败返回 None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                # 端口开放
                service = self._get_service_name(port)
                banner = None

                if self.grab_banner:
                    banner = self._grab_banner(sock, port)

                sock.close()

                return PortInfo(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    protocol="tcp"
                )
            else:
                sock.close()
                return PortInfo(port=port, state="closed")

        except socket.timeout:
            return PortInfo(port=port, state="filtered")
        except ConnectionRefusedError:
            return PortInfo(port=port, state="closed")
        except Exception as e:
            self._logger.debug(f"Port {port} scan error: {e}")
            return PortInfo(port=port, state="unknown")

    async def _async_scan_port(self, host: str, port: int) -> Optional[PortInfo]:
        """异步扫描单个端口（内部方法）

        Args:
            host: 目标主机
            port: 端口号

        Returns:
            PortInfo 对象
        """
        try:
            # 使用 asyncio 创建连接
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

            service = self._get_service_name(port)
            banner = None

            if self.grab_banner:
                try:
                    # 尝试读取Banner
                    data = await asyncio.wait_for(
                        reader.read(1024),
                        timeout=min(2.0, self.timeout)
                    )
                    if data:
                        banner = data.decode("utf-8", errors="replace").strip()
                except (asyncio.TimeoutError, Exception):
                    pass

            writer.close()
            await writer.wait_closed()

            return PortInfo(
                port=port,
                state="open",
                service=service,
                banner=banner,
                protocol="tcp"
            )

        except asyncio.TimeoutError:
            return PortInfo(port=port, state="filtered")
        except ConnectionRefusedError:
            return PortInfo(port=port, state="closed")
        except Exception as e:
            self._logger.debug(f"Async port {port} scan error: {e}")
            return PortInfo(port=port, state="unknown")

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """尝试获取服务Banner

        Args:
            sock: 已连接的socket
            port: 端口号

        Returns:
            Banner字符串，失败返回 None
        """
        try:
            # 设置较短的接收超时
            sock.settimeout(min(2.0, self.timeout))

            # 某些服务需要发送数据才能获取响应
            probe_data = self._get_probe_data(port)
            if probe_data:
                sock.send(probe_data)

            data = sock.recv(1024)
            if data:
                return data.decode("utf-8", errors="replace").strip()[:200]

        except Exception:
            pass

        return None

    def _get_probe_data(self, port: int) -> Optional[bytes]:
        """获取探测数据

        某些服务需要发送特定数据才能获取Banner。

        Args:
            port: 端口号

        Returns:
            探测数据，不需要返回 None
        """
        probes = {
            80: b"GET / HTTP/1.0\r\n\r\n",
            443: b"GET / HTTP/1.0\r\n\r\n",
            8080: b"GET / HTTP/1.0\r\n\r\n",
            8443: b"GET / HTTP/1.0\r\n\r\n",
            25: b"EHLO test\r\n",
            110: b"",  # POP3 会主动发送Banner
            143: b"",  # IMAP 会主动发送Banner
            21: b"",   # FTP 会主动发送Banner
            22: b"",   # SSH 会主动发送Banner
        }
        return probes.get(port)

    def _get_service_name(self, port: int) -> Optional[str]:
        """获取服务名称

        Args:
            port: 端口号

        Returns:
            服务名称
        """
        if not self.resolve_service:
            return None

        # 首先查找内置映射
        if port in self.COMMON_PORTS:
            return self.COMMON_PORTS[port]

        # 尝试使用系统服务映射
        try:
            return socket.getservbyport(port, "tcp")
        except (OSError, socket.error):
            return None

    def _parse_ports(self, ports: str) -> List[int]:
        """解析端口范围字符串

        支持格式:
            - "80"              -> [80]
            - "80,443"          -> [80, 443]
            - "1-100"           -> [1, 2, ..., 100]
            - "22,80,443,8000-9000" -> [22, 80, 443, 8000, ..., 9000]

        Args:
            ports: 端口范围字符串

        Returns:
            端口号列表

        Raises:
            ValueError: 无效的端口格式
        """
        result: Set[int] = set()

        for part in ports.replace(" ", "").split(","):
            part = part.strip()
            if not part:
                continue

            if "-" in part:
                # 端口范围
                try:
                    start, end = map(int, part.split("-", 1))
                    if start < 1 or end > 65535 or start > end:
                        raise ValueError(f"Invalid port range: {part}")
                    result.update(range(start, end + 1))
                except ValueError as e:
                    raise ValueError(f"Invalid port range: {part}") from e
            else:
                # 单个端口
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Invalid port number: {port}")
                    result.add(port)
                except ValueError as e:
                    raise ValueError(f"Invalid port number: {part}") from e

        return sorted(result)

    def stop(self) -> None:
        """停止扫描"""
        self._stop_flag.set()

    def reset(self) -> None:
        """重置扫描器状态"""
        self._stop_flag.clear()

    @classmethod
    def get_common_ports(cls) -> Dict[int, str]:
        """获取常见端口映射"""
        return cls.COMMON_PORTS.copy()

    @classmethod
    def get_top_ports(cls, top: int = 100) -> List[int]:
        """获取Top N常用端口列表"""
        return cls.TOP_100_PORTS[:min(top, len(cls.TOP_100_PORTS))]


# 便捷函数
def scan_ports(
    host: str,
    ports: str = "1-1000",
    timeout: float = 3.0,
    threads: int = 100
) -> List[PortInfo]:
    """便捷函数：扫描端口

    Args:
        host: 目标主机
        ports: 端口范围
        timeout: 超时时间
        threads: 并发线程数

    Returns:
        开放端口列表
    """
    scanner = PortScanner(timeout=timeout, max_threads=threads)
    return scanner.scan(host, ports)


async def async_scan_ports(
    host: str,
    ports: str = "1-1000",
    timeout: float = 3.0,
    concurrency: int = 100
) -> List[PortInfo]:
    """便捷函数：异步扫描端口"""
    scanner = PortScanner(timeout=timeout)
    return await scanner.async_scan(host, ports, concurrency)


# 导出
__all__ = [
    "PortInfo",
    "PortScanner",
    "scan_ports",
    "async_scan_ports",
]
