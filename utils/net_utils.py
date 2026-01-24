#!/usr/bin/env python3
"""
网络工具模块 - AutoRedTeam-Orchestrator

提供常用的网络操作功能，包括：
- 端口检测
- 主机名解析
- IP/CIDR处理
- 目标解析
- 网络信息获取

使用示例:
    from utils.net_utils import is_port_open, resolve_hostname, parse_target

    # 检查端口
    if is_port_open("192.168.1.1", 80):
        print("端口开放")

    # 解析主机名
    ips = resolve_hostname("example.com")

    # 解析目标
    host, port, protocol = parse_target("https://example.com:443")
"""

import socket
import ipaddress
import re
from typing import Optional, List, Tuple, Iterator, Union
from urllib.parse import urlparse


def is_port_open(
    host: str,
    port: int,
    timeout: float = 3.0,
    use_udp: bool = False
) -> bool:
    """
    检查端口是否开放

    Args:
        host: 主机地址（IP或域名）
        port: 端口号
        timeout: 超时时间（秒）
        use_udp: 是否使用UDP（默认TCP）

    Returns:
        端口是否开放
    """
    try:
        sock_type = socket.SOCK_DGRAM if use_udp else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(timeout)

        if use_udp:
            # UDP端口检测：发送空包，检查是否收到ICMP端口不可达
            sock.sendto(b'', (host, port))
            try:
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                # UDP超时可能意味着端口开放（无响应）或被过滤
                return True
        else:
            # TCP连接检测
            result = sock.connect_ex((host, port))
            return result == 0

    except (socket.error, socket.timeout, OSError):
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def scan_ports(
    host: str,
    ports: Union[List[int], range, str],
    timeout: float = 1.0
) -> List[int]:
    """
    扫描开放端口

    Args:
        host: 主机地址
        ports: 端口列表、范围或字符串（如 "80,443,8000-9000"）
        timeout: 每个端口的超时时间

    Returns:
        开放端口列表
    """
    # 解析端口参数
    port_list = []

    if isinstance(ports, str):
        port_list = list(parse_port_range(ports))
    elif isinstance(ports, range):
        port_list = list(ports)
    else:
        port_list = list(ports)

    open_ports = []
    for port in port_list:
        if is_port_open(host, port, timeout):
            open_ports.append(port)

    return open_ports


def resolve_hostname(hostname: str, ipv6: bool = False) -> List[str]:
    """
    解析主机名到IP地址

    Args:
        hostname: 主机名
        ipv6: 是否包含IPv6地址

    Returns:
        IP地址列表
    """
    try:
        # 获取所有地址信息
        family = socket.AF_UNSPEC if ipv6 else socket.AF_INET
        results = socket.getaddrinfo(hostname, None, family)

        # 提取唯一IP
        ips = set()
        for result in results:
            ip = result[4][0]
            ips.add(ip)

        return list(ips)

    except socket.gaierror:
        return []


def reverse_dns(ip: str) -> Optional[str]:
    """
    反向DNS查询

    Args:
        ip: IP地址

    Returns:
        主机名，失败返回None
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def get_local_ip() -> str:
    """
    获取本机IP地址

    Returns:
        本机IP地址
    """
    try:
        # 创建一个UDP socket连接到外部地址（不实际发送数据）
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return '127.0.0.1'


def get_all_local_ips() -> List[str]:
    """
    获取所有本地IP地址

    Returns:
        本机所有IP地址列表
    """
    try:
        hostname = socket.gethostname()
        # 获取所有关联的IP
        ips = socket.gethostbyname_ex(hostname)[2]

        # 过滤回环地址
        return [ip for ip in ips if not ip.startswith('127.')]

    except Exception:
        return [get_local_ip()]


def get_hostname() -> str:
    """
    获取本机主机名

    Returns:
        本机主机名
    """
    return socket.gethostname()


def get_fqdn() -> str:
    """
    获取本机完全限定域名（FQDN）

    Returns:
        本机FQDN
    """
    return socket.getfqdn()


def parse_target(target: str) -> Tuple[str, int, str]:
    """
    解析目标字符串

    支持格式：
    - IP地址: 192.168.1.1
    - 带端口: 192.168.1.1:8080
    - URL: https://example.com:443/path
    - 域名: example.com

    Args:
        target: 目标字符串

    Returns:
        (host, port, protocol) 元组
        - port为0表示未指定
        - protocol为空字符串表示未指定
    """
    host = target
    port = 0
    protocol = ''

    # 检查是否是URL
    if '://' in target:
        parsed = urlparse(target)
        protocol = parsed.scheme.lower()
        host = parsed.hostname or ''
        port = parsed.port or 0

        # 默认端口
        if port == 0:
            default_ports = {'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22}
            port = default_ports.get(protocol, 0)

    # 检查是否带端口（非URL格式）
    elif ':' in target and not target.startswith('['):  # 排除IPv6
        # 可能是 host:port 格式
        parts = target.rsplit(':', 1)
        if len(parts) == 2:
            try:
                port = int(parts[1])
                host = parts[0]
            except ValueError:
                pass

    # 处理IPv6地址
    elif target.startswith('['):
        # [IPv6]:port 格式
        match = re.match(r'\[([^\]]+)\]:?(\d+)?', target)
        if match:
            host = match.group(1)
            if match.group(2):
                port = int(match.group(2))

    return host, port, protocol


def cidr_to_hosts(cidr: str) -> Iterator[str]:
    """
    将CIDR网段转换为主机IP列表

    Args:
        cidr: CIDR表示（如 192.168.1.0/24）

    Yields:
        网段内的主机IP地址

    注意：跳过网络地址和广播地址
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)

        # 对于/32的单个IP
        if network.prefixlen == 32:
            yield str(network.network_address)
            return

        # 跳过网络地址和广播地址
        for host in network.hosts():
            yield str(host)

    except ValueError:
        # 无效的CIDR，尝试作为单个IP
        yield cidr


def ip_in_network(ip: str, network: str) -> bool:
    """
    检查IP是否在指定网段内

    Args:
        ip: IP地址
        network: 网段（CIDR格式）

    Returns:
        IP是否在网段内
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        net_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in net_obj
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    检查是否为私有IP地址

    Args:
        ip: IP地址

    Returns:
        是否为私有IP
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_reserved_ip(ip: str) -> bool:
    """
    检查是否为保留IP地址

    Args:
        ip: IP地址

    Returns:
        是否为保留IP
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_reserved
    except ValueError:
        return False


def is_loopback_ip(ip: str) -> bool:
    """
    检查是否为回环IP地址

    Args:
        ip: IP地址

    Returns:
        是否为回环IP
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_loopback
    except ValueError:
        return False


def parse_port_range(port_range: str) -> Iterator[int]:
    """
    解析端口范围字符串

    支持格式：
    - 单个端口: "80"
    - 端口列表: "80,443,8080"
    - 端口范围: "80-100"
    - 混合格式: "80,443,8000-9000"

    Args:
        port_range: 端口范围字符串

    Yields:
        端口号
    """
    for part in port_range.replace(' ', '').split(','):
        if '-' in part:
            start, end = part.split('-', 1)
            for port in range(int(start), int(end) + 1):
                if 1 <= port <= 65535:
                    yield port
        else:
            port = int(part)
            if 1 <= port <= 65535:
                yield port


def normalize_url(url: str, default_scheme: str = 'https') -> str:
    """
    规范化URL

    Args:
        url: 原始URL
        default_scheme: 默认协议

    Returns:
        规范化后的URL
    """
    url = url.strip()

    # 添加协议
    if not url.startswith(('http://', 'https://')):
        url = f'{default_scheme}://{url}'

    # 解析并重建
    parsed = urlparse(url)

    # 移除默认端口
    netloc = parsed.netloc
    if parsed.scheme == 'http' and netloc.endswith(':80'):
        netloc = netloc[:-3]
    elif parsed.scheme == 'https' and netloc.endswith(':443'):
        netloc = netloc[:-4]

    # 规范化路径
    path = parsed.path or '/'
    if not path.startswith('/'):
        path = '/' + path

    # 重建URL
    from urllib.parse import urlunparse
    return urlunparse((
        parsed.scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ''  # 移除fragment
    ))


def extract_domain(url: str) -> str:
    """
    从URL中提取域名

    Args:
        url: URL字符串

    Returns:
        域名
    """
    if '://' not in url:
        url = 'https://' + url

    parsed = urlparse(url)
    return parsed.hostname or ''


def extract_root_domain(domain: str) -> str:
    """
    提取根域名

    Args:
        domain: 域名（可能包含子域名）

    Returns:
        根域名
    """
    # 常见的公共后缀
    # 注意：完整实现应使用公共后缀列表（PSL）
    common_tlds = [
        '.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.me',
        '.cn', '.jp', '.uk', '.de', '.fr', '.ru', '.au', '.in',
        '.com.cn', '.net.cn', '.org.cn', '.gov.cn', '.co.uk', '.co.jp'
    ]

    domain = domain.lower().strip('.')

    # 检查多级TLD
    for tld in common_tlds:
        if domain.endswith(tld):
            # 提取根域名
            remaining = domain[:-len(tld)]
            parts = remaining.rsplit('.', 1)
            root = parts[-1] if parts else remaining
            return root + tld

    # 默认取最后两个部分
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])

    return domain


def get_service_banner(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
    """
    获取服务Banner

    Args:
        host: 主机地址
        port: 端口号
        timeout: 超时时间

    Returns:
        Banner字符串，失败返回None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # 发送空请求触发响应
        sock.send(b'\r\n')

        # 接收响应
        banner = sock.recv(1024)
        sock.close()

        return banner.decode('utf-8', errors='ignore').strip()

    except Exception:
        return None


def is_valid_mac(mac: str) -> bool:
    """
    验证MAC地址格式

    Args:
        mac: MAC地址字符串

    Returns:
        是否为有效MAC地址
    """
    # 支持多种格式：AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABBCCDDEEFF
    patterns = [
        r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$',
        r'^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$',
        r'^[0-9A-Fa-f]{12}$'
    ]

    for pattern in patterns:
        if re.match(pattern, mac):
            return True

    return False


__all__ = [
    'is_port_open',
    'scan_ports',
    'resolve_hostname',
    'reverse_dns',
    'get_local_ip',
    'get_all_local_ips',
    'get_hostname',
    'get_fqdn',
    'parse_target',
    'cidr_to_hosts',
    'ip_in_network',
    'is_private_ip',
    'is_reserved_ip',
    'is_loopback_ip',
    'parse_port_range',
    'normalize_url',
    'extract_domain',
    'extract_root_domain',
    'get_service_banner',
    'is_valid_mac',
]
