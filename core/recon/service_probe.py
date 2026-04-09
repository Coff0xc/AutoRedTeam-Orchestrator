"""
服务协议探针 — 端口级协议识别

通过发送协议特定探针识别服务类型和版本。
内置替代 nmap 的 -sV 服务版本检测能力。

使用:
    from core.recon.service_probe import ServiceProber, ServiceInfo
    prober = ServiceProber()
    info = await prober.probe_port("192.168.1.1", 22)
    print(info.service, info.version)
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── 已知服务签名 ──

_SERVICE_SIGNATURES: List[Dict[str, Any]] = [
    # SSH
    {"pattern": rb"^SSH-[\d.]+-", "service": "ssh", "extract": r"SSH-([\d.]+)-(.+)"},
    # FTP
    {"pattern": rb"^220[ -]", "service": "ftp", "extract": r"220[ -](.+)"},
    # SMTP
    {"pattern": rb"^220 .*(SMTP|Postfix|sendmail|Exchange|Exim)", "service": "smtp", "extract": r"220 (.+)"},
    # POP3
    {"pattern": rb"^\+OK", "service": "pop3", "extract": r"\+OK (.+)"},
    # IMAP
    {"pattern": rb"^\* OK", "service": "imap", "extract": r"\* OK (.+)"},
    # MySQL
    {"pattern": rb".\x00\x00\x00\x0a([\d.]+)", "service": "mysql", "extract_bytes": True},
    # Redis
    {"pattern": rb"^-ERR\b|^\+PONG|^\$\d+\r\nredis_version", "service": "redis"},
    # MongoDB (wire protocol)
    {"pattern": rb"ismaster|MongoDB", "service": "mongodb"},
    # PostgreSQL error
    {"pattern": rb"FATAL.*PostgreSQL|invalid length of startup packet", "service": "postgresql"},
    # RDP
    {"pattern": rb"^\x03\x00", "service": "rdp"},
    # VNC
    {"pattern": rb"^RFB \d+\.\d+", "service": "vnc", "extract": r"RFB ([\d.]+)"},
    # Telnet
    {"pattern": rb"^\xff[\xfb-\xfe]", "service": "telnet"},
    # Docker API
    {"pattern": rb'"ApiVersion"', "service": "docker-api"},
    # Elasticsearch
    {"pattern": rb'"cluster_name"', "service": "elasticsearch"},
]

# 需要主动发送探针的协议
_PROBES: Dict[str, bytes] = {
    "redis": b"PING\r\n",
    "mysql_check": b"",  # MySQL 会主动发送握手包
    "http": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "redis_info": b"INFO server\r\n",
    "mongodb": b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x15\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",
}


@dataclass
class ServiceInfo:
    """服务信息"""

    port: int
    service: str = "unknown"
    version: Optional[str] = None
    banner: Optional[str] = None
    tls: bool = False
    tls_version: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_expiry: Optional[str] = None
    os_guess: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if v is not None and v != {} and v != "unknown"}
        d["port"] = self.port
        d["service"] = self.service
        return d


class ServiceProber:
    """服务协议探针 — 纯 Python 实现的 nmap -sV 替代

    通过 banner 抓取 + 协议探针识别服务类型和版本。
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def probe_port(self, host: str, port: int) -> ServiceInfo:
        """探测单个端口的服务信息"""
        info = ServiceInfo(port=port)

        # 阶段1: 尝试直接 banner 抓取 (很多服务主动发送 banner)
        banner = await self._grab_banner(host, port)
        if banner:
            info.banner = banner.decode("utf-8", errors="replace").strip()[:500]
            self._match_signature(banner, info)

        # 阶段2: 如果未识别，尝试 HTTP 探针
        if info.service == "unknown":
            http_info = await self._probe_http(host, port)
            if http_info:
                info.service = "http"
                info.extra.update(http_info)
                if http_info.get("server"):
                    info.version = http_info["server"]

        # 阶段3: 如果未识别，尝试 TLS 握手
        if info.service == "unknown" or port in (443, 8443, 993, 995, 465):
            tls_info = await self._probe_tls(host, port)
            if tls_info:
                info.tls = True
                info.tls_version = tls_info.get("version")
                info.cert_subject = tls_info.get("subject")
                info.cert_issuer = tls_info.get("issuer")
                info.cert_expiry = tls_info.get("expiry")
                if info.service == "unknown":
                    info.service = "https" if port in (443, 8443) else "tls"

        # 阶段4: Redis/MongoDB 主动探针
        if info.service == "unknown" and port in (6379, 27017):
            await self._probe_active(host, port, info)

        # OS 猜测
        self._guess_os(info)

        return info

    async def probe_ports(self, host: str, ports: List[int], concurrency: int = 50) -> List[ServiceInfo]:
        """批量探测多个端口"""
        from utils.async_utils import gather_with_limit

        coros = [self.probe_port(host, port) for port in ports]
        results = await gather_with_limit(coros, limit=concurrency, return_exceptions=True)
        return [r for r in results if isinstance(r, ServiceInfo)]

    async def _grab_banner(self, host: str, port: int, send_probe: bytes = b"") -> Optional[bytes]:
        """TCP banner 抓取"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            try:
                if send_probe:
                    writer.write(send_probe)
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                return data if data else None
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            return None

    async def _probe_http(self, host: str, port: int) -> Optional[Dict[str, str]]:
        """HTTP 探针"""
        try:
            probe = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            data = await self._grab_banner(host, port, send_probe=probe)
            if not data:
                return None
            text = data.decode("utf-8", errors="replace")
            if "HTTP/" not in text[:20]:
                return None

            result: Dict[str, str] = {}
            # 解析状态码
            status_match = re.search(r"HTTP/[\d.]+ (\d+)", text)
            if status_match:
                result["status_code"] = status_match.group(1)
            # 解析 Server header
            server_match = re.search(r"Server:\s*(.+?)[\r\n]", text, re.IGNORECASE)
            if server_match:
                result["server"] = server_match.group(1).strip()
            # 解析 X-Powered-By
            powered_match = re.search(r"X-Powered-By:\s*(.+?)[\r\n]", text, re.IGNORECASE)
            if powered_match:
                result["powered_by"] = powered_match.group(1).strip()
            return result
        except Exception:
            return None

    async def _probe_tls(self, host: str, port: int) -> Optional[Dict[str, str]]:
        """TLS/SSL 探针 — 获取证书信息"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=self.timeout
            )
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if not ssl_obj:
                    return None
                cert = ssl_obj.getpeercert(binary_form=False)
                result: Dict[str, str] = {"version": ssl_obj.version()}
                if cert:
                    subj = cert.get("subject", ())
                    if subj:
                        cn = next((v for field_set in subj for k, v in field_set if k == "commonName"), None)
                        if cn:
                            result["subject"] = cn
                    issuer = cert.get("issuer", ())
                    if issuer:
                        icn = next((v for field_set in issuer for k, v in field_set if k == "organizationName"), None)
                        if icn:
                            result["issuer"] = icn
                    if cert.get("notAfter"):
                        result["expiry"] = cert["notAfter"]
                return result
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            return None

    async def _probe_active(self, host: str, port: int, info: ServiceInfo) -> None:
        """主动协议探针 (Redis/MongoDB)"""
        # Redis
        if port == 6379:
            data = await self._grab_banner(host, port, send_probe=_PROBES["redis"])
            if data and (b"+PONG" in data or b"redis_version" in data):
                info.service = "redis"
                ver_match = re.search(rb"redis_version:(\S+)", data)
                if ver_match:
                    info.version = ver_match.group(1).decode()
        # MongoDB
        elif port == 27017:
            data = await self._grab_banner(host, port, send_probe=_PROBES["mongodb"])
            if data and b"ismaster" in data.lower():
                info.service = "mongodb"

    def _match_signature(self, data: bytes, info: ServiceInfo) -> None:
        """匹配已知服务签名"""
        for sig in _SERVICE_SIGNATURES:
            if re.search(sig["pattern"], data):
                info.service = sig["service"]
                # 提取版本
                if "extract" in sig and info.banner:
                    m = re.search(sig["extract"], info.banner)
                    if m:
                        info.version = m.group(1) if m.lastindex else m.group(0)
                # MySQL 特殊处理: 从二进制握手包提取版本
                if sig.get("extract_bytes") and sig["service"] == "mysql":
                    m = re.search(rb"\x0a([\d.]+)", data)
                    if m:
                        info.version = m.group(1).decode("ascii", errors="replace")
                break

    def _guess_os(self, info: ServiceInfo) -> None:
        """根据服务信息猜测操作系统"""
        banner = (info.banner or "").lower() + (info.version or "").lower()
        if any(k in banner for k in ("ubuntu", "debian", "linux", "centos", "fedora", "rhel")):
            info.os_guess = "Linux"
        elif any(k in banner for k in ("windows", "microsoft", "win32", "win64")):
            info.os_guess = "Windows"
        elif any(k in banner for k in ("freebsd", "openbsd", "netbsd")):
            info.os_guess = "BSD"
        elif "darwin" in banner or "macos" in banner:
            info.os_guess = "macOS"
