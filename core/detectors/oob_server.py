#!/usr/bin/env python3
"""
内置 OOB (Out-of-Band) 回调监听器

轻量级 HTTP/DNS 服务器，接收来自目标的 OOB 回调请求，
自动标记对应 token 为已触发。

Usage:
    from core.detectors.advanced_verifier import OOBCallbackManager
    from core.detectors.oob_server import OOBCallbackServer

    manager = OOBCallbackManager(callback_server="http://YOUR_IP:8899")
    server = OOBCallbackServer(manager, port=8899)
    server.start()  # 非阻塞，后台线程运行

    # ... 执行 OOB 检测 ...

    server.stop()
"""

import logging
import re
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import UDPServer, BaseRequestHandler
from typing import TYPE_CHECKING, Any, Dict, Optional
from urllib.parse import parse_qs

if TYPE_CHECKING:
    from .advanced_verifier import OOBCallbackManager

logger = logging.getLogger(__name__)

# 预编译 token 格式验证正则（16 位十六进制）
_TOKEN_RE = re.compile(r"[0-9a-fA-F]{16}")

# ==================== HTTP 回调监听器 ====================


class _OOBHTTPHandler(BaseHTTPRequestHandler):
    """OOB HTTP 回调请求处理器

    处理任意 HTTP 方法，从 URL 路径、查询参数、Host 头提取 token，
    匹配后调用 manager.mark_triggered()。
    """

    # 类属性，由 OOBCallbackServer 注入
    oob_manager: Optional["OOBCallbackManager"] = None
    oob_logger: Optional[logging.Logger] = None

    def _extract_tokens(self) -> list:
        """从请求中提取可能的 token ID

        提取策略（按优先级）:
        1. URL 路径: /<token_id> 或 /<token_id>.<type>.<domain>
        2. 查询参数: ?token=<token_id>
        3. Host 头子域名: <token_id>.callback.example.com

        Returns:
            候选 token ID 列表
        """
        candidates = []

        # 分离路径和查询参数
        path = self.path
        query_string = ""
        if "?" in path:
            path, query_string = path.split("?", 1)

        # 策略 1: URL 路径提取
        # 去除开头的 /，取第一段
        path_stripped = path.strip("/")
        if path_stripped:
            first_segment = path_stripped.split("/")[0]
            # 支持 <token_id>.<type>.<domain> 格式
            token_part = first_segment.split(".")[0]
            if self._is_valid_token(token_part):
                candidates.append(token_part)
            # 完整 segment 也可能是 token
            if self._is_valid_token(first_segment) and first_segment != token_part:
                candidates.append(first_segment)

        # 策略 2: 查询参数 ?token=<token_id>
        if query_string:
            params = parse_qs(query_string)
            for val in params.get("token", []):
                if self._is_valid_token(val):
                    candidates.append(val)

        # 策略 3: Host 头子域名
        host = self.headers.get("Host", "")
        if host:
            # 去掉端口
            host_no_port = host.split(":")[0]
            parts = host_no_port.split(".")
            if len(parts) >= 3:
                # 第一段可能是 token
                subdomain = parts[0]
                if self._is_valid_token(subdomain):
                    candidates.append(subdomain)

        return candidates

    @staticmethod
    def _is_valid_token(value: str) -> bool:
        """检查是否为有效的 token 格式（16 位十六进制）"""
        return bool(_TOKEN_RE.fullmatch(value))

    def _build_trigger_data(self) -> Dict[str, Any]:
        """构建触发数据（请求详情）"""
        client_ip = self.client_address[0] if self.client_address else "unknown"
        return {
            "source_ip": client_ip,
            "source_port": self.client_address[1] if self.client_address else 0,
            "method": self.command or "UNKNOWN",
            "path": self.path,
            "headers": dict(self.headers),
            "timestamp": time.time(),
            "protocol": "http",
        }

    def _handle_request(self):
        """统一处理所有 HTTP 方法"""
        if not self.oob_manager:
            self._send_response(200)
            return

        candidates = self._extract_tokens()
        trigger_data = None
        matched = False

        for token_id in candidates:
            if trigger_data is None:
                trigger_data = self._build_trigger_data()
            if self.oob_manager.mark_triggered(token_id, trigger_data):
                matched = True
                log = self.oob_logger or logger
                log.info(
                    "OOB HTTP 回调命中: token=%s, 来源=%s, 方法=%s, 路径=%s",
                    token_id,
                    trigger_data["source_ip"],
                    trigger_data["method"],
                    trigger_data["path"],
                )
                break  # 命中第一个即可

        if not matched and candidates:
            if trigger_data is None:
                trigger_data = self._build_trigger_data()
            log = self.oob_logger or logger
            log.debug(
                "OOB HTTP 请求未匹配: candidates=%s, 来源=%s",
                candidates,
                trigger_data["source_ip"],
            )

        # 始终返回 200 OK，最小化信息泄露
        self._send_response(200)

    def _send_response(self, code: int):
        """发送最小化响应"""
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    # 处理所有 HTTP 方法
    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request()

    def do_OPTIONS(self):
        self._handle_request()

    def log_message(self, format, *args):  # noqa: A002
        """覆盖默认日志，使用项目日志系统"""
        log = self.oob_logger or logger
        log.debug("OOB HTTP: %s", format % args)


# ==================== DNS 回调监听器 ====================


class _OOBDNSHandler(BaseRequestHandler):
    """OOB DNS 查询处理器

    解析 DNS 请求，从查询名提取 token，
    匹配后调用 manager.mark_triggered()。
    响应固定 A 记录 (127.0.0.1)。
    """

    # 类属性，由 OOBCallbackServer 注入
    oob_manager: Optional["OOBCallbackManager"] = None
    oob_logger: Optional[logging.Logger] = None

    def handle(self):
        """处理 DNS UDP 请求"""
        data = self.request[0]
        sock = self.request[1]

        if len(data) < 12:
            return

        try:
            query_name, query_type = self._parse_dns_query(data)
        except Exception as e:
            log = self.oob_logger or logger
            log.debug("DNS 查询解析失败: %s", e)
            return

        if not query_name:
            return

        log = self.oob_logger or logger
        log.debug("OOB DNS 查询: name=%s, type=%s", query_name, query_type)

        # 从查询名提取 token
        # 格式: <token_id>.<finding_type>.<domain> 或 <token_id>.<domain>
        parts = query_name.lower().split(".")
        matched = False

        if self.oob_manager:
            for part in parts:
                if _OOBHTTPHandler._is_valid_token(part):
                    trigger_data = {
                        "source_ip": self.client_address[0],
                        "source_port": self.client_address[1],
                        "query_name": query_name,
                        "query_type": query_type,
                        "timestamp": time.time(),
                        "protocol": "dns",
                    }
                    if self.oob_manager.mark_triggered(part, trigger_data):
                        matched = True
                        log.info(
                            "OOB DNS 回调命中: token=%s, 查询=%s, 来源=%s",
                            part,
                            query_name,
                            self.client_address[0],
                        )
                        break

        # 构建 DNS 响应
        response = self._build_dns_response(data, query_name, matched)
        sock.sendto(response, self.client_address)

    @staticmethod
    def _parse_dns_query(data: bytes) -> tuple:
        """解析 DNS 查询包

        Args:
            data: 原始 DNS 数据

        Returns:
            (query_name, query_type_str)
        """
        # 跳过 DNS 头部 (12 字节)
        offset = 12
        labels = []

        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:
                # 压缩指针，不在查询部分处理
                offset += 2
                break
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
            offset += length

        query_name = ".".join(labels)

        # 查询类型 (2 字节)
        query_type = 1  # 默认 A 记录
        if offset + 2 <= len(data):
            query_type = struct.unpack("!H", data[offset : offset + 2])[0]

        type_map = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 15: "MX", 2: "NS"}
        query_type_str = type_map.get(query_type, str(query_type))

        return query_name, query_type_str

    @staticmethod
    def _extract_query_section(query_data: bytes) -> bytes:
        """提取 DNS 查询部分（从偏移 12 到 QTYPE+QCLASS 结束）"""
        offset = 12
        while offset < len(query_data):
            length = query_data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1 + length
        # QTYPE + QCLASS
        offset += 4
        return query_data[12:offset]

    @staticmethod
    def _build_dns_response(query_data: bytes, query_name: str, matched: bool) -> bytes:  # noqa: ARG004
        """构建 DNS 响应包

        Args:
            query_data: 原始查询数据
            query_name: 查询域名
            matched: 是否命中 token

        Returns:
            DNS 响应字节流
        """
        if len(query_data) < 12:
            return b""

        # 事务 ID
        transaction_id = query_data[:2]
        query_section = _OOBDNSHandler._extract_query_section(query_data)

        if matched:
            # 返回 A 记录: 127.0.0.1
            # Flags: 标准响应, 无错误
            flags = struct.pack("!H", 0x8180)
            # QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
            counts = struct.pack("!HHHH", 1, 1, 0, 0)

            # 应答部分: 指针 + TYPE A + CLASS IN + TTL + RDLENGTH + 127.0.0.1
            answer = (
                struct.pack("!H", 0xC00C)  # 名称指针 -> 查询名
                + struct.pack("!H", 1)  # TYPE A
                + struct.pack("!H", 1)  # CLASS IN
                + struct.pack("!I", 60)  # TTL 60秒
                + struct.pack("!H", 4)  # RDLENGTH
                + socket.inet_aton("127.0.0.1")  # RDATA
            )

            return transaction_id + flags + counts + query_section + answer
        else:
            # NXDOMAIN 响应
            flags = struct.pack("!H", 0x8183)  # 标准响应, NXDOMAIN
            counts = struct.pack("!HHHH", 1, 0, 0, 0)

            return transaction_id + flags + counts + query_section


# ==================== OOB 回调服务器 ====================


class OOBCallbackServer:
    """内置 OOB 回调监听器

    轻量级 HTTP/DNS 服务器，接收来自目标的 OOB 回调请求，
    自动标记对应 token 为已触发。

    Usage:
        manager = OOBCallbackManager(callback_server="http://YOUR_IP:8899")
        server = OOBCallbackServer(manager, port=8899)
        server.start()  # 非阻塞，后台线程运行

        # ... 执行 OOB 检测 ...

        server.stop()

    Args:
        manager: OOBCallbackManager 实例
        http_port: HTTP 监听端口 (默认 8899)
        dns_port: DNS 监听端口 (默认 8853, 非 53 避免 root 要求)
        bind_address: 绑定地址 (默认 0.0.0.0)
        enable_dns: 是否启用 DNS 监听器 (默认 False)
    """

    def __init__(
        self,
        manager: "OOBCallbackManager",
        http_port: int = 8899,
        dns_port: int = 8853,
        bind_address: str = "0.0.0.0",
        enable_dns: bool = False,
    ):
        self._manager = manager
        self._http_port = http_port
        self._dns_port = dns_port
        self._bind_address = bind_address
        self._enable_dns = enable_dns

        self._http_server: Optional[HTTPServer] = None
        self._dns_server: Optional[UDPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        """服务器是否正在运行"""
        return self._running

    @property
    def http_port(self) -> int:
        """HTTP 监听端口"""
        return self._http_port

    @property
    def dns_port(self) -> int:
        """DNS 监听端口"""
        return self._dns_port

    def start(self):
        """启动 OOB 回调监听器（非阻塞）

        在后台守护线程中启动 HTTP 服务器，
        可选启动 DNS 服务器。

        Raises:
            RuntimeError: 服务器已在运行
            OSError: 端口被占用
        """
        with self._lock:
            if self._running:
                raise RuntimeError("OOB 回调服务器已在运行")

            # 启动 HTTP 服务器
            self._start_http_server()

            # 可选启动 DNS 服务器
            if self._enable_dns:
                self._start_dns_server()

            self._running = True
            logger.info(
                "OOB 回调服务器已启动: HTTP=%s:%d%s",
                self._bind_address,
                self._http_port,
                (", DNS=%s:%d" % (self._bind_address, self._dns_port))
                if self._enable_dns
                else "",
            )

    def stop(self):
        """停止 OOB 回调监听器

        安全关闭所有监听线程和服务器。
        """
        with self._lock:
            if not self._running:
                return

            self._running = False

            # 关闭 HTTP 服务器
            if self._http_server:
                self._http_server.shutdown()
                self._http_server.server_close()
                self._http_server = None

            if self._http_thread:
                self._http_thread.join(timeout=5)
                self._http_thread = None

            # 关闭 DNS 服务器
            if self._dns_server:
                self._dns_server.shutdown()
                self._dns_server.server_close()
                self._dns_server = None

            if self._dns_thread:
                self._dns_thread.join(timeout=5)
                self._dns_thread = None

            logger.info("OOB 回调服务器已停止")

    def _start_http_server(self):
        """启动 HTTP 监听线程"""
        # 创建 handler 子类，注入 manager 引用
        handler_class = type(
            "_BoundOOBHTTPHandler",
            (_OOBHTTPHandler,),
            {"oob_manager": self._manager, "oob_logger": logger},
        )

        self._http_server = HTTPServer(
            (self._bind_address, self._http_port),
            handler_class,
        )
        # 设置超时避免 shutdown 阻塞
        self._http_server.timeout = 1

        self._http_thread = threading.Thread(
            target=self._http_server.serve_forever,
            name="oob-http-listener",
            daemon=True,
        )
        self._http_thread.start()

    def _start_dns_server(self):
        """启动 DNS 监听线程"""
        handler_class = type(
            "_BoundOOBDNSHandler",
            (_OOBDNSHandler,),
            {"oob_manager": self._manager, "oob_logger": logger},
        )

        self._dns_server = UDPServer(
            (self._bind_address, self._dns_port),
            handler_class,
        )
        self._dns_server.timeout = 1

        self._dns_thread = threading.Thread(
            target=self._dns_server.serve_forever,
            name="oob-dns-listener",
            daemon=True,
        )
        self._dns_thread.start()

    def __enter__(self):
        """上下文管理器支持"""
        self.start()
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        """退出时自动停止"""
        self.stop()
        return False
