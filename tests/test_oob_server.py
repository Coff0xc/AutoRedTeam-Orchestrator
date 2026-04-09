#!/usr/bin/env python3
"""
OOB 回调监听器测试

测试 core/detectors/oob_server.py 的 HTTP/DNS 监听器功能
以及 OOBCallbackManager 的 start_listener/stop_listener 集成
"""

import socket
import struct
import time
import urllib.request

import pytest

from core.detectors.advanced_verifier import OOBCallbackManager
from core.detectors.oob_server import OOBCallbackServer, _OOBDNSHandler, _OOBHTTPHandler


# ==================== _OOBHTTPHandler 单元测试 ====================


class TestOOBHTTPHandlerTokenValidation:
    """HTTP Handler 的 token 验证逻辑"""

    def test_valid_token_16_hex(self):
        assert _OOBHTTPHandler._is_valid_token("abcdef0123456789")

    def test_valid_token_uppercase(self):
        assert _OOBHTTPHandler._is_valid_token("ABCDEF0123456789")

    def test_invalid_token_too_short(self):
        assert not _OOBHTTPHandler._is_valid_token("abcdef01")

    def test_invalid_token_too_long(self):
        assert not _OOBHTTPHandler._is_valid_token("abcdef01234567890")

    def test_invalid_token_non_hex(self):
        assert not _OOBHTTPHandler._is_valid_token("ghijklmnopqrstuv")

    def test_invalid_token_empty(self):
        assert not _OOBHTTPHandler._is_valid_token("")


# ==================== _OOBDNSHandler 单元测试 ====================


class TestOOBDNSHandlerParsing:
    """DNS Handler 的解析逻辑"""

    @staticmethod
    def _build_dns_query(name: str, qtype: int = 1) -> bytes:
        """构建简单 DNS 查询包"""
        # DNS 头部: ID=0x1234, flags=标准查询, QDCOUNT=1
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)

        # 查询名: 按 label 编码
        question = b""
        for label in name.split("."):
            question += bytes([len(label)]) + label.encode("ascii")
        question += b"\x00"  # 结束符

        # QTYPE + QCLASS (IN)
        question += struct.pack("!HH", qtype, 1)

        return header + question

    def test_parse_a_record_query(self):
        data = self._build_dns_query("abc123def4567890.ssrf.example.com", qtype=1)
        name, qtype = _OOBDNSHandler._parse_dns_query(data)
        assert name == "abc123def4567890.ssrf.example.com"
        assert qtype == "A"

    def test_parse_txt_record_query(self):
        data = self._build_dns_query("token123.example.com", qtype=16)
        name, qtype = _OOBDNSHandler._parse_dns_query(data)
        assert name == "token123.example.com"
        assert qtype == "TXT"

    def test_build_dns_response_matched(self):
        query = self._build_dns_query("test.example.com")
        response = _OOBDNSHandler._build_dns_response(query, "test.example.com", matched=True)
        # 验证事务 ID 一致
        assert response[:2] == query[:2]
        # 验证 flags 表示正常响应
        flags = struct.unpack("!H", response[2:4])[0]
        assert flags & 0x8000  # QR=1 (response)
        assert (flags & 0x000F) == 0  # RCODE=0 (no error)
        # 验证 ANCOUNT=1
        ancount = struct.unpack("!H", response[6:8])[0]
        assert ancount == 1
        # 验证响应包含 127.0.0.1
        assert socket.inet_aton("127.0.0.1") in response

    def test_build_dns_response_nxdomain(self):
        query = self._build_dns_query("unknown.example.com")
        response = _OOBDNSHandler._build_dns_response(query, "unknown.example.com", matched=False)
        # 验证 RCODE=3 (NXDOMAIN)
        flags = struct.unpack("!H", response[2:4])[0]
        assert (flags & 0x000F) == 3

    def test_build_dns_response_short_data(self):
        response = _OOBDNSHandler._build_dns_response(b"\x00" * 5, "x", matched=True)
        assert response == b""


# ==================== OOBCallbackServer 集成测试 ====================


def _find_free_port() -> int:
    """查找可用端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestOOBCallbackServerHTTP:
    """OOBCallbackServer HTTP 监听器集成测试"""

    @pytest.fixture
    def manager(self):
        return OOBCallbackManager(callback_server="http://127.0.0.1")

    @pytest.fixture
    def server(self, manager):
        port = _find_free_port()
        srv = OOBCallbackServer(
            manager, http_port=port, bind_address="127.0.0.1"
        )
        srv.start()
        # 等待服务器就绪
        time.sleep(0.2)
        yield srv
        srv.stop()

    def test_server_starts_and_stops(self, manager):
        port = _find_free_port()
        srv = OOBCallbackServer(manager, http_port=port, bind_address="127.0.0.1")
        assert not srv.running
        srv.start()
        assert srv.running
        srv.stop()
        assert not srv.running

    def test_double_start_raises(self, server):
        with pytest.raises(RuntimeError, match="已在运行"):
            server.start()

    def test_double_stop_noop(self, server):
        server.stop()
        server.stop()  # 第二次调用不应报错

    def test_context_manager(self, manager):
        port = _find_free_port()
        with OOBCallbackServer(manager, http_port=port, bind_address="127.0.0.1") as srv:
            assert srv.running
        assert not srv.running

    def test_http_callback_path_token(self, manager, server):
        """通过 URL 路径触发 token"""
        token = manager.generate_token("ssrf", "http://target.com", protocol="http")
        token_id = token.token_id
        port = server.http_port

        # 发送请求到 /<token_id>
        url = f"http://127.0.0.1:{port}/{token_id}"
        try:
            urllib.request.urlopen(url, timeout=5)
        except Exception:
            pass

        # 等待处理
        time.sleep(0.3)
        assert manager.check_callback(token_id)

        # 验证触发数据
        t = manager.get_token(token_id)
        assert t.triggered
        assert t.trigger_data["protocol"] == "http"
        assert t.trigger_data["method"] == "GET"

    def test_http_callback_query_param(self, manager, server):
        """通过查询参数 ?token= 触发"""
        token = manager.generate_token("xxe", "http://target.com", protocol="http")
        token_id = token.token_id
        port = server.http_port

        url = f"http://127.0.0.1:{port}/some/path?token={token_id}"
        try:
            urllib.request.urlopen(url, timeout=5)
        except Exception:
            pass

        time.sleep(0.3)
        assert manager.check_callback(token_id)

    def test_http_callback_dotted_path(self, manager, server):
        """路径包含 <token_id>.<type>.<domain> 格式"""
        token = manager.generate_token("rce", "target", protocol="dns")
        token_id = token.token_id
        port = server.http_port

        url = f"http://127.0.0.1:{port}/{token_id}.rce.example.com"
        try:
            urllib.request.urlopen(url, timeout=5)
        except Exception:
            pass

        time.sleep(0.3)
        assert manager.check_callback(token_id)

    def test_http_callback_no_match(self, manager, server):
        """不匹配的请求不触发任何 token"""
        token = manager.generate_token("ssrf", "target", protocol="http")
        port = server.http_port

        url = f"http://127.0.0.1:{port}/invalid_token"
        try:
            urllib.request.urlopen(url, timeout=5)
        except Exception:
            pass

        time.sleep(0.3)
        assert not manager.check_callback(token.token_id)

    def test_http_returns_200(self, manager, server):
        """响应始终为 200 OK"""
        port = server.http_port
        url = f"http://127.0.0.1:{port}/anything"
        resp = urllib.request.urlopen(url, timeout=5)
        assert resp.status == 200

    def test_http_post_method(self, manager, server):
        """POST 请求也能触发"""
        token = manager.generate_token("rce", "target", protocol="http")
        token_id = token.token_id
        port = server.http_port

        url = f"http://127.0.0.1:{port}/{token_id}"
        req = urllib.request.Request(url, data=b"test", method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass

        time.sleep(0.3)
        assert manager.check_callback(token_id)
        t = manager.get_token(token_id)
        assert t.trigger_data["method"] == "POST"


# ==================== DNS 监听器集成测试 ====================


class TestOOBCallbackServerDNS:
    """OOBCallbackServer DNS 监听器集成测试"""

    @pytest.fixture
    def manager(self):
        return OOBCallbackManager(callback_server="oob.test.com")

    @pytest.fixture
    def server(self, manager):
        http_port = _find_free_port()
        dns_port = _find_free_port()
        srv = OOBCallbackServer(
            manager,
            http_port=http_port,
            dns_port=dns_port,
            bind_address="127.0.0.1",
            enable_dns=True,
        )
        srv.start()
        time.sleep(0.2)
        yield srv
        srv.stop()

    @staticmethod
    def _send_dns_query(port: int, name: str, qtype: int = 1) -> bytes:
        """发送 DNS UDP 查询并接收响应"""
        # 构建查询
        header = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
        question = b""
        for label in name.split("."):
            question += bytes([len(label)]) + label.encode("ascii")
        question += b"\x00"
        question += struct.pack("!HH", qtype, 1)

        query = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(query, ("127.0.0.1", port))
            data, _ = sock.recvfrom(512)
            return data
        finally:
            sock.close()

    def test_dns_callback_triggers_token(self, manager, server):
        """DNS 查询触发 token"""
        token = manager.generate_token("ssrf", "target", protocol="dns")
        token_id = token.token_id
        dns_port = server.dns_port

        # 发送 DNS 查询: <token_id>.ssrf.oob.test.com
        query_name = f"{token_id}.ssrf.oob.test.com"
        self._send_dns_query(dns_port, query_name)

        time.sleep(0.3)
        assert manager.check_callback(token_id)

        t = manager.get_token(token_id)
        assert t.trigger_data["protocol"] == "dns"
        assert t.trigger_data["query_name"] == query_name

    def test_dns_response_has_answer_on_match(self, manager, server):
        """命中时 DNS 响应包含 A 记录"""
        token = manager.generate_token("rce", "target", protocol="dns")
        token_id = token.token_id
        dns_port = server.dns_port

        response = self._send_dns_query(dns_port, f"{token_id}.rce.oob.test.com")

        # 验证事务 ID
        assert response[:2] == struct.pack("!H", 0xABCD)
        # ANCOUNT >= 1
        ancount = struct.unpack("!H", response[6:8])[0]
        assert ancount >= 1
        # 响应包含 127.0.0.1
        assert socket.inet_aton("127.0.0.1") in response

    def test_dns_nxdomain_on_no_match(self, manager, server):
        """无匹配时返回 NXDOMAIN"""
        dns_port = server.dns_port
        response = self._send_dns_query(dns_port, "invalid.example.com")

        flags = struct.unpack("!H", response[2:4])[0]
        rcode = flags & 0x000F
        assert rcode == 3  # NXDOMAIN


# ==================== OOBCallbackManager 集成方法测试 ====================


class TestOOBCallbackManagerIntegration:
    """OOBCallbackManager.start_listener/stop_listener 测试"""

    def test_start_and_stop_listener(self):
        manager = OOBCallbackManager(callback_server="http://127.0.0.1")
        port = _find_free_port()
        listener = manager.start_listener(http_port=port, bind_address="127.0.0.1")
        assert listener.running
        manager.stop_listener()
        assert not listener.running

    def test_double_start_listener_raises(self):
        manager = OOBCallbackManager(callback_server="http://127.0.0.1")
        port = _find_free_port()
        manager.start_listener(http_port=port, bind_address="127.0.0.1")
        try:
            with pytest.raises(RuntimeError, match="已在运行"):
                manager.start_listener(http_port=_find_free_port(), bind_address="127.0.0.1")
        finally:
            manager.stop_listener()

    def test_stop_listener_without_start(self):
        """未启动时调用 stop_listener 不报错"""
        manager = OOBCallbackManager(callback_server="http://127.0.0.1")
        manager.stop_listener()  # 不应报错

    def test_end_to_end_with_listener(self):
        """完整流程: 生成 token -> 启动监听 -> HTTP 回调 -> 验证触发"""
        manager = OOBCallbackManager(callback_server="http://127.0.0.1")
        port = _find_free_port()
        manager.start_listener(http_port=port, bind_address="127.0.0.1")

        try:
            time.sleep(0.2)

            token = manager.generate_token("ssrf", "http://target.com", protocol="http")
            assert not manager.check_callback(token.token_id)

            # 模拟目标回调
            url = f"http://127.0.0.1:{port}/{token.token_id}"
            try:
                urllib.request.urlopen(url, timeout=5)
            except Exception:
                pass

            time.sleep(0.3)
            assert manager.check_callback(token.token_id)
        finally:
            manager.stop_listener()
