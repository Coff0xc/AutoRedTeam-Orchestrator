"""
会话管理工具模块

包含工具:
- oob_detect: OOB带外检测
- session_create: 创建HTTP会话
- session_login: 会话登录
- session_request: 会话请求 (带SSRF防护)
- session_context: 获取会话上下文
- smart_payload: 智能Payload变异
- verify_vuln: 统计学漏洞验证
"""

import json
import socket
import ipaddress
from urllib.parse import urlparse


def register_session_tools(mcp):
    """注册会话管理工具到MCP服务器"""

    @mcp.tool()
    def oob_detect(url: str, param: str, vuln_type: str = "ssrf", timeout: int = 30) -> dict:
        """OOB带外检测 - 检测盲SSRF/XXE/SQLi等漏洞

        Args:
            url: 目标URL
            param: 测试参数
            vuln_type: 漏洞类型 (ssrf/xxe/sqli/rce)
            timeout: 等待回调超时(秒)

        Returns:
            OOB检测结果
        """
        from modules.oob_detector import quick_oob_test
        return quick_oob_test(url, param, vuln_type, timeout)

    @mcp.tool()
    def session_create(name: str = None) -> dict:
        """创建HTTP会话 - 用于登录态测试

        Args:
            name: 会话名称 (可选)

        Returns:
            会话ID和信息
        """
        from core.session import get_http_session_manager
        mgr = get_http_session_manager()
        session_id = mgr.create_session(name)
        return {
            "success": True,
            "session_id": session_id,
            "message": f"HTTP会话已创建: {session_id}"
        }

    @mcp.tool()
    def session_login(session_id: str, login_url: str, username: str, password: str,
                      username_field: str = "username", password_field: str = "password") -> dict:
        """会话登录 - 执行登录获取认证态

        Args:
            session_id: 会话ID
            login_url: 登录URL
            username: 用户名
            password: 密码
            username_field: 用户名字段名 (默认username)
            password_field: 密码字段名 (默认password)

        Returns:
            登录结果
        """
        from core.session import get_http_session_manager
        mgr = get_http_session_manager()
        return mgr.login(session_id, login_url, username, password, username_field, password_field)

    @mcp.tool()
    def session_request(session_id: str, url: str, method: str = "GET", data: str = None) -> dict:
        """会话请求 - 使用已认证会话发送请求

        Args:
            session_id: 会话ID
            url: 请求URL
            method: HTTP方法 (GET/POST)
            data: POST数据 (JSON格式)

        Returns:
            响应结果
        """
        # SSRF防护: 验证URL不指向内网
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return {"success": False, "error": "无效的URL"}

            # 解析IP地址
            try:
                ip = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(ip)
                # 阻止私有IP、回环地址、链路本地地址
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return {"success": False, "error": f"SSRF防护: 禁止访问内网地址 {ip}"}
                # 阻止云元数据端点
                if ip == "169.254.169.254":
                    return {"success": False, "error": "SSRF防护: 禁止访问云元数据端点"}
            except socket.gaierror:
                pass  # 无法解析的域名，让后续请求处理
        except Exception:
            return {"success": False, "error": "URL解析失败"}

        from core.session import get_http_session_manager
        mgr = get_http_session_manager()
        data_dict = json.loads(data) if data else None
        return mgr.request(session_id, url, method, data_dict)

    @mcp.tool()
    def session_context(session_id: str) -> dict:
        """获取会话上下文 - 查看Cookie/Token/认证状态

        Args:
            session_id: 会话ID

        Returns:
            会话上下文信息
        """
        from core.session import get_http_session_manager
        return get_http_session_manager().get_context(session_id)

    @mcp.tool()
    def verify_vuln(url: str, param: str, vuln_type: str, payload: str = "", rounds: int = 5) -> dict:
        """统计学漏洞验证 - 多轮测试降低误报

        Args:
            url: 目标URL (需包含参数，如 http://example.com/page?id=1)
            param: 测试参数名
            vuln_type: 漏洞类型 (sqli/xss/lfi/rce/ssrf)
            payload: 测试Payload (XSS/LFI需要)
            rounds: 验证轮数 (默认5轮)

        Returns:
            统计验证结果，包含置信度和建议
        """
        from modules.vuln_verifier import verify_vuln_statistically
        return verify_vuln_statistically(url, param, vuln_type, payload, rounds)

    return ["oob_detect", "session_create", "session_login", "session_request",
            "session_context", "verify_vuln"]
