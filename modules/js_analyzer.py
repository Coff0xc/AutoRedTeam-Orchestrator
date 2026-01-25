#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JS 分析引擎 - 自动提取 API 端点、路由、敏感信息
支持 Vue/React/Angular 等前端框架
"""

import re
import asyncio
import aiohttp
from typing import Set, List, Dict, Optional
from urllib.parse import urljoin, urlparse
from loguru import logger

from utils.mcp_tooling import patch_mcp_tool

# 统一 HTTP 客户端工厂
try:
    from core.http import get_async_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


class JSAnalyzer:
    """JavaScript 静态分析器 (正则表达式模式匹配)"""

    # API 端点正则 (fetch, axios, $.ajax, XMLHttpRequest)
    API_PATTERNS = [
        # fetch('/api/users', {})
        r'''fetch\s*\(\s*['"`]([^'"`]+)['"`]''',
        # axios.get('/api/users')
        r'''axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]''',
        # $.ajax({url: '/api/users'})
        r'''['\"]url['\"]:\s*['"`]([^'"`]+)['"`]''',
        # xhr.open('GET', '/api/users')
        r'''\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`]+)['"`]''',
        # request('/api/users')
        r'''(?:request|http)\.\w+\s*\(\s*['"`]([^'"`]+)['"`]''',
        # 通用路径匹配 (/api/xxx, /v1/xxx)
        r'''['"`](/(?:api|v\d+|graphql|admin|auth|user|data)/[a-zA-Z0-9/_-]+)['"`]''',
    ]

    # 前端路由正则 (Vue Router, React Router, Angular)
    ROUTE_PATTERNS = [
        # Vue Router: path: '/dashboard'
        r'''path:\s*['"`]([/\w-]+)['"`]''',
        # React Router: <Route path="/user/:id">
        r'''<Route\s+path=["']([/\w:-]+)["']''',
        # Angular Router: path: 'dashboard'
        r'''{?\s*path:\s*['"`]([/\w-]+)['"`]''',
        # router.push('/settings')
        r'''router\.(?:push|replace)\s*\(\s*['"`]([/\w-]+)['"`]''',
        # location.href = '/xxx'
        r'''location\.href\s*=\s*['"`]([/\w-]+)['"`]''',
    ]

    # 敏感信息正则 (API Keys, Tokens, Passwords)
    SECRET_PATTERNS = {
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
        'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'jwt': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'api_key_generic': r'''['"`]?(?:api[_-]?key|apikey|access[_-]?token)['"`]?\s*[:=]\s*['"`]([A-Za-z0-9_\-]{20,})['"`]''',
        'password': r'''['"`]password['"`]\s*[:=]\s*['"`]([^'"`]{6,})['"`]''',
        'internal_ip': r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
        'private_domain': r'https?://[a-zA-Z0-9-]+\.(?:local|internal|corp|intra)[/\w.-]*',
    }

    @classmethod
    def extract_api_endpoints(cls, js_content: str) -> Set[str]:
        """
        提取 API 端点

        Args:
            js_content: JavaScript 代码内容

        Returns:
            API 端点集合
        """
        endpoints = set()

        for pattern in cls.API_PATTERNS:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                path = match.group(1).strip()
                # 过滤无效路径
                if cls._is_valid_path(path):
                    endpoints.add(path)

        return endpoints

    @classmethod
    def extract_routes(cls, js_content: str) -> Set[str]:
        """
        提取前端路由

        Args:
            js_content: JavaScript 代码内容

        Returns:
            路由集合
        """
        routes = set()

        for pattern in cls.ROUTE_PATTERNS:
            matches = re.finditer(pattern, js_content)
            for match in matches:
                route = match.group(1).strip()
                if cls._is_valid_route(route):
                    routes.add(route)

        return routes

    @classmethod
    def extract_secrets(cls, js_content: str) -> List[Dict[str, str]]:
        """
        提取敏感信息

        Args:
            js_content: JavaScript 代码内容

        Returns:
            敏感信息列表 [{"type": "aws_key", "value": "AKIA...", "position": 123}]
        """
        secrets = []

        for secret_type, pattern in cls.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, js_content)
            for match in matches:
                secret_value = match.group(1) if match.lastindex else match.group(0)
                # 过滤误报 (常见占位符)
                if cls._is_real_secret(secret_value):
                    secrets.append({
                        "type": secret_type,
                        "value": secret_value,
                        "position": match.start(),
                        "context": cls._get_context(js_content, match.start(), 40)
                    })

        return secrets

    @classmethod
    def _is_valid_path(cls, path: str) -> bool:
        """验证路径有效性"""
        if not path or len(path) < 2:
            return False
        # 排除变量和模板字符串
        invalid_chars = ['{', '}', '$', '+', '"', "'", '\\']
        return not any(char in path for char in invalid_chars)

    @classmethod
    def _is_valid_route(cls, route: str) -> bool:
        """验证路由有效性"""
        if not route or len(route) < 1:
            return False
        # 允许动态路由 (/user/:id)
        return route.startswith('/') or route.replace(':', '').replace('/', '').isalnum()

    @classmethod
    def _is_real_secret(cls, value: str) -> bool:
        """过滤常见占位符"""
        if not value:
            return False
        placeholders = ['example', 'test', 'demo', 'your', 'placeholder', '123456', 'password', 'xxxxxxx']
        value_lower = value.lower()
        return not any(ph in value_lower for ph in placeholders)

    @classmethod
    def _get_context(cls, content: str, position: int, length: int = 40) -> str:
        """获取代码上下文"""
        start = max(0, position - length)
        end = min(len(content), position + length)
        return content[start:end].replace('\n', ' ').strip()

    @classmethod
    async def analyze_url(cls, url: str, max_depth: int = 2, timeout: int = 15) -> Dict:
        """
        异步爬取并分析 URL 的所有 JS 文件

        Args:
            url: 目标 URL
            max_depth: 最大爬取深度 (1=仅当前页, 2=包含链接的JS)
            timeout: 请求超时时间

        Returns:
            分析结果字典
        """
        results = {
            "target": url,
            "js_files": [],
            "endpoints": set(),
            "routes": set(),
            "secrets": []
        }

        try:
            # 使用统一 HTTP 客户端工厂或回退到 aiohttp
            if HAS_HTTP_FACTORY:
                client_ctx = get_async_client(verify_ssl=False)
            else:
                client_ctx = aiohttp.ClientSession()

            async with client_ctx as session:
                # 1. 获取主页面
                html_content = await cls._fetch_content(session, url, timeout)

                # 2. 提取 JS 文件 URL
                js_urls = cls._extract_js_urls(html_content, url)
                results["js_files"] = list(js_urls)

                # 3. 并发下载并分析所有 JS 文件
                tasks = [cls._analyze_js_file(session, js_url, timeout) for js_url in js_urls]
                js_results = await asyncio.gather(*tasks, return_exceptions=True)

                # 4. 合并结果
                for js_result in js_results:
                    if isinstance(js_result, dict):
                        results["endpoints"].update(js_result.get("endpoints", []))
                        results["routes"].update(js_result.get("routes", []))
                        results["secrets"].extend(js_result.get("secrets", []))

                # 转换 set 为 list (JSON 序列化)
                results["endpoints"] = sorted(list(results["endpoints"]))
                results["routes"] = sorted(list(results["routes"]))

        except Exception as e:
            logger.error(f"[JSAnalyzer] 分析失败: {e}")
            results["error"] = str(e)

        return results

    @classmethod
    async def _fetch_content(cls, session: aiohttp.ClientSession, url: str, timeout: int) -> str:
        """异步下载内容"""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as resp:
                if resp.status == 200:
                    return await resp.text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"[JSAnalyzer] 下载失败 {url}: {e}")
        return ""

    @classmethod
    def _extract_js_urls(cls, html_content: str, base_url: str) -> Set[str]:
        """从 HTML 中提取 JS 文件 URL"""
        js_urls = set()

        # <script src="app.js">
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        matches = re.finditer(script_pattern, html_content, re.IGNORECASE)

        for match in matches:
            js_path = match.group(1)
            # 排除外部CDN (可选)
            if not js_path.startswith(('http://', 'https://')):
                js_url = urljoin(base_url, js_path)
            else:
                # 只分析同域JS
                if urlparse(js_path).netloc == urlparse(base_url).netloc:
                    js_url = js_path
                else:
                    continue

            js_urls.add(js_url)

        return js_urls

    @classmethod
    async def _analyze_js_file(cls, session: aiohttp.ClientSession, js_url: str, timeout: int) -> Dict:
        """分析单个 JS 文件"""
        result = {
            "url": js_url,
            "endpoints": set(),
            "routes": set(),
            "secrets": []
        }

        js_content = await cls._fetch_content(session, js_url, timeout)
        if js_content:
            result["endpoints"] = cls.extract_api_endpoints(js_content)
            result["routes"] = cls.extract_routes(js_content)
            result["secrets"] = cls.extract_secrets(js_content)
            logger.info(f"[JSAnalyzer] {js_url} -> {len(result['endpoints'])} endpoints, {len(result['secrets'])} secrets")

        return result


# =========================== MCP 工具注册 ===========================

def register_js_tools(mcp):
    """注册 JS 分析工具到 MCP Server"""
    patch_mcp_tool(mcp)

    @mcp.tool()
    async def js_analyze(url: str) -> dict:
        """
        JS 静态分析 - 自动提取 API 端点、前端路由、敏感信息

        Args:
            url: 目标 URL (自动爬取所有 JS 文件)

        Returns:
            {
                "target": "https://example.com",
                "js_files": ["app.js", "vendor.js"],
                "endpoints": ["/api/users", "/api/login"],
                "routes": ["/dashboard", "/settings"],
                "secrets": [{"type": "aws_key", "value": "AKIA..."}]
            }
        """
        return await JSAnalyzer.analyze_url(url)

    @mcp.tool()
    def js_extract_apis(js_code: str) -> list:
        """
        从 JS 代码中提取 API 端点

        Args:
            js_code: JavaScript 源代码

        Returns:
            API 端点列表
        """
        return list(JSAnalyzer.extract_api_endpoints(js_code))

    @mcp.tool()
    def js_extract_secrets(js_code: str) -> list:
        """
        从 JS 代码中提取敏感信息 (API Keys, Tokens, Passwords)

        Args:
            js_code: JavaScript 源代码

        Returns:
            敏感信息列表 [{"type": "aws_key", "value": "AKIA...", "context": "..."}]
        """
        return JSAnalyzer.extract_secrets(js_code)

    logger.info("[MCP] JS 分析工具已注册: js_analyze, js_extract_apis, js_extract_secrets")


# =========================== 独立测试 ===========================

async def test_js_analyzer():
    """测试函数"""

    # 测试 1: API 端点提取
    test_code = """
    fetch('/api/users', {method: 'GET'});
    axios.post('/v1/login', data);
    $.ajax({url: '/admin/dashboard'});
    xhr.open('GET', '/graphql/query');
    """

    endpoints = JSAnalyzer.extract_api_endpoints(test_code)
    print(f"✅ API 端点: {endpoints}")

    # 测试 2: 敏感信息提取
    secret_code = """
    const apiKey = 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe';
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    """

    secrets = JSAnalyzer.extract_secrets(secret_code)
    print(f"✅ 敏感信息: {secrets}")

    # 测试 3: 实际 URL 分析 (需要联网)
    # result = await JSAnalyzer.analyze_url("https://example.com")
    # print(f"✅ URL 分析: {result}")


if __name__ == "__main__":
    # 配置日志
    logger.remove()
    logger.add(lambda msg: print(msg, end=""), colorize=True, format="<level>{message}</level>")

    # 运行测试
    asyncio.run(test_js_analyzer())
