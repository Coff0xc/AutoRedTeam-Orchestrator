"""
配置管理工具模块

包含工具:
- set_config: 动态调整全局配置
- set_proxy: 设置全局代理
- http_request: 通用HTTP请求
"""

import requests

from ._common import GLOBAL_CONFIG, PROXY_CONFIG, get_verify_ssl


def get_proxies():
    """获取当前代理配置"""
    if PROXY_CONFIG["enabled"] and PROXY_CONFIG["http"]:
        return {"http": PROXY_CONFIG["http"], "https": PROXY_CONFIG["https"]}
    return None


def register_config_tools(mcp):
    """注册配置管理工具到MCP服务器"""

    @mcp.tool()
    def set_config(
        verify_ssl: bool = None,
        rate_limit_delay: float = None,
        max_threads: int = None,
        request_timeout: int = None,
    ) -> dict:
        """配置管理 - 动态调整全局配置

        Args:
            verify_ssl: SSL证书验证开关 (True/False)
            rate_limit_delay: 请求间隔秒数 (0.1-5.0)
            max_threads: 最大并发线程数 (1-100)
            request_timeout: 请求超时秒数 (5-60)
        """
        changes = []

        if verify_ssl is not None:
            GLOBAL_CONFIG["verify_ssl"] = verify_ssl
            changes.append(f"verify_ssl: {verify_ssl}")

        if rate_limit_delay is not None:
            GLOBAL_CONFIG["rate_limit_delay"] = max(0.1, min(5.0, rate_limit_delay))
            changes.append(f"rate_limit_delay: {GLOBAL_CONFIG['rate_limit_delay']}s")

        if max_threads is not None:
            GLOBAL_CONFIG["max_threads"] = max(1, min(100, max_threads))
            changes.append(f"max_threads: {GLOBAL_CONFIG['max_threads']}")

        if request_timeout is not None:
            GLOBAL_CONFIG["request_timeout"] = max(5, min(60, request_timeout))
            changes.append(f"request_timeout: {GLOBAL_CONFIG['request_timeout']}s")

        return {
            "success": True,
            "changes": changes if changes else ["无更改"],
            "current_config": GLOBAL_CONFIG.copy(),
        }

    @mcp.tool()
    def set_proxy(proxy_url: str = None, enabled: bool = True) -> dict:
        """设置全局代理 - 所有HTTP请求将通过代理发送

        Args:
            proxy_url: 代理地址 (如 http://127.0.0.1:8080, socks5://127.0.0.1:1080)
            enabled: 是否启用代理
        """
        if proxy_url:
            PROXY_CONFIG["http"] = proxy_url
            PROXY_CONFIG["https"] = proxy_url
            PROXY_CONFIG["enabled"] = enabled
            return {
                "success": True,
                "message": f"代理已{'启用' if enabled else '禁用'}",
                "proxy": proxy_url,
            }
        else:
            PROXY_CONFIG["enabled"] = False
            PROXY_CONFIG["http"] = None
            PROXY_CONFIG["https"] = None
            return {"success": True, "message": "代理已清除"}

    @mcp.tool()
    def http_request(
        url: str,
        method: str = "GET",
        headers: dict = None,
        data: str = None,
        use_proxy: bool = True,
    ) -> dict:
        """通用HTTP请求 - 支持代理、自定义头、POST数据

        Args:
            url: 请求URL
            method: 请求方法 (GET/POST/PUT/DELETE)
            headers: 自定义请求头 (JSON格式)
            data: POST数据
            use_proxy: 是否使用代理
        """
        try:
            proxies = get_proxies() if use_proxy else None
            req_headers = headers or {}

            if method.upper() == "GET":
                resp = requests.get(
                    url, headers=req_headers, proxies=proxies, timeout=30, verify=get_verify_ssl()
                )
            elif method.upper() == "POST":
                resp = requests.post(
                    url,
                    headers=req_headers,
                    data=data,
                    proxies=proxies,
                    timeout=30,
                    verify=get_verify_ssl(),
                )
            elif method.upper() == "PUT":
                resp = requests.put(
                    url,
                    headers=req_headers,
                    data=data,
                    proxies=proxies,
                    timeout=30,
                    verify=get_verify_ssl(),
                )
            elif method.upper() == "DELETE":
                resp = requests.delete(
                    url, headers=req_headers, proxies=proxies, timeout=30, verify=get_verify_ssl()
                )
            else:
                return {"success": False, "error": f"不支持的方法: {method}"}

            return {
                "success": True,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:5000],
                "cookies": resp.cookies.get_dict(),
                "elapsed": resp.elapsed.total_seconds(),
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    return ["set_config", "set_proxy", "http_request"]
