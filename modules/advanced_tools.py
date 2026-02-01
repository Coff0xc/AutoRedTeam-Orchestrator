#!/usr/bin/env python3
"""
高级渗透工具集成模块 - Advanced Pentest Tools Integration
集成隐蔽模块和漏洞利用模块到 MCP Server
"""

import logging
from typing import Any, Dict, List, Optional

from utils.mcp_tooling import patch_mcp_tool

logger = logging.getLogger(__name__)

# 导入新模块
try:
    pass

    HAS_STEALTH = True
except ImportError as e:
    logger.warning(f"Stealth module not available: {e}")
    HAS_STEALTH = False

try:
    pass

    HAS_EXPLOIT = True
except ImportError as e:
    logger.warning(f"Exploit module not available: {e}")
    HAS_EXPLOIT = False


# ==================== 隐蔽模块工具 ====================


async def stealth_request(
    url: str,
    method: str = "GET",
    params: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    stealth_level: int = 2,
    browser: str = "chrome",
) -> Dict[str, Any]:
    """
    发送隐蔽请求

    Args:
        url: 目标URL
        method: HTTP方法
        params: URL参数
        headers: 自定义Headers
        stealth_level: 隐蔽等级 (1-3)
        browser: 浏览器类型 (chrome, firefox, safari)

    Returns:
        变异后的请求配置
    """
    if not HAS_STEALTH:
        return {"error": "Stealth module not available"}

    from core.stealth.fingerprint_spoofer import BrowserType, FingerprintSpoofer
    from core.stealth.traffic_mutator import MutationConfig, TrafficMutator

    # 配置
    config = MutationConfig()
    if stealth_level >= 2:
        config.add_noise_headers = True
        config.shuffle_params = True
    if stealth_level >= 3:
        config.add_fake_params = True
        config.min_delay = 1.0
        config.max_delay = 5.0

    # 流量变异
    mutator = TrafficMutator(config)
    mutated = mutator.mutate_request(url, method, headers, params)

    # 指纹伪装
    browser_map = {
        "chrome": BrowserType.CHROME,
        "firefox": BrowserType.FIREFOX,
        "safari": BrowserType.SAFARI,
    }
    browser_type = browser_map.get(browser.lower(), BrowserType.CHROME)
    spoofer = FingerprintSpoofer(browser_type)

    # 合并Headers
    stealth_headers = spoofer.get_headers()
    stealth_headers.update(mutated.get("headers", {}))

    return {
        "url": mutated["url"],
        "method": mutated["method"],
        "headers": stealth_headers,
        "params": mutated.get("params"),
        "suggested_delay": mutated.get("delay", 0),
        "browser_profile": spoofer.profile.browser_type.value,
        "stealth_level": stealth_level,
    }


async def proxy_pool_manage(
    action: str,
    proxies: Optional[List[str]] = None,
    proxy_file: Optional[str] = None,
    strategy: str = "random",
) -> Dict[str, Any]:
    """
    代理池管理

    Args:
        action: 操作 (add, remove, get, validate, stats, load)
        proxies: 代理列表 (用于add)
        proxy_file: 代理文件路径 (用于load)
        strategy: 选择策略 (random, fastest, weighted)
    """
    if not HAS_STEALTH:
        return {"error": "Stealth module not available"}

    from core.stealth.proxy_pool import ProxyPool

    # 使用全局代理池
    global _proxy_pool
    if "_proxy_pool" not in globals():
        _proxy_pool = ProxyPool(auto_validate=False)

    pool = _proxy_pool

    if action == "add" and proxies:
        added = pool.add_proxies(proxies)
        return {"action": "add", "added": added, "total": pool.count}

    elif action == "load" and proxy_file:
        added = pool.load_from_file(proxy_file)
        return {"action": "load", "file": proxy_file, "added": added, "total": pool.count}

    elif action == "get":
        proxy = pool.get_proxy(strategy=strategy)
        if proxy:
            return {
                "action": "get",
                "proxy": proxy.url,
                "dict_format": proxy.dict_format,
                "success_rate": proxy.success_rate,
            }
        return {"action": "get", "proxy": None, "error": "No available proxy"}

    elif action == "validate":
        valid = pool.validate_all_sync()
        return {"action": "validate", "valid": valid, "total": pool.count}

    elif action == "stats":
        return {"action": "stats", **pool.get_stats()}

    return {"error": f"Unknown action: {action}"}


async def browser_fingerprint(browser: str = "random") -> Dict[str, Any]:
    """
    生成浏览器指纹配置

    Args:
        browser: chrome, firefox, safari, random
    """
    if not HAS_STEALTH:
        return {"error": "Stealth module not available"}

    from core.stealth.fingerprint_spoofer import (
        BrowserProfileFactory,
        BrowserType,
        FingerprintSpoofer,
    )

    if browser == "random":
        profile = BrowserProfileFactory.create_random_profile()
        spoofer = FingerprintSpoofer()
    else:
        browser_map = {
            "chrome": BrowserType.CHROME,
            "firefox": BrowserType.FIREFOX,
            "safari": BrowserType.SAFARI,
        }
        browser_type = browser_map.get(browser.lower(), BrowserType.CHROME)
        spoofer = FingerprintSpoofer(browser_type)

    config = spoofer.get_request_config()

    return {
        "browser": config["browser_type"],
        "headers": config["headers"],
        "http2_settings": config["http2_settings"],
        "ja3_fingerprint": config["ja3_fingerprint"][:50] + "...",
    }


# ==================== 漏洞利用工具 ====================


async def sqli_detect(
    url: str, param: str, value: str = "1", method: str = "GET", waf_bypass: bool = True
) -> Dict[str, Any]:
    """
    SQL注入检测 (纯Python引擎)

    Args:
        url: 目标URL
        param: 测试参数
        value: 参数原始值
        method: HTTP方法
        waf_bypass: 是否启用WAF绕过
    """
    if not HAS_EXPLOIT:
        return {"error": "Exploit module not available"}

    from core.exploit.pure_sqli import PureSQLiEngine

    engine = PureSQLiEngine(waf_bypass=waf_bypass)

    try:
        result = engine.detect(url, method, param, value)

        return {
            "vulnerable": result.vulnerable,
            "sqli_type": result.sqli_type.value if result.sqli_type else None,
            "db_type": result.db_type.value if result.db_type else None,
            "payload": result.payload,
            "evidence": result.evidence,
            "confidence": result.confidence,
        }
    finally:
        engine.close()


async def sqli_exploit(
    url: str, param: str, query: str, sqli_type: str = "union", db_type: str = "mysql"
) -> Dict[str, Any]:
    """
    SQL注入数据提取

    Args:
        url: 目标URL
        param: 注入参数
        query: SQL查询 (如 "SELECT username FROM users")
        sqli_type: 注入类型 (union, error, blind_boolean, blind_time)
        db_type: 数据库类型 (mysql, postgresql, mssql)
    """
    if not HAS_EXPLOIT:
        return {"error": "Exploit module not available"}

    from core.exploit.pure_sqli import DBType, InjectionPoint, PureSQLiEngine, SQLiType

    engine = PureSQLiEngine()

    try:
        ip = InjectionPoint(
            url=url, method="GET", param=param, original_value="1", position="query"
        )

        data = engine.extract_data(ip, query, SQLiType(sqli_type), DBType(db_type))

        return {
            "success": data is not None,
            "query": query,
            "data": data,
            "sqli_type": sqli_type,
            "db_type": db_type,
        }
    finally:
        engine.close()


async def port_scan_advanced(
    target: str,
    ports: Optional[List[int]] = None,
    scan_type: str = "quick",
    service_detection: bool = True,
    concurrency: int = 100,
) -> Dict[str, Any]:
    """
    高级端口扫描 (纯Python, 无需nmap)

    Args:
        target: 目标IP或域名
        ports: 端口列表 (None则使用预设)
        scan_type: quick(常见端口), full(全端口), custom(自定义)
        service_detection: 是否进行服务识别
        concurrency: 并发数
    """
    if not HAS_EXPLOIT:
        return {"error": "Exploit module not available"}

    from core.exploit.pure_scanner import PurePortScanner, run_async

    scanner = PurePortScanner(concurrency=concurrency, service_detection=service_detection)

    if scan_type == "quick":
        result = run_async(scanner.quick_scan(target))
    elif scan_type == "full":
        result = run_async(scanner.full_scan(target))
    else:
        ports = ports or PurePortScanner.COMMON_PORTS
        result = run_async(scanner.scan_host(target, ports))

    open_ports = [p for p in result.ports if p.state.value == "open"]

    return {
        "host": result.host,
        "ip": result.ip,
        "is_up": result.is_up,
        "scan_type": scan_type,
        "open_ports": [
            {
                "port": p.port,
                "state": p.state.value,
                "service": p.service.name if p.service else "unknown",
                "version": p.service.version if p.service else "",
                "banner": (p.service.banner[:100] if p.service and p.service.banner else ""),
            }
            for p in open_ports
        ],
        "total_scanned": len(result.ports),
        "scan_time": f"{result.scan_time:.2f}s",
    }


async def network_scan(
    cidr: str, ports: Optional[List[int]] = None, concurrency: int = 50
) -> Dict[str, Any]:
    """
    网段扫描

    Args:
        cidr: 网段 (如 192.168.1.0/24)
        ports: 端口列表
        concurrency: 并发数
    """
    if not HAS_EXPLOIT:
        return {"error": "Exploit module not available"}

    from core.exploit.pure_scanner import PurePortScanner, run_async

    scanner = PurePortScanner(concurrency=concurrency, service_detection=False)
    ports = ports or [22, 80, 443, 3389, 8080]

    results = run_async(scanner.scan_network(cidr, ports))

    alive_hosts = [r for r in results if r.is_up]
    hosts_with_ports = [
        {"ip": r.ip, "open_ports": [p.port for p in r.ports if p.state.value == "open"]}
        for r in alive_hosts
    ]

    return {
        "cidr": cidr,
        "total_hosts": len(results),
        "alive_hosts": len(alive_hosts),
        "hosts": hosts_with_ports,
    }


# ==================== 注册函数 (供 MCP Server 调用) ====================


def register_advanced_tools(mcp):
    """
    注册高级渗透工具到 MCP Server

    Usage:
        from modules.advanced_tools import register_advanced_tools
        register_advanced_tools(mcp)
    """
    patch_mcp_tool(mcp)

    # 隐蔽请求
    @mcp.tool()
    async def stealth_http_request(
        url: str, method: str = "GET", stealth_level: int = 2, browser: str = "chrome"
    ) -> Dict[str, Any]:
        """
        生成隐蔽HTTP请求配置 - 流量伪装、指纹模拟

        Args:
            url: 目标URL
            method: HTTP方法 (GET/POST)
            stealth_level: 隐蔽等级 (1=低, 2=中, 3=高)
            browser: 模拟浏览器 (chrome/firefox/safari)

        Returns:
            变异后的请求配置,包含headers、延迟建议等
        """
        return await stealth_request(url, method, stealth_level=stealth_level, browser=browser)

    # 代理池
    @mcp.tool()
    async def proxy_pool(
        action: str = "stats", proxies: Optional[List[str]] = None, strategy: str = "random"
    ) -> Dict[str, Any]:
        """
        代理池管理 - 添加、获取、验证代理

        Args:
            action: 操作类型 (add/get/validate/stats)
            proxies: 代理列表 (用于add操作)
            strategy: 获取策略 (random/fastest/weighted)

        Returns:
            操作结果
        """
        return await proxy_pool_manage(action, proxies, strategy=strategy)

    # 浏览器指纹
    @mcp.tool()
    async def get_browser_fingerprint(browser: str = "random") -> Dict[str, Any]:
        """
        生成浏览器指纹配置 - JA3伪装、HTTP/2配置

        Args:
            browser: 浏览器类型 (chrome/firefox/safari/random)

        Returns:
            完整的浏览器指纹配置
        """
        return await browser_fingerprint(browser)

    # SQLi检测
    @mcp.tool()
    async def pure_sqli_detect(
        url: str, param: str, value: str = "1", waf_bypass: bool = True
    ) -> Dict[str, Any]:
        """
        纯Python SQL注入检测 - 无需sqlmap

        Args:
            url: 目标URL
            param: 测试参数名
            value: 参数原始值
            waf_bypass: 是否启用WAF绕过

        Returns:
            检测结果,包含漏洞类型、数据库类型、置信度
        """
        return await sqli_detect(url, param, value, waf_bypass=waf_bypass)

    # SQLi利用
    @mcp.tool()
    async def pure_sqli_exploit(
        url: str, param: str, query: str, sqli_type: str = "union", db_type: str = "mysql"
    ) -> Dict[str, Any]:
        """
        SQL注入数据提取 - 执行任意SQL查询

        Args:
            url: 目标URL
            param: 注入参数
            query: SQL查询语句
            sqli_type: 注入类型 (union/error/blind_boolean/blind_time)
            db_type: 数据库类型 (mysql/postgresql/mssql)

        Returns:
            提取的数据
        """
        return await sqli_exploit(url, param, query, sqli_type, db_type)

    # 端口扫描
    @mcp.tool()
    async def pure_port_scan(
        target: str, scan_type: str = "quick", service_detection: bool = True
    ) -> Dict[str, Any]:
        """
        纯Python端口扫描 - 无需nmap

        Args:
            target: 目标IP或域名
            scan_type: 扫描类型 (quick=常见端口/full=全端口)
            service_detection: 是否进行服务识别

        Returns:
            扫描结果,包含开放端口和服务信息
        """
        return await port_scan_advanced(
            target, scan_type=scan_type, service_detection=service_detection
        )

    # 网段扫描
    @mcp.tool()
    async def pure_network_scan(cidr: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        网段扫描 - 发现存活主机

        Args:
            cidr: 网段 (如 192.168.1.0/24)
            ports: 要扫描的端口列表

        Returns:
            存活主机及其开放端口
        """
        return await network_scan(cidr, ports)

    logger.info("Advanced pentest tools registered to MCP server")


# 测试
if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    async def test():
        # 测试隐蔽请求
        result = await stealth_request("http://example.com/api/user", stealth_level=3)
        logger.info("Stealth Request Config:")
        logger.info(f"  URL: {result['url']}")
        logger.info(f"  Browser: {result['browser_profile']}")
        logger.info(f"  Headers: {list(result['headers'].keys())[:5]}...")

        # 测试指纹
        fp = await browser_fingerprint("chrome")
        logger.info(f"\nBrowser Fingerprint: {fp['browser']}")

    asyncio.run(test())
