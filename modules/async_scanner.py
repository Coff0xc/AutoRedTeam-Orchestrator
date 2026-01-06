#!/usr/bin/env python3
"""
异步扫描引擎 - 高性能并发扫描
替代原有同步扫描，性能提升3-5倍
"""

import asyncio
import time
import logging
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# 尝试导入异步库
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


@dataclass
class ScanResult:
    """扫描结果"""
    target: str
    success: bool
    data: Dict[str, Any]
    duration: float
    error: Optional[str] = None


class AsyncScanner:
    """异步扫描器基类"""

    def __init__(self, concurrency: int = 50, timeout: float = 10.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)
        return self._semaphore


class AsyncPortScanner(AsyncScanner):
    """异步端口扫描器 - 比同步快5-10倍"""

    async def scan_port(self, host: str, port: int) -> Optional[Dict]:
        """扫描单个端口"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()

            # 尝试获取banner
            banner = await self._grab_banner(host, port)

            return {
                "port": port,
                "state": "open",
                "banner": banner
            }
        except asyncio.TimeoutError:
            return None
        except ConnectionRefusedError:
            return None
        except Exception:
            return None

    async def _grab_banner(self, host: str, port: int) -> str:
        """获取服务banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2.0
            )

            # 发送探测数据
            if port in [80, 8080, 443, 8443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                writer.write(b"\r\n")

            await writer.drain()

            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()

            return banner.decode('utf-8', errors='ignore')[:200]
        except Exception:
            return ""

    async def scan(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """扫描多个端口"""
        start_time = time.time()
        semaphore = await self._get_semaphore()

        async def limited_scan(port: int):
            async with semaphore:
                return await self.scan_port(host, port)

        tasks = [limited_scan(p) for p in ports]
        results = await asyncio.gather(*tasks)

        open_ports = [r for r in results if r is not None]

        return {
            "host": host,
            "open_ports": open_ports,
            "scanned": len(ports),
            "duration": round(time.time() - start_time, 2)
        }


class AsyncDirScanner(AsyncScanner):
    """异步目录扫描器"""

    COMMON_DIRS = [
        "admin", "login", "api", "backup", ".git", ".env", "config",
        "upload", "uploads", "static", "assets", "js", "css",
        "phpinfo.php", "test.php", "robots.txt", "sitemap.xml",
        "wp-admin", "wp-login.php", "phpmyadmin", "console",
        "swagger", "api-docs", "graphql", "actuator", "metrics"
    ]

    def __init__(self, concurrency: int = 20, timeout: float = 5.0):
        super().__init__(concurrency, timeout)
        self._client = None

    async def _get_client(self):
        if self._client is None:
            if HAS_HTTPX:
                self._client = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,
                    verify=False
                )
            elif HAS_AIOHTTP:
                self._client = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                )
        return self._client

    async def check_path(self, base_url: str, path: str) -> Optional[Dict]:
        """检查单个路径"""
        url = urljoin(base_url, path)
        client = await self._get_client()

        try:
            if HAS_HTTPX:
                resp = await client.get(url)
                status = resp.status_code
                length = len(resp.content)
            else:
                async with client.get(url, ssl=False) as resp:
                    status = resp.status
                    length = len(await resp.read())

            if status in [200, 301, 302, 403]:
                return {
                    "path": path,
                    "url": url,
                    "status": status,
                    "length": length
                }
        except Exception:
            pass
        return None

    async def scan(self, base_url: str, paths: Optional[List[str]] = None) -> Dict[str, Any]:
        """扫描目录"""
        start_time = time.time()
        paths = paths or self.COMMON_DIRS
        semaphore = await self._get_semaphore()

        async def limited_check(path: str):
            async with semaphore:
                return await self.check_path(base_url, path)

        tasks = [limited_check(p) for p in paths]
        results = await asyncio.gather(*tasks)

        found = [r for r in results if r is not None]

        return {
            "base_url": base_url,
            "found": found,
            "scanned": len(paths),
            "duration": round(time.time() - start_time, 2)
        }

    async def close(self):
        if self._client:
            if HAS_HTTPX:
                await self._client.aclose()
            else:
                await self._client.close()


class AsyncSubdomainScanner(AsyncScanner):
    """异步子域名扫描器"""

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "api", "dev", "test", "staging",
        "admin", "portal", "vpn", "remote", "m", "mobile",
        "cdn", "static", "img", "blog", "shop", "store",
        "git", "gitlab", "jenkins", "ci", "db", "mysql",
        "redis", "mongo", "auth", "sso", "pay", "demo"
    ]

    async def resolve(self, domain: str) -> Optional[List[str]]:
        """解析域名"""
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.getaddrinfo(domain, None),
                timeout=self.timeout
            )
            return list(set(r[4][0] for r in result))
        except Exception:
            return None

    async def scan(self, domain: str, subdomains: Optional[List[str]] = None) -> Dict[str, Any]:
        """扫描子域名"""
        start_time = time.time()
        subdomains = subdomains or self.COMMON_SUBDOMAINS
        semaphore = await self._get_semaphore()

        async def check_subdomain(sub: str):
            async with semaphore:
                full_domain = f"{sub}.{domain}"
                ips = await self.resolve(full_domain)
                if ips:
                    return {"subdomain": full_domain, "ips": ips}
                return None

        tasks = [check_subdomain(s) for s in subdomains]
        results = await asyncio.gather(*tasks)

        found = [r for r in results if r is not None]

        return {
            "domain": domain,
            "found": found,
            "scanned": len(subdomains),
            "duration": round(time.time() - start_time, 2)
        }


class AsyncVulnScanner(AsyncScanner):
    """异步漏洞扫描器"""

    def __init__(self, concurrency: int = 10, timeout: float = 10.0):
        super().__init__(concurrency, timeout)
        self._client = None

    async def _get_client(self):
        if self._client is None and HAS_HTTPX:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False
            )
        return self._client

    async def test_sqli(self, url: str, param: str) -> Dict[str, Any]:
        """测试SQL注入"""
        payloads = ["'", "\"", "' OR '1'='1", "1' AND '1'='1", "1 AND 1=1"]
        errors = ["sql", "mysql", "syntax", "query", "oracle", "postgresql"]

        client = await self._get_client()
        if not client:
            return {"vulnerable": False, "error": "httpx not installed"}

        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                resp = await client.get(test_url)
                text = resp.text.lower()

                if any(err in text for err in errors):
                    return {
                        "vulnerable": True,
                        "type": "sqli",
                        "payload": payload,
                        "evidence": "SQL error detected"
                    }
            except Exception:
                continue

        return {"vulnerable": False, "type": "sqli"}

    async def test_xss(self, url: str, param: str) -> Dict[str, Any]:
        """测试XSS"""
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>"
        ]

        client = await self._get_client()
        if not client:
            return {"vulnerable": False, "error": "httpx not installed"}

        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                resp = await client.get(test_url)

                if payload in resp.text:
                    return {
                        "vulnerable": True,
                        "type": "xss",
                        "payload": payload,
                        "evidence": "Payload reflected"
                    }
            except Exception:
                continue

        return {"vulnerable": False, "type": "xss"}

    async def test_lfi(self, url: str, param: str) -> Dict[str, Any]:
        """测试LFI"""
        payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..\\..\\..\\windows\\win.ini"
        ]
        indicators = ["root:", "[extensions]", "daemon:"]

        client = await self._get_client()
        if not client:
            return {"vulnerable": False, "error": "httpx not installed"}

        for payload in payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                resp = await client.get(test_url)

                if any(ind in resp.text for ind in indicators):
                    return {
                        "vulnerable": True,
                        "type": "lfi",
                        "payload": payload,
                        "evidence": "File content detected"
                    }
            except Exception:
                continue

        return {"vulnerable": False, "type": "lfi"}

    async def scan_all(self, url: str, param: str) -> Dict[str, Any]:
        """执行所有漏洞测试"""
        start_time = time.time()

        results = await asyncio.gather(
            self.test_sqli(url, param),
            self.test_xss(url, param),
            self.test_lfi(url, param)
        )

        vulnerabilities = [r for r in results if r.get("vulnerable")]

        return {
            "url": url,
            "param": param,
            "vulnerabilities": vulnerabilities,
            "total_tests": len(results),
            "duration": round(time.time() - start_time, 2)
        }

    async def close(self):
        if self._client:
            await self._client.aclose()


# 同步包装器 - 兼容现有代码
def run_async(coro):
    """运行异步协程 (Python 3.10+ 兼容)"""
    try:
        # 检查是否已有运行中的事件循环
        loop = asyncio.get_running_loop()
        # 有运行中的循环时，使用线程池
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        # 没有运行中的循环，直接使用 asyncio.run()
        return asyncio.run(coro)


def async_port_scan(host: str, ports: List[int], concurrency: int = 100) -> Dict:
    """异步端口扫描（同步接口）"""
    scanner = AsyncPortScanner(concurrency=concurrency)
    return run_async(scanner.scan(host, ports))


def async_dir_scan(url: str, paths: Optional[List[str]] = None) -> Dict:
    """异步目录扫描（同步接口）"""
    async def _scan():
        scanner = AsyncDirScanner()
        try:
            return await scanner.scan(url, paths)
        finally:
            await scanner.close()

    return run_async(_scan())


def async_subdomain_scan(domain: str, subdomains: Optional[List[str]] = None) -> Dict:
    """异步子域名扫描（同步接口）"""
    scanner = AsyncSubdomainScanner()
    return run_async(scanner.scan(domain, subdomains))


def async_vuln_scan(url: str, param: str) -> Dict:
    """异步漏洞扫描（同步接口）"""
    async def _scan():
        scanner = AsyncVulnScanner()
        try:
            return await scanner.scan_all(url, param)
        finally:
            await scanner.close()

    return run_async(_scan())
