#!/usr/bin/env python3
"""
代理池管理模块 - Proxy Pool Manager
功能: 代理轮换、健康检查、自动淘汰、链式代理
"""

import asyncio
import random
import time
import logging
import re
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from urllib.parse import urlparse
import threading
import json
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# 尝试导入请求库
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

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ProxyType(Enum):
    """代理类型"""
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class ProxyAnonymity(Enum):
    """代理匿名级别"""
    TRANSPARENT = "transparent"  # 透明代理 (暴露真实IP)
    ANONYMOUS = "anonymous"  # 匿名代理 (隐藏IP但显示代理)
    ELITE = "elite"  # 高匿代理 (完全隐藏)


@dataclass
class Proxy:
    """代理实体"""
    host: str
    port: int
    proxy_type: ProxyType = ProxyType.HTTP
    username: Optional[str] = None
    password: Optional[str] = None
    anonymity: ProxyAnonymity = ProxyAnonymity.ANONYMOUS
    country: Optional[str] = None
    response_time: float = 0.0
    last_check: float = 0.0
    fail_count: int = 0
    success_count: int = 0
    is_valid: bool = True

    @property
    def url(self) -> str:
        """获取代理URL"""
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"

        return f"{self.proxy_type.value}://{auth}{self.host}:{self.port}"

    @property
    def dict_format(self) -> Dict[str, str]:
        """获取 requests 格式的代理字典"""
        proxy_url = self.url
        if self.proxy_type in [ProxyType.HTTP, ProxyType.HTTPS]:
            return {
                "http": proxy_url,
                "https": proxy_url,
            }
        else:
            return {
                "http": proxy_url,
                "https": proxy_url,
            }

    @property
    def success_rate(self) -> float:
        """计算成功率"""
        total = self.success_count + self.fail_count
        if total == 0:
            return 0.0
        return self.success_count / total

    def __hash__(self):
        return hash(f"{self.host}:{self.port}")

    def __eq__(self, other):
        if isinstance(other, Proxy):
            return self.host == other.host and self.port == other.port
        return False


class ProxyValidator:
    """代理验证器"""

    # 测试用 URL
    CHECK_URLS = [
        "http://httpbin.org/ip",
        "http://ip-api.com/json",
        "https://api.ipify.org?format=json",
    ]

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def validate_sync(self, proxy: Proxy) -> Tuple[bool, float]:
        """
        同步验证代理

        Returns:
            (is_valid, response_time)
        """
        if not HAS_REQUESTS:
            logger.warning("requests not installed, skip validation")
            return True, 0.0

        import requests
        from requests.exceptions import RequestException

        start_time = time.time()
        check_url = random.choice(self.CHECK_URLS)

        try:
            resp = requests.get(
                check_url,
                proxies=proxy.dict_format,
                timeout=self.timeout,
                verify=False  # 某些代理有SSL问题
            )
            response_time = time.time() - start_time

            if resp.status_code == 200:
                return True, response_time
            return False, response_time

        except RequestException as e:
            logger.debug(f"Proxy validation failed: {proxy.url} - {e}")
            return False, time.time() - start_time

    async def validate_async(self, proxy: Proxy) -> Tuple[bool, float]:
        """异步验证代理"""
        if not HAS_HTTPX:
            return self.validate_sync(proxy)

        start_time = time.time()
        check_url = random.choice(self.CHECK_URLS)

        try:
            async with httpx.AsyncClient(
                proxies=proxy.dict_format,
                timeout=self.timeout,
                verify=False
            ) as client:
                resp = await client.get(check_url)
                response_time = time.time() - start_time

                if resp.status_code == 200:
                    return True, response_time
                return False, response_time

        except Exception as e:
            logger.debug(f"Async proxy validation failed: {proxy.url} - {e}")
            return False, time.time() - start_time

    def check_anonymity(self, proxy: Proxy, real_ip: str) -> ProxyAnonymity:
        """检查代理匿名级别"""
        if not HAS_REQUESTS:
            return ProxyAnonymity.ANONYMOUS

        import requests

        try:
            resp = requests.get(
                "http://httpbin.org/headers",
                proxies=proxy.dict_format,
                timeout=self.timeout,
                verify=False
            )

            if resp.status_code != 200:
                return ProxyAnonymity.ANONYMOUS

            headers = resp.json().get("headers", {})

            # 检查是否暴露真实IP
            forwarded_for = headers.get("X-Forwarded-For", "")
            via = headers.get("Via", "")

            if real_ip in forwarded_for:
                return ProxyAnonymity.TRANSPARENT

            if forwarded_for or via:
                return ProxyAnonymity.ANONYMOUS

            return ProxyAnonymity.ELITE

        except (ConnectionError, TimeoutError, OSError):
            return ProxyAnonymity.ANONYMOUS


class ProxyPool:
    """
    代理池管理器

    Usage:
        pool = ProxyPool()

        # 添加代理
        pool.add_proxy("http://proxy1.com:8080")
        pool.add_proxy("socks5://user:pass@proxy2.com:1080")

        # 从文件加载
        pool.load_from_file("proxies.txt")

        # 获取代理
        proxy = pool.get_proxy()

        # 报告结果
        pool.report_success(proxy)  # 成功
        pool.report_failure(proxy)  # 失败

        # 自动轮换
        for proxy in pool.rotate():
            # use proxy
            pass
    """

    def __init__(self,
                 max_fail_count: int = 3,
                 check_interval: float = 300.0,
                 auto_validate: bool = True):
        """
        Args:
            max_fail_count: 最大失败次数后移除
            check_interval: 健康检查间隔 (秒)
            auto_validate: 添加时自动验证
        """
        self._proxies: List[Proxy] = []
        self._blacklist: Set[str] = set()
        self._lock = threading.Lock()

        self.max_fail_count = max_fail_count
        self.check_interval = check_interval
        self.auto_validate = auto_validate

        self.validator = ProxyValidator()

        # 统计
        self._stats = {
            "total_added": 0,
            "total_removed": 0,
            "requests_made": 0,
            "requests_success": 0,
            "requests_failed": 0,
        }

    def add_proxy(self, proxy_str: str, validate: bool = None) -> bool:
        """
        添加代理

        Args:
            proxy_str: 代理字符串 (如 "http://host:port" 或 "socks5://user:pass@host:port")
            validate: 是否验证 (None=使用默认配置)
        """
        proxy = self._parse_proxy_string(proxy_str)
        if not proxy:
            return False

        # 检查黑名单
        proxy_key = f"{proxy.host}:{proxy.port}"
        if proxy_key in self._blacklist:
            logger.debug(f"Proxy in blacklist: {proxy_key}")
            return False

        # 检查重复
        with self._lock:
            if proxy in self._proxies:
                return False

        # 验证
        should_validate = validate if validate is not None else self.auto_validate
        if should_validate:
            is_valid, response_time = self.validator.validate_sync(proxy)
            proxy.is_valid = is_valid
            proxy.response_time = response_time
            proxy.last_check = time.time()

            if not is_valid:
                logger.debug(f"Proxy validation failed: {proxy_str}")
                return False

        with self._lock:
            self._proxies.append(proxy)
            self._stats["total_added"] += 1

        logger.info(f"Proxy added: {proxy.url}")
        return True

    def add_proxies(self, proxy_list: List[str]) -> int:
        """批量添加代理"""
        added = 0
        for proxy_str in proxy_list:
            if self.add_proxy(proxy_str):
                added += 1
        return added

    def remove_proxy(self, proxy: Proxy):
        """移除代理"""
        with self._lock:
            if proxy in self._proxies:
                self._proxies.remove(proxy)
                self._stats["total_removed"] += 1
                logger.info(f"Proxy removed: {proxy.url}")

    def blacklist_proxy(self, proxy: Proxy):
        """将代理加入黑名单"""
        proxy_key = f"{proxy.host}:{proxy.port}"
        self._blacklist.add(proxy_key)
        self.remove_proxy(proxy)
        logger.info(f"Proxy blacklisted: {proxy_key}")

    def get_proxy(self, strategy: str = "random") -> Optional[Proxy]:
        """
        获取代理

        Args:
            strategy: random, round_robin, fastest, weighted
        """
        with self._lock:
            valid_proxies = [p for p in self._proxies if p.is_valid]

            if not valid_proxies:
                return None

            if strategy == "random":
                return random.choice(valid_proxies)

            elif strategy == "fastest":
                return min(valid_proxies, key=lambda p: p.response_time)

            elif strategy == "weighted":
                # 按成功率加权
                weights = [max(0.1, p.success_rate) for p in valid_proxies]
                return random.choices(valid_proxies, weights=weights, k=1)[0]

            else:  # round_robin
                proxy = valid_proxies[0]
                self._proxies.remove(proxy)
                self._proxies.append(proxy)
                return proxy

    def rotate(self, count: Optional[int] = None):
        """
        代理轮换生成器

        Args:
            count: 轮换次数 (None=无限)
        """
        i = 0
        while count is None or i < count:
            proxy = self.get_proxy(strategy="round_robin")
            if proxy is None:
                break
            yield proxy
            i += 1

    def report_success(self, proxy: Proxy):
        """报告代理成功"""
        with self._lock:
            if proxy in self._proxies:
                proxy.success_count += 1
                proxy.fail_count = max(0, proxy.fail_count - 1)  # 成功减少失败计数
                self._stats["requests_success"] += 1
                self._stats["requests_made"] += 1

    def report_failure(self, proxy: Proxy):
        """报告代理失败"""
        with self._lock:
            if proxy in self._proxies:
                proxy.fail_count += 1
                self._stats["requests_failed"] += 1
                self._stats["requests_made"] += 1

                # 超过失败次数则移除
                if proxy.fail_count >= self.max_fail_count:
                    proxy.is_valid = False
                    logger.warning(f"Proxy marked invalid: {proxy.url}")

    def load_from_file(self, filepath: str) -> int:
        """
        从文件加载代理列表

        支持格式:
        - 每行一个代理: http://host:port
        - JSON 格式: [{"host": "...", "port": 8080, ...}]
        """
        path = Path(filepath)
        if not path.exists():
            logger.error(f"Proxy file not found: {filepath}")
            return 0

        content = path.read_text(encoding='utf-8')

        # 尝试JSON格式
        try:
            data = json.loads(content)
            if isinstance(data, list):
                added = 0
                for item in data:
                    if isinstance(item, str):
                        if self.add_proxy(item, validate=False):
                            added += 1
                    elif isinstance(item, dict):
                        proxy_str = self._dict_to_proxy_string(item)
                        if proxy_str and self.add_proxy(proxy_str, validate=False):
                            added += 1
                return added
        except json.JSONDecodeError:
            pass

        # 纯文本格式
        added = 0
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                if self.add_proxy(line, validate=False):
                    added += 1

        return added

    def save_to_file(self, filepath: str):
        """保存代理到文件"""
        with self._lock:
            proxies = [p.url for p in self._proxies if p.is_valid]

        path = Path(filepath)
        path.write_text('\n'.join(proxies), encoding='utf-8')
        logger.info(f"Saved {len(proxies)} proxies to {filepath}")

    async def validate_all_async(self, concurrency: int = 10) -> int:
        """异步验证所有代理"""
        if not HAS_HTTPX:
            return self.validate_all_sync()

        semaphore = asyncio.Semaphore(concurrency)
        valid_count = 0

        async def check_proxy(proxy: Proxy):
            nonlocal valid_count
            async with semaphore:
                is_valid, response_time = await self.validator.validate_async(proxy)
                proxy.is_valid = is_valid
                proxy.response_time = response_time
                proxy.last_check = time.time()
                if is_valid:
                    valid_count += 1

        with self._lock:
            proxies = list(self._proxies)

        await asyncio.gather(*[check_proxy(p) for p in proxies])

        logger.info(f"Validated {len(proxies)} proxies, {valid_count} valid")
        return valid_count

    def validate_all_sync(self) -> int:
        """同步验证所有代理"""
        valid_count = 0

        with self._lock:
            proxies = list(self._proxies)

        for proxy in proxies:
            is_valid, response_time = self.validator.validate_sync(proxy)
            proxy.is_valid = is_valid
            proxy.response_time = response_time
            proxy.last_check = time.time()
            if is_valid:
                valid_count += 1

        logger.info(f"Validated {len(proxies)} proxies, {valid_count} valid")
        return valid_count

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            valid_count = sum(1 for p in self._proxies if p.is_valid)
            total = len(self._proxies)

        return {
            **self._stats,
            "total_proxies": total,
            "valid_proxies": valid_count,
            "invalid_proxies": total - valid_count,
            "blacklisted": len(self._blacklist),
            "success_rate": (
                self._stats["requests_success"] / self._stats["requests_made"]
                if self._stats["requests_made"] > 0 else 0.0
            )
        }

    @property
    def count(self) -> int:
        """代理总数"""
        return len(self._proxies)

    @property
    def valid_count(self) -> int:
        """有效代理数"""
        return sum(1 for p in self._proxies if p.is_valid)

    def _parse_proxy_string(self, proxy_str: str) -> Optional[Proxy]:
        """解析代理字符串"""
        try:
            # 标准 URL 格式
            if "://" in proxy_str:
                parsed = urlparse(proxy_str)
                proxy_type = ProxyType(parsed.scheme.lower())

                return Proxy(
                    host=parsed.hostname,
                    port=parsed.port or (1080 if "socks" in parsed.scheme else 8080),
                    proxy_type=proxy_type,
                    username=parsed.username,
                    password=parsed.password,
                )

            # 简单格式: host:port
            match = re.match(r'^([^:]+):(\d+)$', proxy_str)
            if match:
                return Proxy(
                    host=match.group(1),
                    port=int(match.group(2)),
                    proxy_type=ProxyType.HTTP
                )

        except Exception as e:
            logger.error(f"Failed to parse proxy: {proxy_str} - {e}")

        return None

    def _dict_to_proxy_string(self, d: Dict) -> Optional[str]:
        """字典转代理字符串"""
        if "host" not in d or "port" not in d:
            return None

        proxy_type = d.get("type", "http")
        host = d["host"]
        port = d["port"]
        username = d.get("username", "")
        password = d.get("password", "")

        if username and password:
            return f"{proxy_type}://{username}:{password}@{host}:{port}"
        return f"{proxy_type}://{host}:{port}"


class ProxyChain:
    """
    代理链 - 多级代理
    流量路径: Client -> Proxy1 -> Proxy2 -> ... -> Target
    """

    def __init__(self, proxies: List[Proxy] = None):
        self.proxies = proxies or []

    def add(self, proxy: Proxy):
        """添加代理到链"""
        self.proxies.append(proxy)

    def get_chain_config(self) -> Dict[str, Any]:
        """
        获取代理链配置 (用于 proxychains 格式)

        注意: 标准 requests 库不支持代理链，
        需要使用 proxychains 或 tor 等工具
        """
        return {
            "chain_type": "dynamic",  # strict, dynamic, random
            "proxies": [
                {
                    "type": p.proxy_type.value,
                    "host": p.host,
                    "port": p.port,
                    "username": p.username,
                    "password": p.password,
                }
                for p in self.proxies
            ]
        }

    def to_proxychains_config(self) -> str:
        """生成 proxychains.conf 格式配置"""
        lines = [
            "# ProxyChain Configuration",
            "dynamic_chain",
            "proxy_dns",
            "tcp_read_time_out 15000",
            "tcp_connect_time_out 8000",
            "",
            "[ProxyList]",
        ]

        for proxy in self.proxies:
            proxy_type = proxy.proxy_type.value
            if proxy_type == "https":
                proxy_type = "http"

            if proxy.username and proxy.password:
                lines.append(
                    f"{proxy_type} {proxy.host} {proxy.port} {proxy.username} {proxy.password}"
                )
            else:
                lines.append(f"{proxy_type} {proxy.host} {proxy.port}")

        return '\n'.join(lines)


# 便捷函数
def create_proxy_pool_from_file(filepath: str, validate: bool = False) -> ProxyPool:
    """从文件创建代理池"""
    pool = ProxyPool(auto_validate=validate)
    pool.load_from_file(filepath)
    return pool


def get_free_proxy_sources() -> List[str]:
    """获取免费代理源 URL (仅供参考，实际使用建议自建代理池)"""
    return [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    ]


if __name__ == "__main__":
    # 测试
    pool = ProxyPool(auto_validate=False)

    # 添加测试代理
    pool.add_proxy("http://127.0.0.1:8080")
    pool.add_proxy("socks5://127.0.0.1:1080")

    print(f"Total proxies: {pool.count}")
    print(f"Stats: {pool.get_stats()}")

    # 获取代理
    proxy = pool.get_proxy()
    if proxy:
        print(f"Selected proxy: {proxy.url}")
        print(f"Dict format: {proxy.dict_format}")
