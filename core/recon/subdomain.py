#!/usr/bin/env python3
"""
subdomain.py - 子域名枚举模块

提供子域名发现功能，支持字典暴破和DNS解析。

使用方式:
    from core.recon.subdomain import SubdomainEnumerator

    enumerator = SubdomainEnumerator()
    subdomains = enumerator.enumerate("example.com")

    for sub in subdomains:
        print(f"{sub.subdomain} -> {sub.ip_addresses}")
"""

import asyncio
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .dns_resolver import DNSResolver

logger = logging.getLogger(__name__)


@dataclass
class SubdomainInfo:
    """子域名信息

    Attributes:
        subdomain: 完整子域名
        ip_addresses: IP地址列表
        is_wildcard: 是否为通配符域名
        cname: CNAME记录
        metadata: 额外元数据
    """

    subdomain: str
    ip_addresses: List[str] = field(default_factory=list)
    is_wildcard: bool = False
    cname: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "subdomain": self.subdomain,
            "ip_addresses": self.ip_addresses,
            "is_wildcard": self.is_wildcard,
            "cname": self.cname,
            "metadata": self.metadata,
        }


class SubdomainEnumerator:
    """子域名枚举器

    通过字典暴破和DNS解析发现子域名。

    Attributes:
        timeout: DNS查询超时时间
        threads: 并发线程数
        wordlist: 自定义字典路径
        max_subdomains: 最大子域名数量
    """

    # 内置常用子域名字典
    COMMON_SUBDOMAINS: List[str] = [
        # 常见通用子域名
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "ns2",
        "dns",
        "dns1",
        "dns2",
        "ns",
        "mx",
        "mx1",
        "mx2",
        # 开发/测试环境
        "dev",
        "development",
        "staging",
        "stage",
        "test",
        "testing",
        "qa",
        "uat",
        "demo",
        "sandbox",
        "beta",
        "alpha",
        "pre",
        "preprod",
        # 管理/后台
        "admin",
        "administrator",
        "manage",
        "manager",
        "management",
        "console",
        "dashboard",
        "control",
        "panel",
        "cp",
        "cpanel",
        "backend",
        "back",
        "backoffice",
        "internal",
        "intranet",
        # API/服务
        "api",
        "api1",
        "api2",
        "apis",
        "rest",
        "graphql",
        "ws",
        "websocket",
        "rpc",
        "grpc",
        "gateway",
        "proxy",
        "service",
        "services",
        # 移动端
        "m",
        "mobile",
        "wap",
        "app",
        "apps",
        "ios",
        "android",
        # 静态资源
        "static",
        "assets",
        "img",
        "images",
        "image",
        "media",
        "files",
        "css",
        "js",
        "cdn",
        "cdn1",
        "cdn2",
        "download",
        "downloads",
        # 数据库/缓存
        "db",
        "database",
        "mysql",
        "postgresql",
        "postgres",
        "mongo",
        "mongodb",
        "redis",
        "memcache",
        "memcached",
        "elastic",
        "elasticsearch",
        # 监控/日志
        "monitor",
        "monitoring",
        "metrics",
        "grafana",
        "prometheus",
        "kibana",
        "log",
        "logs",
        "logging",
        "elk",
        # CI/CD
        "jenkins",
        "ci",
        "cd",
        "build",
        "deploy",
        "gitlab",
        "git",
        "svn",
        "repo",
        "repository",
        "code",
        "source",
        # 云服务
        "cloud",
        "aws",
        "azure",
        "gcp",
        "s3",
        "bucket",
        "storage",
        # 邮件
        "email",
        "mail2",
        "mail3",
        "mailserver",
        "exchange",
        "postfix",
        "imap",
        "pop3",
        "newsletter",
        # VPN/远程
        "vpn",
        "vpn1",
        "vpn2",
        "remote",
        "rdp",
        "ssh",
        "bastion",
        "jump",
        # 认证
        "auth",
        "login",
        "sso",
        "oauth",
        "identity",
        "ldap",
        "ad",
        # 帮助/支持
        "help",
        "support",
        "docs",
        "documentation",
        "wiki",
        "kb",
        "faq",
        "forum",
        "community",
        "blog",
        # 搜索
        "search",
        "solr",
        "elastic",
        # 其他常见
        "portal",
        "home",
        "shop",
        "store",
        "pay",
        "payment",
        "checkout",
        "cart",
        "order",
        "orders",
        "account",
        "accounts",
        "user",
        "users",
        "profile",
        "member",
        "members",
        "customer",
        "clients",
        "partner",
        "partners",
        "vendor",
        "vendors",
        "supplier",
        "report",
        "reports",
        "analytics",
        "stats",
        "statistics",
        "status",
        "health",
        "ping",
        "alive",
        "old",
        "new",
        "v1",
        "v2",
        "v3",
        "legacy",
        "archive",
        "secure",
        "ssl",
        "https",
        "cert",
        "certs",
        "www1",
        "www2",
        "www3",
        "web",
        "web1",
        "web2",
        "node",
        "node1",
        "node2",
        "server",
        "server1",
        "server2",
        "host",
        "host1",
        "host2",
        "vps",
        "vps1",
        "vps2",
        "bbs",
        "news",
        "video",
        "live",
        "stream",
        "oa",
        "erp",
        "crm",
        "hr",
        "finance",
    ]

    # 词表缓存（类级别，所有实例共享）
    _WORDLIST_CACHE: Dict[str, List[str]] = {}
    _CACHE_LOCK = threading.Lock()

    def __init__(
        self,
        timeout: float = 5.0,
        threads: int = 50,
        wordlist: Optional[str] = None,
        max_subdomains: int = 1000,
    ):
        """初始化子域名枚举器

        Args:
            timeout: DNS查询超时时间
            threads: 并发线程数
            wordlist: 自定义字典路径
            max_subdomains: 最大子域名数量
        """
        self.timeout = timeout
        self.threads = threads
        self.wordlist = wordlist
        self.max_subdomains = max_subdomains

        # DNS解析器
        self._resolver = DNSResolver(timeout=timeout)

        # 线程安全
        self._lock = threading.Lock()
        self._stop_flag = threading.Event()

        # 进度回调
        self._progress_callback: Optional[Callable[[int, int, str], None]] = None

        # 实例级自定义词表（避免污染类变量）
        self._custom_words: List[str] = []

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def enumerate(
        self, domain: str, custom_wordlist: Optional[List[str]] = None
    ) -> List[SubdomainInfo]:
        """枚举子域名

        Args:
            domain: 目标域名
            custom_wordlist: 自定义字典列表

        Returns:
            发现的子域名列表
        """
        # 加载字典
        wordlist = self._load_wordlist(custom_wordlist)

        # 检测通配符域名
        wildcard_ips = self._detect_wildcard(domain)

        results: List[SubdomainInfo] = []
        total = len(wordlist)
        processed = 0

        self._logger.info(f"Starting subdomain enumeration for {domain} with {total} words")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}

            for word in wordlist:
                if self._stop_flag.is_set():
                    break

                if len(results) >= self.max_subdomains:
                    break

                subdomain = f"{word}.{domain}"
                futures[executor.submit(self._check_subdomain, subdomain, wildcard_ips)] = subdomain

            for future in as_completed(futures):
                if self._stop_flag.is_set():
                    break

                processed += 1
                subdomain = futures[future]

                try:
                    result = future.result()
                    if result and not result.is_wildcard:
                        with self._lock:
                            if len(results) < self.max_subdomains:
                                results.append(result)

                except Exception as e:
                    self._logger.debug(f"Error checking {subdomain}: {e}")

                # 报告进度
                if self._progress_callback and processed % 100 == 0:
                    self._progress_callback(processed, total, subdomain)

        self._logger.info(f"Found {len(results)} subdomains for {domain}")
        return sorted(results, key=lambda x: x.subdomain)

    async def async_enumerate(
        self, domain: str, custom_wordlist: Optional[List[str]] = None, concurrency: int = 100
    ) -> List[SubdomainInfo]:
        """异步枚举子域名

        Args:
            domain: 目标域名
            custom_wordlist: 自定义字典列表
            concurrency: 并发数

        Returns:
            发现的子域名列表
        """
        wordlist = self._load_wordlist(custom_wordlist)
        wildcard_ips = self._detect_wildcard(domain)

        results: List[SubdomainInfo] = []
        semaphore = asyncio.Semaphore(concurrency)

        async def check_with_limit(word: str):
            async with semaphore:
                if self._stop_flag.is_set():
                    return None
                subdomain = f"{word}.{domain}"
                return await self._async_check_subdomain(subdomain, wildcard_ips)

        tasks = [check_with_limit(word) for word in wordlist[: self.max_subdomains * 2]]
        check_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in check_results:
            if isinstance(result, SubdomainInfo) and not result.is_wildcard:
                if len(results) < self.max_subdomains:
                    results.append(result)

        return sorted(results, key=lambda x: x.subdomain)

    def _check_subdomain(self, subdomain: str, wildcard_ips: Set[str]) -> Optional[SubdomainInfo]:
        """检查单个子域名

        Args:
            subdomain: 子域名
            wildcard_ips: 通配符IP集合

        Returns:
            SubdomainInfo对象，不存在返回None
        """
        try:
            ips = self._resolver.resolve(subdomain)
            if ips:
                # 检查是否为通配符
                is_wildcard = bool(wildcard_ips and set(ips) == wildcard_ips)

                return SubdomainInfo(
                    subdomain=subdomain,
                    ip_addresses=ips,
                    is_wildcard=is_wildcard,
                )
        except Exception as e:
            self._logger.debug(f"DNS resolution failed for {subdomain}: {e}")

        return None

    async def _async_check_subdomain(
        self, subdomain: str, wildcard_ips: Set[str]
    ) -> Optional[SubdomainInfo]:
        """异步检查单个子域名"""
        try:
            ips = await self._resolver.async_resolve(subdomain)
            if ips:
                is_wildcard = bool(wildcard_ips and set(ips) == wildcard_ips)

                return SubdomainInfo(
                    subdomain=subdomain,
                    ip_addresses=ips,
                    is_wildcard=is_wildcard,
                )
        except Exception as e:
            self._logger.debug(f"Async DNS resolution failed for {subdomain}: {e}")

        return None

    def _detect_wildcard(self, domain: str) -> Set[str]:
        """检测通配符DNS

        Args:
            domain: 目标域名

        Returns:
            通配符IP集合
        """
        # 生成随机子域名
        import random
        import string

        random_sub = "".join(random.choices(string.ascii_lowercase, k=12))
        wildcard_domain = f"{random_sub}.{domain}"

        try:
            ips = self._resolver.resolve(wildcard_domain)
            if ips:
                self._logger.info(f"Wildcard DNS detected for {domain}: {ips}")
                return set(ips)
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return set()

    def _load_wordlist(self, custom_wordlist: Optional[List[str]] = None) -> List[str]:
        """加载字典（带缓存）

        Args:
            custom_wordlist: 自定义字典列表

        Returns:
            字典单词列表
        """
        # 计算缓存键（基于 wordlist 路径）
        cache_key = self.wordlist or "__builtin__"

        with self._CACHE_LOCK:
            if cache_key not in self._WORDLIST_CACHE:
                # 缓存未命中，从磁盘加载
                words: Set[str] = set()

                # 从文件加载字典
                if self.wordlist:
                    wordlist_path = Path(self.wordlist)
                    if wordlist_path.exists():
                        try:
                            with open(wordlist_path, "r", encoding="utf-8") as f:
                                for line in f:
                                    word = line.strip().lower()
                                    if word and not word.startswith("#"):
                                        words.add(word)
                        except Exception as e:
                            self._logger.warning(f"Failed to load wordlist: {e}")

                # 添加内置字典
                words.update(self.COMMON_SUBDOMAINS)

                self._WORDLIST_CACHE[cache_key] = list(words)

        # 返回缓存副本，合并自定义词表和实例级词表
        result: Set[str] = set(self._WORDLIST_CACHE[cache_key])

        if custom_wordlist:
            result.update(custom_wordlist)

        if self._custom_words:
            result.update(self._custom_words)

        return list(result)

    def set_progress_callback(self, callback: Callable[[int, int, str], None]) -> None:
        """设置进度回调

        Args:
            callback: 回调函数，签名为 callback(processed, total, current)
        """
        self._progress_callback = callback

    def stop(self) -> None:
        """停止枚举"""
        self._stop_flag.set()

    def reset(self) -> None:
        """重置状态"""
        self._stop_flag.clear()

    def add_words(self, words: List[str]) -> None:
        """添加自定义单词到实例级字典

        Args:
            words: 单词列表
        """
        self._custom_words.extend(words)

    @classmethod
    def get_common_subdomains(cls) -> List[str]:
        """获取内置字典"""
        return cls.COMMON_SUBDOMAINS.copy()


# 便捷函数
def enumerate_subdomains(
    domain: str, timeout: float = 5.0, threads: int = 50, max_results: int = 1000
) -> List[SubdomainInfo]:
    """便捷函数：枚举子域名

    Args:
        domain: 目标域名
        timeout: DNS超时时间
        threads: 并发线程数
        max_results: 最大结果数

    Returns:
        子域名列表
    """
    enumerator = SubdomainEnumerator(timeout=timeout, threads=threads, max_subdomains=max_results)
    return enumerator.enumerate(domain)


async def async_enumerate_subdomains(
    domain: str, timeout: float = 5.0, concurrency: int = 100, max_results: int = 1000
) -> List[SubdomainInfo]:
    """便捷函数：异步枚举子域名"""
    enumerator = SubdomainEnumerator(timeout=timeout, max_subdomains=max_results)
    return await enumerator.async_enumerate(domain, concurrency=concurrency)


# 导出
__all__ = [
    "SubdomainInfo",
    "SubdomainEnumerator",
    "enumerate_subdomains",
    "async_enumerate_subdomains",
]
