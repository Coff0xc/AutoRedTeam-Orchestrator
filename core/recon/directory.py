#!/usr/bin/env python3
"""
directory.py - 目录扫描模块

提供Web目录和文件枚举功能。

使用方式:
    from core.recon.directory import DirectoryScanner, DirectoryInfo

    scanner = DirectoryScanner()
    results = scanner.scan("https://example.com")

    for item in results:
        print(f"{item.path} - {item.status_code}")
"""

import ssl
import logging
import threading
import urllib.request
import urllib.error
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Callable
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger(__name__)


@dataclass
class DirectoryInfo:
    """目录/文件信息

    Attributes:
        path: 路径
        url: 完整URL
        status_code: HTTP状态码
        content_length: 内容长度
        content_type: 内容类型
        redirect_url: 重定向URL
        is_directory: 是否为目录
        metadata: 额外元数据
    """
    path: str
    url: str
    status_code: int
    content_length: int = 0
    content_type: Optional[str] = None
    redirect_url: Optional[str] = None
    is_directory: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "path": self.path,
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "redirect_url": self.redirect_url,
            "is_directory": self.is_directory,
        }


class DirectoryScanner:
    """目录扫描器

    通过字典暴破发现Web目录和文件。

    Attributes:
        timeout: 请求超时时间
        threads: 并发线程数
        verify_ssl: 是否验证SSL证书
        user_agent: 自定义User-Agent
        extensions: 文件扩展名列表
        wordlist: 自定义字典路径
        max_results: 最大结果数
    """

    # 内置常用目录字典
    COMMON_DIRECTORIES: List[str] = [
        # 管理后台
        "admin", "administrator", "admin.php", "admin.html", "admin.asp",
        "manage", "manager", "management", "backend", "backoffice",
        "console", "dashboard", "control", "panel", "cp", "cpanel",
        "login", "signin", "auth", "authenticate",
        # 配置/敏感文件
        ".git", ".git/config", ".git/HEAD", ".gitignore",
        ".svn", ".svn/entries", ".svn/wc.db",
        ".env", ".env.local", ".env.production", ".env.development",
        ".htaccess", ".htpasswd", "web.config",
        "config", "config.php", "config.inc.php", "configuration.php",
        "settings.php", "settings.py", "settings.json", "settings.xml",
        "database.yml", "database.php", "db.php", "db.sql",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        # 备份文件
        "backup", "backups", "bak", "old", "temp", "tmp",
        "backup.zip", "backup.tar.gz", "backup.sql", "backup.tar",
        "site.zip", "www.zip", "web.zip", "html.zip",
        "dump.sql", "database.sql", "db.sql.gz",
        # API
        "api", "api/v1", "api/v2", "api/v3", "apis",
        "rest", "graphql", "swagger", "swagger-ui", "swagger.json",
        "openapi", "openapi.json", "openapi.yaml",
        "docs", "documentation", "apidocs", "api-docs",
        # 静态资源
        "static", "assets", "public", "resources",
        "css", "js", "images", "img", "media", "files",
        "upload", "uploads", "download", "downloads",
        "attachment", "attachments",
        # 常见目录
        "test", "testing", "dev", "development", "debug",
        "demo", "example", "examples", "sample", "samples",
        "include", "includes", "inc", "lib", "libs", "library",
        "vendor", "vendors", "node_modules", "bower_components",
        "src", "source", "app", "application", "bin",
        # 日志/错误
        "log", "logs", "error", "errors", "debug.log", "error.log",
        "access.log", "error_log", "debug.txt",
        # 信息泄露
        "phpinfo.php", "info.php", "test.php", "i.php",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "humans.txt", "security.txt", ".well-known",
        # 框架特定
        "wp-admin", "wp-content", "wp-includes", "wp-login.php",
        "administrator", "components", "modules", "templates",
        "actuator", "actuator/env", "actuator/health", "actuator/info",
        "elmah.axd", "trace.axd",
        # 版本控制/编辑器
        ".idea", ".vscode", ".project", ".settings",
        "CVS", ".cvsignore",
        "nbproject", ".netbeans",
        # 其他
        "cgi-bin", "cgi", "bin", "scripts",
        "server-status", "server-info",
        "phpmyadmin", "pma", "mysql", "myadmin",
        "webmail", "mail", "email",
        "forum", "bbs", "blog", "news",
    ]

    # 敏感文件
    SENSITIVE_FILES: List[str] = [
        ".git/config", ".git/HEAD", ".gitignore",
        ".svn/entries", ".svn/wc.db",
        ".env", ".env.local", ".env.production",
        ".htaccess", ".htpasswd",
        "web.config", "config.php", "config.inc.php",
        "wp-config.php", "wp-config.php.bak",
        "database.yml", "settings.py",
        "phpinfo.php", "info.php", "test.php",
        "robots.txt", "sitemap.xml",
        "backup.zip", "backup.sql", "dump.sql",
        "main.js.map", "app.js.map", "bundle.js.map",
        "composer.json", "package.json", "Gemfile",
        ".DS_Store", "Thumbs.db",
    ]

    def __init__(
        self,
        timeout: float = 10.0,
        threads: int = 20,
        verify_ssl: bool = True,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        extensions: Optional[List[str]] = None,
        wordlist: Optional[str] = None,
        max_results: int = 500
    ):
        """初始化目录扫描器

        Args:
            timeout: 请求超时时间
            threads: 并发线程数
            verify_ssl: 是否验证SSL证书
            user_agent: 自定义User-Agent
            extensions: 文件扩展名列表
            wordlist: 自定义字典路径
            max_results: 最大结果数
        """
        self.timeout = timeout
        self.threads = threads
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent
        self.extensions = extensions or [".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".txt"]
        self.wordlist = wordlist
        self.max_results = max_results

        # SSL上下文
        self._ssl_context = self._create_ssl_context()

        # 线程安全
        self._lock = threading.Lock()
        self._stop_flag = threading.Event()

        # 进度回调
        self._progress_callback: Optional[Callable[[int, int, str], None]] = None

        # 404页面特征
        self._404_signature: Optional[str] = None

        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _create_ssl_context(self) -> ssl.SSLContext:
        """创建SSL上下文"""
        if self.verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def scan(
        self,
        base_url: str,
        custom_wordlist: Optional[List[str]] = None,
        scan_sensitive: bool = True
    ) -> List[DirectoryInfo]:
        """扫描目录

        Args:
            base_url: 基础URL
            custom_wordlist: 自定义字典列表
            scan_sensitive: 是否扫描敏感文件

        Returns:
            发现的目录/文件列表
        """
        base_url = base_url.rstrip("/")

        # 检测404特征
        self._detect_404_signature(base_url)

        # 加载字典
        wordlist = self._load_wordlist(custom_wordlist, scan_sensitive)

        results: List[DirectoryInfo] = []
        total = len(wordlist)
        processed = 0

        self._logger.info(f"Starting directory scan for {base_url} with {total} paths")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}

            for path in wordlist:
                if self._stop_flag.is_set():
                    break

                if len(results) >= self.max_results:
                    break

                url = f"{base_url}/{path}"
                futures[executor.submit(self._check_path, url, path)] = path

            for future in as_completed(futures):
                if self._stop_flag.is_set():
                    break

                processed += 1
                path = futures[future]

                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            if len(results) < self.max_results:
                                results.append(result)

                except Exception as e:
                    self._logger.debug(f"Error checking {path}: {e}")

                # 报告进度
                if self._progress_callback and processed % 50 == 0:
                    self._progress_callback(processed, total, path)

        self._logger.info(f"Found {len(results)} paths for {base_url}")
        return sorted(results, key=lambda x: x.path)

    async def async_scan(
        self,
        base_url: str,
        custom_wordlist: Optional[List[str]] = None,
        concurrency: int = 50
    ) -> List[DirectoryInfo]:
        """异步扫描目录

        Args:
            base_url: 基础URL
            custom_wordlist: 自定义字典列表
            concurrency: 并发数

        Returns:
            发现的目录/文件列表
        """
        base_url = base_url.rstrip("/")

        # 检测404特征
        self._detect_404_signature(base_url)

        wordlist = self._load_wordlist(custom_wordlist)

        results: List[DirectoryInfo] = []
        semaphore = asyncio.Semaphore(concurrency)

        async def check_with_limit(path: str):
            async with semaphore:
                if self._stop_flag.is_set():
                    return None
                url = f"{base_url}/{path}"
                # 在线程池中执行同步请求
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, self._check_path, url, path)

        tasks = [check_with_limit(path) for path in wordlist]
        check_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in check_results:
            if isinstance(result, DirectoryInfo):
                if len(results) < self.max_results:
                    results.append(result)

        return sorted(results, key=lambda x: x.path)

    def _check_path(self, url: str, path: str) -> Optional[DirectoryInfo]:
        """检查单个路径

        Args:
            url: 完整URL
            path: 路径

        Returns:
            DirectoryInfo对象，不存在返回None
        """
        try:
            headers = {"User-Agent": self.user_agent}
            req = urllib.request.Request(url, headers=headers, method="GET")

            with urllib.request.urlopen(
                req,
                timeout=self.timeout,
                context=self._ssl_context
            ) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                content_length = int(resp.headers.get("Content-Length", 0))

                # 读取部分内容检查404
                body = resp.read(2000).decode("utf-8", errors="replace")

                # 检查是否为伪装的404
                if self._is_fake_404(body, status):
                    return None

                return DirectoryInfo(
                    path=path,
                    url=url,
                    status_code=status,
                    content_length=content_length,
                    content_type=content_type,
                    is_directory=path.endswith("/") or not "." in path.split("/")[-1],
                )

        except urllib.error.HTTPError as e:
            # 处理重定向
            if e.code in [301, 302, 303, 307, 308]:
                redirect_url = e.headers.get("Location", "")
                return DirectoryInfo(
                    path=path,
                    url=url,
                    status_code=e.code,
                    redirect_url=redirect_url,
                    is_directory=redirect_url.endswith("/"),
                )
            # 403 Forbidden 也可能是存在的目录
            elif e.code == 403:
                return DirectoryInfo(
                    path=path,
                    url=url,
                    status_code=e.code,
                    is_directory=True,
                )

        except Exception as e:
            self._logger.debug(f"Request error for {url}: {e}")

        return None

    def _detect_404_signature(self, base_url: str) -> None:
        """检测404页面特征

        Args:
            base_url: 基础URL
        """
        import random
        import string

        # 生成随机路径
        random_path = ''.join(random.choices(string.ascii_lowercase, k=16))
        test_url = f"{base_url}/{random_path}"

        try:
            headers = {"User-Agent": self.user_agent}
            req = urllib.request.Request(test_url, headers=headers)

            with urllib.request.urlopen(
                req,
                timeout=self.timeout,
                context=self._ssl_context
            ) as resp:
                if resp.status == 200:
                    # 服务器返回200但可能是自定义404页面
                    body = resp.read(5000).decode("utf-8", errors="replace")
                    # 提取特征
                    if "not found" in body.lower() or "404" in body:
                        self._404_signature = body[:500]

        except urllib.error.HTTPError:
            pass
        except Exception as e:
            self._logger.debug(f"404 detection error: {e}")

    def _is_fake_404(self, body: str, status: int) -> bool:
        """检查是否为伪装的404页面

        Args:
            body: 响应体
            status: 状态码

        Returns:
            是否为伪装的404
        """
        if status != 200:
            return False

        # 检查常见404特征
        lower_body = body.lower()
        if any(sig in lower_body for sig in ["not found", "404", "page doesn't exist", "cannot be found"]):
            return True

        # 检查与已知404页面的相似度
        if self._404_signature:
            # 简单的相似度检查
            if body[:300] == self._404_signature[:300]:
                return True

        return False

    def _load_wordlist(
        self,
        custom_wordlist: Optional[List[str]] = None,
        include_sensitive: bool = True
    ) -> List[str]:
        """加载字典

        Args:
            custom_wordlist: 自定义字典列表
            include_sensitive: 是否包含敏感文件

        Returns:
            路径列表
        """
        paths: Set[str] = set()

        # 添加自定义字典
        if custom_wordlist:
            paths.update(custom_wordlist)

        # 从文件加载字典
        if self.wordlist:
            wordlist_path = Path(self.wordlist)
            if wordlist_path.exists():
                try:
                    with open(wordlist_path, "r", encoding="utf-8") as f:
                        for line in f:
                            path = line.strip()
                            if path and not path.startswith("#"):
                                paths.add(path)
                except Exception as e:
                    self._logger.warning(f"Failed to load wordlist: {e}")

        # 添加内置字典
        paths.update(self.COMMON_DIRECTORIES)

        # 添加敏感文件
        if include_sensitive:
            paths.update(self.SENSITIVE_FILES)

        # 生成带扩展名的路径
        extended_paths: Set[str] = set()
        for path in paths:
            extended_paths.add(path)
            # 为没有扩展名的路径添加扩展名
            if "." not in path.split("/")[-1]:
                for ext in self.extensions:
                    extended_paths.add(f"{path}{ext}")

        return list(extended_paths)

    def set_progress_callback(
        self,
        callback: Callable[[int, int, str], None]
    ) -> None:
        """设置进度回调"""
        self._progress_callback = callback

    def stop(self) -> None:
        """停止扫描"""
        self._stop_flag.set()

    def reset(self) -> None:
        """重置状态"""
        self._stop_flag.clear()
        self._404_signature = None

    def scan_sensitive_files(self, base_url: str) -> List[DirectoryInfo]:
        """只扫描敏感文件

        Args:
            base_url: 基础URL

        Returns:
            发现的敏感文件列表
        """
        return self.scan(base_url, custom_wordlist=self.SENSITIVE_FILES, scan_sensitive=False)

    @classmethod
    def get_common_directories(cls) -> List[str]:
        """获取内置目录字典"""
        return cls.COMMON_DIRECTORIES.copy()

    @classmethod
    def get_sensitive_files(cls) -> List[str]:
        """获取敏感文件列表"""
        return cls.SENSITIVE_FILES.copy()


# 便捷函数
def scan_directories(
    base_url: str,
    timeout: float = 10.0,
    threads: int = 20,
    max_results: int = 500
) -> List[DirectoryInfo]:
    """便捷函数：扫描目录

    Args:
        base_url: 基础URL
        timeout: 超时时间
        threads: 并发线程数
        max_results: 最大结果数

    Returns:
        目录列表
    """
    scanner = DirectoryScanner(
        timeout=timeout,
        threads=threads,
        max_results=max_results
    )
    return scanner.scan(base_url)


async def async_scan_directories(
    base_url: str,
    timeout: float = 10.0,
    concurrency: int = 50,
    max_results: int = 500
) -> List[DirectoryInfo]:
    """便捷函数：异步扫描目录"""
    scanner = DirectoryScanner(
        timeout=timeout,
        max_results=max_results
    )
    return await scanner.async_scan(base_url, concurrency=concurrency)


# 导出
__all__ = [
    "DirectoryInfo",
    "DirectoryScanner",
    "scan_directories",
    "async_scan_directories",
]
