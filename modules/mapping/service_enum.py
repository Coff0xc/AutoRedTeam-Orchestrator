"""
Service Enumeration - 服务枚举模块
深度服务探测和信息收集
"""

import asyncio
import re
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    port: int
    protocol: str
    service: str
    version: str = ""
    banner: str = ""
    extra: Dict = None


class ServiceEnumerator:
    """服务枚举器"""
    
    # 常见端口服务映射
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
        143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp",
        993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        2049: "nfs", 2181: "zookeeper", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 5672: "rabbitmq", 5900: "vnc", 6379: "redis",
        6443: "kubernetes", 8080: "http-proxy", 8443: "https-alt",
        9000: "php-fpm", 9200: "elasticsearch", 9300: "elasticsearch",
        11211: "memcached", 27017: "mongodb", 50000: "sap",
    }
    
    # Banner Grab探针
    PROBES = {
        "http": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
        "https": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
        "ftp": b"",  # FTP服务端先发banner
        "ssh": b"",  # SSH服务端先发banner
        "smtp": b"EHLO test\r\n",
        "pop3": b"",
        "imap": b"",
        "mysql": b"",  # MySQL先发握手包
        "redis": b"INFO\r\n",
        "memcached": b"stats\r\n",
        "mongodb": b"",  # MongoDB二进制协议
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    async def grab_banner(self, host: str, port: int) -> Optional[str]:
        """抓取服务Banner"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            service = self.PORT_SERVICE_MAP.get(port, "unknown")
            probe = self.PROBES.get(service, b"")
            
            # 某些服务先发送banner
            if service in ["ftp", "ssh", "pop3", "imap", "mysql", "smtp"]:
                banner = await asyncio.wait_for(reader.read(1024), timeout=5)
            else:
                if probe:
                    writer.write(probe)
                    await writer.drain()
                banner = await asyncio.wait_for(reader.read(2048), timeout=5)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
            
        except Exception as e:
            logger.debug(f"Banner grab failed {host}:{port}: {e}")
            return None
    
    async def enumerate_service(self, host: str, port: int) -> ServiceInfo:
        """枚举单个服务"""
        service = self.PORT_SERVICE_MAP.get(port, "unknown")
        banner = await self.grab_banner(host, port)
        version = ""
        
        if banner:
            # 提取版本信息
            version_patterns = [
                r"Server:\s*([^\r\n]+)",  # HTTP
                r"SSH-([\d.]+)-([^\r\n]+)",  # SSH
                r"220.*?([^\r\n]+)",  # FTP/SMTP
                r"MySQL.*?([\d.]+)",  # MySQL
                r"redis_version:([\d.]+)",  # Redis
                r"PostgreSQL\s+([\d.]+)",  # PostgreSQL
                r"MongoDB\s+([\d.]+)",  # MongoDB
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, banner, re.I)
                if match:
                    version = match.group(1)
                    break
        
        return ServiceInfo(
            port=port,
            protocol="tcp",
            service=service,
            version=version,
            banner=banner[:200] if banner else "",
        )
    
    async def enumerate_all(self, host: str, ports: List[int]) -> List[ServiceInfo]:
        """枚举所有端口服务"""
        tasks = [self.enumerate_service(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        services = []
        for result in results:
            if isinstance(result, ServiceInfo):
                services.append(result)
        
        return services


class HTTPEnumerator:
    """HTTP服务深度枚举"""
    
    # 常见敏感路径
    SENSITIVE_PATHS = [
        # 信息泄露
        "/.git/config", "/.svn/entries", "/.env", "/.env.local",
        "/config.php", "/wp-config.php", "/configuration.php",
        "/config/database.yml", "/config.yml", "/settings.py",
        "/phpinfo.php", "/info.php", "/test.php",
        
        # 备份文件
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
        "/www.zip", "/wwwroot.zip", "/web.zip", "/site.zip",
        "/.bak", "/web.config.bak", "/config.php.bak",
        
        # 管理后台
        "/admin", "/admin/", "/administrator", "/manager",
        "/wp-admin", "/wp-login.php", "/admin.php", "/login",
        "/phpmyadmin", "/pma", "/adminer.php", "/console",
        
        # API接口
        "/api", "/api/v1", "/api/v2", "/graphql", "/graphiql",
        "/swagger.json", "/swagger-ui.html", "/api-docs",
        "/openapi.json", "/redoc",
        
        # 调试接口
        "/actuator", "/actuator/health", "/actuator/env",
        "/actuator/heapdump", "/actuator/mappings",
        "/jolokia", "/metrics", "/debug", "/trace",
        "/.well-known/security.txt", "/server-status", "/server-info",
        
        # 版本控制
        "/.git/HEAD", "/.gitignore", "/.hg/", "/.bzr/",
        "/CVS/Root", "/CVS/Entries",
        
        # 云服务
        "/.aws/credentials", "/.docker/config.json",
        "/kubernetes/config", "/.kube/config",
        
        # 常见文件
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/clientaccesspolicy.xml", "/security.txt",
        "/humans.txt", "/readme.md", "/README.md",
        "/CHANGELOG.md", "/LICENSE", "/package.json",
        "/composer.json", "/Gemfile", "/requirements.txt",
    ]
    
    # 虚拟主机爆破
    VHOST_WORDLIST = [
        "admin", "api", "app", "beta", "blog", "cdn", "cms",
        "dashboard", "dev", "docs", "ftp", "git", "gitlab",
        "internal", "jenkins", "jira", "mail", "manage",
        "monitor", "mysql", "new", "old", "portal", "private",
        "prod", "proxy", "qa", "redis", "secure", "staging",
        "static", "store", "support", "test", "vpn", "web",
        "wiki", "www", "www2", "api-dev", "api-test",
    ]
    
    def __init__(self, http_client=None):
        self.http_client = http_client
    
    async def probe_paths(self, base_url: str) -> List[Dict]:
        """探测敏感路径"""
        found = []
        
        for path in self.SENSITIVE_PATHS:
            url = base_url.rstrip('/') + path
            try:
                resp = await self.http_client.get(url)
                status = resp.get("status", 0)
                
                if status == 200:
                    body = resp.get("body", "")
                    # 过滤假阳性
                    if not self._is_false_positive(path, body):
                        found.append({
                            "path": path,
                            "url": url,
                            "status": status,
                            "size": len(body),
                        })
                        logger.info(f"[+] Found: {url}")
                        
                elif status in [301, 302, 403]:
                    found.append({
                        "path": path,
                        "url": url,
                        "status": status,
                        "note": "Redirect or Forbidden"
                    })
                    
            except Exception as e:
                logger.debug(f"Probe error {url}: {e}")
        
        return found
    
    def _is_false_positive(self, path: str, body: str) -> bool:
        """检测假阳性"""
        fp_patterns = [
            r"404.*not found",
            r"page.*not.*exist",
            r"cannot be found",
            r"does not exist",
            r"page not found",
        ]
        
        for pattern in fp_patterns:
            if re.search(pattern, body, re.I):
                return True
        
        # 检查特定路径的内容
        if ".git" in path and "[core]" not in body:
            return True
        if ".env" in path and "=" not in body:
            return True
        if "swagger" in path and "swagger" not in body.lower():
            return True
        
        return False
    
    async def enumerate_vhosts(self, ip: str, domain: str, port: int = 80) -> List[str]:
        """虚拟主机枚举"""
        found = []
        scheme = "https" if port == 443 else "http"
        
        for prefix in self.VHOST_WORDLIST:
            vhost = f"{prefix}.{domain}"
            url = f"{scheme}://{ip}:{port}/"
            
            try:
                resp = await self.http_client.get(
                    url, 
                    headers={"Host": vhost}
                )
                
                if resp.get("status") == 200:
                    found.append(vhost)
                    logger.info(f"[+] VHost found: {vhost}")
                    
            except Exception as e:
                logger.debug(f"VHost error {vhost}: {e}")
        
        return found


class SMBEnumerator:
    """SMB服务枚举"""
    
    async def enumerate(self, host: str, port: int = 445) -> Dict:
        """枚举SMB服务"""
        result = {
            "host": host,
            "port": port,
            "shares": [],
            "os": "",
            "domain": "",
        }
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10
            )
            
            # SMB Negotiate请求(简化版)
            negotiate = bytes.fromhex(
                "00000054ff534d4272000000001843c80000000000000000000000000000"
                "fffe00000000003100024e54204c4d20302e313200024e54204c414e4d41"
                "4e20312e3000024e54204c414e4d414e20322e30000253454355524954"
                "592d4d4f44452d534d42000002"
            )
            
            writer.write(negotiate)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            
            if response:
                result["status"] = "open"
                # 简单解析响应
                if b"SMB" in response:
                    result["smb_version"] = "SMB1/2"
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"SMB enum error {host}: {e}")
            result["status"] = "error"
        
        return result
