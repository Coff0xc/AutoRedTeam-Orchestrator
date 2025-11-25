"""
Asset Discovery - 增强资产发现模块
多维度信息收集：子域名、端口、JS解析、证书透明度等
"""

import asyncio
import re
import json
import logging
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAsset:
    """发现的资产"""
    hostname: str
    ip: str = ""
    ports: List[int] = field(default_factory=list)
    source: str = ""
    tags: List[str] = field(default_factory=list)


class CertTransparency:
    """证书透明度查询"""
    
    SOURCES = [
        "https://crt.sh/?q=%.{domain}&output=json",
        "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
    ]
    
    async def query(self, domain: str, http_client) -> Set[str]:
        """查询证书透明度日志"""
        subdomains = set()
        
        # crt.sh查询
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "[]"))
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
                logger.info(f"[crt.sh] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        return subdomains


class JSParser:
    """JavaScript文件解析器 - 提取URL和敏感信息"""
    
    PATTERNS = {
        "url": r'(?:"|\'|\`)(((?:[a-zA-Z]{1,10}://|//)[^"\'/]{1,}\.[a-zA-Z]{2,}[^"\s]{0,})|((?:/|\.\./|\./)[^"\s]*?(?:\?[^"\s]*)?))',
        "endpoint": r'(?:"|\'|\`)((?:/[a-zA-Z0-9_\-\.]+)+(?:\?[^"\'\`]*)?)',
        "api_path": r'["\']/(api|v[0-9]+|graphql|rest)/[^"\']*["\']',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "jwt": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        "api_key": r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        "secret": r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        "password": r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        "token": r'["\']?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        "s3_bucket": r'[a-z0-9.-]+\.s3\.amazonaws\.com',
        "firebase": r'[a-z0-9.-]+\.firebaseio\.com',
        "google_api": r'AIza[0-9A-Za-z\-_]{35}',
    }
    
    def parse(self, js_content: str, base_url: str = "") -> Dict[str, List[str]]:
        """解析JS内容"""
        results = {
            "urls": [],
            "endpoints": [],
            "secrets": [],
            "subdomains": [],
        }
        
        # 提取URL
        url_matches = re.findall(self.PATTERNS["url"], js_content)
        for match in url_matches:
            url = match[0] if isinstance(match, tuple) else match
            if url and len(url) > 3:
                results["urls"].append(url)
        
        # 提取API端点
        endpoint_matches = re.findall(self.PATTERNS["endpoint"], js_content)
        for ep in endpoint_matches:
            if ep and len(ep) > 1 and not ep.endswith(('.js', '.css', '.png', '.jpg')):
                results["endpoints"].append(ep)
        
        # 提取敏感信息
        for key in ["aws_key", "jwt", "api_key", "secret", "google_api"]:
            matches = re.findall(self.PATTERNS[key], js_content)
            results["secrets"].extend([(key, m) for m in matches])
        
        # 提取子域名
        if base_url:
            domain = urlparse(base_url).netloc.split(".")[-2] + "." + urlparse(base_url).netloc.split(".")[-1]
            subdomain_pattern = rf'[a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(domain)}'
            results["subdomains"] = list(set(re.findall(subdomain_pattern, js_content)))
        
        return results


class WaybackMachine:
    """Wayback Machine历史数据收集"""
    
    async def get_urls(self, domain: str, http_client) -> List[str]:
        """获取历史URL"""
        urls = []
        try:
            api_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            resp = await http_client.get(api_url)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "[]"))
                urls = [row[0] for row in data[1:] if row][:500]  # 限制500条
                logger.info(f"[Wayback] Found {len(urls)} historical URLs")
        except Exception as e:
            logger.debug(f"Wayback error: {e}")
        return urls


class PassiveDNS:
    """被动DNS查询"""
    
    async def query(self, domain: str, http_client) -> Set[str]:
        """查询被动DNS记录"""
        subdomains = set()
        
        # RapidDNS
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                matches = re.findall(rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(domain)})', resp.get("body", ""))
                subdomains.update(matches)
        except Exception as e:
            logger.debug(f"RapidDNS error: {e}")
        
        return subdomains


class WebCrawler:
    """轻量级爬虫 - 发现隐藏资产"""
    
    def __init__(self, max_depth: int = 2, max_pages: int = 50):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.found_urls = set()
        self.found_forms = []
        self.found_params = set()
    
    async def crawl(self, start_url: str, http_client) -> Dict:
        """爬取网站"""
        await self._crawl_page(start_url, 0, http_client)
        
        return {
            "urls": list(self.found_urls),
            "forms": self.found_forms,
            "params": list(self.found_params),
            "pages_crawled": len(self.visited)
        }
    
    async def _crawl_page(self, url: str, depth: int, http_client):
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        
        self.visited.add(url)
        
        try:
            resp = await http_client.get(url)
            if resp.get("status") != 200:
                return
            
            body = resp.get("body", "")
            base_domain = urlparse(url).netloc
            
            # 提取链接
            links = re.findall(r'href=["\']([^"\']+)["\']', body)
            for link in links:
                full_url = self._normalize_url(link, url)
                if full_url and base_domain in full_url:
                    self.found_urls.add(full_url)
                    await self._crawl_page(full_url, depth + 1, http_client)
            
            # 提取表单
            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', body, re.S | re.I)
            for action, form_body in forms:
                inputs = re.findall(r'name=["\']([^"\']+)["\']', form_body)
                self.found_forms.append({
                    "action": self._normalize_url(action, url),
                    "inputs": inputs
                })
                self.found_params.update(inputs)
            
            # 提取URL参数
            param_matches = re.findall(r'[?&]([a-zA-Z0-9_]+)=', body)
            self.found_params.update(param_matches)
            
        except Exception as e:
            logger.debug(f"Crawl error {url}: {e}")
    
    def _normalize_url(self, url: str, base: str) -> Optional[str]:
        if not url or url.startswith(('#', 'javascript:', 'mailto:')):
            return None
        if url.startswith('//'):
            return 'https:' + url
        if url.startswith('/'):
            parsed = urlparse(base)
            return f"{parsed.scheme}://{parsed.netloc}{url}"
        if not url.startswith('http'):
            return base.rsplit('/', 1)[0] + '/' + url
        return url


class AssetDiscovery:
    """综合资产发现引擎"""
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.cert_transparency = CertTransparency()
        self.js_parser = JSParser()
        self.wayback = WaybackMachine()
        self.passive_dns = PassiveDNS()
        self.crawler = WebCrawler()
    
    async def full_discovery(self, domain: str) -> Dict:
        """全面资产发现"""
        results = {
            "subdomains": set(),
            "urls": [],
            "endpoints": [],
            "secrets": [],
            "forms": [],
            "params": set(),
        }
        
        if not self.http_client:
            logger.warning("No HTTP client provided")
            return results
        
        # 并行执行多个发现任务
        tasks = [
            self.cert_transparency.query(domain, self.http_client),
            self.passive_dns.query(domain, self.http_client),
            self.wayback.get_urls(domain, self.http_client),
        ]
        
        ct_subs, pdns_subs, wayback_urls = await asyncio.gather(*tasks, return_exceptions=True)
        
        if isinstance(ct_subs, set):
            results["subdomains"].update(ct_subs)
        if isinstance(pdns_subs, set):
            results["subdomains"].update(pdns_subs)
        if isinstance(wayback_urls, list):
            results["urls"].extend(wayback_urls)
        
        logger.info(f"[AssetDiscovery] Found {len(results['subdomains'])} subdomains")
        
        return {
            "subdomains": list(results["subdomains"]),
            "urls": results["urls"],
            "endpoints": results["endpoints"],
            "secrets": results["secrets"],
        }
