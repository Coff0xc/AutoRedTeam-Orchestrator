"""
Online Payload Sources - 在线Payload资源集成
自动从GitHub等源获取最新Payload
"""

import asyncio
import logging
import json
import re
from typing import Dict, List, Set
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class OnlinePayloadManager:
    """在线Payload管理器 - 集成互联网资源"""
    
    # GitHub原始文件源
    GITHUB_SOURCES = {
        "PayloadsAllTheThings": {
            "sqli": [
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/Auth_Bypass.txt",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MSSQL.txt",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/FUZZDB_MYSQL.txt",
            ],
            "xss": [
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/xss-without-parentheses.txt",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruders/IntrudersXSS.txt",
            ],
            "lfi": [
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/JHADDIX_LFI.txt",
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/File%20Inclusion/Intruders/File_Inclusion_Windows.txt",
            ],
            "ssrf": [
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/Intruder/SSRF.txt",
            ],
            "ssti": [
                "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Intruders/ssti.txt",
            ],
        },
        "SecLists": {
            "sqli": [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/quick-SQLi.txt",
            ],
            "xss": [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
            ],
            "lfi": [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
            ],
            "passwords": [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/best1050.txt",
            ],
            "usernames": [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt",
            ],
            "subdomains": [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
            ],
            "directories": [
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
                "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
            ],
        },
        "fuzzdb": {
            "sqli": [
                "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/xplatform.txt",
            ],
            "xss": [
                "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/xss/xss-rsnake.txt",
            ],
            "lfi": [
                "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/lfi/JHADDIX_LFI.txt",
            ],
            "rce": [
                "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/os-cmd-execution/command-execution-unix.txt",
            ],
        },
    }
    
    # Nuclei模板源
    NUCLEI_TEMPLATES = {
        "cves": "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/cves",
        "vulnerabilities": "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/vulnerabilities",
        "exposures": "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/exposures",
    }
    
    def __init__(self, cache_dir: str = "./cache/payloads", http_client=None):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.http_client = http_client
        self.payloads: Dict[str, Set[str]] = {
            "sqli": set(), "xss": set(), "lfi": set(), "rce": set(),
            "ssrf": set(), "ssti": set(), "xxe": set(),
            "passwords": set(), "usernames": set(),
            "subdomains": set(), "directories": set(),
        }
    
    async def fetch_all(self, force_refresh: bool = False) -> Dict[str, int]:
        """获取所有在线Payload"""
        stats = {}
        
        for source_name, categories in self.GITHUB_SOURCES.items():
            logger.info(f"[*] Fetching from {source_name}...")
            
            for category, urls in categories.items():
                for url in urls:
                    payloads = await self._fetch_url(url, force_refresh)
                    if payloads:
                        self.payloads[category].update(payloads)
        
        for category, payload_set in self.payloads.items():
            stats[category] = len(payload_set)
            logger.info(f"[+] {category}: {len(payload_set)} payloads")
        
        return stats
    
    async def _fetch_url(self, url: str, force_refresh: bool = False) -> List[str]:
        """从URL获取Payload列表"""
        # 检查缓存
        cache_file = self.cache_dir / f"{hash(url)}.txt"
        
        if not force_refresh and cache_file.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age < timedelta(days=7):  # 7天缓存
                return cache_file.read_text().splitlines()
        
        # 获取在线内容
        try:
            if self.http_client:
                resp = await self.http_client.get(url)
                if resp.get("status") == 200:
                    content = resp.get("body", "")
                    payloads = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
                    
                    # 保存缓存
                    cache_file.write_text("\n".join(payloads))
                    return payloads
            else:
                import urllib.request
                with urllib.request.urlopen(url, timeout=30) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    payloads = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
                    cache_file.write_text("\n".join(payloads))
                    return payloads
                    
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
        
        return []
    
    def get_payloads(self, category: str, limit: int = None) -> List[str]:
        """获取指定类型的Payload"""
        payloads = list(self.payloads.get(category, set()))
        if limit:
            return payloads[:limit]
        return payloads
    
    def get_all_stats(self) -> Dict[str, int]:
        """获取所有Payload统计"""
        return {cat: len(payloads) for cat, payloads in self.payloads.items()}
    
    def save_to_file(self, category: str, filepath: str):
        """保存Payload到文件"""
        payloads = self.payloads.get(category, set())
        Path(filepath).write_text("\n".join(sorted(payloads)))
    
    def load_custom_payloads(self, category: str, filepath: str):
        """加载自定义Payload文件"""
        if Path(filepath).exists():
            custom = Path(filepath).read_text().splitlines()
            self.payloads[category].update([p.strip() for p in custom if p.strip()])


class ExploitDBIntegration:
    """Exploit-DB集成"""
    
    EXPLOITDB_API = "https://www.exploit-db.com/search?q={query}"
    EXPLOITDB_RAW = "https://www.exploit-db.com/raw/{id}"
    
    async def search(self, query: str, http_client) -> List[Dict]:
        """搜索Exploit-DB"""
        results = []
        # 注意: Exploit-DB可能需要绕过反爬
        # 这里提供接口框架，实际使用需要处理反爬
        return results


class HackerOneDisclosures:
    """HackerOne公开报告集成"""
    
    HACKTIVITY_API = "https://hackerone.com/hacktivity"
    
    async def get_recent(self, http_client, limit: int = 50) -> List[Dict]:
        """获取最近的公开报告"""
        # 需要处理API认证
        return []


class NucleiTemplateManager:
    """Nuclei模板管理器"""
    
    TEMPLATE_REPO = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
    
    async def list_templates(self, http_client, category: str = None) -> List[str]:
        """列出可用模板"""
        templates = []
        try:
            resp = await http_client.get(self.TEMPLATE_REPO)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "{}"))
                for item in data.get("tree", []):
                    path = item.get("path", "")
                    if path.endswith(".yaml"):
                        if category is None or category in path:
                            templates.append(path)
        except Exception as e:
            logger.debug(f"Failed to list templates: {e}")
        return templates
    
    def get_template_stats(self) -> Dict:
        """获取模板统计（本地nuclei-templates）"""
        template_dir = Path.home() / "nuclei-templates"
        if not template_dir.exists():
            return {"error": "nuclei-templates not found"}
        
        stats = {}
        for category_dir in template_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("."):
                count = len(list(category_dir.rglob("*.yaml")))
                if count > 0:
                    stats[category_dir.name] = count
        
        return stats
