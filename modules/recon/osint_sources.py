"""
OSINT Sources - 开源情报源集成
支持多个在线API进行资产发现
"""

import asyncio
import json
import logging
import re
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


@dataclass
class OSINTResult:
    """OSINT查询结果"""
    source: str
    data_type: str  # subdomain, ip, port, email, etc.
    value: str
    extra: Dict = None


class OSINTSource(ABC):
    """OSINT数据源基类"""
    
    @abstractmethod
    async def query(self, target: str, http_client) -> List[OSINTResult]:
        pass


class CrtshSource(OSINTSource):
    """crt.sh证书透明度"""
    
    async def query(self, domain: str, http_client) -> List[OSINTResult]:
        results = []
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "[]"))
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub and sub not in seen:
                            seen.add(sub)
                            results.append(OSINTResult(
                                source="crt.sh",
                                data_type="subdomain",
                                value=sub,
                                extra={"issuer": entry.get("issuer_name", "")}
                            ))
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        return results


class SecurityTrailsSource(OSINTSource):
    """SecurityTrails API (需要API Key)"""
    
    API_BASE = "https://api.securitytrails.com/v1"
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
    
    async def query(self, domain: str, http_client) -> List[OSINTResult]:
        if not self.api_key:
            return []
        
        results = []
        headers = {"APIKEY": self.api_key}
        
        # 子域名查询
        url = f"{self.API_BASE}/domain/{domain}/subdomains"
        try:
            resp = await http_client.get(url, headers=headers)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "{}"))
                for sub in data.get("subdomains", []):
                    results.append(OSINTResult(
                        source="securitytrails",
                        data_type="subdomain",
                        value=f"{sub}.{domain}"
                    ))
        except Exception as e:
            logger.debug(f"SecurityTrails error: {e}")
        
        return results


class ShodanSource(OSINTSource):
    """Shodan API (需要API Key)"""
    
    API_BASE = "https://api.shodan.io"
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
    
    async def query(self, target: str, http_client) -> List[OSINTResult]:
        if not self.api_key:
            return []
        
        results = []
        
        # 判断是域名还是IP
        is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)
        
        if is_ip:
            url = f"{self.API_BASE}/shodan/host/{target}?key={self.api_key}"
        else:
            url = f"{self.API_BASE}/dns/domain/{target}?key={self.api_key}"
        
        try:
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "{}"))
                
                if is_ip:
                    # IP查询结果
                    for port_data in data.get("data", []):
                        results.append(OSINTResult(
                            source="shodan",
                            data_type="port",
                            value=str(port_data.get("port", "")),
                            extra={
                                "product": port_data.get("product", ""),
                                "version": port_data.get("version", ""),
                                "banner": port_data.get("data", "")[:200]
                            }
                        ))
                else:
                    # 域名查询结果
                    for sub in data.get("subdomains", []):
                        results.append(OSINTResult(
                            source="shodan",
                            data_type="subdomain",
                            value=f"{sub}.{target}"
                        ))
        except Exception as e:
            logger.debug(f"Shodan error: {e}")
        
        return results


class CensysSource(OSINTSource):
    """Censys API (需要API Key)"""
    
    API_BASE = "https://search.censys.io/api/v2"
    
    def __init__(self, api_id: str = "", api_secret: str = ""):
        self.api_id = api_id
        self.api_secret = api_secret
    
    async def query(self, target: str, http_client) -> List[OSINTResult]:
        if not self.api_id or not self.api_secret:
            return []
        
        results = []
        # Censys API实现
        return results


class VirusTotalSource(OSINTSource):
    """VirusTotal API (需要API Key)"""
    
    API_BASE = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str = ""):
        self.api_key = api_key
    
    async def query(self, domain: str, http_client) -> List[OSINTResult]:
        if not self.api_key:
            return []
        
        results = []
        headers = {"x-apikey": self.api_key}
        url = f"{self.API_BASE}/domains/{domain}/subdomains"
        
        try:
            resp = await http_client.get(url, headers=headers)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "{}"))
                for item in data.get("data", []):
                    results.append(OSINTResult(
                        source="virustotal",
                        data_type="subdomain",
                        value=item.get("id", "")
                    ))
        except Exception as e:
            logger.debug(f"VirusTotal error: {e}")
        
        return results


class AlienVaultOTX(OSINTSource):
    """AlienVault OTX (免费)"""
    
    API_BASE = "https://otx.alienvault.com/api/v1"
    
    async def query(self, domain: str, http_client) -> List[OSINTResult]:
        results = []
        url = f"{self.API_BASE}/indicators/domain/{domain}/passive_dns"
        
        try:
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "{}"))
                seen = set()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "")
                    if hostname.endswith(domain) and hostname not in seen:
                        seen.add(hostname)
                        results.append(OSINTResult(
                            source="alienvault",
                            data_type="subdomain",
                            value=hostname,
                            extra={"ip": record.get("address", "")}
                        ))
        except Exception as e:
            logger.debug(f"AlienVault error: {e}")
        
        return results


class ThreatCrowdSource(OSINTSource):
    """ThreatCrowd (免费)"""
    
    API_BASE = "https://www.threatcrowd.org/searchApi/v2"
    
    async def query(self, domain: str, http_client) -> List[OSINTResult]:
        results = []
        url = f"{self.API_BASE}/domain/report/?domain={domain}"
        
        try:
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                data = json.loads(resp.get("body", "{}"))
                for sub in data.get("subdomains", []):
                    results.append(OSINTResult(
                        source="threatcrowd",
                        data_type="subdomain",
                        value=sub
                    ))
                for ip in data.get("resolutions", []):
                    results.append(OSINTResult(
                        source="threatcrowd",
                        data_type="ip",
                        value=ip.get("ip_address", ""),
                        extra={"last_resolved": ip.get("last_resolved", "")}
                    ))
        except Exception as e:
            logger.debug(f"ThreatCrowd error: {e}")
        
        return results


class HackerTargetSource(OSINTSource):
    """HackerTarget (免费有限额)"""
    
    API_BASE = "https://api.hackertarget.com"
    
    async def query(self, domain: str, http_client) -> List[OSINTResult]:
        results = []
        
        # 子域名查询
        url = f"{self.API_BASE}/hostsearch/?q={domain}"
        try:
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                body = resp.get("body", "")
                if "error" not in body.lower():
                    for line in body.splitlines():
                        if "," in line:
                            subdomain, ip = line.split(",", 1)
                            results.append(OSINTResult(
                                source="hackertarget",
                                data_type="subdomain",
                                value=subdomain.strip(),
                                extra={"ip": ip.strip()}
                            ))
        except Exception as e:
            logger.debug(f"HackerTarget error: {e}")
        
        return results


class RapidDNSSource(OSINTSource):
    """RapidDNS (免费)"""
    
    async def query(self, domain: str, http_client) -> List[OSINTResult]:
        results = []
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        
        try:
            resp = await http_client.get(url)
            if resp.get("status") == 200:
                body = resp.get("body", "")
                pattern = rf'([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(domain)})'
                matches = set(re.findall(pattern, body))
                for sub in matches:
                    results.append(OSINTResult(
                        source="rapiddns",
                        data_type="subdomain",
                        value=sub.lower()
                    ))
        except Exception as e:
            logger.debug(f"RapidDNS error: {e}")
        
        return results


class OSINTAggregator:
    """OSINT数据聚合器"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # 初始化所有数据源
        self.sources: List[OSINTSource] = [
            CrtshSource(),
            AlienVaultOTX(),
            ThreatCrowdSource(),
            HackerTargetSource(),
            RapidDNSSource(),
        ]
        
        # 添加需要API Key的源
        if self.config.get("securitytrails_key"):
            self.sources.append(SecurityTrailsSource(self.config["securitytrails_key"]))
        if self.config.get("shodan_key"):
            self.sources.append(ShodanSource(self.config["shodan_key"]))
        if self.config.get("virustotal_key"):
            self.sources.append(VirusTotalSource(self.config["virustotal_key"]))
    
    async def gather_all(self, target: str, http_client) -> Dict[str, List]:
        """从所有源收集数据"""
        all_results = {
            "subdomains": [],
            "ips": [],
            "ports": [],
            "emails": [],
        }
        
        tasks = [source.query(target, http_client) for source in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        seen_subdomains = set()
        seen_ips = set()
        
        for result in results:
            if isinstance(result, Exception):
                continue
            
            for item in result:
                if item.data_type == "subdomain" and item.value not in seen_subdomains:
                    seen_subdomains.add(item.value)
                    all_results["subdomains"].append({
                        "value": item.value,
                        "source": item.source,
                        "extra": item.extra
                    })
                elif item.data_type == "ip" and item.value not in seen_ips:
                    seen_ips.add(item.value)
                    all_results["ips"].append({
                        "value": item.value,
                        "source": item.source,
                        "extra": item.extra
                    })
                elif item.data_type == "port":
                    all_results["ports"].append({
                        "value": item.value,
                        "source": item.source,
                        "extra": item.extra
                    })
        
        logger.info(f"[OSINT] Gathered {len(all_results['subdomains'])} subdomains from {len(self.sources)} sources")
        
        return all_results
    
    def get_source_count(self) -> int:
        return len(self.sources)
