"""
DNS Resolver - DNS解析模块
"""

import asyncio
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    hostname: str
    record_type: str
    value: str
    ttl: int = 0


class DNSResolver:
    """DNS解析器"""
    
    def __init__(self):
        self.cache: Dict[str, List[DNSRecord]] = {}
    
    async def resolve(self, hostname: str, record_types: List[str] = None) -> List[DNSRecord]:
        """解析DNS记录"""
        record_types = record_types or ['A', 'AAAA', 'CNAME']
        records = []
        
        try:
            import socket
            # 基本A记录解析
            try:
                ip = socket.gethostbyname(hostname)
                records.append(DNSRecord(hostname, 'A', ip))
            except socket.gaierror:
                pass
            
        except Exception as e:
            logger.error(f"DNS resolve error for {hostname}: {e}")
        
        self.cache[hostname] = records
        return records

    async def bulk_resolve(self, hostnames: List[str]) -> Dict[str, List[DNSRecord]]:
        """批量解析"""
        tasks = [self.resolve(h) for h in hostnames]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        resolved = {}
        for hostname, result in zip(hostnames, results):
            if isinstance(result, list):
                resolved[hostname] = result
            else:
                resolved[hostname] = []
        
        return resolved

    def get_ips(self, hostname: str) -> List[str]:
        """获取hostname的所有IP"""
        records = self.cache.get(hostname, [])
        return [r.value for r in records if r.record_type in ['A', 'AAAA']]
