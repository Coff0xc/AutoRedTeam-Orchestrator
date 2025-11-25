"""
Service Scanner - 服务漏洞扫描器
针对常见服务的专项漏洞检测
"""

import asyncio
import socket
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ServiceFinding:
    service: str
    host: str
    port: int
    vuln_type: str
    severity: str
    details: str


class ServiceScanner:
    """服务漏洞扫描器"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.findings: List[ServiceFinding] = []
    
    async def scan_redis(self, host: str, port: int = 6379) -> List[ServiceFinding]:
        """Redis未授权访问检测"""
        findings = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # 发送INFO命令
            writer.write(b"INFO\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            response_str = response.decode('utf-8', errors='ignore')
            
            if "redis_version" in response_str or "$" in response_str:
                finding = ServiceFinding(
                    service="redis", host=host, port=port,
                    vuln_type="Unauthorized Access",
                    severity="critical",
                    details=f"Redis未授权访问，可执行任意命令"
                )
                findings.append(finding)
                self.findings.append(finding)
                logger.info(f"[!] Redis未授权: {host}:{port}")
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"Redis scan error {host}:{port}: {e}")
        
        return findings
    
    async def scan_mongodb(self, host: str, port: int = 27017) -> List[ServiceFinding]:
        """MongoDB未授权访问检测"""
        findings = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # MongoDB wire protocol - isMaster命令
            msg = bytes([
                0x3f, 0x00, 0x00, 0x00,  # messageLength
                0x01, 0x00, 0x00, 0x00,  # requestID
                0x00, 0x00, 0x00, 0x00,  # responseTo
                0xd4, 0x07, 0x00, 0x00,  # opCode (OP_QUERY)
                0x00, 0x00, 0x00, 0x00,  # flags
                0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00,  # admin.$cmd
                0x00, 0x00, 0x00, 0x00,  # numberToSkip
                0x01, 0x00, 0x00, 0x00,  # numberToReturn
                0x15, 0x00, 0x00, 0x00,  # document length
                0x01, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,  # "isMaster"
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f,  # 1.0 (double)
                0x00  # document end
            ])
            
            writer.write(msg)
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            if len(response) > 4 and b"ismaster" in response.lower():
                finding = ServiceFinding(
                    service="mongodb", host=host, port=port,
                    vuln_type="Unauthorized Access",
                    severity="critical",
                    details="MongoDB未授权访问，数据库暴露"
                )
                findings.append(finding)
                self.findings.append(finding)
                logger.info(f"[!] MongoDB未授权: {host}:{port}")
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"MongoDB scan error {host}:{port}: {e}")
        
        return findings
    
    async def scan_mysql(self, host: str, port: int = 3306) -> List[ServiceFinding]:
        """MySQL弱口令检测"""
        findings = []
        
        weak_creds = [
            ("root", ""), ("root", "root"), ("root", "123456"),
            ("root", "password"), ("mysql", "mysql"), ("admin", "admin")
        ]
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # 读取握手包
            greeting = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            if len(greeting) > 4:
                # MySQL服务存在
                version_end = greeting[5:].find(b'\x00')
                if version_end > 0:
                    version = greeting[5:5+version_end].decode('utf-8', errors='ignore')
                    finding = ServiceFinding(
                        service="mysql", host=host, port=port,
                        vuln_type="Version Disclosure",
                        severity="low",
                        details=f"MySQL版本: {version}"
                    )
                    findings.append(finding)
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"MySQL scan error {host}:{port}: {e}")
        
        return findings
    
    async def scan_elasticsearch(self, host: str, port: int = 9200) -> List[ServiceFinding]:
        """Elasticsearch未授权访问检测"""
        findings = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # 发送HTTP请求
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            response_str = response.decode('utf-8', errors='ignore')
            
            if "cluster_name" in response_str or "elasticsearch" in response_str.lower():
                finding = ServiceFinding(
                    service="elasticsearch", host=host, port=port,
                    vuln_type="Unauthorized Access",
                    severity="critical",
                    details="Elasticsearch未授权访问，可读取索引数据"
                )
                findings.append(finding)
                self.findings.append(finding)
                logger.info(f"[!] Elasticsearch未授权: {host}:{port}")
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"Elasticsearch scan error {host}:{port}: {e}")
        
        return findings
    
    async def scan_memcached(self, host: str, port: int = 11211) -> List[ServiceFinding]:
        """Memcached未授权访问检测"""
        findings = []
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            writer.write(b"stats\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            response_str = response.decode('utf-8', errors='ignore')
            
            if "STAT" in response_str or "version" in response_str.lower():
                finding = ServiceFinding(
                    service="memcached", host=host, port=port,
                    vuln_type="Unauthorized Access",
                    severity="high",
                    details="Memcached未授权访问，可能导致信息泄露或DDoS放大"
                )
                findings.append(finding)
                self.findings.append(finding)
                logger.info(f"[!] Memcached未授权: {host}:{port}")
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            logger.debug(f"Memcached scan error {host}:{port}: {e}")
        
        return findings
    
    async def scan_all(self, host: str, ports: Dict[str, int] = None) -> List[ServiceFinding]:
        """扫描所有支持的服务"""
        default_ports = {
            "redis": 6379,
            "mongodb": 27017,
            "mysql": 3306,
            "elasticsearch": 9200,
            "memcached": 11211
        }
        
        ports = ports or default_ports
        all_findings = []
        
        tasks = []
        if "redis" in ports:
            tasks.append(self.scan_redis(host, ports["redis"]))
        if "mongodb" in ports:
            tasks.append(self.scan_mongodb(host, ports["mongodb"]))
        if "mysql" in ports:
            tasks.append(self.scan_mysql(host, ports["mysql"]))
        if "elasticsearch" in ports:
            tasks.append(self.scan_elasticsearch(host, ports["elasticsearch"]))
        if "memcached" in ports:
            tasks.append(self.scan_memcached(host, ports["memcached"]))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
        
        return all_findings
    
    def get_findings(self) -> List[ServiceFinding]:
        return self.findings
    
    def get_critical_findings(self) -> List[ServiceFinding]:
        return [f for f in self.findings if f.severity == "critical"]
