"""
Port Scanner - 端口扫描模块
封装Nmap进行端口和服务探测
"""

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    product: str = ""
    extra_info: str = ""


@dataclass 
class HostInfo:
    ip: str
    hostname: str = ""
    state: str = "unknown"
    ports: List[PortInfo] = field(default_factory=list)
    os_match: str = ""


class PortScanner:
    """
    端口扫描器
    基于Nmap的端口和服务检测
    """
    
    SCAN_PROFILES = {
        "quick": {"ports": "--top-ports 100", "timing": "-T4"},
        "standard": {"ports": "--top-ports 1000", "timing": "-T3"},
        "full": {"ports": "-p-", "timing": "-T4"},
        "stealth": {"ports": "--top-ports 1000", "timing": "-T2", "extra": "-sS"},
        "udp": {"ports": "--top-ports 100", "timing": "-T4", "extra": "-sU"},
    }
    
    def __init__(self, workspace: str = "/tmp/mapping"):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.scan_results: Dict[str, HostInfo] = {}
    
    async def scan(self, target: str, profile: str = "standard", 
                   service_detection: bool = True, os_detection: bool = False) -> HostInfo:
        """
        执行端口扫描
        
        Args:
            target: 目标IP或域名
            profile: 扫描配置 (quick/standard/full/stealth/udp)
            service_detection: 是否启用服务版本检测
            os_detection: 是否启用OS检测
        """
        safe_name = target.replace('.', '_').replace('/', '_')
        xml_output = self.workspace / f"nmap_{safe_name}.xml"
        
        profile_config = self.SCAN_PROFILES.get(profile, self.SCAN_PROFILES["standard"])
        
        cmd = ["nmap", target, "-oX", str(xml_output)]
        cmd.append(profile_config["ports"])
        cmd.append(profile_config["timing"])
        
        if profile_config.get("extra"):
            cmd.append(profile_config["extra"])
        
        if service_detection:
            cmd.append("-sV")
        
        if os_detection:
            cmd.append("-O")
        
        logger.info(f"Running: {' '.join(cmd)}")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            timeout = 900 if profile == "full" else 300
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            if xml_output.exists():
                host_info = self._parse_nmap_xml(xml_output)
                if host_info:
                    self.scan_results[target] = host_info
                    return host_info
            
            return HostInfo(ip=target, state="down")
            
        except asyncio.TimeoutError:
            logger.error(f"Nmap scan timeout for {target}")
            return HostInfo(ip=target, state="timeout")
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return HostInfo(ip=target, state="error")

    def _parse_nmap_xml(self, xml_path: Path) -> Optional[HostInfo]:
        """解析Nmap XML输出"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            host_elem = root.find('.//host')
            if host_elem is None:
                return None
            
            # 获取IP
            addr_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            ip = addr_elem.get('addr') if addr_elem is not None else "unknown"
            
            # 获取主机名
            hostname_elem = host_elem.find('.//hostname')
            hostname = hostname_elem.get('name', '') if hostname_elem is not None else ''
            
            # 获取状态
            status_elem = host_elem.find('.//status')
            state = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'
            
            # 解析端口
            ports = []
            for port_elem in host_elem.findall('.//port'):
                state_elem = port_elem.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue
                
                service_elem = port_elem.find('service')
                port_info = PortInfo(
                    port=int(port_elem.get('portid')),
                    protocol=port_elem.get('protocol', 'tcp'),
                    state='open',
                    service=service_elem.get('name', 'unknown') if service_elem is not None else 'unknown',
                    version=service_elem.get('version', '') if service_elem is not None else '',
                    product=service_elem.get('product', '') if service_elem is not None else '',
                    extra_info=service_elem.get('extrainfo', '') if service_elem is not None else ''
                )
                ports.append(port_info)
            
            # OS检测
            os_match = ""
            os_elem = host_elem.find('.//osmatch')
            if os_elem is not None:
                os_match = os_elem.get('name', '')
            
            return HostInfo(
                ip=ip,
                hostname=hostname,
                state=state,
                ports=ports,
                os_match=os_match
            )
            
        except Exception as e:
            logger.error(f"XML parse error: {e}")
            return None

    async def bulk_scan(self, targets: List[str], profile: str = "quick") -> Dict[str, HostInfo]:
        """批量扫描多个目标"""
        results = {}
        
        for target in targets:
            logger.info(f"Scanning {target}...")
            result = await self.scan(target, profile)
            results[target] = result
            
            # 避免过快触发防护
            await asyncio.sleep(1)
        
        return results

    def get_open_ports(self, target: str) -> List[int]:
        """获取目标的开放端口列表"""
        host_info = self.scan_results.get(target)
        if host_info:
            return [p.port for p in host_info.ports]
        return []

    def get_web_services(self, target: str) -> List[PortInfo]:
        """获取Web服务端口"""
        host_info = self.scan_results.get(target)
        if not host_info:
            return []
        
        web_services = []
        for port in host_info.ports:
            if port.service in ['http', 'https', 'http-proxy', 'http-alt'] or \
               port.port in [80, 443, 8080, 8443, 8000, 8888, 3000]:
                web_services.append(port)
        
        return web_services

    def export_results(self, output_file: str):
        """导出扫描结果"""
        import json
        
        data = {}
        for target, host_info in self.scan_results.items():
            data[target] = {
                "ip": host_info.ip,
                "hostname": host_info.hostname,
                "state": host_info.state,
                "os": host_info.os_match,
                "ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "version": p.version,
                        "product": p.product
                    }
                    for p in host_info.ports
                ]
            }
        
        Path(output_file).write_text(json.dumps(data, indent=2))
