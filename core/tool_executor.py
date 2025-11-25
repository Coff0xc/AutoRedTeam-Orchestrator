"""
Tool Executor - Kali Linux 工具执行器
负责调度和执行各种安全工具
"""

import asyncio
import subprocess
import shutil
import json
import os
import re
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"


@dataclass
class ToolResult:
    tool: str
    status: ToolStatus
    output: str
    error: str
    execution_time: float
    parsed_data: Any = None


class ToolExecutor:
    """Kali Linux 工具执行器"""
    
    REQUIRED_TOOLS = {
        "subfinder": "subfinder",
        "nmap": "nmap", 
        "nuclei": "nuclei",
        "httpx": "httpx",
        "dnsx": "dnsx",
    }
    
    def __init__(self, workspace: str = "/tmp/redteam", timeout: int = 300):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.available_tools = self._check_tools()
        
    def _check_tools(self) -> Dict[str, bool]:
        available = {}
        for name, binary in self.REQUIRED_TOOLS.items():
            available[name] = shutil.which(binary) is not None
            if not available[name]:
                logger.warning(f"Tool not found: {name}")
        return available

    def get_tool_status(self) -> Dict[str, bool]:
        return self.available_tools

    async def _run_async(self, cmd: List[str], timeout: int = None) -> Tuple[str, str, int]:
        timeout = timeout or self.timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore'), proc.returncode
        except asyncio.TimeoutError:
            proc.kill()
            return "", f"Timeout after {timeout}s", -1
        except Exception as e:
            return "", str(e), -1

    def _run_sync(self, cmd: List[str], timeout: int = None) -> Tuple[str, str, int]:
        timeout = timeout or self.timeout
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Timeout after {timeout}s", -1
        except Exception as e:
            return "", str(e), -1

    async def run_subfinder(self, domain: str, threads: int = 50) -> ToolResult:
        """运行Subfinder子域名枚举"""
        start = time.time()
        if not self.available_tools.get("subfinder"):
            return ToolResult("subfinder", ToolStatus.NOT_FOUND, "", "Not installed", 0)
        
        outfile = self.workspace / f"subfinder_{domain.replace('.','_')}.txt"
        cmd = ["subfinder", "-d", domain, "-o", str(outfile), "-silent", "-t", str(threads)]
        
        stdout, stderr, code = await self._run_async(cmd, 180)
        
        subdomains = []
        if outfile.exists():
            subdomains = [s.strip() for s in outfile.read_text().split('\n') if s.strip()]
        
        return ToolResult(
            "subfinder", ToolStatus.SUCCESS if code == 0 else ToolStatus.FAILED,
            stdout, stderr, time.time() - start,
            {"subdomains": subdomains, "count": len(subdomains)}
        )

    async def run_nmap(self, target: str, ports: str = "top-1000", sV: bool = True) -> ToolResult:
        """运行Nmap端口扫描"""
        start = time.time()
        if not self.available_tools.get("nmap"):
            return ToolResult("nmap", ToolStatus.NOT_FOUND, "", "Not installed", 0)
        
        safe_target = target.replace('.', '_').replace('/', '_')
        xml_file = self.workspace / f"nmap_{safe_target}.xml"
        
        cmd = ["nmap", target, "-oX", str(xml_file), "-T4"]
        
        if ports == "top-100":
            cmd.extend(["--top-ports", "100"])
        elif ports == "top-1000":
            cmd.extend(["--top-ports", "1000"])
        elif ports == "all":
            cmd.append("-p-")
        else:
            cmd.extend(["-p", ports])
        
        if sV:
            cmd.append("-sV")
        
        stdout, stderr, code = await self._run_async(cmd, 600)
        
        parsed = self._parse_nmap_xml(xml_file) if xml_file.exists() else {}
        
        return ToolResult(
            "nmap", ToolStatus.SUCCESS if code == 0 else ToolStatus.FAILED,
            stdout, stderr, time.time() - start, parsed
        )

    def _parse_nmap_xml(self, xml_path: Path) -> Dict:
        """解析Nmap XML输出"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            results = {"hosts": []}
            
            for host in root.findall('.//host'):
                addr = host.find('.//address[@addrtype="ipv4"]')
                ip = addr.get('addr') if addr is not None else "unknown"
                
                host_data = {"ip": ip, "ports": [], "hostname": ""}
                
                hostname = host.find('.//hostname')
                if hostname is not None:
                    host_data["hostname"] = hostname.get('name', '')
                
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        service = port.find('service')
                        port_info = {
                            "port": int(port.get('portid')),
                            "protocol": port.get('protocol'),
                            "service": service.get('name', 'unknown') if service is not None else 'unknown',
                            "version": service.get('version', '') if service is not None else '',
                            "product": service.get('product', '') if service is not None else ''
                        }
                        host_data["ports"].append(port_info)
                
                if host_data["ports"]:
                    results["hosts"].append(host_data)
            
            return results
        except Exception as e:
            logger.error(f"Nmap XML parse error: {e}")
            return {}

    async def run_nuclei(self, targets: List[str], templates: List[str] = None, severity: str = None) -> ToolResult:
        """运行Nuclei漏洞扫描"""
        start = time.time()
        if not self.available_tools.get("nuclei"):
            return ToolResult("nuclei", ToolStatus.NOT_FOUND, "", "Not installed", 0)
        
        target_file = self.workspace / "nuclei_targets.txt"
        target_file.write_text('\n'.join(targets))
        
        json_file = self.workspace / f"nuclei_results_{int(time.time())}.json"
        
        cmd = ["nuclei", "-l", str(target_file), "-jsonl", "-o", str(json_file), "-silent"]
        
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        
        if severity:
            cmd.extend(["-severity", severity])
        
        stdout, stderr, code = await self._run_async(cmd, 900)
        
        findings = []
        if json_file.exists():
            for line in json_file.read_text().split('\n'):
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        
        return ToolResult(
            "nuclei", ToolStatus.SUCCESS if code == 0 else ToolStatus.FAILED,
            stdout, stderr, time.time() - start,
            {"findings": findings, "count": len(findings)}
        )

    async def run_httpx(self, targets: List[str]) -> ToolResult:
        """运行httpx进行HTTP探测"""
        start = time.time()
        if not self.available_tools.get("httpx"):
            return ToolResult("httpx", ToolStatus.NOT_FOUND, "", "Not installed", 0)
        
        target_file = self.workspace / "httpx_targets.txt"
        target_file.write_text('\n'.join(targets))
        
        json_file = self.workspace / "httpx_results.json"
        
        cmd = ["httpx", "-l", str(target_file), "-json", "-o", str(json_file), 
               "-silent", "-status-code", "-title", "-tech-detect"]
        
        stdout, stderr, code = await self._run_async(cmd, 300)
        
        results = []
        if json_file.exists():
            for line in json_file.read_text().split('\n'):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        
        return ToolResult(
            "httpx", ToolStatus.SUCCESS if code == 0 else ToolStatus.FAILED,
            stdout, stderr, time.time() - start,
            {"results": results, "count": len(results)}
        )

    async def run_dnsx(self, subdomains: List[str]) -> ToolResult:
        """运行dnsx进行DNS解析验证"""
        start = time.time()
        if not self.available_tools.get("dnsx"):
            return ToolResult("dnsx", ToolStatus.NOT_FOUND, "", "Not installed", 0)
        
        input_file = self.workspace / "dnsx_input.txt"
        input_file.write_text('\n'.join(subdomains))
        
        output_file = self.workspace / "dnsx_output.json"
        
        cmd = ["dnsx", "-l", str(input_file), "-json", "-o", str(output_file), "-silent", "-a", "-resp"]
        
        stdout, stderr, code = await self._run_async(cmd, 180)
        
        results = []
        if output_file.exists():
            for line in output_file.read_text().split('\n'):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        
        return ToolResult(
            "dnsx", ToolStatus.SUCCESS if code == 0 else ToolStatus.FAILED,
            stdout, stderr, time.time() - start,
            {"results": results, "resolved": len(results)}
        )

    def cleanup(self):
        """清理临时文件"""
        import shutil
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
            self.workspace.mkdir(parents=True, exist_ok=True)
