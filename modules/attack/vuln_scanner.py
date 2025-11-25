"""
Vulnerability Scanner - 漏洞扫描模块
基于Nuclei的智能漏洞扫描
"""

import asyncio
import json
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    template_id: str
    name: str
    severity: Severity
    host: str
    matched_at: str
    description: str = ""
    reference: List[str] = None
    extracted_results: List[str] = None
    curl_command: str = ""
    raw_data: Dict = None
    
    def __post_init__(self):
        if self.reference is None:
            self.reference = []
        if self.extracted_results is None:
            self.extracted_results = []
        if self.raw_data is None:
            self.raw_data = {}


class VulnScanner:
    """
    漏洞扫描器
    基于Nuclei的目标化漏洞检测
    """
    
    # 服务类型到模板的映射
    SERVICE_TEMPLATES = {
        "web": ["cves", "vulnerabilities", "exposures", "misconfigurations", "default-logins"],
        "mysql": ["mysql", "cves"],
        "redis": ["redis", "cves"],
        "ssh": ["ssh", "default-logins"],
        "ftp": ["ftp", "default-logins"],
        "smb": ["smb", "cves"],
        "mongodb": ["mongodb"],
        "elasticsearch": ["elasticsearch"],
    }
    
    def __init__(self, workspace: str = "/tmp/attack"):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.findings: List[Finding] = []
    
    async def scan(self, targets: List[str], templates: List[str] = None,
                   severity: str = "critical,high,medium", 
                   rate_limit: int = 150, timeout: int = 900) -> List[Finding]:
        """
        执行Nuclei漏洞扫描
        
        Args:
            targets: 目标URL列表
            templates: 模板标签列表
            severity: 严重程度过滤
            rate_limit: 速率限制
            timeout: 超时时间
        """
        if not targets:
            return []
        
        # 写入目标文件
        target_file = self.workspace / "targets.txt"
        target_file.write_text('\n'.join(targets))
        
        output_file = self.workspace / f"nuclei_output_{int(asyncio.get_event_loop().time())}.jsonl"
        
        cmd = [
            "nuclei",
            "-l", str(target_file),
            "-jsonl",
            "-o", str(output_file),
            "-silent",
            "-severity", severity,
            "-rl", str(rate_limit),
            "-c", "50"  # 并发数
        ]
        
        # 添加模板
        if templates:
            for t in templates:
                cmd.extend(["-tags", t])
        
        logger.info(f"Running Nuclei scan on {len(targets)} targets")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            findings = self._parse_results(output_file)
            self.findings.extend(findings)
            
            logger.info(f"Nuclei scan complete: {len(findings)} findings")
            return findings
            
        except asyncio.TimeoutError:
            logger.error("Nuclei scan timeout")
            return []
        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            return []

    def _parse_results(self, output_file: Path) -> List[Finding]:
        """解析Nuclei JSONL输出"""
        findings = []
        
        if not output_file.exists():
            return findings
        
        for line in output_file.read_text().split('\n'):
            if not line.strip():
                continue
            
            try:
                data = json.loads(line)
                
                severity_str = data.get("info", {}).get("severity", "info")
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.INFO
                
                finding = Finding(
                    template_id=data.get("template-id", "unknown"),
                    name=data.get("info", {}).get("name", "Unknown"),
                    severity=severity,
                    host=data.get("host", ""),
                    matched_at=data.get("matched-at", ""),
                    description=data.get("info", {}).get("description", ""),
                    reference=data.get("info", {}).get("reference", []),
                    extracted_results=data.get("extracted-results", []),
                    curl_command=data.get("curl-command", ""),
                    raw_data=data
                )
                findings.append(finding)
                
            except json.JSONDecodeError:
                continue
        
        return findings

    async def scan_web(self, urls: List[str]) -> List[Finding]:
        """Web漏洞专项扫描"""
        return await self.scan(
            urls,
            templates=self.SERVICE_TEMPLATES["web"],
            severity="critical,high,medium"
        )

    async def scan_service(self, targets: List[str], service_type: str) -> List[Finding]:
        """服务漏洞专项扫描"""
        templates = self.SERVICE_TEMPLATES.get(service_type, ["cves"])
        return await self.scan(targets, templates=templates)

    async def scan_cves(self, targets: List[str], year: int = None) -> List[Finding]:
        """CVE漏洞扫描"""
        templates = ["cve"]
        if year:
            templates = [f"cve-{year}"]
        
        return await self.scan(targets, templates=templates, severity="critical,high")

    def get_critical_findings(self) -> List[Finding]:
        """获取严重漏洞"""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def get_findings_by_host(self, host: str) -> List[Finding]:
        """按主机获取漏洞"""
        return [f for f in self.findings if host in f.host]

    def get_statistics(self) -> Dict[str, int]:
        """获取漏洞统计"""
        stats = {s.value: 0 for s in Severity}
        for finding in self.findings:
            stats[finding.severity.value] += 1
        return stats

    def export_findings(self, output_file: str, format: str = "json"):
        """导出漏洞发现"""
        data = [
            {
                "id": f.template_id,
                "name": f.name,
                "severity": f.severity.value,
                "host": f.host,
                "matched_at": f.matched_at,
                "description": f.description,
                "reference": f.reference,
                "curl_command": f.curl_command
            }
            for f in self.findings
        ]
        
        if format == "json":
            Path(output_file).write_text(json.dumps(data, indent=2, ensure_ascii=False))
        elif format == "csv":
            import csv
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys() if data else [])
                writer.writeheader()
                writer.writerows(data)
