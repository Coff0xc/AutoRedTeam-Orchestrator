#!/usr/bin/env python3
"""
SSL/TLS安全扫描工具集
"""

import subprocess
import json
import logging
import re
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class SSLScanTool(BaseTool):
    """SSLScan扫描"""
    name: str = "sslscan"
    description: str = "SSLScan - SSL/TLS配置和漏洞扫描"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标主机:端口", required=True),
        ToolParameter("show_certs", "boolean", "显示证书详情", required=False, default=True),
        ToolParameter("no_check_certificate", "boolean", "不验证证书", required=False, default=True),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        show_certs = params.get("show_certs", True)
        no_check = params.get("no_check_certificate", True)
        
        # 确保目标包含端口
        if ":" not in target:
            target = f"{target}:443"
        
        cmd = ["sslscan", "--xml=-"]
        if show_certs:
            cmd.append("--show-certificate")
        if no_check:
            cmd.append("--no-check-certificate")
        cmd.append(target)
        
        try:
            logger.info(f"执行SSLScan: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            parsed = self._parse_output(result.stdout)
            parsed["command"] = ' '.join(cmd)
            parsed["raw_output"] = result.stdout
            
            return parsed
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "sslscan未安装，请运行: apt install sslscan"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """解析SSLScan输出"""
        result = {
            "success": True,
            "protocols": [],
            "ciphers": [],
            "vulnerabilities": [],
            "certificate": {}
        }
        
        lines = output.split('\n')
        section = None
        
        for line in lines:
            line = line.strip()
            
            # 协议检测
            if "SSLv2" in line or "SSLv3" in line or "TLSv" in line:
                if "enabled" in line.lower():
                    proto = re.search(r'(SSLv\d|TLSv\d\.\d)', line)
                    if proto:
                        result["protocols"].append({
                            "version": proto.group(1),
                            "enabled": True
                        })
                        # 不安全协议警告
                        if "SSLv2" in line or "SSLv3" in line:
                            result["vulnerabilities"].append({
                                "name": f"不安全协议: {proto.group(1)}",
                                "severity": "high",
                                "description": f"服务器支持已废弃的{proto.group(1)}协议"
                            })
            
            # 漏洞检测
            if "Heartbleed" in line and "vulnerable" in line.lower():
                result["vulnerabilities"].append({
                    "name": "Heartbleed (CVE-2014-0160)",
                    "severity": "critical",
                    "description": "服务器存在Heartbleed漏洞"
                })
            
            if "POODLE" in line and "vulnerable" in line.lower():
                result["vulnerabilities"].append({
                    "name": "POODLE Attack",
                    "severity": "high",
                    "description": "服务器存在POODLE漏洞"
                })
            
            # 弱密码套件
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "EXPORT", "NULL"]
            for weak in weak_ciphers:
                if weak in line and ("Accepted" in line or "enabled" in line.lower()):
                    result["ciphers"].append({
                        "cipher": line,
                        "weak": True
                    })
                    break
            else:
                if "Accepted" in line:
                    result["ciphers"].append({
                        "cipher": line,
                        "weak": False
                    })
        
        return result


@dataclass
class TestSSLTool(BaseTool):
    """TestSSL.sh扫描"""
    name: str = "testssl"
    description: str = "testssl.sh - 全面的SSL/TLS测试工具"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标主机:端口", required=True),
        ToolParameter("protocols", "boolean", "检测协议", required=False, default=True),
        ToolParameter("vulns", "boolean", "检测漏洞", required=False, default=True),
        ToolParameter("severity", "string", "严重性过滤", required=False, default="",
                     choices=["", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    ])
    timeout: int = 600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        protocols = params.get("protocols", True)
        vulns = params.get("vulns", True)
        severity = params.get("severity", "")
        
        if ":" not in target:
            target = f"{target}:443"
        
        cmd = ["testssl.sh", "--jsonfile=-", "--quiet"]
        
        if protocols:
            cmd.append("-p")
        if vulns:
            cmd.append("-U")  # 检测所有漏洞
        if severity:
            cmd.extend(["--severity", severity])
        
        cmd.append(target)
        
        try:
            logger.info(f"执行testssl: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            findings = []
            try:
                data = json.loads(result.stdout)
                for item in data:
                    findings.append({
                        "id": item.get("id"),
                        "severity": item.get("severity"),
                        "finding": item.get("finding"),
                        "cve": item.get("cve"),
                        "cwe": item.get("cwe")
                    })
            except json.JSONDecodeError:
                # 解析文本输出
                findings = self._parse_text(result.stdout)
            
            return {
                "success": True,
                "target": target,
                "findings": findings,
                "total_findings": len(findings),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "testssl.sh未安装，请运行: apt install testssl.sh"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_text(self, output: str) -> List[Dict[str, Any]]:
        """解析testssl文本输出"""
        findings = []
        
        vuln_patterns = [
            (r"(Heartbleed.*vulnerable)", "critical", "CVE-2014-0160"),
            (r"(CCS.*vulnerable)", "high", "CVE-2014-0224"),
            (r"(ROBOT.*vulnerable)", "high", ""),
            (r"(CRIME.*vulnerable)", "medium", "CVE-2012-4929"),
            (r"(BREACH.*vulnerable)", "medium", "CVE-2013-3587"),
            (r"(POODLE.*vulnerable)", "high", "CVE-2014-3566"),
            (r"(DROWN.*vulnerable)", "critical", "CVE-2016-0800"),
            (r"(LOGJAM.*vulnerable)", "high", "CVE-2015-4000"),
            (r"(BEAST.*vulnerable)", "medium", "CVE-2011-3389"),
            (r"(LUCKY13.*vulnerable)", "medium", "CVE-2013-0169"),
            (r"(RC4.*vulnerable)", "medium", "CVE-2013-2566"),
        ]
        
        for line in output.split('\n'):
            for pattern, severity, cve in vuln_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "finding": line.strip(),
                        "severity": severity,
                        "cve": cve
                    })
        
        return findings
