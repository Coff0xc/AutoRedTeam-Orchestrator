#!/usr/bin/env python3
"""
Nikto Web漏洞扫描工具
"""

import subprocess
import json
import logging
import tempfile
import os
import re
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class NiktoScanTool(BaseTool):
    """Nikto Web扫描"""
    name: str = "nikto_scan"
    description: str = "Nikto - 全面的Web服务器扫描器"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标URL或IP", required=True),
        ToolParameter("port", "integer", "目标端口", required=False, default=80),
        ToolParameter("ssl", "boolean", "使用SSL", required=False, default=False),
        ToolParameter("tuning", "string", "扫描调优选项", required=False, default="",
                     choices=["", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "a", "b", "c", "x"]),
        ToolParameter("timeout", "integer", "连接超时(秒)", required=False, default=10),
    ])
    timeout: int = 1800
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        port = params.get("port", 80)
        ssl = params.get("ssl", False)
        tuning = params.get("tuning", "")
        timeout_val = params.get("timeout", 10)
        
        # 清理目标URL
        if target.startswith(("http://", "https://")):
            target = re.sub(r'^https?://', '', target)
            target = target.split('/')[0]
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        
        cmd = [
            "nikto", "-h", target, "-p", str(port),
            "-Format", "json", "-output", output_file,
            "-Timeout", str(timeout_val)
        ]
        
        if ssl or port == 443:
            cmd.append("-ssl")
        if tuning:
            cmd.extend(["-Tuning", tuning])
        
        try:
            logger.info(f"执行Nikto: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            findings = []
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        
                    if isinstance(data, dict):
                        host_data = data
                    elif isinstance(data, list) and len(data) > 0:
                        host_data = data[0]
                    else:
                        host_data = {}
                    
                    vulnerabilities = host_data.get("vulnerabilities", [])
                    for vuln in vulnerabilities:
                        findings.append({
                            "id": vuln.get("id"),
                            "osvdb": vuln.get("OSVDB"),
                            "method": vuln.get("method"),
                            "url": vuln.get("url"),
                            "message": vuln.get("msg"),
                            "references": vuln.get("references", "")
                        })
                        
                except json.JSONDecodeError:
                    # 解析原始输出
                    findings = self._parse_text_output(result.stdout)
            else:
                findings = self._parse_text_output(result.stdout)
            
            return {
                "success": True,
                "target": target,
                "port": port,
                "ssl": ssl,
                "findings": findings,
                "total_findings": len(findings),
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "nikto未安装，请运行: apt install nikto"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def _parse_text_output(self, output: str) -> List[Dict[str, Any]]:
        """解析Nikto文本输出"""
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('+'):
                # 移除开头的 + 符号
                content = line[1:].strip()
                
                # 尝试提取OSVDB ID
                osvdb_match = re.search(r'OSVDB-(\d+)', content)
                osvdb = osvdb_match.group(1) if osvdb_match else None
                
                # 提取URL
                url_match = re.search(r'(/[^\s:]+)', content)
                url = url_match.group(1) if url_match else None
                
                findings.append({
                    "message": content,
                    "osvdb": osvdb,
                    "url": url
                })
        
        return findings


@dataclass
class ZAPScanTool(BaseTool):
    """OWASP ZAP扫描"""
    name: str = "zap_scan"
    description: str = "OWASP ZAP - 自动化Web应用安全扫描"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标URL", required=True),
        ToolParameter("scan_type", "string", "扫描类型", required=False, default="baseline",
                     choices=["baseline", "full", "api"]),
        ToolParameter("ajax_spider", "boolean", "使用AJAX爬虫", required=False, default=False),
    ])
    timeout: int = 3600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        scan_type = params.get("scan_type", "baseline")
        ajax_spider = params.get("ajax_spider", False)
        
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            report_file = tmp.name
        
        # ZAP Docker命令
        if scan_type == "baseline":
            script = "zap-baseline.py"
        elif scan_type == "full":
            script = "zap-full-scan.py"
        else:
            script = "zap-api-scan.py"
        
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.path.dirname(report_file)}:/zap/wrk:rw",
            "ghcr.io/zaproxy/zaproxy:stable",
            script, "-t", target,
            "-J", os.path.basename(report_file)
        ]
        
        if ajax_spider:
            cmd.append("-j")
        
        try:
            logger.info(f"执行ZAP: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            alerts = []
            if os.path.exists(report_file):
                try:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                    
                    for site in data.get("site", []):
                        for alert in site.get("alerts", []):
                            alerts.append({
                                "name": alert.get("name"),
                                "risk": alert.get("riskdesc"),
                                "confidence": alert.get("confidence"),
                                "description": alert.get("desc"),
                                "solution": alert.get("solution"),
                                "reference": alert.get("reference"),
                                "count": alert.get("count"),
                                "instances": alert.get("instances", [])[:5]  # 限制实例数
                            })
                except json.JSONDecodeError:
                    pass
            
            return {
                "success": True,
                "target": target,
                "scan_type": scan_type,
                "alerts": alerts,
                "total_alerts": len(alerts),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "Docker未安装或ZAP镜像未拉取"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if os.path.exists(report_file):
                os.unlink(report_file)
