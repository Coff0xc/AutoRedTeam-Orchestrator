#!/usr/bin/env python3
"""
Nuclei漏洞扫描工具集
"""

import subprocess
import json
import logging
import tempfile
import os
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter
from utils.terminal_output import run_with_realtime_output

logger = logging.getLogger(__name__)


@dataclass
class NucleiScanTool(BaseTool):
    """Nuclei漏洞扫描"""
    name: str = "nuclei_scan"
    description: str = "Nuclei - 快速可定制的漏洞扫描器"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标URL或IP", required=True),
        ToolParameter("severity", "string", "漏洞严重性过滤", required=False, default="",
                     choices=["", "info", "low", "medium", "high", "critical"]),
        ToolParameter("tags", "string", "模板标签过滤(逗号分隔)", required=False, default=""),
        ToolParameter("rate_limit", "integer", "请求速率限制", required=False, default=150),
        ToolParameter("timeout", "integer", "超时时间(秒)", required=False, default=10),
    ])
    timeout: int = 1800  # 30分钟
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        severity = params.get("severity", "")
        tags = params.get("tags", "")
        rate_limit = params.get("rate_limit", 150)
        timeout_val = params.get("timeout", 10)
        
        # 创建临时文件保存JSON结果
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            json_output = tmp.name
            
        cmd = [
            "nuclei", "-u", target, 
            "-silent", # 保持静默，只输出发现的结果
            "-je", json_output, # 导出JSON结果到文件
            "-rate-limit", str(rate_limit),
            "-timeout", str(timeout_val)
        ]
        
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
        
        try:
            # 使用实时输出运行器
            # 注意：这里不需要 -json，因为我们希望 stdout 是人类可读的（虽然 -silent 会抑制大部分非结果输出）
            # 如果想要看到扫描进度，可以去掉 -silent，但 Nuclei 的进度条可能会弄乱日志
            # 建议：保持 -silent，Nuclei 只有在发现漏洞时才会有输出，这正是我们想要的
            
            result = run_with_realtime_output(
                cmd, 
                tool_name=self.name, 
                target=target, 
                timeout=self.timeout
            )
            
            # 解析JSON输出文件
            vulnerabilities = []
            if os.path.exists(json_output):
                try:
                    # Nuclei 的 -je 输出是一个 JSON 数组还是多个 JSON 对象？
                    # 通常是多个 JSON 对象，每行一个，或者是一个大数组
                    # 检查文件内容
                    with open(json_output, 'r') as f:
                        content = f.read()
                        if content.strip():
                            # 尝试作为整个JSON数组解析
                            try:
                                data = json.loads(content)
                                if isinstance(data, list):
                                    for vuln in data:
                                        vulnerabilities.append(self._parse_vuln_item(vuln))
                            except:
                                # 尝试逐行解析
                                for line in content.split('\n'):
                                    if line.strip():
                                        try:
                                            vuln = json.loads(line)
                                            vulnerabilities.append(self._parse_vuln_item(vuln))
                                        except:
                                            pass
                except Exception as e:
                    logger.error(f"解析Nuclei JSON失败: {e}")
            
            # 按严重性排序
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 5))
            
            return {
                "success": True,
                "target": target,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "by_severity": self._count_by_severity(vulnerabilities),
                "command": ' '.join(cmd)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if os.path.exists(json_output):
                os.unlink(json_output)

    def _parse_vuln_item(self, vuln: Dict) -> Dict:
        """解析单个漏洞条目"""
        return {
            "template_id": vuln.get("template-id"),
            "template_name": vuln.get("info", {}).get("name"),
            "severity": vuln.get("info", {}).get("severity"),
            "type": vuln.get("type"),
            "host": vuln.get("host"),
            "matched_at": vuln.get("matched-at"),
            "description": vuln.get("info", {}).get("description"),
            "tags": vuln.get("info", {}).get("tags", []),
            "reference": vuln.get("info", {}).get("reference", []),
            "extracted_results": vuln.get("extracted-results", []),
            "curl_command": vuln.get("curl-command"),
            "matcher_name": vuln.get("matcher-name")
        }
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """按严重性统计"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
        return counts


@dataclass
class NucleiTemplateScanTool(BaseTool):
    """Nuclei模板扫描"""
    name: str = "nuclei_template"
    description: str = "Nuclei模板扫描 - 使用特定漏洞模板扫描"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标URL或IP", required=True),
        ToolParameter("template_type", "string", "模板类型", required=True,
                     choices=["cves", "vulnerabilities", "exposures", "misconfiguration", 
                             "takeovers", "default-logins", "file", "fuzzing"]),
        ToolParameter("year", "string", "CVE年份过滤(仅cves类型)", required=False, default=""),
    ])
    timeout: int = 1200
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        template_type = params["template_type"]
        year = params.get("year", "")
        
        # 构建模板路径
        template_path = template_type
        if template_type == "cves" and year:
            template_path = f"cves/{year}"
        
        cmd = [
            "nuclei", "-u", target,
            "-t", template_path,
            "-json", "-silent"
        ]
        
        try:
            logger.info(f"执行Nuclei模板扫描: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            vulnerabilities = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append({
                            "template_id": vuln.get("template-id"),
                            "name": vuln.get("info", {}).get("name"),
                            "severity": vuln.get("info", {}).get("severity"),
                            "host": vuln.get("host"),
                            "matched_at": vuln.get("matched-at"),
                            "description": vuln.get("info", {}).get("description"),
                            "reference": vuln.get("info", {}).get("reference", [])
                        })
                    except json.JSONDecodeError:
                        pass
            
            return {
                "success": True,
                "target": target,
                "template_type": template_type,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "nuclei未安装"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class NucleiWorkflowTool(BaseTool):
    """Nuclei工作流扫描"""
    name: str = "nuclei_workflow"
    description: str = "Nuclei工作流 - 执行预定义的扫描工作流"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标URL或IP", required=True),
        ToolParameter("workflow", "string", "工作流名称", required=True,
                     choices=["wordpress", "joomla", "drupal", "magento", 
                             "springboot", "apache", "nginx", "iis"]),
    ])
    timeout: int = 1800
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        workflow = params["workflow"]
        
        # 工作流到模板标签映射
        workflow_tags = {
            "wordpress": "wordpress",
            "joomla": "joomla", 
            "drupal": "drupal",
            "magento": "magento",
            "springboot": "springboot",
            "apache": "apache",
            "nginx": "nginx",
            "iis": "iis"
        }
        
        tags = workflow_tags.get(workflow, workflow)
        
        cmd = [
            "nuclei", "-u", target,
            "-tags", tags,
            "-json", "-silent",
            "-severity", "low,medium,high,critical"
        ]
        
        try:
            logger.info(f"执行Nuclei工作流: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            vulnerabilities = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append({
                            "template_id": vuln.get("template-id"),
                            "name": vuln.get("info", {}).get("name"),
                            "severity": vuln.get("info", {}).get("severity"),
                            "matched_at": vuln.get("matched-at"),
                        })
                    except json.JSONDecodeError:
                        pass
            
            return {
                "success": True,
                "target": target,
                "workflow": workflow,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "command": ' '.join(cmd)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
