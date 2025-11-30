#!/usr/bin/env python3
"""
Web侦察工具集
"""

import subprocess
import json
import logging
import re
from typing import Any, Dict, List
from dataclasses import dataclass, field

import requests

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class WhatWebTool(BaseTool):
    """WhatWeb技术识别"""
    name: str = "whatweb"
    description: str = "WhatWeb - 识别Web技术栈和框架"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标URL", required=True),
        ToolParameter("aggression", "integer", "扫描强度(1-4)", required=False, default=1),
        ToolParameter("verbose", "boolean", "详细输出", required=False, default=False),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        aggression = params.get("aggression", 1)
        verbose = params.get("verbose", False)
        
        # 确保URL有协议
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        cmd = ["whatweb", "-a", str(aggression), "--color=never"]
        if verbose:
            cmd.append("-v")
        cmd.extend(["--log-json=-", target])
        
        try:
            logger.info(f"执行WhatWeb: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析JSON输出
            technologies = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict) and "plugins" in data:
                            for plugin_name, plugin_data in data["plugins"].items():
                                tech = {"name": plugin_name}
                                if isinstance(plugin_data, dict):
                                    if "version" in plugin_data:
                                        tech["version"] = plugin_data["version"]
                                    if "string" in plugin_data:
                                        tech["details"] = plugin_data["string"]
                                technologies.append(tech)
                    except json.JSONDecodeError:
                        pass
            
            return {
                "success": True,
                "target": target,
                "technologies": technologies,
                "count": len(technologies),
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "whatweb未安装，请运行: apt install whatweb"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class WapalyzerTool(BaseTool):
    """Wappalyzer技术识别"""
    name: str = "wappalyzer"
    description: str = "Wappalyzer - 识别网站使用的技术"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        
        # 尝试使用wappalyzer-cli
        try:
            cmd = ["wappalyzer", url, "--pretty"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    return {
                        "success": True,
                        "url": url,
                        "technologies": data.get("technologies", []),
                        "command": ' '.join(cmd)
                    }
                except json.JSONDecodeError:
                    pass
                    
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # 回退到简单HTTP分析
        return self._simple_analysis(url)
    
    def _simple_analysis(self, url: str) -> Dict[str, Any]:
        """简单的技术分析"""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            technologies = []
            
            # 从响应头分析
            server = response.headers.get("Server", "")
            if server:
                technologies.append({"name": "Server", "value": server})
            
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                technologies.append({"name": "X-Powered-By", "value": powered_by})
            
            # 从内容分析
            content = response.text.lower()
            
            tech_patterns = {
                "WordPress": [r"wp-content", r"wp-includes"],
                "Drupal": [r"drupal", r"sites/default"],
                "Joomla": [r"joomla", r"/components/"],
                "Laravel": [r"laravel"],
                "Django": [r"csrfmiddlewaretoken"],
                "React": [r"react", r"__react"],
                "Vue.js": [r"vue", r"__vue__"],
                "Angular": [r"ng-", r"angular"],
                "jQuery": [r"jquery"],
                "Bootstrap": [r"bootstrap"],
                "PHP": [r"\.php", r"phpsessid"],
                "ASP.NET": [r"asp\.net", r"__viewstate"],
                "Node.js": [r"express"],
                "Nginx": [r"nginx"],
                "Apache": [r"apache"],
            }
            
            for tech, patterns in tech_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content):
                        if not any(t["name"] == tech for t in technologies):
                            technologies.append({"name": tech, "detected_by": "content_pattern"})
                        break
            
            return {
                "success": True,
                "url": url,
                "technologies": technologies,
                "response_headers": dict(response.headers),
                "status_code": response.status_code,
                "note": "简单分析模式，完整分析请安装wappalyzer"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class WafDetectTool(BaseTool):
    """WAF检测"""
    name: str = "wafw00f"
    description: str = "WAF检测 - 识别Web应用防火墙"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标URL", required=True),
        ToolParameter("find_all", "boolean", "查找所有WAF", required=False, default=False),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        find_all = params.get("find_all", False)
        
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        
        cmd = ["wafw00f", target]
        if find_all:
            cmd.append("-a")
        
        try:
            logger.info(f"执行wafw00f: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            output = result.stdout
            detected_waf = []
            
            # 查找检测到的WAF
            for line in output.split('\n'):
                if "is behind" in line.lower():
                    # 提取WAF名称
                    match = re.search(r'is behind\s+(.+?)(?:\s+WAF|\s*$)', line, re.IGNORECASE)
                    if match:
                        detected_waf.append(match.group(1).strip())
                elif "No WAF" in line:
                    detected_waf = []
                    break
            
            return {
                "success": True,
                "target": target,
                "waf_detected": len(detected_waf) > 0,
                "waf_names": detected_waf,
                "raw_output": output,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "检测超时"}
        except FileNotFoundError:
            return {"success": False, "error": "wafw00f未安装，请运行: apt install wafw00f 或 pip install wafw00f"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class HttpxProbeTool(BaseTool):
    """Httpx探测"""
    name: str = "httpx_probe"
    description: str = "Httpx - HTTP探测和信息收集"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("targets", "string", "目标URL列表(逗号分隔)", required=True),
        ToolParameter("ports", "string", "端口列表", required=False, default="80,443,8080,8443"),
        ToolParameter("title", "boolean", "获取页面标题", required=False, default=True),
        ToolParameter("status_code", "boolean", "获取状态码", required=False, default=True),
        ToolParameter("tech_detect", "boolean", "技术检测", required=False, default=True),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        targets = params["targets"].split(",")
        ports = params.get("ports", "80,443,8080,8443")
        title = params.get("title", True)
        status_code = params.get("status_code", True)
        tech_detect = params.get("tech_detect", True)
        
        target_input = "\n".join([t.strip() for t in targets])
        
        cmd = ["httpx", "-silent", "-json", "-p", ports]
        if title:
            cmd.append("-title")
        if status_code:
            cmd.append("-status-code")
        if tech_detect:
            cmd.append("-tech-detect")
        
        try:
            logger.info(f"执行httpx: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                input=target_input,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            results = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        results.append({
                            "url": data.get("url"),
                            "status_code": data.get("status_code"),
                            "title": data.get("title"),
                            "technologies": data.get("tech", []),
                            "content_length": data.get("content_length"),
                            "webserver": data.get("webserver"),
                            "host": data.get("host"),
                            "port": data.get("port")
                        })
                    except json.JSONDecodeError:
                        pass
            
            return {
                "success": True,
                "targets": targets,
                "results": results,
                "alive_count": len(results),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "探测超时"}
        except FileNotFoundError:
            return {"success": False, "error": "httpx未安装，请运行: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"}
        except Exception as e:
            return {"success": False, "error": str(e)}
