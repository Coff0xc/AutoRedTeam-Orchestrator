#!/usr/bin/env python3
"""
子域名枚举工具集
"""

import subprocess
import json
import logging
import tempfile
import os
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class SubfinderTool(BaseTool):
    """Subfinder子域名枚举"""
    name: str = "subfinder"
    description: str = "Subfinder - 快速被动子域名枚举工具"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("domain", "string", "目标域名", required=True),
        ToolParameter("recursive", "boolean", "是否递归枚举", required=False, default=False),
        ToolParameter("timeout", "integer", "超时时间(秒)", required=False, default=30),
    ])
    timeout: int = 300
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        domain = params["domain"]
        recursive = params.get("recursive", False)
        timeout_val = params.get("timeout", 30)
        
        cmd = ["subfinder", "-d", domain, "-silent", "-json"]
        if recursive:
            cmd.append("-recursive")
        cmd.extend(["-timeout", str(timeout_val)])
        
        try:
            logger.info(f"执行Subfinder: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        subdomains.append({
                            "host": data.get("host"),
                            "source": data.get("source")
                        })
                    except json.JSONDecodeError:
                        # 非JSON输出，直接作为子域名
                        subdomains.append({"host": line, "source": "unknown"})
            
            return {
                "success": True,
                "domain": domain,
                "subdomains": subdomains,
                "count": len(subdomains),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "枚举超时"}
        except FileNotFoundError:
            return {"success": False, "error": "subfinder未安装，请运行: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class AmassEnumTool(BaseTool):
    """Amass子域名枚举"""
    name: str = "amass_enum"
    description: str = "Amass - 深度子域名枚举和网络映射"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("domain", "string", "目标域名", required=True),
        ToolParameter("passive", "boolean", "仅被动枚举", required=False, default=True),
        ToolParameter("timeout", "integer", "超时时间(分钟)", required=False, default=5),
    ])
    timeout: int = 600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        domain = params["domain"]
        passive = params.get("passive", True)
        timeout_min = params.get("timeout", 5)
        
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            cmd = ["amass", "enum", "-d", domain, "-o", output_file]
            if passive:
                cmd.append("-passive")
            cmd.extend(["-timeout", str(timeout_min)])
            
            logger.info(f"执行Amass: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            subdomains = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            
            return {
                "success": True,
                "domain": domain,
                "subdomains": subdomains,
                "count": len(subdomains),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "枚举超时"}
        except FileNotFoundError:
            return {"success": False, "error": "amass未安装，请运行: apt install amass"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)


@dataclass 
class AssetfinderTool(BaseTool):
    """Assetfinder子域名查找"""
    name: str = "assetfinder"
    description: str = "Assetfinder - 快速查找相关域名和子域名"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("domain", "string", "目标域名", required=True),
        ToolParameter("subs_only", "boolean", "仅返回子域名", required=False, default=True),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        domain = params["domain"]
        subs_only = params.get("subs_only", True)
        
        cmd = ["assetfinder"]
        if subs_only:
            cmd.append("--subs-only")
        cmd.append(domain)
        
        try:
            logger.info(f"执行Assetfinder: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            subdomains = list(set([
                line.strip() 
                for line in result.stdout.strip().split('\n') 
                if line.strip()
            ]))
            
            return {
                "success": True,
                "domain": domain,
                "subdomains": subdomains,
                "count": len(subdomains),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "查找超时"}
        except FileNotFoundError:
            return {"success": False, "error": "assetfinder未安装，请运行: go install github.com/tomnomnom/assetfinder@latest"}
        except Exception as e:
            return {"success": False, "error": str(e)}
