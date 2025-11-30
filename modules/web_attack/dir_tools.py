#!/usr/bin/env python3
"""
目录和文件扫描工具集
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
class DirbTool(BaseTool):
    """Dirb目录扫描"""
    name: str = "dirb"
    description: str = "Dirb - Web目录暴力扫描工具"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("wordlist", "string", "字典文件路径", required=False, 
                     default="/usr/share/wordlists/dirb/common.txt"),
        ToolParameter("extensions", "string", "文件扩展名(逗号分隔)", required=False, default=""),
        ToolParameter("cookie", "string", "Cookie", required=False, default=""),
        ToolParameter("user_agent", "string", "User-Agent", required=False, default=""),
        ToolParameter("ignore_code", "string", "忽略状态码", required=False, default=""),
    ])
    timeout: int = 1800
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = params.get("extensions", "")
        cookie = params.get("cookie", "")
        user_agent = params.get("user_agent", "")
        ignore_code = params.get("ignore_code", "")
        
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        
        cmd = ["dirb", url, wordlist, "-S"]  # -S: 静默模式
        
        if extensions:
            cmd.extend(["-X", f".{extensions.replace(',', ',.')}"])
        if cookie:
            cmd.extend(["-c", cookie])
        if user_agent:
            cmd.extend(["-a", user_agent])
        if ignore_code:
            cmd.extend(["-N", ignore_code])
        
        try:
            logger.info(f"执行Dirb: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            findings = self._parse_output(result.stdout)
            
            return {
                "success": True,
                "url": url,
                "wordlist": wordlist,
                "findings": findings,
                "total_found": len(findings),
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "dirb未安装，请运行: apt install dirb"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        """解析Dirb输出"""
        findings = []
        
        # 匹配URL和状态码
        pattern = r"\+\s*(https?://[^\s]+)\s*\(CODE:(\d+)\|SIZE:(\d+)\)"
        
        for match in re.finditer(pattern, output):
            findings.append({
                "url": match.group(1),
                "status_code": int(match.group(2)),
                "size": int(match.group(3))
            })
        
        return findings


@dataclass
class GobusterTool(BaseTool):
    """Gobuster目录扫描"""
    name: str = "gobuster"
    description: str = "Gobuster - 快速目录/DNS/VHost暴力扫描"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("wordlist", "string", "字典文件", required=False,
                     default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
        ToolParameter("mode", "string", "扫描模式", required=False, default="dir",
                     choices=["dir", "dns", "vhost", "fuzz"]),
        ToolParameter("extensions", "string", "文件扩展名", required=False, default=""),
        ToolParameter("threads", "integer", "线程数", required=False, default=10),
        ToolParameter("status_codes", "string", "显示的状态码", required=False, default="200,204,301,302,307,401,403"),
        ToolParameter("exclude_length", "string", "排除的响应长度", required=False, default=""),
    ])
    timeout: int = 1800
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
        mode = params.get("mode", "dir")
        extensions = params.get("extensions", "")
        threads = params.get("threads", 10)
        status_codes = params.get("status_codes", "200,204,301,302,307,401,403")
        exclude_length = params.get("exclude_length", "")
        
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        
        cmd = [
            "gobuster", mode,
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-q",  # 安静模式
            "-o", "-"  # 输出到stdout
        ]
        
        if mode == "dir":
            cmd.extend(["-s", status_codes])
            if extensions:
                cmd.extend(["-x", extensions])
            if exclude_length:
                cmd.extend(["--exclude-length", exclude_length])
        
        try:
            logger.info(f"执行Gobuster: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            findings = self._parse_output(result.stdout, mode)
            
            return {
                "success": True,
                "url": url,
                "mode": mode,
                "findings": findings,
                "total_found": len(findings),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "gobuster未安装，请运行: apt install gobuster"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str, mode: str) -> List[Dict[str, Any]]:
        """解析Gobuster输出"""
        findings = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            if mode == "dir":
                # 格式: /path (Status: 200) [Size: 1234]
                pattern = r"(/[^\s]*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]"
                match = re.search(pattern, line)
                if match:
                    findings.append({
                        "path": match.group(1),
                        "status_code": int(match.group(2)),
                        "size": int(match.group(3))
                    })
            elif mode == "dns":
                # 格式: Found: subdomain.example.com
                if "Found:" in line:
                    findings.append({"subdomain": line.split("Found:")[-1].strip()})
            elif mode == "vhost":
                # 格式: Found: vhost.example.com (Status: 200)
                pattern = r"Found:\s*(\S+)"
                match = re.search(pattern, line)
                if match:
                    findings.append({"vhost": match.group(1)})
        
        return findings


@dataclass
class FeroxbusterTool(BaseTool):
    """Feroxbuster递归目录扫描"""
    name: str = "feroxbuster"
    description: str = "Feroxbuster - 快速递归内容发现工具"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("wordlist", "string", "字典文件", required=False,
                     default="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"),
        ToolParameter("extensions", "string", "文件扩展名", required=False, default=""),
        ToolParameter("threads", "integer", "线程数", required=False, default=50),
        ToolParameter("depth", "integer", "递归深度", required=False, default=2),
        ToolParameter("status_codes", "string", "过滤状态码", required=False, default=""),
        ToolParameter("filter_size", "string", "过滤响应大小", required=False, default=""),
    ])
    timeout: int = 3600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
        extensions = params.get("extensions", "")
        threads = params.get("threads", 50)
        depth = params.get("depth", 2)
        status_codes = params.get("status_codes", "")
        filter_size = params.get("filter_size", "")
        
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        
        cmd = [
            "feroxbuster",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-d", str(depth),
            "-q",  # 安静模式
            "--json"
        ]
        
        if extensions:
            cmd.extend(["-x", extensions])
        if status_codes:
            cmd.extend(["-s", status_codes])
        if filter_size:
            cmd.extend(["-S", filter_size])
        
        try:
            logger.info(f"执行Feroxbuster: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            findings = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if data.get("type") == "response":
                            findings.append({
                                "url": data.get("url"),
                                "status_code": data.get("status"),
                                "size": data.get("content_length"),
                                "lines": data.get("line_count"),
                                "words": data.get("word_count")
                            })
                    except json.JSONDecodeError:
                        pass
            
            return {
                "success": True,
                "url": url,
                "findings": findings,
                "total_found": len(findings),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "feroxbuster未安装，请运行: apt install feroxbuster"}
        except Exception as e:
            return {"success": False, "error": str(e)}
