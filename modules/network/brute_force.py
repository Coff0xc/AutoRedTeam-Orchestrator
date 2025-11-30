#!/usr/bin/env python3
"""
密码暴力破解工具集
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
class HydraTool(BaseTool):
    """Hydra密码爆破"""
    name: str = "hydra"
    description: str = "Hydra - 网络服务密码暴力破解工具"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP或主机名", required=True),
        ToolParameter("service", "string", "目标服务", required=True,
                     choices=["ssh", "ftp", "telnet", "mysql", "mssql", "postgres", 
                             "rdp", "smb", "vnc", "http-get", "http-post-form", 
                             "smtp", "pop3", "imap", "ldap"]),
        ToolParameter("port", "integer", "目标端口(可选)", required=False, default=0),
        ToolParameter("username", "string", "用户名", required=False, default=""),
        ToolParameter("username_list", "string", "用户名字典", required=False, default=""),
        ToolParameter("password", "string", "密码", required=False, default=""),
        ToolParameter("password_list", "string", "密码字典", required=False, 
                     default="/usr/share/wordlists/rockyou.txt"),
        ToolParameter("threads", "integer", "线程数", required=False, default=4),
        ToolParameter("http_form", "string", "HTTP表单参数(用户^密码^失败标识)", required=False, default=""),
        ToolParameter("stop_on_success", "boolean", "成功后停止", required=False, default=True),
    ])
    timeout: int = 3600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        service = params["service"]
        port = params.get("port", 0)
        username = params.get("username", "")
        username_list = params.get("username_list", "")
        password = params.get("password", "")
        password_list = params.get("password_list", "/usr/share/wordlists/rockyou.txt")
        threads = params.get("threads", 4)
        http_form = params.get("http_form", "")
        stop_on_success = params.get("stop_on_success", True)
        
        cmd = ["hydra", "-t", str(threads), "-V"]
        
        # 用户名
        if username:
            cmd.extend(["-l", username])
        elif username_list:
            cmd.extend(["-L", username_list])
        else:
            cmd.extend(["-l", "admin"])  # 默认用户名
        
        # 密码
        if password:
            cmd.extend(["-p", password])
        elif password_list:
            cmd.extend(["-P", password_list])
        
        if stop_on_success:
            cmd.append("-f")
        
        # 端口
        if port > 0:
            cmd.extend(["-s", str(port)])
        
        # 服务
        if service.startswith("http"):
            if http_form:
                cmd.append(f"{target}")
                cmd.append(f"{service}")
                cmd.append(http_form)
            else:
                cmd.extend(["-m", "/"])
                cmd.append(target)
                cmd.append(service)
        else:
            cmd.append(target)
            cmd.append(service)
        
        try:
            logger.info(f"执行Hydra: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析结果
            credentials = self._parse_output(result.stdout)
            
            return {
                "success": True,
                "target": target,
                "service": service,
                "credentials": credentials,
                "found_count": len(credentials),
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "暴力破解超时"}
        except FileNotFoundError:
            return {"success": False, "error": "hydra未安装，请运行: apt install hydra"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> List[Dict[str, str]]:
        """解析Hydra输出"""
        credentials = []
        
        # 匹配成功的凭证
        # 格式: [service] host: x.x.x.x   login: admin   password: password123
        pattern = r"\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S*)"
        
        for match in re.finditer(pattern, output, re.IGNORECASE):
            credentials.append({
                "service": match.group(1),
                "host": match.group(2),
                "username": match.group(3),
                "password": match.group(4)
            })
        
        return credentials


@dataclass
class MedusaTool(BaseTool):
    """Medusa密码爆破"""
    name: str = "medusa"
    description: str = "Medusa - 并行密码暴力破解工具"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP", required=True),
        ToolParameter("module", "string", "目标模块", required=True,
                     choices=["ssh", "ftp", "telnet", "mysql", "mssql", "postgres", 
                             "rdp", "smbnt", "vnc", "http", "smtp", "pop3", "imap"]),
        ToolParameter("port", "integer", "目标端口", required=False, default=0),
        ToolParameter("username", "string", "用户名", required=False, default=""),
        ToolParameter("username_list", "string", "用户名字典", required=False, default=""),
        ToolParameter("password_list", "string", "密码字典", required=True),
        ToolParameter("threads", "integer", "线程数", required=False, default=4),
        ToolParameter("stop_on_success", "boolean", "成功后停止", required=False, default=True),
    ])
    timeout: int = 3600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        module = params["module"]
        port = params.get("port", 0)
        username = params.get("username", "")
        username_list = params.get("username_list", "")
        password_list = params["password_list"]
        threads = params.get("threads", 4)
        stop_on_success = params.get("stop_on_success", True)
        
        cmd = ["medusa", "-h", target, "-M", module, "-P", password_list, "-t", str(threads)]
        
        if username:
            cmd.extend(["-u", username])
        elif username_list:
            cmd.extend(["-U", username_list])
        
        if port > 0:
            cmd.extend(["-n", str(port)])
        
        if stop_on_success:
            cmd.append("-f")
        
        try:
            logger.info(f"执行Medusa: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            credentials = self._parse_output(result.stdout)
            
            return {
                "success": True,
                "target": target,
                "module": module,
                "credentials": credentials,
                "found_count": len(credentials),
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "暴力破解超时"}
        except FileNotFoundError:
            return {"success": False, "error": "medusa未安装，请运行: apt install medusa"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> List[Dict[str, str]]:
        """解析Medusa输出"""
        credentials = []
        
        pattern = r"ACCOUNT FOUND:.*Host:\s*(\S+).*User:\s*(\S+).*Password:\s*(\S*)"
        
        for match in re.finditer(pattern, output, re.IGNORECASE):
            credentials.append({
                "host": match.group(1),
                "username": match.group(2),
                "password": match.group(3)
            })
        
        return credentials


@dataclass
class CrackMapExecTool(BaseTool):
    """CrackMapExec网络攻击"""
    name: str = "crackmapexec"
    description: str = "CrackMapExec - 网络渗透测试和后渗透工具"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP/范围/CIDR", required=True),
        ToolParameter("protocol", "string", "协议", required=True,
                     choices=["smb", "ssh", "winrm", "ldap", "mssql", "rdp"]),
        ToolParameter("username", "string", "用户名", required=False, default=""),
        ToolParameter("password", "string", "密码", required=False, default=""),
        ToolParameter("hash", "string", "NTLM哈希", required=False, default=""),
        ToolParameter("domain", "string", "域名", required=False, default=""),
        ToolParameter("action", "string", "执行动作", required=False, default="",
                     choices=["", "shares", "sessions", "disks", "loggedon-users", 
                             "users", "groups", "computers", "pass-pol"]),
        ToolParameter("command", "string", "执行命令", required=False, default=""),
        ToolParameter("sam", "boolean", "导出SAM", required=False, default=False),
        ToolParameter("lsa", "boolean", "导出LSA", required=False, default=False),
    ])
    timeout: int = 600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        protocol = params["protocol"]
        username = params.get("username", "")
        password = params.get("password", "")
        ntlm_hash = params.get("hash", "")
        domain = params.get("domain", "")
        action = params.get("action", "")
        command = params.get("command", "")
        sam = params.get("sam", False)
        lsa = params.get("lsa", False)
        
        cmd = ["crackmapexec", protocol, target]
        
        if username:
            cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])
        if ntlm_hash:
            cmd.extend(["-H", ntlm_hash])
        if domain:
            cmd.extend(["-d", domain])
        if action:
            cmd.append(f"--{action}")
        if command:
            cmd.extend(["-x", command])
        if sam:
            cmd.append("--sam")
        if lsa:
            cmd.append("--lsa")
        
        try:
            logger.info(f"执行CrackMapExec: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析结果
            parsed = self._parse_output(result.stdout, protocol)
            
            return {
                "success": True,
                "target": target,
                "protocol": protocol,
                **parsed,
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "执行超时"}
        except FileNotFoundError:
            return {"success": False, "error": "crackmapexec未安装，请运行: apt install crackmapexec"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str, protocol: str) -> Dict[str, Any]:
        """解析CrackMapExec输出"""
        result = {
            "hosts": [],
            "credentials": [],
            "shares": [],
            "users": []
        }
        
        for line in output.split('\n'):
            # 匹配主机状态
            host_pattern = r"(\d+\.\d+\.\d+\.\d+)\s+.*\((.*?)\)"
            host_match = re.search(host_pattern, line)
            if host_match:
                status = "+" if "[+]" in line else "-" if "[-]" in line else "*"
                result["hosts"].append({
                    "ip": host_match.group(1),
                    "info": host_match.group(2),
                    "status": status
                })
            
            # 匹配凭证
            if "[+]" in line and (":" in line or "Pwn3d!" in line):
                result["credentials"].append(line.strip())
            
            # 匹配共享
            if "READ" in line or "WRITE" in line:
                result["shares"].append(line.strip())
        
        return result
