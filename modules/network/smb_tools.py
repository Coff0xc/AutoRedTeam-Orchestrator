#!/usr/bin/env python3
"""
SMB攻击工具集
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
class SMBEnumTool(BaseTool):
    """SMB枚举"""
    name: str = "enum4linux"
    description: str = "Enum4linux - SMB/Samba枚举工具"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP", required=True),
        ToolParameter("username", "string", "用户名", required=False, default=""),
        ToolParameter("password", "string", "密码", required=False, default=""),
        ToolParameter("all", "boolean", "执行所有枚举", required=False, default=True),
        ToolParameter("users", "boolean", "枚举用户", required=False, default=False),
        ToolParameter("shares", "boolean", "枚举共享", required=False, default=False),
        ToolParameter("groups", "boolean", "枚举组", required=False, default=False),
    ])
    timeout: int = 600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        username = params.get("username", "")
        password = params.get("password", "")
        enum_all = params.get("all", True)
        users = params.get("users", False)
        shares = params.get("shares", False)
        groups = params.get("groups", False)
        
        cmd = ["enum4linux"]
        
        if username:
            cmd.extend(["-u", username])
        if password:
            cmd.extend(["-p", password])
        
        if enum_all:
            cmd.append("-a")
        else:
            if users:
                cmd.append("-U")
            if shares:
                cmd.append("-S")
            if groups:
                cmd.append("-G")
        
        cmd.append(target)
        
        try:
            logger.info(f"执行Enum4linux: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            parsed = self._parse_output(result.stdout)
            
            return {
                "success": True,
                "target": target,
                **parsed,
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "枚举超时"}
        except FileNotFoundError:
            return {"success": False, "error": "enum4linux未安装，请运行: apt install enum4linux"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """解析Enum4linux输出"""
        result = {
            "workgroup": None,
            "domain": None,
            "os_info": None,
            "users": [],
            "shares": [],
            "groups": [],
            "password_policy": {}
        }
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            # 工作组
            if "Workgroup:" in line:
                match = re.search(r"Workgroup:\s*(\S+)", line)
                if match:
                    result["workgroup"] = match.group(1)
            
            # 域名
            if "Domain:" in line:
                match = re.search(r"Domain:\s*(\S+)", line)
                if match:
                    result["domain"] = match.group(1)
            
            # 操作系统
            if "OS:" in line:
                result["os_info"] = line.split("OS:")[-1].strip()
            
            # 用户
            if "user:" in line.lower():
                user_match = re.search(r"user:\[([^\]]+)\]", line)
                if user_match:
                    result["users"].append(user_match.group(1))
            
            # 共享
            if "Sharename" in line:
                current_section = "shares"
            elif current_section == "shares" and line.strip() and not line.startswith("-"):
                parts = line.split()
                if len(parts) >= 2:
                    result["shares"].append({
                        "name": parts[0],
                        "type": parts[1] if len(parts) > 1 else "",
                        "comment": " ".join(parts[2:]) if len(parts) > 2 else ""
                    })
            
            # 组
            if "group:" in line.lower():
                group_match = re.search(r"group:\[([^\]]+)\]", line)
                if group_match:
                    result["groups"].append(group_match.group(1))
            
            # 密码策略
            if "Minimum password length:" in line:
                result["password_policy"]["min_length"] = line.split(":")[-1].strip()
            if "Password history length:" in line:
                result["password_policy"]["history_length"] = line.split(":")[-1].strip()
            if "Maximum password age:" in line:
                result["password_policy"]["max_age"] = line.split(":")[-1].strip()
            if "Account lockout threshold:" in line:
                result["password_policy"]["lockout_threshold"] = line.split(":")[-1].strip()
        
        return result


@dataclass
class SMBClientTool(BaseTool):
    """SMB客户端"""
    name: str = "smbclient"
    description: str = "SMBClient - SMB客户端工具"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP", required=True),
        ToolParameter("share", "string", "共享名称", required=False, default=""),
        ToolParameter("username", "string", "用户名", required=False, default=""),
        ToolParameter("password", "string", "密码", required=False, default=""),
        ToolParameter("domain", "string", "域名", required=False, default=""),
        ToolParameter("action", "string", "执行动作", required=True,
                     choices=["list", "download", "upload", "command"]),
        ToolParameter("remote_path", "string", "远程路径", required=False, default=""),
        ToolParameter("local_path", "string", "本地路径", required=False, default=""),
        ToolParameter("command", "string", "SMB命令", required=False, default=""),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        share = params.get("share", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        action = params["action"]
        remote_path = params.get("remote_path", "")
        local_path = params.get("local_path", "")
        command = params.get("command", "")
        
        if action == "list" and not share:
            # 列出共享
            cmd = ["smbclient", "-L", target]
            if username:
                cmd.extend(["-U", f"{username}%{password}" if password else username])
            else:
                cmd.extend(["-N"])  # 无密码
            if domain:
                cmd.extend(["-W", domain])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                shares = self._parse_shares(result.stdout)
                return {
                    "success": True,
                    "target": target,
                    "shares": shares,
                    "command": ' '.join(cmd)
                }
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        elif action == "list" and share:
            # 列出共享内容
            cmd = ["smbclient", f"//{target}/{share}"]
            if username:
                cmd.extend(["-U", f"{username}%{password}" if password else username])
            else:
                cmd.extend(["-N"])
            cmd.extend(["-c", f"ls {remote_path}" if remote_path else "ls"])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                files = self._parse_files(result.stdout)
                return {
                    "success": True,
                    "target": target,
                    "share": share,
                    "files": files,
                    "command": ' '.join(cmd)
                }
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        elif action == "download":
            cmd = ["smbclient", f"//{target}/{share}"]
            if username:
                cmd.extend(["-U", f"{username}%{password}" if password else username])
            else:
                cmd.extend(["-N"])
            cmd.extend(["-c", f"get {remote_path} {local_path}"])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                return {
                    "success": result.returncode == 0,
                    "target": target,
                    "share": share,
                    "downloaded": remote_path,
                    "local_path": local_path,
                    "output": result.stdout,
                    "command": ' '.join(cmd)
                }
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        elif action == "command":
            cmd = ["smbclient", f"//{target}/{share}"]
            if username:
                cmd.extend(["-U", f"{username}%{password}" if password else username])
            else:
                cmd.extend(["-N"])
            cmd.extend(["-c", command])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
                return {
                    "success": True,
                    "target": target,
                    "share": share,
                    "output": result.stdout,
                    "command": ' '.join(cmd)
                }
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        return {"success": False, "error": "无效的action参数"}
    
    def _parse_shares(self, output: str) -> List[Dict[str, str]]:
        """解析共享列表"""
        shares = []
        for line in output.split('\n'):
            if 'Disk' in line or 'IPC' in line or 'Printer' in line:
                parts = line.split()
                if len(parts) >= 2:
                    shares.append({
                        "name": parts[0],
                        "type": parts[1],
                        "comment": " ".join(parts[2:]) if len(parts) > 2 else ""
                    })
        return shares
    
    def _parse_files(self, output: str) -> List[Dict[str, Any]]:
        """解析文件列表"""
        files = []
        for line in output.split('\n'):
            # 格式: filename   D   0  Tue Nov 21 10:00:00 2023
            if line.strip() and not line.startswith("smb:"):
                parts = line.split()
                if len(parts) >= 3:
                    files.append({
                        "name": parts[0],
                        "type": "dir" if "D" in parts[1] else "file",
                        "size": parts[2] if len(parts) > 2 else "0"
                    })
        return files
