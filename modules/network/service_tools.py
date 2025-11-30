#!/usr/bin/env python3
"""
网络服务测试工具集
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
class FTPCheckTool(BaseTool):
    """FTP服务检测"""
    name: str = "ftp_check"
    description: str = "FTP检测 - 检测FTP服务和匿名登录"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP", required=True),
        ToolParameter("port", "integer", "端口", required=False, default=21),
        ToolParameter("check_anonymous", "boolean", "检测匿名登录", required=False, default=True),
        ToolParameter("username", "string", "用户名", required=False, default=""),
        ToolParameter("password", "string", "密码", required=False, default=""),
    ])
    timeout: int = 30
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        port = params.get("port", 21)
        check_anonymous = params.get("check_anonymous", True)
        username = params.get("username", "")
        password = params.get("password", "")
        
        result = {
            "success": True,
            "target": target,
            "port": port,
            "banner": None,
            "anonymous_access": False,
            "login_success": False,
            "files": []
        }
        
        try:
            import ftplib
            
            # 获取banner
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=self.timeout)
            result["banner"] = ftp.getwelcome()
            
            # 检测匿名登录
            if check_anonymous:
                try:
                    ftp.login("anonymous", "anonymous@test.com")
                    result["anonymous_access"] = True
                    
                    # 列出根目录
                    try:
                        files = []
                        ftp.retrlines('LIST', files.append)
                        result["files"] = files[:20]  # 限制数量
                    except:
                        pass
                    
                    ftp.quit()
                except ftplib.error_perm:
                    result["anonymous_access"] = False
            
            # 尝试指定凭证登录
            if username and password:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target, port, timeout=self.timeout)
                    ftp.login(username, password)
                    result["login_success"] = True
                    ftp.quit()
                except ftplib.error_perm:
                    result["login_success"] = False
            
            return result
            
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class SSHAuditTool(BaseTool):
    """SSH安全审计"""
    name: str = "ssh_audit"
    description: str = "SSH审计 - 分析SSH配置安全性"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP", required=True),
        ToolParameter("port", "integer", "端口", required=False, default=22),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        port = params.get("port", 22)
        
        cmd = ["ssh-audit", "-j", f"{target}:{port}"]
        
        try:
            logger.info(f"执行SSH审计: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            try:
                data = json.loads(result.stdout)
                return {
                    "success": True,
                    "target": target,
                    "port": port,
                    "banner": data.get("banner", {}).get("raw"),
                    "fingerprints": data.get("fingerprints", []),
                    "kex": data.get("kex", []),
                    "key": data.get("key", []),
                    "enc": data.get("enc", []),
                    "mac": data.get("mac", []),
                    "recommendations": data.get("recommendations", {})
                }
            except json.JSONDecodeError:
                # 解析文本输出
                return {
                    "success": True,
                    "target": target,
                    "port": port,
                    "raw_output": result.stdout
                }
                
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "审计超时"}
        except FileNotFoundError:
            return {"success": False, "error": "ssh-audit未安装，请运行: apt install ssh-audit"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class RDPCheckTool(BaseTool):
    """RDP服务检测"""
    name: str = "rdp_check"
    description: str = "RDP检测 - 检测RDP服务和安全配置"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP", required=True),
        ToolParameter("port", "integer", "端口", required=False, default=3389),
    ])
    timeout: int = 30
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        port = params.get("port", 3389)
        
        result = {
            "success": True,
            "target": target,
            "port": port,
            "rdp_available": False,
            "nla_required": None,
            "encryption": None,
            "vulnerabilities": []
        }
        
        # 使用nmap脚本检测
        cmd = [
            "nmap", "-p", str(port),
            "--script", "rdp-enum-encryption,rdp-vuln-ms12-020",
            "-Pn", target
        ]
        
        try:
            logger.info(f"执行RDP检测: {' '.join(cmd)}")
            nmap_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            output = nmap_result.stdout
            
            if "open" in output and "ms-wbt-server" in output:
                result["rdp_available"] = True
            
            # 检测NLA
            if "NLA" in output or "Network Level Authentication" in output:
                result["nla_required"] = "NLA" in output
            
            # 检测加密
            enc_match = re.search(r"Encryption level:\s*(\S+)", output)
            if enc_match:
                result["encryption"] = enc_match.group(1)
            
            # 检测漏洞
            if "VULNERABLE" in output:
                if "MS12-020" in output:
                    result["vulnerabilities"].append({
                        "id": "MS12-020",
                        "name": "BlueKeep predecessor",
                        "severity": "critical"
                    })
            
            result["raw_output"] = output
            
            return result
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "检测超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class SNMPWalkTool(BaseTool):
    """SNMP枚举"""
    name: str = "snmpwalk"
    description: str = "SNMPWalk - SNMP信息枚举"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP", required=True),
        ToolParameter("community", "string", "团体字符串", required=False, default="public"),
        ToolParameter("version", "string", "SNMP版本", required=False, default="2c",
                     choices=["1", "2c", "3"]),
        ToolParameter("oid", "string", "OID", required=False, default=""),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        community = params.get("community", "public")
        version = params.get("version", "2c")
        oid = params.get("oid", "")
        
        cmd = ["snmpwalk", "-v", version, "-c", community, target]
        if oid:
            cmd.append(oid)
        
        try:
            logger.info(f"执行SNMPWalk: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            entries = []
            for line in result.stdout.split('\n'):
                if line.strip() and "=" in line:
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        entries.append({
                            "oid": parts[0].strip(),
                            "value": parts[1].strip()
                        })
            
            # 提取关键信息
            system_info = {}
            for entry in entries:
                oid_lower = entry["oid"].lower()
                if "sysdescr" in oid_lower:
                    system_info["description"] = entry["value"]
                elif "syscontact" in oid_lower:
                    system_info["contact"] = entry["value"]
                elif "sysname" in oid_lower:
                    system_info["name"] = entry["value"]
                elif "syslocation" in oid_lower:
                    system_info["location"] = entry["value"]
            
            return {
                "success": True,
                "target": target,
                "community": community,
                "version": version,
                "system_info": system_info,
                "entries": entries[:100],  # 限制数量
                "total_entries": len(entries),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "SNMP枚举超时"}
        except FileNotFoundError:
            return {"success": False, "error": "snmpwalk未安装，请运行: apt install snmp"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class LDAPEnumTool(BaseTool):
    """LDAP枚举"""
    name: str = "ldap_enum"
    description: str = "LDAP枚举 - Active Directory/LDAP信息收集"
    category: ToolCategory = ToolCategory.NETWORK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP/域名", required=True),
        ToolParameter("port", "integer", "端口", required=False, default=389),
        ToolParameter("base_dn", "string", "Base DN", required=False, default=""),
        ToolParameter("username", "string", "用户名", required=False, default=""),
        ToolParameter("password", "string", "密码", required=False, default=""),
        ToolParameter("search_filter", "string", "搜索过滤器", required=False, default="(objectClass=*)"),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        port = params.get("port", 389)
        base_dn = params.get("base_dn", "")
        username = params.get("username", "")
        password = params.get("password", "")
        search_filter = params.get("search_filter", "(objectClass=*)")
        
        # 使用ldapsearch
        cmd = ["ldapsearch", "-x", "-H", f"ldap://{target}:{port}"]
        
        if base_dn:
            cmd.extend(["-b", base_dn])
        if username:
            cmd.extend(["-D", username])
        if password:
            cmd.extend(["-w", password])
        
        cmd.append(search_filter)
        
        try:
            logger.info(f"执行LDAP枚举: ldapsearch -H ldap://{target}:{port}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            entries = self._parse_ldap_output(result.stdout)
            
            return {
                "success": True,
                "target": target,
                "port": port,
                "entries": entries,
                "total_entries": len(entries),
                "raw_output": result.stdout[:5000]  # 限制输出
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "LDAP枚举超时"}
        except FileNotFoundError:
            return {"success": False, "error": "ldapsearch未安装，请运行: apt install ldap-utils"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_ldap_output(self, output: str) -> List[Dict[str, Any]]:
        """解析LDAP输出"""
        entries = []
        current_entry = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#'):
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                continue
            
            if ': ' in line:
                key, value = line.split(': ', 1)
                if key in current_entry:
                    if isinstance(current_entry[key], list):
                        current_entry[key].append(value)
                    else:
                        current_entry[key] = [current_entry[key], value]
                else:
                    current_entry[key] = value
        
        if current_entry:
            entries.append(current_entry)
        
        return entries[:50]  # 限制数量
