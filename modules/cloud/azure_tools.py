#!/usr/bin/env python3
"""
Azure云安全工具
"""

import subprocess
import json
import logging
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class AzureEnumTool(BaseTool):
    """Azure资源枚举"""
    name: str = "azure_enum"
    description: str = "Azure资源枚举 - 发现Azure订阅中的资源"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("subscription", "string", "订阅ID(可选)", required=False, default=""),
        ToolParameter("resource_type", "string", "资源类型", required=False, default="all",
                     choices=["all", "vm", "storage", "webapp", "sql", "keyvault"]),
    ])
    timeout: int = 300
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        subscription = params.get("subscription", "")
        resource_type = params.get("resource_type", "all")
        
        result = {
            "success": True,
            "subscription": subscription,
            "resources": {}
        }
        
        try:
            # 检查Azure CLI
            check = subprocess.run(
                ["az", "account", "show"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if check.returncode != 0:
                return {
                    "success": False,
                    "error": "Azure CLI未登录，请运行: az login"
                }
            
            account = json.loads(check.stdout)
            result["account"] = {
                "name": account.get("name"),
                "id": account.get("id"),
                "user": account.get("user", {}).get("name")
            }
            
            # 枚举资源
            resources_to_enum = [resource_type] if resource_type != "all" else [
                "vm", "storage", "webapp", "sql"
            ]
            
            for res_type in resources_to_enum:
                if res_type == "vm":
                    result["resources"]["vms"] = self._enum_vms(subscription)
                elif res_type == "storage":
                    result["resources"]["storage"] = self._enum_storage(subscription)
                elif res_type == "webapp":
                    result["resources"]["webapps"] = self._enum_webapps(subscription)
                elif res_type == "sql":
                    result["resources"]["sql"] = self._enum_sql(subscription)
            
        except FileNotFoundError:
            return {"success": False, "error": "Azure CLI未安装"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        
        return result
    
    def _run_az_cmd(self, cmd: List[str], subscription: str = "") -> Dict:
        """执行Azure CLI命令"""
        full_cmd = ["az"] + cmd + ["--output", "json"]
        if subscription:
            full_cmd.extend(["--subscription", subscription])
        
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout else {}
        return {"error": result.stderr}
    
    def _enum_vms(self, subscription: str) -> Dict:
        """枚举虚拟机"""
        try:
            vms = self._run_az_cmd(["vm", "list"], subscription)
            
            if isinstance(vms, list):
                return {
                    "vms": [
                        {
                            "name": vm.get("name"),
                            "location": vm.get("location"),
                            "size": vm.get("hardwareProfile", {}).get("vmSize"),
                            "os": vm.get("storageProfile", {}).get("osDisk", {}).get("osType"),
                            "public_ips": []
                        }
                        for vm in vms
                    ],
                    "count": len(vms)
                }
            return vms
        except Exception as e:
            return {"error": str(e)}
    
    def _enum_storage(self, subscription: str) -> Dict:
        """枚举存储账户"""
        try:
            accounts = self._run_az_cmd(["storage", "account", "list"], subscription)
            
            if isinstance(accounts, list):
                return {
                    "accounts": [
                        {
                            "name": acc.get("name"),
                            "location": acc.get("location"),
                            "kind": acc.get("kind"),
                            "public_access": acc.get("allowBlobPublicAccess", False)
                        }
                        for acc in accounts
                    ],
                    "count": len(accounts)
                }
            return accounts
        except Exception as e:
            return {"error": str(e)}
    
    def _enum_webapps(self, subscription: str) -> Dict:
        """枚举Web应用"""
        try:
            apps = self._run_az_cmd(["webapp", "list"], subscription)
            
            if isinstance(apps, list):
                return {
                    "apps": [
                        {
                            "name": app.get("name"),
                            "url": f"https://{app.get('defaultHostName', '')}",
                            "state": app.get("state"),
                            "https_only": app.get("httpsOnly", False)
                        }
                        for app in apps
                    ],
                    "count": len(apps)
                }
            return apps
        except Exception as e:
            return {"error": str(e)}
    
    def _enum_sql(self, subscription: str) -> Dict:
        """枚举SQL数据库"""
        try:
            servers = self._run_az_cmd(["sql", "server", "list"], subscription)
            
            if isinstance(servers, list):
                return {
                    "servers": [
                        {
                            "name": srv.get("name"),
                            "fqdn": srv.get("fullyQualifiedDomainName"),
                            "admin": srv.get("administratorLogin"),
                            "state": srv.get("state")
                        }
                        for srv in servers
                    ],
                    "count": len(servers)
                }
            return servers
        except Exception as e:
            return {"error": str(e)}
