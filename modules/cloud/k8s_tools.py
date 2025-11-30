#!/usr/bin/env python3
"""
Kubernetes安全工具
"""

import subprocess
import json
import logging
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class KubeHunterTool(BaseTool):
    """Kubernetes集群安全扫描"""
    name: str = "kube_hunter"
    description: str = "Kube-hunter - Kubernetes集群安全扫描"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标API Server地址", required=False, default=""),
        ToolParameter("mode", "string", "扫描模式", required=False, default="remote",
                     choices=["remote", "internal", "network"]),
        ToolParameter("cidr", "string", "扫描网段(CIDR)", required=False, default=""),
    ])
    timeout: int = 300
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params.get("target", "")
        mode = params.get("mode", "remote")
        cidr = params.get("cidr", "")
        
        cmd = ["kube-hunter", "--json"]
        
        if mode == "remote" and target:
            cmd.extend(["--remote", target])
        elif mode == "network" and cidr:
            cmd.extend(["--cidr", cidr])
        elif mode == "internal":
            cmd.append("--internal")
        else:
            cmd.append("--internal")
        
        try:
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
                        "mode": mode,
                        "nodes": data.get("nodes", []),
                        "services": data.get("services", []),
                        "vulnerabilities": data.get("vulnerabilities", []),
                        "hunters": data.get("hunters", [])
                    }
                except json.JSONDecodeError:
                    return {
                        "success": True,
                        "mode": mode,
                        "raw_output": result.stdout
                    }
            else:
                return {"success": False, "error": result.stderr}
                
        except FileNotFoundError:
            return {
                "success": False,
                "error": "kube-hunter未安装，请运行: pip install kube-hunter",
                "install_cmd": "pip install kube-hunter"
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class KubectlEnumTool(BaseTool):
    """Kubernetes资源枚举"""
    name: str = "kubectl_enum"
    description: str = "Kubectl枚举 - 枚举Kubernetes集群资源"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("namespace", "string", "命名空间", required=False, default=""),
        ToolParameter("resource_type", "string", "资源类型", required=False, default="all",
                     choices=["all", "pods", "services", "secrets", "configmaps", "deployments"]),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        namespace = params.get("namespace", "")
        resource_type = params.get("resource_type", "all")
        
        result = {
            "success": True,
            "namespace": namespace or "all",
            "resources": {}
        }
        
        try:
            # 检查kubectl连接
            check = subprocess.run(
                ["kubectl", "cluster-info"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if check.returncode != 0:
                return {
                    "success": False,
                    "error": "无法连接到Kubernetes集群"
                }
            
            resources_to_enum = [resource_type] if resource_type != "all" else [
                "pods", "services", "secrets", "configmaps", "deployments"
            ]
            
            for res_type in resources_to_enum:
                result["resources"][res_type] = self._get_resources(res_type, namespace)
            
        except FileNotFoundError:
            return {"success": False, "error": "kubectl未安装"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        
        return result
    
    def _get_resources(self, resource_type: str, namespace: str) -> Dict:
        """获取资源"""
        cmd = ["kubectl", "get", resource_type, "-o", "json"]
        if namespace:
            cmd.extend(["-n", namespace])
        else:
            cmd.append("--all-namespaces")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                items = data.get("items", [])
                
                # 简化输出
                simplified = []
                for item in items:
                    metadata = item.get("metadata", {})
                    simplified.append({
                        "name": metadata.get("name"),
                        "namespace": metadata.get("namespace"),
                        "created": metadata.get("creationTimestamp")
                    })
                
                return {"items": simplified, "count": len(items)}
            else:
                return {"error": result.stderr}
                
        except Exception as e:
            return {"error": str(e)}


@dataclass
class KubeSecretsTool(BaseTool):
    """Kubernetes Secrets提取"""
    name: str = "kube_secrets"
    description: str = "提取Kubernetes Secrets(需要适当权限)"
    category: ToolCategory = ToolCategory.CREDENTIAL_ACCESS
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("namespace", "string", "命名空间", required=False, default="default"),
        ToolParameter("secret_name", "string", "Secret名称(可选)", required=False, default=""),
        ToolParameter("decode", "boolean", "Base64解码", required=False, default=True),
    ])
    timeout: int = 30
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        namespace = params.get("namespace", "default")
        secret_name = params.get("secret_name", "")
        decode = params.get("decode", True)
        
        try:
            if secret_name:
                cmd = ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "json"]
            else:
                cmd = ["kubectl", "get", "secrets", "-n", namespace, "-o", "json"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode != 0:
                return {"success": False, "error": result.stderr}
            
            data = json.loads(result.stdout)
            secrets = []
            
            items = [data] if secret_name else data.get("items", [])
            
            for item in items:
                secret_info = {
                    "name": item.get("metadata", {}).get("name"),
                    "namespace": item.get("metadata", {}).get("namespace"),
                    "type": item.get("type"),
                    "data": {}
                }
                
                secret_data = item.get("data", {})
                for key, value in secret_data.items():
                    if decode:
                        import base64
                        try:
                            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                            secret_info["data"][key] = decoded[:100] + "..." if len(decoded) > 100 else decoded
                        except:
                            secret_info["data"][key] = "[无法解码]"
                    else:
                        secret_info["data"][key] = value[:50] + "..." if len(value) > 50 else value
                
                secrets.append(secret_info)
            
            return {
                "success": True,
                "namespace": namespace,
                "secrets": secrets,
                "count": len(secrets)
            }
            
        except FileNotFoundError:
            return {"success": False, "error": "kubectl未安装"}
        except Exception as e:
            return {"success": False, "error": str(e)}
