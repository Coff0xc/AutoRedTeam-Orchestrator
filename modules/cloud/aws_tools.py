#!/usr/bin/env python3
"""
AWS云安全工具
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
class AWSEnumTool(BaseTool):
    """AWS资源枚举"""
    name: str = "aws_enum"
    description: str = "AWS资源枚举 - 发现AWS账户中的资源和配置问题"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("profile", "string", "AWS配置文件", required=False, default="default"),
        ToolParameter("region", "string", "AWS区域", required=False, default="us-east-1"),
        ToolParameter("service", "string", "目标服务", required=False, default="all",
                     choices=["all", "s3", "ec2", "iam", "lambda", "rds", "secrets"]),
    ])
    timeout: int = 300
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        profile = params.get("profile", "default")
        region = params.get("region", "us-east-1")
        service = params.get("service", "all")
        
        results = {
            "success": True,
            "profile": profile,
            "region": region,
            "resources": {}
        }
        
        services_to_check = [service] if service != "all" else [
            "s3", "ec2", "iam", "lambda", "rds"
        ]
        
        for svc in services_to_check:
            try:
                if svc == "s3":
                    results["resources"]["s3"] = self._enum_s3(profile, region)
                elif svc == "ec2":
                    results["resources"]["ec2"] = self._enum_ec2(profile, region)
                elif svc == "iam":
                    results["resources"]["iam"] = self._enum_iam(profile, region)
                elif svc == "lambda":
                    results["resources"]["lambda"] = self._enum_lambda(profile, region)
                elif svc == "rds":
                    results["resources"]["rds"] = self._enum_rds(profile, region)
            except Exception as e:
                results["resources"][svc] = {"error": str(e)}
        
        return results
    
    def _run_aws_cli(self, cmd: List[str], profile: str, region: str) -> Dict:
        """执行AWS CLI命令"""
        full_cmd = ["aws", "--profile", profile, "--region", region] + cmd + ["--output", "json"]
        
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout else {}
        raise Exception(result.stderr)
    
    def _enum_s3(self, profile: str, region: str) -> Dict:
        """枚举S3存储桶"""
        try:
            buckets = self._run_aws_cli(["s3api", "list-buckets"], profile, region)
            
            bucket_info = []
            for bucket in buckets.get("Buckets", [])[:10]:  # 限制数量
                name = bucket.get("Name")
                info = {"name": name}
                
                # 检查公开访问
                try:
                    acl = self._run_aws_cli(
                        ["s3api", "get-bucket-acl", "--bucket", name],
                        profile, region
                    )
                    info["acl"] = acl.get("Grants", [])
                    info["public"] = self._check_public_acl(acl)
                except:
                    info["acl"] = "无法获取"
                
                bucket_info.append(info)
            
            return {"buckets": bucket_info, "count": len(buckets.get("Buckets", []))}
        except Exception as e:
            return {"error": str(e)}
    
    def _check_public_acl(self, acl: Dict) -> bool:
        """检查是否公开访问"""
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                return True
        return False
    
    def _enum_ec2(self, profile: str, region: str) -> Dict:
        """枚举EC2实例"""
        try:
            instances = self._run_aws_cli(
                ["ec2", "describe-instances"],
                profile, region
            )
            
            instance_list = []
            for reservation in instances.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_list.append({
                        "id": instance.get("InstanceId"),
                        "type": instance.get("InstanceType"),
                        "state": instance.get("State", {}).get("Name"),
                        "public_ip": instance.get("PublicIpAddress"),
                        "private_ip": instance.get("PrivateIpAddress"),
                    })
            
            return {"instances": instance_list, "count": len(instance_list)}
        except Exception as e:
            return {"error": str(e)}
    
    def _enum_iam(self, profile: str, region: str) -> Dict:
        """枚举IAM用户和角色"""
        try:
            users = self._run_aws_cli(["iam", "list-users"], profile, region)
            roles = self._run_aws_cli(["iam", "list-roles"], profile, region)
            
            return {
                "users": [u.get("UserName") for u in users.get("Users", [])],
                "roles": [r.get("RoleName") for r in roles.get("Roles", [])][:20],
                "user_count": len(users.get("Users", [])),
                "role_count": len(roles.get("Roles", []))
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _enum_lambda(self, profile: str, region: str) -> Dict:
        """枚举Lambda函数"""
        try:
            functions = self._run_aws_cli(
                ["lambda", "list-functions"],
                profile, region
            )
            
            return {
                "functions": [
                    {
                        "name": f.get("FunctionName"),
                        "runtime": f.get("Runtime"),
                        "memory": f.get("MemorySize"),
                        "timeout": f.get("Timeout")
                    }
                    for f in functions.get("Functions", [])
                ],
                "count": len(functions.get("Functions", []))
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _enum_rds(self, profile: str, region: str) -> Dict:
        """枚举RDS数据库"""
        try:
            instances = self._run_aws_cli(
                ["rds", "describe-db-instances"],
                profile, region
            )
            
            return {
                "databases": [
                    {
                        "identifier": db.get("DBInstanceIdentifier"),
                        "engine": db.get("Engine"),
                        "status": db.get("DBInstanceStatus"),
                        "public": db.get("PubliclyAccessible"),
                        "endpoint": db.get("Endpoint", {}).get("Address")
                    }
                    for db in instances.get("DBInstances", [])
                ],
                "count": len(instances.get("DBInstances", []))
            }
        except Exception as e:
            return {"error": str(e)}


@dataclass
class S3ScannerTool(BaseTool):
    """S3存储桶安全扫描"""
    name: str = "s3_scanner"
    description: str = "S3Scanner - 扫描公开的S3存储桶"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("bucket", "string", "存储桶名称或目标域名", required=True),
        ToolParameter("enumerate", "boolean", "枚举对象", required=False, default=True),
        ToolParameter("check_permissions", "boolean", "检查权限配置", required=False, default=True),
    ])
    timeout: int = 120
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        bucket = params["bucket"]
        enumerate_objects = params.get("enumerate", True)
        check_permissions = params.get("check_permissions", True)
        
        result = {
            "success": True,
            "bucket": bucket,
            "exists": False,
            "public_access": False,
            "permissions": {},
            "objects": []
        }
        
        # 检查存储桶是否存在
        try:
            check_cmd = ["aws", "s3", "ls", f"s3://{bucket}", "--no-sign-request"]
            check_result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if check_result.returncode == 0:
                result["exists"] = True
                result["public_access"] = True
                
                if enumerate_objects:
                    # 解析对象列表
                    for line in check_result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                result["objects"].append({
                                    "date": parts[0],
                                    "time": parts[1],
                                    "size": parts[2],
                                    "name": " ".join(parts[3:])
                                })
            else:
                # 存储桶可能存在但不公开
                if "NoSuchBucket" not in check_result.stderr:
                    result["exists"] = True
                    result["public_access"] = False
                    
        except subprocess.TimeoutExpired:
            result["error"] = "检查超时"
        except Exception as e:
            result["error"] = str(e)
        
        # 检查权限配置
        if check_permissions and result["exists"]:
            result["permissions"] = self._check_permissions(bucket)
        
        return result
    
    def _check_permissions(self, bucket: str) -> Dict:
        """检查存储桶权限"""
        permissions = {
            "read": False,
            "write": False,
            "read_acp": False,
            "write_acp": False
        }
        
        # 测试读取权限
        try:
            cmd = ["aws", "s3", "ls", f"s3://{bucket}", "--no-sign-request"]
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            permissions["read"] = result.returncode == 0
        except:
            pass
        
        # 测试上传权限 (创建测试文件)
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=True) as f:
                f.write(b"test")
                f.flush()
                cmd = ["aws", "s3", "cp", f.name, f"s3://{bucket}/.test", "--no-sign-request"]
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode == 0:
                    permissions["write"] = True
                    # 清理测试文件
                    subprocess.run(
                        ["aws", "s3", "rm", f"s3://{bucket}/.test", "--no-sign-request"],
                        capture_output=True, timeout=10
                    )
        except:
            pass
        
        return permissions
