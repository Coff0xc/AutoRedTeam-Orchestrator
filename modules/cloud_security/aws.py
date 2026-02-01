#!/usr/bin/env python3
"""
AWS安全测试模块

提供AWS云环境安全检测功能，包括:
- S3存储桶安全检测
- IAM权限审计
- EC2安全组检测
- RDS安全检测
- CloudTrail审计
- KMS密钥管理检测

作者: AutoRedTeam
版本: 3.0.0
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .base import (
    BaseCloudTester,
    CloudFinding,
    CloudSeverity,
    CloudVulnType,
)

logger = logging.getLogger(__name__)

# 尝试导入boto3
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class AWSTester(BaseCloudTester):
    """
    AWS安全测试器

    对AWS云资源进行安全扫描。

    使用示例:
        # 使用默认凭证
        tester = AWSTester()
        findings = tester.scan()

        # 指定配置
        tester = AWSTester(config={
            'region': 'us-east-1',
            'profile': 'my-profile'
        })
        findings = tester.scan()
    """

    name = "aws"
    provider = "aws"
    description = "AWS安全测试器"
    version = "3.0.0"

    # 危险IAM操作
    DANGEROUS_ACTIONS = [
        "*",
        "iam:*",
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "s3:*",
        "ec2:*",
        "lambda:*",
        "sts:AssumeRole",
    ]

    # 敏感端口
    SENSITIVE_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化AWS测试器

        Args:
            config: 可选配置，可包含:
                - region: AWS区域
                - profile: AWS配置文件名
                - access_key: AWS访问密钥
                - secret_key: AWS密钥
        """
        super().__init__(config)

        if not HAS_BOTO3:
            logger.warning("boto3未安装，AWS扫描功能受限")
            return

        self.region = self.config.get("region", "us-east-1")
        self.profile = self.config.get("profile")

        # 初始化boto3 session
        try:
            if self.profile:
                self._session = boto3.Session(profile_name=self.profile, region_name=self.region)
            elif self.config.get("access_key") and self.config.get("secret_key"):
                self._session = boto3.Session(
                    aws_access_key_id=self.config["access_key"],
                    aws_secret_access_key=self.config["secret_key"],
                    region_name=self.region,
                )
            else:
                self._session = boto3.Session(region_name=self.region)
        except Exception as e:
            logger.error(f"初始化AWS会话失败: {e}")
            self._session = None

    def scan(self) -> List[CloudFinding]:
        """执行完整的AWS安全扫描"""
        self.clear_findings()

        if not HAS_BOTO3 or not self._session:
            logger.warning("无法执行AWS扫描：boto3未初始化")
            return self._findings

        try:
            # 执行各项检查
            self.check_s3_public_buckets()
            self.check_iam_policies()
            self.check_security_groups()
            self.check_rds_public()
            self.check_cloudtrail()
            self.check_ec2_metadata()

        except NoCredentialsError:
            logger.error("AWS凭证未配置")
        except Exception as e:
            logger.error(f"AWS扫描失败: {e}")

        return self._findings

    def check_s3_public_buckets(self) -> List[CloudFinding]:
        """检测公开的S3存储桶"""
        findings = []

        try:
            s3 = self._session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])

            for bucket in buckets:
                bucket_name = bucket["Name"]

                # 检查存储桶ACL
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)

                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})

                        # 检查是否公开
                        if grantee.get("URI") in [
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        ]:
                            finding = self._create_finding(
                                vuln_type=CloudVulnType.AWS_S3_PUBLIC,
                                severity=CloudSeverity.HIGH,
                                resource_type="S3Bucket",
                                resource_name=bucket_name,
                                region=self.region,
                                title=f"S3存储桶公开访问: {bucket_name}",
                                description=(
                                    f"S3存储桶 {bucket_name} 配置了公开访问权限，"
                                    "可能导致数据泄露。"
                                ),
                                remediation=(
                                    "1. 移除公开访问权限\n"
                                    "2. 启用S3 Block Public Access\n"
                                    "3. 使用存储桶策略限制访问"
                                ),
                                evidence={
                                    "grantee_uri": grantee.get("URI"),
                                    "permission": grant.get("Permission"),
                                },
                                compliance=["CIS-AWS-2.1.5", "HIPAA", "PCI-DSS"],
                            )
                            findings.append(finding)
                            break

                except ClientError as e:
                    logger.debug(f"获取存储桶ACL失败 {bucket_name}: {e}")

                # 检查存储桶策略
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy["Policy"])

                    for statement in policy_doc.get("Statement", []):
                        if statement.get("Effect") == "Allow":
                            principal = statement.get("Principal", {})
                            if principal == "*" or principal.get("AWS") == "*":
                                self._create_finding(
                                    vuln_type=CloudVulnType.AWS_S3_ACL_MISCONFIGURED,
                                    severity=CloudSeverity.HIGH,
                                    resource_type="S3Bucket",
                                    resource_name=bucket_name,
                                    title=f"S3存储桶策略允许所有人访问: {bucket_name}",
                                    description='存储桶策略中包含Principal: "*"',
                                    remediation="限制Principal为特定账户或角色",
                                    evidence={"statement": statement},
                                )

                except ClientError:
                    pass  # 没有策略

        except Exception as e:
            logger.error(f"S3检查失败: {e}")

        return findings

    def check_iam_policies(self) -> List[CloudFinding]:
        """检测IAM权限配置"""
        findings = []

        try:
            iam = self._session.client("iam")

            # 检查用户
            users = iam.list_users().get("Users", [])

            for user in users:
                user_name = user["UserName"]

                # 检查内联策略
                inline_policies = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])

                for policy_name in inline_policies:
                    policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                    policy_doc = policy.get("PolicyDocument", {})

                    self._check_policy_document(policy_doc, "User", user_name, policy_name)

                # 检查附加策略
                attached = iam.list_attached_user_policies(UserName=user_name).get(
                    "AttachedPolicies", []
                )

                for policy in attached:
                    if policy["PolicyArn"].endswith(":policy/AdministratorAccess"):
                        self._create_finding(
                            vuln_type=CloudVulnType.AWS_IAM_OVERPERMISSION,
                            severity=CloudSeverity.HIGH,
                            resource_type="IAMUser",
                            resource_name=user_name,
                            title=f"用户拥有管理员权限: {user_name}",
                            description="用户附加了AdministratorAccess策略",
                            remediation="使用最小权限原则，创建自定义策略",
                            evidence={"policy_arn": policy["PolicyArn"]},
                        )

            # 检查角色
            roles = iam.list_roles().get("Roles", [])

            for role in roles:
                role_name = role["RoleName"]

                # 跳过AWS服务角色
                if role_name.startswith("AWS"):
                    continue

                # 检查信任策略
                assume_policy = role.get("AssumeRolePolicyDocument", {})
                for statement in assume_policy.get("Statement", []):
                    principal = statement.get("Principal", {})
                    if principal == "*" or principal.get("AWS") == "*":
                        self._create_finding(
                            vuln_type=CloudVulnType.AWS_IAM_OVERPERMISSION,
                            severity=CloudSeverity.CRITICAL,
                            resource_type="IAMRole",
                            resource_name=role_name,
                            title=f"角色信任策略允许任意主体: {role_name}",
                            description="角色的信任策略允许任意AWS账户承担",
                            remediation="限制Principal为特定账户或角色",
                            evidence={"statement": statement},
                        )

        except Exception as e:
            logger.error(f"IAM检查失败: {e}")

        return findings

    def _check_policy_document(
        self, policy_doc: Dict, resource_type: str, resource_name: str, policy_name: str
    ) -> None:
        """检查策略文档"""
        for statement in policy_doc.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # 检查通配符权限
            if "*" in actions and "*" in resources:
                self._create_finding(
                    vuln_type=CloudVulnType.AWS_IAM_WILDCARD,
                    severity=CloudSeverity.CRITICAL,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    title=f"IAM策略使用通配符: {policy_name}",
                    description="策略允许对所有资源执行所有操作",
                    remediation="遵循最小权限原则，明确指定Action和Resource",
                    evidence={"actions": actions, "resources": resources},
                )

            # 检查危险操作
            for action in actions:
                if action in self.DANGEROUS_ACTIONS:
                    self._create_finding(
                        vuln_type=CloudVulnType.AWS_IAM_OVERPERMISSION,
                        severity=CloudSeverity.HIGH,
                        resource_type=resource_type,
                        resource_name=resource_name,
                        title=f"IAM策略包含危险操作: {action}",
                        description=f"策略 {policy_name} 允许危险操作 {action}",
                        remediation="移除或限制危险操作",
                        evidence={"action": action, "policy": policy_name},
                    )

    def check_security_groups(self) -> List[CloudFinding]:
        """检测安全组配置"""
        findings = []

        try:
            ec2 = self._session.client("ec2")
            security_groups = ec2.describe_security_groups().get("SecurityGroups", [])

            for sg in security_groups:
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "unknown")

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)

                    for ip_range in rule.get("IpRanges", []):
                        cidr = ip_range.get("CidrIp", "")

                        if cidr == "0.0.0.0/0":
                            # 检查是否是敏感端口
                            for port, service in self.SENSITIVE_PORTS.items():
                                if from_port <= port <= to_port:
                                    self._create_finding(
                                        vuln_type=CloudVulnType.AWS_SECURITY_GROUP,
                                        severity=CloudSeverity.HIGH,
                                        resource_type="SecurityGroup",
                                        resource_name=sg_name,
                                        resource_id=sg_id,
                                        region=self.region,
                                        title=f"安全组开放敏感端口到互联网: {service}({port})",
                                        description=(
                                            f"安全组 {sg_name} 允许从任意IP访问端口 {port} ({service})"
                                        ),
                                        remediation=(
                                            "1. 限制源IP范围\n"
                                            "2. 使用VPN或堡垒机\n"
                                            "3. 使用AWS Systems Manager Session Manager"
                                        ),
                                        evidence={"port": port, "service": service, "cidr": cidr},
                                        compliance=["CIS-AWS-4.1", "PCI-DSS-1.3.1"],
                                    )
                                    break

        except Exception as e:
            logger.error(f"安全组检查失败: {e}")

        return findings

    def check_rds_public(self) -> List[CloudFinding]:
        """检测公开访问的RDS实例"""
        findings = []

        try:
            rds = self._session.client("rds")
            instances = rds.describe_db_instances().get("DBInstances", [])

            for instance in instances:
                instance_id = instance["DBInstanceIdentifier"]

                if instance.get("PubliclyAccessible", False):
                    finding = self._create_finding(
                        vuln_type=CloudVulnType.AWS_RDS_PUBLIC,
                        severity=CloudSeverity.HIGH,
                        resource_type="RDSInstance",
                        resource_name=instance_id,
                        region=self.region,
                        title=f"RDS实例可公开访问: {instance_id}",
                        description=(
                            f"RDS实例 {instance_id} 配置为可公开访问，" "存在数据库泄露风险。"
                        ),
                        remediation=(
                            "1. 修改实例设置禁用公开访问\n" "2. 使用私有子网\n" "3. 限制安全组规则"
                        ),
                        evidence={
                            "engine": instance.get("Engine"),
                            "endpoint": instance.get("Endpoint", {}).get("Address"),
                        },
                        compliance=["CIS-AWS-2.3.1"],
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"RDS检查失败: {e}")

        return findings

    def check_cloudtrail(self) -> List[CloudFinding]:
        """检测CloudTrail配置"""
        findings = []

        try:
            cloudtrail = self._session.client("cloudtrail")
            trails = cloudtrail.describe_trails().get("trailList", [])

            if not trails:
                self._create_finding(
                    vuln_type=CloudVulnType.AWS_CLOUDTRAIL_DISABLED,
                    severity=CloudSeverity.HIGH,
                    resource_type="CloudTrail",
                    resource_name="N/A",
                    region=self.region,
                    title="CloudTrail未启用",
                    description="未配置CloudTrail，无法审计AWS API调用",
                    remediation="创建并启用CloudTrail跟踪",
                    compliance=["CIS-AWS-2.1", "HIPAA", "PCI-DSS"],
                )
                return findings

            for trail in trails:
                trail_name = trail["Name"]
                status = cloudtrail.get_trail_status(Name=trail_name)

                if not status.get("IsLogging", False):
                    self._create_finding(
                        vuln_type=CloudVulnType.AWS_CLOUDTRAIL_DISABLED,
                        severity=CloudSeverity.MEDIUM,
                        resource_type="CloudTrail",
                        resource_name=trail_name,
                        title=f"CloudTrail未启用日志记录: {trail_name}",
                        description="CloudTrail跟踪存在但未启用日志记录",
                        remediation="启用CloudTrail日志记录",
                        compliance=["CIS-AWS-2.1"],
                    )

        except Exception as e:
            logger.error(f"CloudTrail检查失败: {e}")

        return findings

    def check_ec2_metadata(self) -> List[CloudFinding]:
        """检测EC2元数据服务配置"""
        findings = []

        try:
            ec2 = self._session.client("ec2")
            instances = ec2.describe_instances().get("Reservations", [])

            for reservation in instances:
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]

                    metadata_options = instance.get("MetadataOptions", {})

                    # 检查IMDSv1是否启用
                    if metadata_options.get("HttpTokens") != "required":
                        self._create_finding(
                            vuln_type=CloudVulnType.AWS_EC2_METADATA,
                            severity=CloudSeverity.MEDIUM,
                            resource_type="EC2Instance",
                            resource_name=instance_id,
                            region=self.region,
                            title=f"EC2实例使用IMDSv1: {instance_id}",
                            description=(
                                "EC2实例允许使用不安全的IMDSv1元数据服务，"
                                "可能遭受SSRF攻击窃取凭证。"
                            ),
                            remediation=(
                                "1. 强制使用IMDSv2\n"
                                "2. 设置 HttpTokens=required\n"
                                "3. 减少HttpPutResponseHopLimit"
                            ),
                            evidence={"metadata_options": metadata_options},
                            compliance=["CIS-AWS-5.6"],
                        )

        except Exception as e:
            logger.error(f"EC2元数据检查失败: {e}")

        return findings


# 便捷函数
def scan_aws(region: str = "us-east-1", profile: str = None) -> Dict[str, Any]:
    """
    快速AWS安全扫描

    Args:
        region: AWS区域
        profile: AWS配置文件名

    Returns:
        扫描结果摘要
    """
    tester = AWSTester(config={"region": region, "profile": profile})
    findings = tester.scan()
    return tester.get_summary().to_dict()


__all__ = [
    "AWSTester",
    "scan_aws",
]
