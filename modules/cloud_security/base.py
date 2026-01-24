#!/usr/bin/env python3
"""
云安全测试基类模块

提供统一的云安全测试接口、结果数据结构和漏洞类型定义。
所有云安全测试器都应继承自BaseCloudTester。

作者: AutoRedTeam
版本: 3.0.0
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import asyncio
import logging

logger = logging.getLogger(__name__)


class CloudVulnType(Enum):
    """云安全漏洞类型枚举"""

    # Kubernetes相关
    K8S_PRIVILEGED_CONTAINER = 'k8s_privileged_container'
    K8S_HOST_PATH_MOUNT = 'k8s_host_path_mount'
    K8S_SENSITIVE_MOUNT = 'k8s_sensitive_mount'
    K8S_INSECURE_CAPABILITY = 'k8s_insecure_capability'
    K8S_RBAC_OVERPERMISSION = 'k8s_rbac_overpermission'
    K8S_SERVICE_ACCOUNT_TOKEN = 'k8s_service_account_token'
    K8S_NETWORK_POLICY_MISSING = 'k8s_network_policy_missing'
    K8S_SECRET_EXPOSURE = 'k8s_secret_exposure'
    K8S_POD_SECURITY_POLICY = 'k8s_pod_security_policy'
    K8S_CONTAINER_ESCAPE = 'k8s_container_escape'

    # AWS相关
    AWS_S3_PUBLIC = 'aws_s3_public_bucket'
    AWS_S3_ACL_MISCONFIGURED = 'aws_s3_acl_misconfigured'
    AWS_IAM_OVERPERMISSION = 'aws_iam_overpermission'
    AWS_IAM_WILDCARD = 'aws_iam_wildcard'
    AWS_IAM_ROOT_USAGE = 'aws_iam_root_usage'
    AWS_EC2_METADATA = 'aws_ec2_metadata_exposed'
    AWS_RDS_PUBLIC = 'aws_rds_public'
    AWS_SECURITY_GROUP = 'aws_security_group_wide_open'
    AWS_CLOUDTRAIL_DISABLED = 'aws_cloudtrail_disabled'
    AWS_KMS_KEY_ROTATION = 'aws_kms_key_rotation_disabled'

    # Azure相关
    AZURE_STORAGE_PUBLIC = 'azure_storage_public'
    AZURE_RBAC_OVERPERMISSION = 'azure_rbac_overpermission'
    AZURE_NSG_WIDE_OPEN = 'azure_nsg_wide_open'
    AZURE_KEY_VAULT = 'azure_key_vault_misconfigured'
    AZURE_AD_MISCONFIGURED = 'azure_ad_misconfigured'
    AZURE_SQL_FIREWALL = 'azure_sql_firewall_open'

    # GCP相关
    GCP_STORAGE_PUBLIC = 'gcp_storage_public'
    GCP_IAM_OVERPERMISSION = 'gcp_iam_overpermission'
    GCP_FIREWALL_WIDE_OPEN = 'gcp_firewall_wide_open'
    GCP_SERVICE_ACCOUNT = 'gcp_service_account_key_exposed'

    # gRPC相关
    GRPC_REFLECTION_ENABLED = 'grpc_reflection_enabled'
    GRPC_NO_TLS = 'grpc_no_tls'
    GRPC_AUTH_MISSING = 'grpc_auth_missing'
    GRPC_INSECURE_CHANNEL = 'grpc_insecure_channel'

    # 通用云安全
    CLOUD_METADATA_EXPOSED = 'cloud_metadata_exposed'
    CLOUD_SSRF = 'cloud_ssrf'
    CLOUD_CREDENTIAL_LEAK = 'cloud_credential_leak'


class CloudSeverity(Enum):
    """云安全漏洞严重性"""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

    @property
    def score(self) -> int:
        """获取严重性分数"""
        scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        return scores.get(self.value, 0)

    def __lt__(self, other: 'CloudSeverity') -> bool:
        return self.score < other.score

    def __gt__(self, other: 'CloudSeverity') -> bool:
        return self.score > other.score


@dataclass
class CloudFinding:
    """云安全发现"""
    vuln_type: CloudVulnType
    severity: CloudSeverity
    resource_type: str
    resource_name: str
    resource_id: str = ''
    region: str = ''
    title: str = ''
    description: str = ''
    remediation: str = ''
    evidence: Dict[str, Any] = field(default_factory=dict)
    compliance: List[str] = field(default_factory=list)  # 合规标准引用

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'vuln_type': self.vuln_type.value,
            'severity': self.severity.value,
            'resource_type': self.resource_type,
            'resource_name': self.resource_name,
            'resource_id': self.resource_id,
            'region': self.region,
            'title': self.title,
            'description': self.description,
            'remediation': self.remediation,
            'evidence': self.evidence,
            'compliance': self.compliance
        }


@dataclass
class CloudScanSummary:
    """云安全扫描摘要"""
    provider: str
    target: str
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_type: Dict[str, int] = field(default_factory=dict)
    findings: List[CloudFinding] = field(default_factory=list)
    scan_duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'provider': self.provider,
            'target': self.target,
            'total_findings': self.total_findings,
            'findings_by_severity': self.findings_by_severity,
            'findings_by_type': self.findings_by_type,
            'findings': [f.to_dict() for f in self.findings],
            'scan_duration': self.scan_duration
        }


class BaseCloudTester(ABC):
    """
    云安全测试基类

    所有云安全测试器都应继承此类并实现scan()方法。

    使用示例:
        class MyCloudTester(BaseCloudTester):
            name = 'my_cloud_tester'
            provider = 'aws'

            def scan(self) -> List[CloudFinding]:
                # 实现扫描逻辑
                return self._findings
    """

    # 子类应覆盖这些属性
    name: str = 'base'
    provider: str = 'generic'
    description: str = 'Base Cloud Security Tester'
    version: str = '1.0.0'

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化测试器

        Args:
            config: 可选配置字典
        """
        self.config = config or {}
        self._findings: List[CloudFinding] = []

        # 通用配置
        self.timeout = self.config.get('timeout', 30)

    @abstractmethod
    def scan(self) -> List[CloudFinding]:
        """
        执行扫描（子类必须实现）

        Returns:
            扫描发现列表
        """
        pass

    async def async_scan(self) -> List[CloudFinding]:
        """
        异步执行扫描

        默认实现使用线程池运行同步scan()方法。
        子类可以覆盖此方法提供真正的异步实现。

        Returns:
            扫描发现列表
        """
        return await asyncio.to_thread(self.scan)

    def _add_finding(self, finding: CloudFinding) -> None:
        """添加扫描发现"""
        self._findings.append(finding)
        logger.info(
            f"[{self.name}] 发现问题: {finding.vuln_type.value} "
            f"- {finding.severity.value} - {finding.resource_name}"
        )

    def _create_finding(
        self,
        vuln_type: CloudVulnType,
        severity: CloudSeverity,
        resource_type: str,
        resource_name: str,
        title: str = '',
        description: str = '',
        remediation: str = '',
        **kwargs
    ) -> CloudFinding:
        """创建并添加发现的便捷方法"""
        finding = CloudFinding(
            vuln_type=vuln_type,
            severity=severity,
            resource_type=resource_type,
            resource_name=resource_name,
            title=title,
            description=description,
            remediation=remediation,
            **kwargs
        )
        self._add_finding(finding)
        return finding

    @property
    def findings(self) -> List[CloudFinding]:
        """获取扫描发现"""
        return self._findings

    def clear_findings(self) -> None:
        """清空扫描发现"""
        self._findings = []

    def get_summary(self) -> CloudScanSummary:
        """获取扫描摘要"""
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}

        for finding in self._findings:
            # 按严重性统计
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            # 按类型统计
            vtype = finding.vuln_type.value
            by_type[vtype] = by_type.get(vtype, 0) + 1

        return CloudScanSummary(
            provider=self.provider,
            target=self.config.get('target', ''),
            total_findings=len(self._findings),
            findings_by_severity=by_severity,
            findings_by_type=by_type,
            findings=self._findings
        )

    def generate_report(self) -> str:
        """生成扫描报告"""
        summary = self.get_summary()

        lines = [
            "=" * 60,
            f"{self.provider.upper()} 云安全扫描报告",
            "=" * 60,
            f"目标: {summary.target}",
            f"发现问题数: {summary.total_findings}",
            "",
            "-" * 60,
            "严重性分布:",
            "-" * 60,
        ]

        for sev, count in sorted(summary.findings_by_severity.items()):
            icon = {'critical': '[!]', 'high': '[+]', 'medium': '[*]', 'low': '[-]', 'info': '[i]'}.get(sev, '[ ]')
            lines.append(f"  {icon} {sev.upper()}: {count}")

        lines.extend([
            "",
            "-" * 60,
            "问题详情:",
            "-" * 60,
        ])

        for finding in self._findings:
            severity_icon = {
                'critical': '[CRITICAL]',
                'high': '[HIGH]',
                'medium': '[MEDIUM]',
                'low': '[LOW]',
                'info': '[INFO]'
            }.get(finding.severity.value, '[?]')

            lines.extend([
                f"{severity_icon} {finding.title}",
                f"   资源: {finding.resource_type}/{finding.resource_name}",
                f"   描述: {finding.description}",
                f"   修复: {finding.remediation}",
                ""
            ])

        lines.append("=" * 60)

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider='{self.provider}'>"


# 导出
__all__ = [
    'CloudVulnType',
    'CloudSeverity',
    'CloudFinding',
    'CloudScanSummary',
    'BaseCloudTester',
]
