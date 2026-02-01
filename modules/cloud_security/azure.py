#!/usr/bin/env python3
"""
Azure安全测试模块

提供Azure云环境安全检测功能，包括:
- 存储账户安全检测
- RBAC权限审计
- 网络安全组检测
- Key Vault安全检测
- Azure AD配置检测
- SQL防火墙检测

作者: AutoRedTeam
版本: 3.0.0
"""

import logging
from typing import Any, Dict, List, Optional

from .base import (
    BaseCloudTester,
    CloudFinding,
    CloudSeverity,
    CloudVulnType,
)

logger = logging.getLogger(__name__)

# 尝试导入Azure SDK
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient

    HAS_AZURE_SDK = True
except ImportError:
    HAS_AZURE_SDK = False


class AzureTester(BaseCloudTester):
    """
    Azure安全测试器

    对Azure云资源进行安全扫描。

    使用示例:
        tester = AzureTester(config={
            'subscription_id': 'your-subscription-id'
        })
        findings = tester.scan()
    """

    name = "azure"
    provider = "azure"
    description = "Azure安全测试器"
    version = "3.0.0"

    # 危险NSG端口
    SENSITIVE_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
    }

    # 危险RBAC角色
    DANGEROUS_ROLES = [
        "Owner",
        "Contributor",
        "User Access Administrator",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化Azure测试器

        Args:
            config: 可选配置，可包含:
                - subscription_id: Azure订阅ID
                - tenant_id: Azure租户ID
                - resource_group: 资源组名称
        """
        super().__init__(config)

        if not HAS_AZURE_SDK:
            logger.warning("Azure SDK未安装，Azure扫描功能受限")
            return

        self.subscription_id = self.config.get("subscription_id")
        self.tenant_id = self.config.get("tenant_id")
        self.resource_group = self.config.get("resource_group")

        if not self.subscription_id:
            logger.warning("未提供Azure订阅ID")
            self._credential = None
            return

        try:
            self._credential = DefaultAzureCredential()
        except Exception as e:
            logger.error(f"Azure认证失败: {e}")
            self._credential = None

    def scan(self) -> List[CloudFinding]:
        """执行完整的Azure安全扫描"""
        self.clear_findings()

        if not HAS_AZURE_SDK or not self._credential:
            logger.warning("无法执行Azure扫描：SDK未初始化或认证失败")
            return self._findings

        try:
            # 执行各项检查
            self.check_storage_accounts()
            self.check_network_security_groups()
            self.check_key_vaults()
            self.check_rbac_assignments()
            self.check_sql_firewalls()

        except Exception as e:
            logger.error(f"Azure扫描失败: {e}")

        return self._findings

    def check_storage_accounts(self) -> List[CloudFinding]:
        """检测存储账户安全配置"""
        findings = []

        try:
            storage_client = StorageManagementClient(self._credential, self.subscription_id)

            accounts = storage_client.storage_accounts.list()

            for account in accounts:
                account_name = account.name
                resource_group = account.id.split("/")[4]

                # 检查是否允许公共Blob访问
                if account.allow_blob_public_access:
                    finding = self._create_finding(
                        vuln_type=CloudVulnType.AZURE_STORAGE_PUBLIC,
                        severity=CloudSeverity.HIGH,
                        resource_type="StorageAccount",
                        resource_name=account_name,
                        title=f"存储账户允许公共Blob访问: {account_name}",
                        description=(
                            f"存储账户 {account_name} 允许公共Blob访问，" "可能导致数据泄露。"
                        ),
                        remediation=(
                            "1. 禁用公共Blob访问\n"
                            "2. 使用SAS令牌或Azure AD进行访问控制\n"
                            "3. 配置私有终结点"
                        ),
                        evidence={
                            "allow_blob_public_access": True,
                            "resource_group": resource_group,
                        },
                        compliance=["CIS-Azure-3.1", "HIPAA"],
                    )
                    findings.append(finding)

                # 检查HTTPS传输
                if not account.enable_https_traffic_only:
                    self._create_finding(
                        vuln_type=CloudVulnType.AZURE_STORAGE_PUBLIC,
                        severity=CloudSeverity.MEDIUM,
                        resource_type="StorageAccount",
                        resource_name=account_name,
                        title=f"存储账户允许HTTP访问: {account_name}",
                        description="存储账户未强制使用HTTPS",
                        remediation='启用"需要安全传输"选项',
                        evidence={"enable_https_only": False},
                    )

                # 检查加密
                encryption = account.encryption
                if not encryption or not encryption.key_source:
                    self._create_finding(
                        vuln_type=CloudVulnType.AZURE_STORAGE_PUBLIC,
                        severity=CloudSeverity.MEDIUM,
                        resource_type="StorageAccount",
                        resource_name=account_name,
                        title=f"存储账户加密配置不完整: {account_name}",
                        description="存储账户加密配置不完整",
                        remediation="确保启用存储加密",
                        evidence={},
                    )

        except Exception as e:
            logger.error(f"存储账户检查失败: {e}")

        return findings

    def check_network_security_groups(self) -> List[CloudFinding]:
        """检测网络安全组配置"""
        findings = []

        try:
            network_client = NetworkManagementClient(self._credential, self.subscription_id)

            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                nsg_name = nsg.name
                nsg_id = nsg.id

                for rule in nsg.security_rules or []:
                    if rule.direction != "Inbound" or rule.access != "Allow":
                        continue

                    source = rule.source_address_prefix or ""

                    # 检查是否允许任意来源
                    if source in ["*", "Internet", "0.0.0.0/0"]:
                        dest_port = rule.destination_port_range

                        # 检查敏感端口
                        for port, service in self.SENSITIVE_PORTS.items():
                            if dest_port == "*" or dest_port == str(port):
                                self._create_finding(
                                    vuln_type=CloudVulnType.AZURE_NSG_WIDE_OPEN,
                                    severity=CloudSeverity.HIGH,
                                    resource_type="NetworkSecurityGroup",
                                    resource_name=nsg_name,
                                    resource_id=nsg_id,
                                    title=f"NSG开放敏感端口到互联网: {service}({port})",
                                    description=(
                                        f"NSG {nsg_name} 的规则 {rule.name} "
                                        f"允许从互联网访问端口 {port} ({service})"
                                    ),
                                    remediation=(
                                        "1. 限制源地址范围\n"
                                        "2. 使用Azure Bastion\n"
                                        "3. 配置Just-In-Time访问"
                                    ),
                                    evidence={
                                        "rule_name": rule.name,
                                        "port": port,
                                        "source": source,
                                    },
                                    compliance=["CIS-Azure-6.1"],
                                )
                                break

        except Exception as e:
            logger.error(f"NSG检查失败: {e}")

        return findings

    def check_key_vaults(self) -> List[CloudFinding]:
        """检测Key Vault安全配置"""
        findings = []

        try:
            kv_client = KeyVaultManagementClient(self._credential, self.subscription_id)

            vaults = kv_client.vaults.list()

            for vault in vaults:
                vault_name = vault.name
                properties = vault.properties

                # 检查软删除
                if not properties.enable_soft_delete:
                    self._create_finding(
                        vuln_type=CloudVulnType.AZURE_KEY_VAULT,
                        severity=CloudSeverity.MEDIUM,
                        resource_type="KeyVault",
                        resource_name=vault_name,
                        title=f"Key Vault未启用软删除: {vault_name}",
                        description="Key Vault未启用软删除保护",
                        remediation="启用软删除以防止意外删除",
                        compliance=["CIS-Azure-8.4"],
                    )

                # 检查清除保护
                if not properties.enable_purge_protection:
                    self._create_finding(
                        vuln_type=CloudVulnType.AZURE_KEY_VAULT,
                        severity=CloudSeverity.MEDIUM,
                        resource_type="KeyVault",
                        resource_name=vault_name,
                        title=f"Key Vault未启用清除保护: {vault_name}",
                        description="Key Vault未启用清除保护",
                        remediation="启用清除保护以增强安全性",
                    )

                # 检查网络规则
                network_acls = properties.network_acls
                if network_acls and network_acls.default_action == "Allow":
                    self._create_finding(
                        vuln_type=CloudVulnType.AZURE_KEY_VAULT,
                        severity=CloudSeverity.HIGH,
                        resource_type="KeyVault",
                        resource_name=vault_name,
                        title=f"Key Vault允许公共网络访问: {vault_name}",
                        description="Key Vault的默认网络规则允许所有网络访问",
                        remediation="配置网络规则，限制访问来源",
                        compliance=["CIS-Azure-8.6"],
                    )

        except Exception as e:
            logger.error(f"Key Vault检查失败: {e}")

        return findings

    def check_rbac_assignments(self) -> List[CloudFinding]:
        """检测RBAC权限分配"""
        findings = []

        try:
            auth_client = AuthorizationManagementClient(self._credential, self.subscription_id)

            # 获取所有角色分配
            assignments = auth_client.role_assignments.list()

            for assignment in assignments:
                # 获取角色定义
                role_def_id = assignment.role_definition_id
                principal_id = assignment.principal_id
                scope = assignment.scope

                try:
                    role_def = auth_client.role_definitions.get_by_id(role_def_id)
                    role_name = role_def.role_name

                    # 检查危险角色
                    if role_name in self.DANGEROUS_ROLES:
                        # 检查是否在订阅级别
                        if scope == f"/subscriptions/{self.subscription_id}":
                            self._create_finding(
                                vuln_type=CloudVulnType.AZURE_RBAC_OVERPERMISSION,
                                severity=CloudSeverity.HIGH,
                                resource_type="RoleAssignment",
                                resource_name=assignment.name,
                                title=f"订阅级别的高权限角色分配: {role_name}",
                                description=(
                                    f"Principal {principal_id} 被分配了订阅级别的 {role_name} 角色"
                                ),
                                remediation=(
                                    "1. 使用最小权限原则\n"
                                    "2. 在资源组级别分配权限\n"
                                    "3. 创建自定义角色"
                                ),
                                evidence={
                                    "role_name": role_name,
                                    "principal_id": principal_id,
                                    "scope": scope,
                                },
                                compliance=["CIS-Azure-1.23"],
                            )

                except (KeyError, TypeError, ValueError):
                    continue

        except Exception as e:
            logger.error(f"RBAC检查失败: {e}")

        return findings

    def check_sql_firewalls(self) -> List[CloudFinding]:
        """检测SQL Server防火墙规则"""
        findings = []

        try:
            # 注意：需要azure-mgmt-sql包
            from azure.mgmt.sql import SqlManagementClient

            sql_client = SqlManagementClient(self._credential, self.subscription_id)

            servers = sql_client.servers.list()

            for server in servers:
                server_name = server.name
                resource_group = server.id.split("/")[4]

                # 获取防火墙规则
                rules = sql_client.firewall_rules.list_by_server(resource_group, server_name)

                for rule in rules:
                    start_ip = rule.start_ip_address
                    end_ip = rule.end_ip_address

                    # 检查是否允许所有Azure服务
                    if start_ip == "0.0.0.0" and end_ip == "0.0.0.0":
                        self._create_finding(
                            vuln_type=CloudVulnType.AZURE_SQL_FIREWALL,
                            severity=CloudSeverity.MEDIUM,
                            resource_type="SQLServer",
                            resource_name=server_name,
                            title=f"SQL Server允许所有Azure服务访问: {server_name}",
                            description="防火墙规则允许所有Azure服务访问",
                            remediation="仅允许特定的Azure服务访问",
                            evidence={"rule_name": rule.name},
                        )

                    # 检查是否开放所有IP
                    if start_ip == "0.0.0.0" and end_ip == "255.255.255.255":
                        self._create_finding(
                            vuln_type=CloudVulnType.AZURE_SQL_FIREWALL,
                            severity=CloudSeverity.CRITICAL,
                            resource_type="SQLServer",
                            resource_name=server_name,
                            title=f"SQL Server防火墙完全开放: {server_name}",
                            description="防火墙规则允许所有IP地址访问",
                            remediation="限制防火墙规则，仅允许必要的IP",
                            evidence={
                                "rule_name": rule.name,
                                "start_ip": start_ip,
                                "end_ip": end_ip,
                            },
                            compliance=["CIS-Azure-4.1.1"],
                        )

        except ImportError:
            logger.debug("azure-mgmt-sql未安装，跳过SQL检查")
        except Exception as e:
            logger.error(f"SQL防火墙检查失败: {e}")

        return findings


# 便捷函数
def scan_azure(subscription_id: str) -> Dict[str, Any]:
    """
    快速Azure安全扫描

    Args:
        subscription_id: Azure订阅ID

    Returns:
        扫描结果摘要
    """
    tester = AzureTester(config={"subscription_id": subscription_id})
    findings = tester.scan()
    return tester.get_summary().to_dict()


__all__ = [
    "AzureTester",
    "scan_azure",
]
