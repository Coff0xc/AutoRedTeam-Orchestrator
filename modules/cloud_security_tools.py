#!/usr/bin/env python3
"""
云安全MCP工具注册模块
注册: Kubernetes安全检测、gRPC安全测试
"""

import logging

from utils.mcp_tooling import patch_mcp_tool

logger = logging.getLogger(__name__)


def register_cloud_security_tools(mcp):
    """注册云安全工具到MCP Server"""
    patch_mcp_tool(mcp)

    registered_tools = []

    # ========== Kubernetes安全工具 ==========

    @mcp.tool()
    def k8s_privileged_check(namespace: str = "default", kubeconfig: str = "") -> dict:
        """K8s特权容器检测 - 检查特权容器和危险能力

        检测内容:
            - privileged: true容器
            - 危险能力: SYS_ADMIN, SYS_PTRACE, NET_ADMIN等

        Args:
            namespace: 目标命名空间
            kubeconfig: kubeconfig文件路径 (可选)

        Returns:
            {
                "findings": [...],
                "privileged_count": int,
                "dangerous_caps_count": int
            }
        """
        try:
            from modules.cloud_security.kubernetes_enhanced import KubernetesSecurityTester

            tester = KubernetesSecurityTester(kubeconfig if kubeconfig else None)
            findings = tester.check_privileged_containers(namespace)

            privileged = sum(1 for f in findings if f.vuln_type.value == "privileged_container")
            caps = sum(1 for f in findings if f.vuln_type.value == "insecure_capability")

            return {
                "success": True,
                "namespace": namespace,
                "finding_count": len(findings),
                "privileged_count": privileged,
                "dangerous_caps_count": caps,
                "findings": [
                    {
                        "type": f.vuln_type.value,
                        "severity": f.severity.value,
                        "resource": f"{f.resource_type}/{f.resource_name}",
                        "title": f.title,
                        "remediation": f.remediation,
                    }
                    for f in findings
                ],
            }

        except ImportError as e:
            return {"success": False, "error": f"模块导入失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("k8s_privileged_check")

    @mcp.tool()
    def k8s_hostpath_check(namespace: str = "default", kubeconfig: str = "") -> dict:
        """K8s宿主机路径挂载检测 - 检查危险的hostPath挂载

        检测敏感路径:
            - /, /etc, /var/run/docker.sock
            - /proc, /sys, /dev
            - /root, /home

        Args:
            namespace: 目标命名空间
            kubeconfig: kubeconfig文件路径 (可选)

        Returns:
            {
                "findings": [...],
                "critical_mounts": int,
                "total_mounts": int
            }
        """
        try:
            from modules.cloud_security.kubernetes_enhanced import KubernetesSecurityTester

            tester = KubernetesSecurityTester(kubeconfig if kubeconfig else None)
            findings = tester.check_host_path_mounts(namespace)

            critical = sum(1 for f in findings if f.severity.value == "critical")

            return {
                "success": True,
                "namespace": namespace,
                "total_mounts": len(findings),
                "critical_mounts": critical,
                "findings": [
                    {
                        "severity": f.severity.value,
                        "resource": f"{f.resource_type}/{f.resource_name}",
                        "path": f.evidence.get("path", ""),
                        "title": f.title,
                        "remediation": f.remediation,
                    }
                    for f in findings
                ],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("k8s_hostpath_check")

    @mcp.tool()
    def k8s_rbac_audit(namespace: str = "default", kubeconfig: str = "") -> dict:
        """K8s RBAC权限审计 - 检查过度权限配置

        检测内容:
            - cluster-admin绑定
            - 高权限ClusterRole绑定
            - 危险RBAC规则

        Args:
            namespace: 目标命名空间
            kubeconfig: kubeconfig文件路径 (可选)

        Returns:
            {
                "findings": [...],
                "overpermission_count": int
            }
        """
        try:
            from modules.cloud_security.kubernetes_enhanced import KubernetesSecurityTester

            tester = KubernetesSecurityTester(kubeconfig if kubeconfig else None)
            findings = tester.check_rbac_permissions(namespace)

            return {
                "success": True,
                "namespace": namespace,
                "overpermission_count": len(findings),
                "findings": [
                    {
                        "type": f.vuln_type.value,
                        "severity": f.severity.value,
                        "resource": f"{f.resource_type}/{f.resource_name}",
                        "title": f.title,
                        "description": f.description,
                        "remediation": f.remediation,
                        "evidence": f.evidence,
                    }
                    for f in findings
                ],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("k8s_rbac_audit")

    @mcp.tool()
    def k8s_network_policy_check(namespace: str = "default", kubeconfig: str = "") -> dict:
        """K8s网络策略检查 - 检测缺失的NetworkPolicy

        Args:
            namespace: 目标命名空间
            kubeconfig: kubeconfig文件路径 (可选)

        Returns:
            {
                "has_network_policy": bool,
                "findings": [...]
            }
        """
        try:
            from modules.cloud_security.kubernetes_enhanced import KubernetesSecurityTester

            tester = KubernetesSecurityTester(kubeconfig if kubeconfig else None)
            findings = tester.check_network_policies(namespace)

            return {
                "success": True,
                "namespace": namespace,
                "has_network_policy": len(findings) == 0,
                "findings": [
                    {
                        "severity": f.severity.value,
                        "title": f.title,
                        "description": f.description,
                        "remediation": f.remediation,
                    }
                    for f in findings
                ],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("k8s_network_policy_check")

    @mcp.tool()
    def k8s_secrets_check(namespace: str = "default", kubeconfig: str = "") -> dict:
        """K8s敏感信息检查 - 检测环境变量中的硬编码敏感信息

        Args:
            namespace: 目标命名空间
            kubeconfig: kubeconfig文件路径 (可选)

        Returns:
            {
                "findings": [...],
                "exposed_secrets_count": int
            }
        """
        try:
            from modules.cloud_security.kubernetes_enhanced import KubernetesSecurityTester

            tester = KubernetesSecurityTester(kubeconfig if kubeconfig else None)
            findings = tester.check_secrets_in_env(namespace)

            return {
                "success": True,
                "namespace": namespace,
                "exposed_secrets_count": len(findings),
                "findings": [
                    {
                        "severity": f.severity.value,
                        "resource": f"{f.resource_type}/{f.resource_name}",
                        "title": f.title,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                    }
                    for f in findings
                ],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("k8s_secrets_check")

    @mcp.tool()
    def k8s_manifest_scan(file_path: str) -> dict:
        """K8s Manifest文件扫描 - 扫描YAML配置文件的安全问题

        扫描内容:
            - Pod/Deployment/DaemonSet等资源
            - 特权容器、危险能力、hostPath挂载

        Args:
            file_path: YAML manifest文件路径

        Returns:
            {
                "findings": [...],
                "total_issues": int
            }
        """
        try:
            from modules.cloud_security.kubernetes_enhanced import KubernetesSecurityTester

            tester = KubernetesSecurityTester()
            findings = tester.scan_manifest_file(file_path)

            return {
                "success": True,
                "file_path": file_path,
                "total_issues": len(findings),
                "findings": [
                    {
                        "type": f.vuln_type.value,
                        "severity": f.severity.value,
                        "resource": f"{f.resource_type}/{f.resource_name}",
                        "title": f.title,
                        "description": f.description,
                        "remediation": f.remediation,
                    }
                    for f in findings
                ],
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("k8s_manifest_scan")

    @mcp.tool()
    def k8s_full_scan(namespace: str = "default", kubeconfig: str = "") -> dict:
        """K8s完整安全扫描 - 执行所有K8s安全检测

        包含:
            - 特权容器检测
            - hostPath挂载检测
            - ServiceAccount Token检测
            - RBAC权限审计
            - NetworkPolicy检查
            - 敏感信息检测

        Args:
            namespace: 目标命名空间
            kubeconfig: kubeconfig文件路径 (可选)

        Returns:
            {
                "total_findings": int,
                "by_severity": {...},
                "by_type": {...},
                "findings": [...]
            }
        """
        try:
            from modules.cloud_security.kubernetes_enhanced import KubernetesSecurityTester

            tester = KubernetesSecurityTester(kubeconfig if kubeconfig else None)
            result = tester.full_scan(namespace)

            return {"success": True, **result}

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("k8s_full_scan")

    # ========== gRPC安全工具 ==========

    @mcp.tool()
    def grpc_reflection_test(target: str) -> dict:
        """gRPC反射API测试 - 检测是否启用反射API

        反射API可能泄露服务定义和方法列表

        Args:
            target: gRPC目标 (host:port 或 grpc://host:port)

        Returns:
            {
                "vulnerable": bool,
                "reflection_enabled": bool,
                "services": [...],
                "remediation": str
            }
        """
        try:
            from modules.cloud_security.grpc_security import GRPCSecurityTester

            tester = GRPCSecurityTester()
            return tester.test_reflection(target)

        except ImportError as e:
            return {"success": False, "error": f"模块导入失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("grpc_reflection_test")

    @mcp.tool()
    def grpc_tls_test(target: str) -> dict:
        """gRPC TLS配置测试 - 检测TLS加密配置

        检测内容:
            - 是否接受明文连接
            - TLS版本
            - 证书配置

        Args:
            target: gRPC目标 (host:port)

        Returns:
            {
                "vulnerable": bool,
                "tls_enabled": bool,
                "tls_version": str,
                "issues": [...],
                "remediation": str
            }
        """
        try:
            from modules.cloud_security.grpc_security import GRPCSecurityTester

            tester = GRPCSecurityTester()
            return tester.test_tls(target)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("grpc_tls_test")

    @mcp.tool()
    def grpc_auth_test(target: str) -> dict:
        """gRPC认证绕过测试 - 检测认证机制

        测试无认证和伪造Token的请求

        Args:
            target: gRPC目标 (host:port)

        Returns:
            {
                "vulnerable": bool,
                "auth_required": bool,
                "tests": [...],
                "remediation": str
            }
        """
        try:
            from modules.cloud_security.grpc_security import GRPCSecurityTester

            tester = GRPCSecurityTester()
            return tester.test_auth_bypass(target)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("grpc_auth_test")

    @mcp.tool()
    def grpc_full_scan(target: str) -> dict:
        """gRPC完整安全扫描 - 执行所有gRPC安全测试

        包含:
            - TLS配置检测
            - 反射API检测
            - 认证绕过测试
            - Metadata注入测试

        Args:
            target: gRPC目标 (host:port)

        Returns:
            {
                "vulnerabilities": [...],
                "tests": {...},
                "summary": {...},
                "recommendations": [...]
            }
        """
        try:
            from modules.cloud_security.grpc_security import GRPCSecurityTester

            tester = GRPCSecurityTester()
            return tester.full_scan(target)

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("grpc_full_scan")

    logger.info(f"已注册 {len(registered_tools)} 个云安全工具")
    return registered_tools
