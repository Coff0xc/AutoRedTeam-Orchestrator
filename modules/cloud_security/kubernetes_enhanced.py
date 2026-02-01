#!/usr/bin/env python3
"""
Kubernetes安全增强检测模块
检测: Pod逃逸、RBAC配置、敏感挂载、网络策略
作者: AutoRedTeam
"""

import json
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class K8sVulnType(Enum):
    """K8s漏洞类型"""

    POD_ESCAPE = "pod_escape"
    PRIVILEGED_CONTAINER = "privileged_container"
    HOST_PATH_MOUNT = "host_path_mount"
    SENSITIVE_MOUNT = "sensitive_mount"
    RBAC_OVERPERMISSION = "rbac_overpermission"
    SERVICE_ACCOUNT_TOKEN = "service_account_token"
    NETWORK_POLICY_MISSING = "network_policy_missing"
    SECRET_EXPOSURE = "secret_exposure"
    IMAGE_VULNERABILITY = "image_vulnerability"
    INSECURE_CAPABILITY = "insecure_capability"


class K8sSeverity(Enum):
    """严重性"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class K8sFinding:
    """K8s安全发现"""

    vuln_type: K8sVulnType
    severity: K8sSeverity
    resource_type: str
    resource_name: str
    namespace: str
    title: str
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class KubernetesSecurityTester:
    """Kubernetes安全测试器"""

    # 危险能力列表
    DANGEROUS_CAPABILITIES = [
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "NET_ADMIN",
        "NET_RAW",
        "SYS_RAWIO",
        "MKNOD",
    ]

    # 敏感挂载路径
    SENSITIVE_PATHS = [
        "/",
        "/etc",
        "/etc/shadow",
        "/etc/passwd",
        "/var/run/docker.sock",
        "/var/run/crio/crio.sock",
        "/var/run/containerd/containerd.sock",
        "/proc",
        "/sys",
        "/dev",
        "/root",
        "/home",
    ]

    # 危险RBAC规则
    DANGEROUS_RBAC_RULES = [
        {"verbs": ["*"], "resources": ["*"]},  # 通配权限
        {"verbs": ["create"], "resources": ["pods"]},  # Pod创建
        {"verbs": ["create"], "resources": ["pods/exec"]},  # Pod exec
        {"verbs": ["get"], "resources": ["secrets"]},  # Secret读取
        {"verbs": ["list"], "resources": ["secrets"]},
        {"verbs": ["create", "patch"], "resources": ["daemonsets"]},
        {"verbs": ["create", "patch"], "resources": ["deployments"]},
        {"verbs": ["impersonate"], "resources": ["users", "groups"]},
    ]

    def __init__(self, kubeconfig: Optional[str] = None):
        """
        初始化K8s安全测试器

        Args:
            kubeconfig: kubeconfig文件路径
        """
        self.kubeconfig = kubeconfig
        self._findings: List[K8sFinding] = []

    def _run_kubectl(self, args: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """执行kubectl命令"""
        cmd = ["kubectl"]

        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])

        cmd.extend(args)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except FileNotFoundError:
            return False, "kubectl not found"
        except Exception as e:
            return False, str(e)

    def _parse_yaml_manifest(self, content: str) -> List[Dict]:
        """解析YAML manifest"""
        try:
            import yaml

            docs = list(yaml.safe_load_all(content))
            return [d for d in docs if d is not None]
        except ImportError:
            # 简单解析
            return self._simple_yaml_parse(content)
        except yaml.YAMLError:
            return []

    def _simple_yaml_parse(self, content: str) -> List[Dict]:
        """简单YAML解析 (备用)"""
        # 基础实现，仅用于没有PyYAML的情况
        docs = []
        current_doc = {}

        for line in content.split("\n"):
            if line.strip() == "---":
                if current_doc:
                    docs.append(current_doc)
                    current_doc = {}
                continue

            if ":" in line and not line.strip().startswith("#"):
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if value:
                    current_doc[key] = value

        if current_doc:
            docs.append(current_doc)

        return docs

    def check_privileged_containers(self, namespace: str = "default") -> List[K8sFinding]:
        """检查特权容器"""
        findings = []

        success, output = self._run_kubectl(["get", "pods", "-n", namespace, "-o", "json"])

        if not success:
            logger.warning(f"无法获取Pod列表: {output}")
            return findings

        try:
            data = json.loads(output)

            for pod in data.get("items", []):
                pod_name = pod.get("metadata", {}).get("name", "unknown")

                for container in pod.get("spec", {}).get("containers", []):
                    container_name = container.get("name", "unknown")
                    security_context = container.get("securityContext", {})

                    # 检查特权模式
                    if security_context.get("privileged", False):
                        findings.append(
                            K8sFinding(
                                vuln_type=K8sVulnType.PRIVILEGED_CONTAINER,
                                severity=K8sSeverity.CRITICAL,
                                resource_type="Pod",
                                resource_name=pod_name,
                                namespace=namespace,
                                title=f"特权容器: {container_name}",
                                description="容器以特权模式运行,可能导致容器逃逸",
                                remediation="移除privileged: true配置,使用最小权限原则",
                                evidence={"container": container_name},
                            )
                        )

                    # 检查危险能力
                    capabilities = security_context.get("capabilities", {})
                    add_caps = capabilities.get("add", [])

                    for cap in add_caps:
                        if cap in self.DANGEROUS_CAPABILITIES:
                            findings.append(
                                K8sFinding(
                                    vuln_type=K8sVulnType.INSECURE_CAPABILITY,
                                    severity=K8sSeverity.HIGH,
                                    resource_type="Pod",
                                    resource_name=pod_name,
                                    namespace=namespace,
                                    title=f"危险能力: {cap}",
                                    description=f"容器添加了危险能力{cap},可能导致安全风险",
                                    remediation="移除不必要的能力,仅保留必需权限",
                                    evidence={"container": container_name, "capability": cap},
                                )
                            )

        except json.JSONDecodeError:
            logger.error("解析Pod JSON失败")

        return findings

    def check_host_path_mounts(self, namespace: str = "default") -> List[K8sFinding]:
        """检查宿主机路径挂载"""
        findings = []

        success, output = self._run_kubectl(["get", "pods", "-n", namespace, "-o", "json"])

        if not success:
            return findings

        try:
            data = json.loads(output)

            for pod in data.get("items", []):
                pod_name = pod.get("metadata", {}).get("name", "unknown")
                volumes = pod.get("spec", {}).get("volumes", [])

                for volume in volumes:
                    host_path = volume.get("hostPath", {})
                    if host_path:
                        path = host_path.get("path", "")
                        volume_name = volume.get("name", "unknown")

                        # 判断敏感级别
                        severity = K8sSeverity.MEDIUM
                        for sensitive_path in self.SENSITIVE_PATHS[:7]:  # 前7个最危险
                            if path == sensitive_path or path.startswith(sensitive_path + "/"):
                                severity = K8sSeverity.CRITICAL
                                break

                        findings.append(
                            K8sFinding(
                                vuln_type=K8sVulnType.HOST_PATH_MOUNT,
                                severity=severity,
                                resource_type="Pod",
                                resource_name=pod_name,
                                namespace=namespace,
                                title=f"宿主机路径挂载: {path}",
                                description=f"Pod挂载了宿主机路径{path},可能导致信息泄露或容器逃逸",
                                remediation="避免挂载宿主机路径,使用PVC或ConfigMap/Secret",
                                evidence={"volume": volume_name, "path": path},
                            )
                        )

        except json.JSONDecodeError:
            pass

        return findings

    def check_service_account_tokens(self, namespace: str = "default") -> List[K8sFinding]:
        """检查ServiceAccount Token自动挂载"""
        findings = []

        success, output = self._run_kubectl(["get", "pods", "-n", namespace, "-o", "json"])

        if not success:
            return findings

        try:
            data = json.loads(output)

            for pod in data.get("items", []):
                pod_name = pod.get("metadata", {}).get("name", "unknown")
                spec = pod.get("spec", {})

                # 检查是否自动挂载SA Token
                automount = spec.get("automountServiceAccountToken", True)

                if automount:
                    sa_name = spec.get("serviceAccountName", "default")

                    findings.append(
                        K8sFinding(
                            vuln_type=K8sVulnType.SERVICE_ACCOUNT_TOKEN,
                            severity=K8sSeverity.MEDIUM,
                            resource_type="Pod",
                            resource_name=pod_name,
                            namespace=namespace,
                            title=f"自动挂载ServiceAccount Token",
                            description=f"Pod自动挂载了{sa_name}的Token,可能被攻击者利用",
                            remediation="设置automountServiceAccountToken: false,仅在需要时挂载",
                            evidence={"service_account": sa_name},
                        )
                    )

        except json.JSONDecodeError:
            pass

        return findings

    def check_rbac_permissions(self, namespace: str = "default") -> List[K8sFinding]:
        """检查RBAC权限配置"""
        findings = []

        # 获取ClusterRoleBindings
        success, output = self._run_kubectl(["get", "clusterrolebindings", "-o", "json"])

        if success:
            try:
                data = json.loads(output)

                for binding in data.get("items", []):
                    binding_name = binding.get("metadata", {}).get("name", "unknown")
                    role_ref = binding.get("roleRef", {})
                    subjects = binding.get("subjects", [])

                    # 检查是否绑定到cluster-admin
                    if role_ref.get("name") == "cluster-admin":
                        for subject in subjects:
                            if subject.get("kind") == "ServiceAccount":
                                findings.append(
                                    K8sFinding(
                                        vuln_type=K8sVulnType.RBAC_OVERPERMISSION,
                                        severity=K8sSeverity.CRITICAL,
                                        resource_type="ClusterRoleBinding",
                                        resource_name=binding_name,
                                        namespace="cluster",
                                        title=f"ServiceAccount绑定cluster-admin",
                                        description="ServiceAccount拥有集群管理员权限,风险极高",
                                        remediation="使用最小权限原则,创建自定义Role",
                                        evidence={
                                            "subject": subject.get("name"),
                                            "namespace": subject.get("namespace", "default"),
                                        },
                                    )
                                )

            except json.JSONDecodeError:
                pass

        # 获取RoleBindings
        success, output = self._run_kubectl(["get", "rolebindings", "-n", namespace, "-o", "json"])

        if success:
            try:
                data = json.loads(output)

                for binding in data.get("items", []):
                    binding_name = binding.get("metadata", {}).get("name", "unknown")
                    role_ref = binding.get("roleRef", {})

                    # 检查是否绑定危险Role
                    if role_ref.get("kind") == "ClusterRole":
                        role_name = role_ref.get("name", "")
                        if role_name in ["admin", "edit", "cluster-admin"]:
                            findings.append(
                                K8sFinding(
                                    vuln_type=K8sVulnType.RBAC_OVERPERMISSION,
                                    severity=K8sSeverity.HIGH,
                                    resource_type="RoleBinding",
                                    resource_name=binding_name,
                                    namespace=namespace,
                                    title=f"绑定高权限ClusterRole: {role_name}",
                                    description=f"RoleBinding引用了高权限的{role_name}角色",
                                    remediation="创建自定义Role,仅授予必要权限",
                                    evidence={"role": role_name},
                                )
                            )

            except json.JSONDecodeError:
                pass

        return findings

    def check_network_policies(self, namespace: str = "default") -> List[K8sFinding]:
        """检查网络策略"""
        findings = []

        # 获取命名空间的NetworkPolicy
        success, output = self._run_kubectl(
            ["get", "networkpolicies", "-n", namespace, "-o", "json"]
        )

        if not success:
            return findings

        try:
            data = json.loads(output)
            policies = data.get("items", [])

            if not policies:
                findings.append(
                    K8sFinding(
                        vuln_type=K8sVulnType.NETWORK_POLICY_MISSING,
                        severity=K8sSeverity.MEDIUM,
                        resource_type="Namespace",
                        resource_name=namespace,
                        namespace=namespace,
                        title="缺少NetworkPolicy",
                        description="命名空间没有定义NetworkPolicy,所有Pod间可以自由通信",
                        remediation="定义NetworkPolicy限制Pod间网络访问",
                        evidence={},
                    )
                )

        except json.JSONDecodeError:
            pass

        return findings

    def check_secrets_in_env(self, namespace: str = "default") -> List[K8sFinding]:
        """检查环境变量中的敏感信息"""
        findings = []

        success, output = self._run_kubectl(["get", "pods", "-n", namespace, "-o", "json"])

        if not success:
            return findings

        try:
            data = json.loads(output)

            # 敏感关键词
            sensitive_keywords = [
                "password",
                "passwd",
                "pwd",
                "secret",
                "api_key",
                "apikey",
                "token",
                "credential",
            ]

            for pod in data.get("items", []):
                pod_name = pod.get("metadata", {}).get("name", "unknown")

                for container in pod.get("spec", {}).get("containers", []):
                    container_name = container.get("name", "unknown")
                    env_vars = container.get("env", [])

                    for env in env_vars:
                        env_name = env.get("name", "").lower()
                        env_value = env.get("value", "")

                        # 检查是否直接设置了敏感值
                        if env_value and any(kw in env_name for kw in sensitive_keywords):
                            findings.append(
                                K8sFinding(
                                    vuln_type=K8sVulnType.SECRET_EXPOSURE,
                                    severity=K8sSeverity.HIGH,
                                    resource_type="Pod",
                                    resource_name=pod_name,
                                    namespace=namespace,
                                    title=f"环境变量中硬编码敏感信息: {env.get('name')}",
                                    description="敏感信息直接在环境变量中硬编码,应使用Secret",
                                    remediation="使用Kubernetes Secret存储敏感信息",
                                    evidence={
                                        "container": container_name,
                                        "env_name": env.get("name"),
                                    },
                                )
                            )

        except json.JSONDecodeError:
            pass

        return findings

    def scan_manifest_file(self, file_path: str) -> List[K8sFinding]:
        """扫描K8s manifest文件"""
        findings = []

        try:
            path = Path(file_path)
            content = path.read_text(encoding="utf-8")

            docs = self._parse_yaml_manifest(content)

            for doc in docs:
                if not doc:
                    continue

                kind = doc.get("kind", "")
                metadata = doc.get("metadata", {})
                name = metadata.get("name", "unknown")
                namespace = metadata.get("namespace", "default")

                if kind == "Pod":
                    findings.extend(self._scan_pod_spec(doc.get("spec", {}), name, namespace))
                elif kind in ["Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"]:
                    pod_spec = doc.get("spec", {}).get("template", {}).get("spec", {})
                    findings.extend(self._scan_pod_spec(pod_spec, name, namespace))

        except Exception as e:
            logger.error(f"扫描manifest失败: {e}")

        return findings

    def _scan_pod_spec(self, spec: Dict, name: str, namespace: str) -> List[K8sFinding]:
        """扫描Pod Spec"""
        findings = []

        for container in spec.get("containers", []):
            container_name = container.get("name", "unknown")
            security_context = container.get("securityContext", {})

            # 特权容器
            if security_context.get("privileged", False):
                findings.append(
                    K8sFinding(
                        vuln_type=K8sVulnType.PRIVILEGED_CONTAINER,
                        severity=K8sSeverity.CRITICAL,
                        resource_type="Pod",
                        resource_name=name,
                        namespace=namespace,
                        title=f"特权容器: {container_name}",
                        description="容器配置为特权模式",
                        remediation="移除privileged: true",
                        evidence={"container": container_name},
                    )
                )

            # 危险能力
            caps = security_context.get("capabilities", {}).get("add", [])
            for cap in caps:
                if cap in self.DANGEROUS_CAPABILITIES:
                    findings.append(
                        K8sFinding(
                            vuln_type=K8sVulnType.INSECURE_CAPABILITY,
                            severity=K8sSeverity.HIGH,
                            resource_type="Pod",
                            resource_name=name,
                            namespace=namespace,
                            title=f"危险能力: {cap}",
                            description=f"容器添加了{cap}能力",
                            remediation="移除不必要的能力",
                            evidence={"container": container_name, "capability": cap},
                        )
                    )

        # 宿主机路径挂载
        for volume in spec.get("volumes", []):
            host_path = volume.get("hostPath", {})
            if host_path:
                path = host_path.get("path", "")
                severity = K8sSeverity.HIGH if path in self.SENSITIVE_PATHS else K8sSeverity.MEDIUM

                findings.append(
                    K8sFinding(
                        vuln_type=K8sVulnType.HOST_PATH_MOUNT,
                        severity=severity,
                        resource_type="Pod",
                        resource_name=name,
                        namespace=namespace,
                        title=f"宿主机路径挂载: {path}",
                        description=f"挂载了宿主机路径{path}",
                        remediation="避免挂载宿主机路径",
                        evidence={"volume": volume.get("name"), "path": path},
                    )
                )

        return findings

    def full_scan(self, namespace: str = "default") -> Dict[str, Any]:
        """完整安全扫描

        Args:
            namespace: 目标命名空间

        Returns:
            扫描结果
        """
        all_findings = []

        # 执行所有检查
        all_findings.extend(self.check_privileged_containers(namespace))
        all_findings.extend(self.check_host_path_mounts(namespace))
        all_findings.extend(self.check_service_account_tokens(namespace))
        all_findings.extend(self.check_rbac_permissions(namespace))
        all_findings.extend(self.check_network_policies(namespace))
        all_findings.extend(self.check_secrets_in_env(namespace))

        self._findings = all_findings

        # 统计
        by_severity = {}
        by_type = {}

        for finding in all_findings:
            sev = finding.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            vtype = finding.vuln_type.value
            by_type[vtype] = by_type.get(vtype, 0) + 1

        return {
            "namespace": namespace,
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "findings": [
                {
                    "type": f.vuln_type.value,
                    "severity": f.severity.value,
                    "resource": f"{f.resource_type}/{f.resource_name}",
                    "namespace": f.namespace,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in all_findings
            ],
        }

    def generate_report(self) -> str:
        """生成扫描报告"""
        lines = [
            "=" * 60,
            "Kubernetes安全扫描报告",
            "=" * 60,
            f"发现问题数: {len(self._findings)}",
            "",
            "-" * 60,
            "问题详情:",
            "-" * 60,
        ]

        for finding in self._findings:
            severity_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "ℹ️",
            }.get(finding.severity.value, "⚪")

            lines.extend(
                [
                    f"{severity_icon} [{finding.severity.value.upper()}] {finding.title}",
                    f"   资源: {finding.resource_type}/{finding.resource_name}",
                    f"   命名空间: {finding.namespace}",
                    f"   描述: {finding.description}",
                    f"   修复: {finding.remediation}",
                    "",
                ]
            )

        lines.append("=" * 60)

        return "\n".join(lines)


# 便捷函数
def scan_k8s_namespace(namespace: str = "default", kubeconfig: str = None) -> Dict[str, Any]:
    """快速扫描K8s命名空间"""
    tester = KubernetesSecurityTester(kubeconfig)
    return tester.full_scan(namespace)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    namespace = sys.argv[1] if len(sys.argv) > 1 else "default"

    tester = KubernetesSecurityTester()
    result = tester.full_scan(namespace)

    logger.info(f"发现问题数: {result['total_findings']}")
    logger.info(f"严重性分布: {result['by_severity']}")
