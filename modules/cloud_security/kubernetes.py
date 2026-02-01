#!/usr/bin/env python3
"""
Kubernetes安全测试模块

提供全面的Kubernetes安全检测功能，包括:
- 特权容器检测
- 危险能力检测
- 宿主机路径挂载检测
- RBAC权限审计
- 网络策略检查
- Secrets暴露检测
- Pod安全策略检查
- 清单文件扫描

作者: AutoRedTeam
版本: 3.0.0
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    BaseCloudTester,
    CloudFinding,
    CloudSeverity,
    CloudVulnType,
)

logger = logging.getLogger(__name__)


class KubernetesTester(BaseCloudTester):
    """
    Kubernetes安全测试器

    对Kubernetes集群和清单文件进行安全扫描。

    使用示例:
        # 扫描集群
        tester = KubernetesTester(config={'namespace': 'default'})
        findings = tester.scan()

        # 扫描清单文件
        tester = KubernetesTester()
        findings = tester.scan_manifest('/path/to/deployment.yaml')
    """

    name = "kubernetes"
    provider = "kubernetes"
    description = "Kubernetes安全测试器"
    version = "3.0.0"

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
        "SYS_CHROOT",
        "AUDIT_WRITE",
        "SETFCAP",
    ]

    # 敏感挂载路径
    SENSITIVE_PATHS = {
        "/": CloudSeverity.CRITICAL,
        "/etc": CloudSeverity.CRITICAL,
        "/etc/shadow": CloudSeverity.CRITICAL,
        "/etc/passwd": CloudSeverity.HIGH,
        "/var/run/docker.sock": CloudSeverity.CRITICAL,
        "/var/run/crio/crio.sock": CloudSeverity.CRITICAL,
        "/var/run/containerd/containerd.sock": CloudSeverity.CRITICAL,
        "/proc": CloudSeverity.HIGH,
        "/sys": CloudSeverity.HIGH,
        "/dev": CloudSeverity.HIGH,
        "/root": CloudSeverity.HIGH,
        "/home": CloudSeverity.MEDIUM,
        "/var/log": CloudSeverity.MEDIUM,
    }

    # 危险RBAC权限
    DANGEROUS_VERBS = ["*", "create", "update", "patch", "delete"]
    SENSITIVE_RESOURCES = [
        "secrets",
        "pods",
        "pods/exec",
        "pods/attach",
        "pods/portforward",
        "daemonsets",
        "deployments",
        "replicasets",
        "statefulsets",
        "configmaps",
        "serviceaccounts",
        "clusterroles",
        "clusterrolebindings",
        "roles",
        "rolebindings",
        "nodes",
        "persistentvolumes",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化Kubernetes测试器

        Args:
            config: 可选配置，可包含:
                - kubeconfig: kubeconfig文件路径
                - namespace: 目标命名空间
                - context: Kubernetes上下文
        """
        super().__init__(config)

        self.kubeconfig = self.config.get("kubeconfig")
        self.namespace = self.config.get("namespace", "default")
        self.context = self.config.get("context")

    def scan(self) -> List[CloudFinding]:
        """执行完整的Kubernetes安全扫描"""
        self.clear_findings()

        # 检查kubectl是否可用
        if not self._check_kubectl():
            logger.warning("kubectl不可用，跳过集群扫描")
            return self._findings

        # 执行各项检查
        self.check_privileged_containers()
        self.check_host_path_mounts()
        self.check_dangerous_capabilities()
        self.check_service_account_tokens()
        self.check_rbac_permissions()
        self.check_network_policies()
        self.check_secrets_in_env()
        self.check_host_network()

        return self._findings

    def _check_kubectl(self) -> bool:
        """检查kubectl是否可用"""
        try:
            result = subprocess.run(
                ["kubectl", "version", "--client", "--short"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, OSError, FileNotFoundError):
            return False

    def _run_kubectl(self, args: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """执行kubectl命令"""
        cmd = ["kubectl"]

        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])

        if self.context:
            cmd.extend(["--context", self.context])

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

    def _get_resources(self, resource_type: str, namespace: str = None) -> List[Dict]:
        """获取Kubernetes资源"""
        args = ["get", resource_type, "-o", "json"]

        if namespace:
            args.extend(["-n", namespace])
        elif resource_type not in ["namespaces", "nodes", "clusterroles", "clusterrolebindings"]:
            args.extend(["-n", self.namespace])

        success, output = self._run_kubectl(args)

        if not success:
            return []

        try:
            data = json.loads(output)
            return data.get("items", [])
        except json.JSONDecodeError:
            return []

    def check_privileged_containers(self) -> List[CloudFinding]:
        """检测特权容器"""
        findings = []
        pods = self._get_resources("pods")

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            namespace = pod.get("metadata", {}).get("namespace", self.namespace)

            for container in pod.get("spec", {}).get("containers", []):
                container_name = container.get("name", "unknown")
                security_context = container.get("securityContext", {})

                if security_context.get("privileged", False):
                    finding = self._create_finding(
                        vuln_type=CloudVulnType.K8S_PRIVILEGED_CONTAINER,
                        severity=CloudSeverity.CRITICAL,
                        resource_type="Pod",
                        resource_name=f"{namespace}/{pod_name}",
                        title=f"特权容器: {container_name}",
                        description=(
                            f"容器 {container_name} 以特权模式运行，" "可能导致容器逃逸和集群接管。"
                        ),
                        remediation=(
                            "1. 移除 privileged: true 配置\n"
                            "2. 使用最小权限原则\n"
                            "3. 如需特权，考虑使用特定Capabilities替代"
                        ),
                        evidence={"container": container_name},
                        compliance=["CIS-K8s-5.2.1", "PCI-DSS-2.2.4"],
                    )
                    findings.append(finding)

        return findings

    def check_host_path_mounts(self) -> List[CloudFinding]:
        """检测宿主机路径挂载"""
        findings = []
        pods = self._get_resources("pods")

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            namespace = pod.get("metadata", {}).get("namespace", self.namespace)
            volumes = pod.get("spec", {}).get("volumes", [])

            for volume in volumes:
                host_path = volume.get("hostPath", {})
                if not host_path:
                    continue

                path = host_path.get("path", "")
                volume_name = volume.get("name", "unknown")

                # 确定严重性
                severity = CloudSeverity.MEDIUM
                for sensitive_path, sev in self.SENSITIVE_PATHS.items():
                    if path == sensitive_path or path.startswith(sensitive_path + "/"):
                        severity = sev
                        break

                finding = self._create_finding(
                    vuln_type=CloudVulnType.K8S_HOST_PATH_MOUNT,
                    severity=severity,
                    resource_type="Pod",
                    resource_name=f"{namespace}/{pod_name}",
                    title=f"宿主机路径挂载: {path}",
                    description=(f"Pod挂载了宿主机路径 {path}，" "可能导致信息泄露或容器逃逸。"),
                    remediation=(
                        "1. 避免挂载宿主机路径\n"
                        "2. 使用PVC或ConfigMap/Secret替代\n"
                        "3. 如必须挂载，使用只读模式"
                    ),
                    evidence={"volume": volume_name, "path": path},
                    compliance=["CIS-K8s-5.2.4"],
                )
                findings.append(finding)

        return findings

    def check_dangerous_capabilities(self) -> List[CloudFinding]:
        """检测危险能力"""
        findings = []
        pods = self._get_resources("pods")

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            namespace = pod.get("metadata", {}).get("namespace", self.namespace)

            for container in pod.get("spec", {}).get("containers", []):
                container_name = container.get("name", "unknown")
                security_context = container.get("securityContext", {})
                capabilities = security_context.get("capabilities", {})
                add_caps = capabilities.get("add", [])

                for cap in add_caps:
                    if cap in self.DANGEROUS_CAPABILITIES:
                        finding = self._create_finding(
                            vuln_type=CloudVulnType.K8S_INSECURE_CAPABILITY,
                            severity=CloudSeverity.HIGH,
                            resource_type="Pod",
                            resource_name=f"{namespace}/{pod_name}",
                            title=f"危险能力: {cap}",
                            description=(
                                f"容器 {container_name} 添加了危险能力 {cap}，"
                                "可能导致权限提升或逃逸。"
                            ),
                            remediation=(
                                "1. 移除不必要的能力\n"
                                '2. 使用 securityContext.capabilities.drop: ["ALL"]\n'
                                "3. 仅添加最小必需的能力"
                            ),
                            evidence={"container": container_name, "capability": cap},
                            compliance=["CIS-K8s-5.2.8"],
                        )
                        findings.append(finding)

        return findings

    def check_service_account_tokens(self) -> List[CloudFinding]:
        """检测ServiceAccount Token自动挂载"""
        findings = []
        pods = self._get_resources("pods")

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            namespace = pod.get("metadata", {}).get("namespace", self.namespace)
            spec = pod.get("spec", {})

            # 检查是否自动挂载SA Token
            automount = spec.get("automountServiceAccountToken", True)

            if automount:
                sa_name = spec.get("serviceAccountName", "default")

                finding = self._create_finding(
                    vuln_type=CloudVulnType.K8S_SERVICE_ACCOUNT_TOKEN,
                    severity=CloudSeverity.MEDIUM,
                    resource_type="Pod",
                    resource_name=f"{namespace}/{pod_name}",
                    title="自动挂载ServiceAccount Token",
                    description=(
                        f"Pod自动挂载了 {sa_name} 的Token，" "如果容器被入侵，Token可能被滥用。"
                    ),
                    remediation=(
                        "1. 设置 automountServiceAccountToken: false\n"
                        "2. 仅在需要时手动挂载Token\n"
                        "3. 使用最小权限的ServiceAccount"
                    ),
                    evidence={"service_account": sa_name},
                    compliance=["CIS-K8s-5.1.6"],
                )
                findings.append(finding)

        return findings

    def check_rbac_permissions(self) -> List[CloudFinding]:
        """检测RBAC权限配置"""
        findings = []

        # 检查ClusterRoleBindings
        crbs = self._get_resources("clusterrolebindings")

        for crb in crbs:
            crb_name = crb.get("metadata", {}).get("name", "unknown")
            role_ref = crb.get("roleRef", {})
            subjects = crb.get("subjects", [])

            # 检查是否绑定到cluster-admin
            if role_ref.get("name") == "cluster-admin":
                for subject in subjects:
                    if subject.get("kind") == "ServiceAccount":
                        finding = self._create_finding(
                            vuln_type=CloudVulnType.K8S_RBAC_OVERPERMISSION,
                            severity=CloudSeverity.CRITICAL,
                            resource_type="ClusterRoleBinding",
                            resource_name=crb_name,
                            title="ServiceAccount绑定cluster-admin",
                            description=(
                                f'ServiceAccount {subject.get("name")} 拥有集群管理员权限，'
                                "风险极高。"
                            ),
                            remediation=(
                                "1. 使用最小权限原则\n"
                                "2. 创建自定义Role\n"
                                "3. 避免使用内置的cluster-admin角色"
                            ),
                            evidence={
                                "subject": subject.get("name"),
                                "namespace": subject.get("namespace", "default"),
                            },
                            compliance=["CIS-K8s-5.1.1"],
                        )
                        findings.append(finding)

        # 检查ClusterRoles中的通配符权限
        roles = self._get_resources("clusterroles")

        for role in roles:
            role_name = role.get("metadata", {}).get("name", "unknown")

            for rule in role.get("rules", []):
                verbs = rule.get("verbs", [])
                resources = rule.get("resources", [])
                api_groups = rule.get("apiGroups", [])

                # 检查通配符权限
                if "*" in verbs and "*" in resources:
                    finding = self._create_finding(
                        vuln_type=CloudVulnType.K8S_RBAC_OVERPERMISSION,
                        severity=CloudSeverity.HIGH,
                        resource_type="ClusterRole",
                        resource_name=role_name,
                        title="ClusterRole使用通配符权限",
                        description=(
                            f"ClusterRole {role_name} 使用了通配符权限，" "可能导致权限过大。"
                        ),
                        remediation=(
                            "1. 明确指定需要的verbs和resources\n"
                            "2. 避免使用*通配符\n"
                            "3. 遵循最小权限原则"
                        ),
                        evidence={"verbs": verbs, "resources": resources, "apiGroups": api_groups},
                        compliance=["CIS-K8s-5.1.3"],
                    )
                    findings.append(finding)

        return findings

    def check_network_policies(self) -> List[CloudFinding]:
        """检测网络策略"""
        findings = []

        # 获取命名空间的NetworkPolicy
        policies = self._get_resources("networkpolicies")

        if not policies:
            finding = self._create_finding(
                vuln_type=CloudVulnType.K8S_NETWORK_POLICY_MISSING,
                severity=CloudSeverity.MEDIUM,
                resource_type="Namespace",
                resource_name=self.namespace,
                title="缺少NetworkPolicy",
                description=(
                    f"命名空间 {self.namespace} 没有定义NetworkPolicy，" "所有Pod间可以自由通信。"
                ),
                remediation=(
                    "1. 定义NetworkPolicy限制Pod间网络访问\n"
                    "2. 实施默认拒绝策略\n"
                    "3. 仅允许必要的网络流量"
                ),
                evidence={},
                compliance=["CIS-K8s-5.3.2"],
            )
            findings.append(finding)

        return findings

    def check_secrets_in_env(self) -> List[CloudFinding]:
        """检测环境变量中的敏感信息"""
        findings = []
        pods = self._get_resources("pods")

        sensitive_keywords = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_key",
            "apikey",
            "token",
            "credential",
            "private_key",
            "access_key",
        ]

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            namespace = pod.get("metadata", {}).get("namespace", self.namespace)

            for container in pod.get("spec", {}).get("containers", []):
                container_name = container.get("name", "unknown")
                env_vars = container.get("env", [])

                for env in env_vars:
                    env_name = env.get("name", "").lower()
                    env_value = env.get("value", "")

                    # 检查是否直接设置了敏感值
                    if env_value and any(kw in env_name for kw in sensitive_keywords):
                        finding = self._create_finding(
                            vuln_type=CloudVulnType.K8S_SECRET_EXPOSURE,
                            severity=CloudSeverity.HIGH,
                            resource_type="Pod",
                            resource_name=f"{namespace}/{pod_name}",
                            title=f'环境变量中硬编码敏感信息: {env.get("name")}',
                            description=(
                                f"容器 {container_name} 的环境变量中直接硬编码了敏感信息，"
                                "应使用Kubernetes Secret。"
                            ),
                            remediation=(
                                "1. 使用Kubernetes Secret存储敏感信息\n"
                                "2. 通过secretKeyRef引用Secret\n"
                                "3. 考虑使用外部密钥管理服务"
                            ),
                            evidence={"container": container_name, "env_name": env.get("name")},
                            compliance=["CIS-K8s-5.4.1"],
                        )
                        findings.append(finding)

        return findings

    def check_host_network(self) -> List[CloudFinding]:
        """检测使用宿主机网络的Pod"""
        findings = []
        pods = self._get_resources("pods")

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "unknown")
            namespace = pod.get("metadata", {}).get("namespace", self.namespace)
            spec = pod.get("spec", {})

            if spec.get("hostNetwork", False):
                finding = self._create_finding(
                    vuln_type=CloudVulnType.K8S_CONTAINER_ESCAPE,
                    severity=CloudSeverity.HIGH,
                    resource_type="Pod",
                    resource_name=f"{namespace}/{pod_name}",
                    title="Pod使用宿主机网络",
                    description=(
                        "Pod使用hostNetwork: true，" "可以访问宿主机网络栈，存在安全风险。"
                    ),
                    remediation=(
                        "1. 避免使用hostNetwork\n"
                        "2. 使用Service和Ingress暴露服务\n"
                        "3. 如必须使用，限制Pod的能力"
                    ),
                    evidence={},
                    compliance=["CIS-K8s-5.2.5"],
                )
                findings.append(finding)

            # 检查hostPID和hostIPC
            if spec.get("hostPID", False):
                self._create_finding(
                    vuln_type=CloudVulnType.K8S_CONTAINER_ESCAPE,
                    severity=CloudSeverity.HIGH,
                    resource_type="Pod",
                    resource_name=f"{namespace}/{pod_name}",
                    title="Pod使用宿主机PID命名空间",
                    description="Pod使用hostPID: true，可以看到宿主机进程。",
                    remediation="移除hostPID: true配置",
                    compliance=["CIS-K8s-5.2.3"],
                )

            if spec.get("hostIPC", False):
                self._create_finding(
                    vuln_type=CloudVulnType.K8S_CONTAINER_ESCAPE,
                    severity=CloudSeverity.MEDIUM,
                    resource_type="Pod",
                    resource_name=f"{namespace}/{pod_name}",
                    title="Pod使用宿主机IPC命名空间",
                    description="Pod使用hostIPC: true，可以访问宿主机IPC。",
                    remediation="移除hostIPC: true配置",
                    compliance=["CIS-K8s-5.2.4"],
                )

        return findings

    def scan_manifest(self, manifest_path: str) -> List[CloudFinding]:
        """
        扫描Kubernetes清单文件

        Args:
            manifest_path: YAML清单文件路径

        Returns:
            扫描发现列表
        """
        self.clear_findings()

        try:
            path = Path(manifest_path)
            content = path.read_text(encoding="utf-8")

            # 尝试使用yaml库解析
            try:
                import yaml

                docs = list(yaml.safe_load_all(content))
            except ImportError:
                # 简单解析
                docs = self._simple_yaml_parse(content)

            for doc in docs:
                if not doc:
                    continue

                kind = doc.get("kind", "")
                metadata = doc.get("metadata", {})
                name = metadata.get("name", "unknown")
                namespace = metadata.get("namespace", "default")

                if kind == "Pod":
                    self._scan_pod_spec(doc.get("spec", {}), name, namespace)
                elif kind in [
                    "Deployment",
                    "DaemonSet",
                    "StatefulSet",
                    "ReplicaSet",
                    "Job",
                    "CronJob",
                ]:
                    template = doc.get("spec", {}).get("template", {})
                    pod_spec = template.get("spec", {})
                    self._scan_pod_spec(pod_spec, name, namespace)

        except Exception as e:
            logger.error(f"扫描清单文件失败: {e}")

        return self._findings

    def _scan_pod_spec(self, spec: Dict, name: str, namespace: str) -> None:
        """扫描Pod Spec"""
        # 检查特权容器
        for container in spec.get("containers", []):
            container_name = container.get("name", "unknown")
            security_context = container.get("securityContext", {})

            if security_context.get("privileged", False):
                self._create_finding(
                    vuln_type=CloudVulnType.K8S_PRIVILEGED_CONTAINER,
                    severity=CloudSeverity.CRITICAL,
                    resource_type="Pod",
                    resource_name=f"{namespace}/{name}",
                    title=f"特权容器: {container_name}",
                    description="容器配置为特权模式",
                    remediation="移除privileged: true",
                    evidence={"container": container_name},
                )

            # 检查危险能力
            caps = security_context.get("capabilities", {}).get("add", [])
            for cap in caps:
                if cap in self.DANGEROUS_CAPABILITIES:
                    self._create_finding(
                        vuln_type=CloudVulnType.K8S_INSECURE_CAPABILITY,
                        severity=CloudSeverity.HIGH,
                        resource_type="Pod",
                        resource_name=f"{namespace}/{name}",
                        title=f"危险能力: {cap}",
                        description=f"容器添加了危险能力 {cap}",
                        remediation="移除不必要的能力",
                        evidence={"container": container_name, "capability": cap},
                    )

        # 检查宿主机路径挂载
        for volume in spec.get("volumes", []):
            host_path = volume.get("hostPath", {})
            if host_path:
                path = host_path.get("path", "")
                severity = self.SENSITIVE_PATHS.get(path, CloudSeverity.MEDIUM)

                self._create_finding(
                    vuln_type=CloudVulnType.K8S_HOST_PATH_MOUNT,
                    severity=severity,
                    resource_type="Pod",
                    resource_name=f"{namespace}/{name}",
                    title=f"宿主机路径挂载: {path}",
                    description=f"挂载了宿主机路径 {path}",
                    remediation="避免挂载宿主机路径",
                    evidence={"volume": volume.get("name"), "path": path},
                )

    def _simple_yaml_parse(self, content: str) -> List[Dict]:
        """简单YAML解析（备用）"""
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


# 便捷函数
def scan_k8s_namespace(namespace: str = "default", kubeconfig: str = None) -> Dict[str, Any]:
    """
    快速扫描Kubernetes命名空间

    Args:
        namespace: 目标命名空间
        kubeconfig: kubeconfig文件路径

    Returns:
        扫描结果摘要
    """
    tester = KubernetesTester(config={"namespace": namespace, "kubeconfig": kubeconfig})
    findings = tester.scan()
    return tester.get_summary().to_dict()


def scan_k8s_manifest(manifest_path: str) -> Dict[str, Any]:
    """
    快速扫描Kubernetes清单文件

    Args:
        manifest_path: 清单文件路径

    Returns:
        扫描结果摘要
    """
    tester = KubernetesTester()
    findings = tester.scan_manifest(manifest_path)
    return tester.get_summary().to_dict()


__all__ = [
    "KubernetesTester",
    "scan_k8s_namespace",
    "scan_k8s_manifest",
]
