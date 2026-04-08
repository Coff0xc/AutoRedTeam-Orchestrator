#!/usr/bin/env python3
"""
Kubernetes 安全测试模块单元测试

测试 modules/cloud_security/kubernetes.py 的各项功能。
"""

import json
import subprocess
from unittest.mock import Mock, patch

from core.cloud_security.base import CloudSeverity
from core.cloud_security.kubernetes import KubernetesTester


class TestKubernetesTesterInit:
    """Kubernetes 测试器初始化测试"""

    def test_init_default(self):
        """测试默认初始化"""
        tester = KubernetesTester()

        assert tester.namespace == "default"
        assert tester.kubeconfig is None
        assert tester.context is None

    def test_init_with_config(self):
        """测试带配置的初始化"""
        config = {
            "kubeconfig": "/path/to/kubeconfig",
            "namespace": "production",
            "context": "my-cluster",
        }
        tester = KubernetesTester(config)

        assert tester.kubeconfig == "/path/to/kubeconfig"
        assert tester.namespace == "production"
        assert tester.context == "my-cluster"

    def test_dangerous_capabilities_defined(self):
        """测试危险能力列表已定义"""
        tester = KubernetesTester()

        assert "SYS_ADMIN" in tester.DANGEROUS_CAPABILITIES
        assert "NET_ADMIN" in tester.DANGEROUS_CAPABILITIES
        assert len(tester.DANGEROUS_CAPABILITIES) > 0

    def test_sensitive_paths_defined(self):
        """测试敏感路径已定义"""
        tester = KubernetesTester()

        assert "/" in tester.SENSITIVE_PATHS
        assert "/var/run/docker.sock" in tester.SENSITIVE_PATHS
        assert tester.SENSITIVE_PATHS["/"] == CloudSeverity.CRITICAL


class TestCheckKubectl:
    """kubectl 检查测试"""

    def test_kubectl_available(self):
        """测试 kubectl 可用"""
        tester = KubernetesTester()

        # Mock subprocess
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            result = tester._check_kubectl()

        assert result is True

    def test_kubectl_not_available(self):
        """测试 kubectl 不可用"""
        tester = KubernetesTester()

        # Mock subprocess - 返回非零
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            result = tester._check_kubectl()

        assert result is False

    def test_kubectl_exception(self):
        """测试 kubectl 异常"""
        tester = KubernetesTester()

        # Mock subprocess - 抛出异常
        with patch("subprocess.run", side_effect=FileNotFoundError("kubectl not found")):
            result = tester._check_kubectl()

        assert result is False


class TestRunKubectl:
    """kubectl 命令执行测试"""

    def test_run_kubectl_success(self):
        """测试成功执行 kubectl 命令"""
        tester = KubernetesTester()

        # Mock subprocess
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = '{"items": []}'

        with patch("subprocess.run", return_value=mock_result):
            success, output = tester._run_kubectl(["get", "pods", "-o", "json"])

        assert success is True
        assert output == '{"items": []}'

    def test_run_kubectl_failure(self):
        """测试 kubectl 命令失败"""
        tester = KubernetesTester()

        # Mock subprocess - 失败
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "Error: connection refused"

        with patch("subprocess.run", return_value=mock_result):
            success, output = tester._run_kubectl(["get", "pods"])

        assert success is False

    def test_run_kubectl_with_kubeconfig_and_context(self):
        """测试带 kubeconfig 和 context 的 kubectl 命令"""
        tester = KubernetesTester(
            config={"kubeconfig": "/path/to/kubeconfig", "context": "my-cluster"}
        )

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "{}"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            tester._run_kubectl(["get", "pods"])

        # _run_kubectl 添加 --kubeconfig 和 --context，不添加 -n
        call_args = mock_run.call_args[0][0]
        assert "--kubeconfig" in call_args
        assert "--context" in call_args


class TestCheckPrivilegedContainers:
    """特权容器检测测试"""

    def test_privileged_container_detected(self):
        """测试检测到特权容器"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 特权容器
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "privileged-pod", "namespace": "default"},
                    "spec": {
                        "containers": [{"name": "nginx", "securityContext": {"privileged": True}}]
                    },
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_privileged_containers()

        assert len(findings) > 0
        assert findings[0].severity == CloudSeverity.CRITICAL
        assert "privileged-pod" in findings[0].resource_name

    def test_no_privileged_containers(self):
        """测试没有特权容器"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 无特权容器
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "normal-pod", "namespace": "default"},
                    "spec": {
                        "containers": [{"name": "nginx", "securityContext": {"privileged": False}}]
                    },
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_privileged_containers()

        assert len(findings) == 0

    def test_no_security_context(self):
        """测试没有 securityContext"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 没有 securityContext
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "pod", "namespace": "default"},
                    "spec": {"containers": [{"name": "nginx"}]},
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_privileged_containers()

        # 没有 securityContext 不应该报告为特权容器
        assert len(findings) == 0


class TestCheckHostPathMounts:
    """宿主机路径挂载检测测试"""

    def test_sensitive_hostpath_detected(self):
        """测试检测到敏感宿主机路径挂载"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 挂载 docker.sock
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "dangerous-pod", "namespace": "default"},
                    "spec": {
                        "volumes": [
                            {"name": "docker-sock", "hostPath": {"path": "/var/run/docker.sock"}}
                        ]
                    },
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_host_path_mounts()

        assert len(findings) > 0
        assert findings[0].severity == CloudSeverity.CRITICAL
        assert "/var/run/docker.sock" in str(findings[0].evidence)

    def test_root_path_mounted(self):
        """测试检测到根路径挂载"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 挂载根路径
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "root-mount-pod", "namespace": "default"},
                    "spec": {"volumes": [{"name": "root", "hostPath": {"path": "/"}}]},
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_host_path_mounts()

        assert len(findings) > 0
        assert findings[0].severity == CloudSeverity.CRITICAL

    def test_no_hostpath_mounts(self):
        """测试没有宿主机路径挂载"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 使用 emptyDir
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "safe-pod", "namespace": "default"},
                    "spec": {"volumes": [{"name": "cache", "emptyDir": {}}]},
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_host_path_mounts()

        assert len(findings) == 0


class TestCheckDangerousCapabilities:
    """危险能力检测测试"""

    def test_dangerous_capability_detected(self):
        """测试检测到危险能力"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - SYS_ADMIN 能力
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "cap-pod", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "securityContext": {
                                    "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"]}
                                },
                            }
                        ]
                    },
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_dangerous_capabilities()

        assert len(findings) > 0
        assert "SYS_ADMIN" in str(findings[0].evidence)

    def test_safe_capabilities(self):
        """测试安全的能力"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 安全能力
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "safe-pod", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "securityContext": {"capabilities": {"add": ["CHOWN", "SETUID"]}},
                            }
                        ]
                    },
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_dangerous_capabilities()

        # 安全能力不应该报告
        assert len(findings) == 0


class TestCheckRBACPermissions:
    """RBAC 权限审计测试"""

    def test_dangerous_rbac_detected(self):
        """测试检测到危险 RBAC 权限 - 通配符权限的 ClusterRole"""
        tester = KubernetesTester()

        # check_rbac_permissions 先查 clusterrolebindings，再查 clusterroles
        # Mock _get_resources 返回对应资源
        empty_crbs = []
        wildcard_roles = [
            {
                "metadata": {"name": "admin-role"},
                "rules": [
                    {"apiGroups": [""], "resources": ["*"], "verbs": ["*"]}
                ],
            }
        ]

        with patch.object(
            tester,
            "_get_resources",
            side_effect=[empty_crbs, wildcard_roles],
        ):
            findings = tester.check_rbac_permissions()

        assert len(findings) > 0
        # 通配符权限应被检测到
        assert findings[0].severity == CloudSeverity.HIGH

    def test_safe_rbac(self):
        """测试安全的 RBAC 权限"""
        tester = KubernetesTester()

        # Mock _get_resources: 无 CRB，安全 ClusterRole
        empty_crbs = []
        safe_roles = [
            {
                "metadata": {"name": "reader-role"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["pods", "services"],
                        "verbs": ["get", "list", "watch"],
                    }
                ],
            }
        ]

        with patch.object(
            tester,
            "_get_resources",
            side_effect=[empty_crbs, safe_roles],
        ):
            findings = tester.check_rbac_permissions()

        # 只读权限不应该报告
        assert len(findings) == 0


class TestCheckNetworkPolicies:
    """网络策略检查测试"""

    def test_no_network_policies(self):
        """测试没有网络策略"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 无网络策略
        netpol_json = {"items": []}

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(netpol_json))):
            findings = tester.check_network_policies()

        assert len(findings) > 0
        assert findings[0].severity == CloudSeverity.MEDIUM

    def test_network_policies_exist(self):
        """测试存在网络策略"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 有网络策略
        netpol_json = {
            "items": [
                {
                    "metadata": {"name": "deny-all", "namespace": "default"},
                    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(netpol_json))):
            findings = tester.check_network_policies()

        # 有网络策略不应该报告
        assert len(findings) == 0


class TestCheckSecretsInEnv:
    """环境变量中的 Secrets 检测测试"""

    def test_secrets_in_env_detected(self):
        """测试检测到环境变量中硬编码的敏感信息"""
        tester = KubernetesTester()

        # 实现检测的是硬编码 value 且 env name 包含敏感关键字
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "app-pod", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "env": [
                                    {
                                        "name": "DB_PASSWORD",
                                        "value": "super_secret_123",
                                    }
                                ],
                            }
                        ]
                    },
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_secrets_in_env()

        assert len(findings) > 0
        assert findings[0].severity == CloudSeverity.HIGH

    def test_no_secrets_in_env(self):
        """测试环境变量中没有 Secrets"""
        tester = KubernetesTester()

        # APP_ENV 不包含敏感关键字（password/secret/token 等）
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "app-pod", "namespace": "default"},
                    "spec": {
                        "containers": [
                            {"name": "app", "env": [{"name": "APP_ENV", "value": "production"}]}
                        ]
                    },
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_secrets_in_env()

        assert len(findings) == 0


class TestCheckHostNetwork:
    """宿主机网络检测测试"""

    def test_host_network_detected(self):
        """测试检测到使用宿主机网络"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 使用 hostNetwork
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "host-net-pod", "namespace": "default"},
                    "spec": {"hostNetwork": True},
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_host_network()

        assert len(findings) > 0
        assert findings[0].severity in [CloudSeverity.HIGH, CloudSeverity.MEDIUM]

    def test_no_host_network(self):
        """测试没有使用宿主机网络"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 不使用 hostNetwork
        pods_json = {
            "items": [
                {
                    "metadata": {"name": "normal-pod", "namespace": "default"},
                    "spec": {"hostNetwork": False},
                }
            ]
        }

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(pods_json))):
            findings = tester.check_host_network()

        assert len(findings) == 0


class TestFullScan:
    """完整扫描测试"""

    def test_full_scan_kubectl_unavailable(self):
        """测试 kubectl 不可用时的完整扫描"""
        tester = KubernetesTester()

        with patch.object(tester, "_check_kubectl", return_value=False):
            findings = tester.scan()

        # kubectl 不可用应该返回空列表
        assert len(findings) == 0

    def test_full_scan_execution(self):
        """测试完整扫描执行所有检查"""
        tester = KubernetesTester()

        # Mock kubectl 可用，所有检查返回空列表（实际返回类型）
        with patch.object(tester, "_check_kubectl", return_value=True):
            with patch.object(tester, "check_privileged_containers", return_value=[]):
                with patch.object(tester, "check_host_path_mounts", return_value=[]):
                    with patch.object(tester, "check_dangerous_capabilities", return_value=[]):
                        with patch.object(
                            tester, "check_service_account_tokens", return_value=[]
                        ):
                            with patch.object(tester, "check_rbac_permissions", return_value=[]):
                                with patch.object(
                                    tester, "check_network_policies", return_value=[]
                                ):
                                    with patch.object(
                                        tester, "check_secrets_in_env", return_value=[]
                                    ):
                                        with patch.object(
                                            tester, "check_host_network", return_value=[]
                                        ):
                                            findings = tester.scan()

        # 应该执行所有检查
        assert isinstance(findings, list)


class TestManifestScanning:
    """清单文件扫描测试"""

    def test_scan_manifest_privileged(self):
        """测试扫描特权容器清单"""
        tester = KubernetesTester()

        manifest_content = """
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      privileged: true
"""

        if hasattr(tester, "scan_manifest"):
            with patch("pathlib.Path.read_text", return_value=manifest_content):
                findings = tester.scan_manifest("/path/to/manifest.yaml")

            assert len(findings) > 0
            assert any(f.severity == CloudSeverity.CRITICAL for f in findings)

    def test_scan_manifest_safe(self):
        """测试扫描安全清单"""
        tester = KubernetesTester()

        manifest_content = """
apiVersion: v1
kind: Pod
metadata:
  name: safe-pod
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      privileged: false
      runAsNonRoot: true
      readOnlyRootFilesystem: true
"""

        if hasattr(tester, "scan_manifest"):
            with patch("pathlib.Path.read_text", return_value=manifest_content):
                findings = tester.scan_manifest("/path/to/manifest.yaml")

            # 安全清单应该没有 CRITICAL 漏洞
            critical_findings = [f for f in findings if f.severity == CloudSeverity.CRITICAL]
            assert len(critical_findings) == 0


class TestEdgeCases:
    """边缘情况测试"""

    def test_empty_pods_list(self):
        """测试空 Pod 列表"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 空列表
        empty_json = {"items": []}

        with patch.object(tester, "_run_kubectl", return_value=(True, json.dumps(empty_json))):
            findings = tester.check_privileged_containers()

        assert len(findings) == 0

    def test_malformed_json(self):
        """测试格式错误的 JSON"""
        tester = KubernetesTester()

        # Mock kubectl 输出 - 无效 JSON
        # _get_resources 内部解析失败返回 []，所以 check 方法遍历空列表返回 []
        with patch.object(tester, "_run_kubectl", return_value=(True, "invalid json")):
            findings = tester.check_privileged_containers()

        # 应该正确处理错误，返回空列表
        assert len(findings) == 0

    def test_kubectl_timeout(self):
        """测试 kubectl 超时"""
        tester = KubernetesTester()

        # Mock subprocess 超时
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("kubectl", 30)):
            result = tester._check_kubectl()

        assert result is False

    def test_multiple_namespaces(self):
        """测试多命名空间扫描"""
        tester = KubernetesTester(config={"namespace": "production"})

        assert tester.namespace == "production"

        # 切换命名空间
        tester.namespace = "staging"
        assert tester.namespace == "staging"
