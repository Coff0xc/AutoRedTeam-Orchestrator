#!/usr/bin/env python3
"""
Kubernetes 安全相关常量

包含:
- 危险能力列表
- 敏感挂载路径
- 危险RBAC权限
- 安全基线配置

这些常量被多个 Kubernetes 安全模块共享。
"""

from typing import Dict, List, Set

# ============================================================
# 危险容器能力 (Capabilities)
# ============================================================

DANGEROUS_CAPABILITIES: List[str] = [
    "SYS_ADMIN",       # 完全管理员权限，可逃逸容器
    "SYS_PTRACE",      # 进程跟踪，可注入其他进程
    "SYS_MODULE",      # 加载内核模块
    "DAC_READ_SEARCH", # 绕过文件读取权限检查
    "NET_ADMIN",       # 网络管理，可嗅探流量
    "NET_RAW",         # 原始套接字，可伪造数据包
    "SYS_RAWIO",       # 原始I/O访问
    "MKNOD",           # 创建设备文件
    "SYS_CHROOT",      # chroot权限
    "AUDIT_WRITE",     # 写入审计日志
    "SETFCAP",         # 设置文件能力
    "SYS_BOOT",        # 重启系统
    "SYS_TIME",        # 修改系统时间
    "WAKE_ALARM",      # 唤醒系统
]

# 高危能力（可直接导致容器逃逸）
CRITICAL_CAPABILITIES: Set[str] = {
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
}

# ============================================================
# 敏感挂载路径
# ============================================================

SENSITIVE_MOUNT_PATHS: Dict[str, str] = {
    # 路径: 严重程度
    "/": "critical",
    "/etc": "critical",
    "/etc/shadow": "critical",
    "/etc/passwd": "high",
    "/etc/kubernetes": "critical",
    "/var/run/docker.sock": "critical",
    "/var/run/crio/crio.sock": "critical",
    "/var/run/containerd/containerd.sock": "critical",
    "/proc": "high",
    "/sys": "high",
    "/dev": "high",
    "/root": "high",
    "/home": "medium",
    "/var/log": "medium",
    "/tmp": "low",
}

# 容器运行时套接字路径
CONTAINER_RUNTIME_SOCKETS: List[str] = [
    "/var/run/docker.sock",
    "/var/run/crio/crio.sock",
    "/var/run/containerd/containerd.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
]

# ============================================================
# 危险 RBAC 权限
# ============================================================

# 危险动词
DANGEROUS_VERBS: List[str] = [
    "*",        # 通配符
    "create",
    "update",
    "patch",
    "delete",
    "deletecollection",
    "impersonate",
    "escalate",
    "bind",
]

# 敏感资源
SENSITIVE_RESOURCES: List[str] = [
    "secrets",
    "pods",
    "pods/exec",
    "pods/attach",
    "pods/portforward",
    "pods/log",
    "daemonsets",
    "deployments",
    "replicasets",
    "statefulsets",
    "configmaps",
    "serviceaccounts",
    "serviceaccounts/token",
    "roles",
    "rolebindings",
    "clusterroles",
    "clusterrolebindings",
    "nodes",
    "nodes/proxy",
    "persistentvolumes",
    "persistentvolumeclaims",
]

# 高危 RBAC 规则组合
DANGEROUS_RBAC_RULES: List[Dict[str, List[str]]] = [
    {"verbs": ["*"], "resources": ["*"]},                    # 完全权限
    {"verbs": ["create"], "resources": ["pods"]},            # 创建Pod
    {"verbs": ["create", "get"], "resources": ["pods/exec"]}, # Pod exec
    {"verbs": ["get", "list"], "resources": ["secrets"]},    # 读取Secrets
    {"verbs": ["create", "patch"], "resources": ["daemonsets"]},
    {"verbs": ["create", "patch"], "resources": ["deployments"]},
    {"verbs": ["impersonate"], "resources": ["users", "groups", "serviceaccounts"]},
    {"verbs": ["escalate", "bind"], "resources": ["roles", "clusterroles"]},
]

# ============================================================
# Pod 安全标准 (PSS)
# ============================================================

# 受限级别应禁止的配置
PSS_RESTRICTED_VIOLATIONS: Dict[str, str] = {
    "privileged": "容器以特权模式运行",
    "hostNetwork": "使用宿主机网络命名空间",
    "hostPID": "使用宿主机PID命名空间",
    "hostIPC": "使用宿主机IPC命名空间",
    "hostPath": "挂载宿主机路径",
    "allowPrivilegeEscalation": "允许权限提升",
    "runAsRoot": "以root用户运行",
}

# ============================================================
# 安全基线配置
# ============================================================

# 推荐的安全上下文配置
RECOMMENDED_SECURITY_CONTEXT: Dict[str, any] = {
    "runAsNonRoot": True,
    "readOnlyRootFilesystem": True,
    "allowPrivilegeEscalation": False,
    "capabilities": {
        "drop": ["ALL"],
    },
}

# 推荐的资源限制
RECOMMENDED_RESOURCE_LIMITS: Dict[str, str] = {
    "cpu": "1000m",
    "memory": "512Mi",
    "ephemeral-storage": "1Gi",
}
