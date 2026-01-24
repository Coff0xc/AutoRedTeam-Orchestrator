#!/usr/bin/env python3
"""
云安全测试模块

提供全面的云环境安全测试功能，包括:
- Kubernetes安全测试
- AWS安全测试
- Azure安全测试
- gRPC安全测试

使用示例:
    # Kubernetes扫描
    from modules.cloud_security import KubernetesTester
    tester = KubernetesTester(config={'namespace': 'default'})
    findings = tester.scan()

    # AWS扫描
    from modules.cloud_security import AWSTester
    tester = AWSTester(config={'region': 'us-east-1'})
    findings = tester.scan()

    # 清单文件扫描
    from modules.cloud_security import scan_k8s_manifest
    result = scan_k8s_manifest('/path/to/deployment.yaml')

作者: AutoRedTeam
版本: 3.0.0
"""

# 基础类和类型
from .base import (
    CloudVulnType,
    CloudSeverity,
    CloudFinding,
    CloudScanSummary,
    BaseCloudTester,
)

# Kubernetes
from .kubernetes import (
    KubernetesTester,
    scan_k8s_namespace,
    scan_k8s_manifest,
)

# AWS
from .aws import (
    AWSTester,
    scan_aws,
)

# Azure
from .azure import (
    AzureTester,
    scan_azure,
)

# gRPC
from .grpc import (
    GRPCTester,
    scan_grpc,
    enumerate_grpc_services,
)


# 版本信息
__version__ = '3.0.0'
__author__ = 'AutoRedTeam'


__all__ = [
    # 版本
    '__version__',
    '__author__',

    # 基础类型
    'CloudVulnType',
    'CloudSeverity',
    'CloudFinding',
    'CloudScanSummary',
    'BaseCloudTester',

    # Kubernetes
    'KubernetesTester',
    'scan_k8s_namespace',
    'scan_k8s_manifest',

    # AWS
    'AWSTester',
    'scan_aws',

    # Azure
    'AzureTester',
    'scan_azure',

    # gRPC
    'GRPCTester',
    'scan_grpc',
    'enumerate_grpc_services',
]
