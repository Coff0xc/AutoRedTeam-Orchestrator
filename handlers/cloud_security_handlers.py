"""
云安全工具处理器
包含: k8s_scan, grpc_scan, aws_scan
"""

from typing import Any, Dict, List

from .error_handling import ErrorCategory, extract_target, handle_errors, validate_inputs
from .tooling import tool


def register_cloud_security_tools(mcp, counter, logger):
    """注册云安全工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CLOUD)
    async def k8s_scan(manifest_path: str = None, namespace: str = "default") -> Dict[str, Any]:
        """Kubernetes安全扫描 - 检测K8s配置安全问题

        检测: 特权容器、HostPath挂载、RBAC问题、网络策略、Secrets暴露

        Args:
            manifest_path: K8s清单文件路径 (可选)
            namespace: 命名空间

        Returns:
            安全发现
        """
        from modules.cloud_security import KubernetesTester, scan_k8s_manifest

        if manifest_path:
            findings = scan_k8s_manifest(manifest_path)
        else:
            tester = KubernetesTester(config={"namespace": namespace})
            findings = tester.scan()

        return {
            "success": True,
            "findings": [f.to_dict() for f in findings],
            "critical": len([f for f in findings if f.severity.value == "critical"]),
            "high": len([f for f in findings if f.severity.value == "high"]),
            "total": len(findings),
        }

    @tool(mcp)
    @validate_inputs(target="target")
    @handle_errors(logger, category=ErrorCategory.CLOUD, context_extractor=extract_target)
    async def grpc_scan(target: str) -> Dict[str, Any]:
        """gRPC安全扫描 - 检测gRPC服务安全问题

        检测: 反射服务、TLS配置、认证问题

        Args:
            target: gRPC服务地址 (host:port)

        Returns:
            安全发现
        """
        from modules.cloud_security import scan_grpc

        result = scan_grpc(target)

        return {
            "success": True,
            "target": target,
            "findings": result if isinstance(result, list) else [result],
        }

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.CLOUD)
    async def aws_scan(region: str = "us-east-1", services: List[str] = None) -> Dict[str, Any]:
        """AWS安全扫描 - 检测AWS配置安全问题

        需要: 配置AWS凭证 (环境变量或~/.aws/credentials)

        Args:
            region: AWS区域
            services: 要检查的服务列表

        Returns:
            安全发现
        """
        from modules.cloud_security import scan_aws

        result = scan_aws(region=region, services=services)

        return {
            "success": True,
            "region": region,
            "findings": result if isinstance(result, list) else [result],
        }

    counter.add("cloud_security", 3)
    logger.info("[Cloud Security] 已注册 3 个云安全工具")
