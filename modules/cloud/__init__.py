"""
云安全模块 - Cloud Security Tools
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.mcp_server import MCPServer

from modules.cloud.aws_tools import AWSEnumTool, S3ScannerTool
from modules.cloud.azure_tools import AzureEnumTool
from modules.cloud.k8s_tools import KubeHunterTool


def register_cloud_tools(server: 'MCPServer'):
    """注册云安全工具"""
    tools = [
        AWSEnumTool(),
        S3ScannerTool(),
        AzureEnumTool(),
        KubeHunterTool(),
    ]
    
    for tool in tools:
        server.register_tool(tool)


__all__ = [
    "register_cloud_tools",
    "AWSEnumTool",
    "S3ScannerTool"
]
