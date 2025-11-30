"""
漏洞扫描模块 - Vulnerability Scanning Tools
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.mcp_server import MCPServer

from modules.vuln_scan.nuclei_tools import NucleiScanTool, NucleiTemplateScanTool
from modules.vuln_scan.nikto_tools import NiktoScanTool
from modules.vuln_scan.ssl_tools import SSLScanTool, TestSSLTool
from modules.vuln_scan.vuln_search import SearchsploitTool, CVESearchTool


def register_vuln_tools(server: 'MCPServer'):
    """注册漏洞扫描工具"""
    tools = [
        NucleiScanTool(),
        NucleiTemplateScanTool(),
        NiktoScanTool(),
        SSLScanTool(),
        TestSSLTool(),
        SearchsploitTool(),
        CVESearchTool(),
    ]
    
    for tool in tools:
        server.register_tool(tool)


__all__ = [
    "register_vuln_tools",
    "NucleiScanTool",
    "NiktoScanTool",
    "SSLScanTool",
    "SearchsploitTool"
]
