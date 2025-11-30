"""
信息收集模块 - Reconnaissance Tools
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.mcp_server import MCPServer

from modules.recon.nmap_tools import (
    NmapScanTool, NmapQuickScanTool, NmapServiceScanTool, 
    NmapOSScanTool, NmapVulnScanTool
)
from modules.recon.subdomain_tools import (
    SubfinderTool, AmassEnumTool, AssetfinderTool
)
from modules.recon.dns_tools import (
    DNSEnumTool, DNSReconTool, DnsxTool
)
from modules.recon.osint_tools import (
    WhoisLookupTool, TheHarvesterTool, ShodanLookupTool
)
from modules.recon.web_recon_tools import (
    WhatWebTool, WapalyzerTool, WafDetectTool
)


def register_recon_tools(server: 'MCPServer'):
    """注册信息收集工具"""
    tools = [
        # Nmap工具
        NmapScanTool(),
        NmapQuickScanTool(),
        NmapServiceScanTool(),
        NmapOSScanTool(),
        NmapVulnScanTool(),
        
        # 子域名工具
        SubfinderTool(),
        AmassEnumTool(),
        AssetfinderTool(),
        
        # DNS工具
        DNSEnumTool(),
        DNSReconTool(),
        DnsxTool(),
        
        # OSINT工具
        WhoisLookupTool(),
        TheHarvesterTool(),
        ShodanLookupTool(),
        
        # Web侦察工具
        WhatWebTool(),
        WapalyzerTool(),
        WafDetectTool(),
    ]
    
    for tool in tools:
        server.register_tool(tool)


__all__ = [
    "register_recon_tools",
    "NmapScanTool",
    "SubfinderTool", 
    "DNSEnumTool",
    "WhoisLookupTool",
    "WhatWebTool"
]
