"""
信息收集模块 - Reconnaissance Tools
"""

from typing import TYPE_CHECKING

from modules.recon.dns_tools import DNSEnumTool, DNSReconTool, DnsxTool
from modules.recon.nmap_tools import (
    NmapOSScanTool,
    NmapQuickScanTool,
    NmapScanTool,
    NmapServiceScanTool,
    NmapVulnScanTool,
)
from modules.recon.osint_tools import ShodanLookupTool, TheHarvesterTool, WhoisLookupTool
from modules.recon.subdomain_tools import AmassEnumTool, AssetfinderTool, SubfinderTool
from modules.recon.web_recon_tools import WafDetectTool, WapalyzerTool, WhatWebTool

# TYPE_CHECKING imports removed (legacy)


def register_recon_tools(server: "MCPServer"):
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
    "WhatWebTool",
]
