"""
信息收集模块 - Reconnaissance Tools
"""

from modules.recon.cdn_bypass import CDNDetectTool, HistoricalDNSTool, RealIPFinderTool
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


def register_recon_tools(server):
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
        # CDN识别与真实IP发现
        CDNDetectTool(),
        RealIPFinderTool(),
        HistoricalDNSTool(),
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
    "CDNDetectTool",
    "RealIPFinderTool",
    "HistoricalDNSTool",
]
