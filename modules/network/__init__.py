"""
网络攻击模块 - Network Attack Tools
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.mcp_server import MCPServer

from modules.network.brute_force import HydraTool, MedusaTool, CrackMapExecTool
from modules.network.smb_tools import SMBEnumTool, SMBClientTool
from modules.network.service_tools import (
    FTPCheckTool, SSHAuditTool, RDPCheckTool, 
    SNMPWalkTool, LDAPEnumTool
)


def register_network_tools(server: 'MCPServer'):
    """注册网络攻击工具"""
    tools = [
        HydraTool(),
        MedusaTool(),
        CrackMapExecTool(),
        SMBEnumTool(),
        SMBClientTool(),
        FTPCheckTool(),
        SSHAuditTool(),
        RDPCheckTool(),
        SNMPWalkTool(),
        LDAPEnumTool(),
    ]
    
    for tool in tools:
        server.register_tool(tool)


__all__ = [
    "register_network_tools",
    "HydraTool",
    "CrackMapExecTool",
    "SMBEnumTool"
]
