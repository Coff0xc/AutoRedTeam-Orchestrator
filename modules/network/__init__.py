"""
网络攻击模块 - Network Attack Tools
"""

from typing import TYPE_CHECKING

from modules.network.brute_force import CrackMapExecTool, HydraTool, MedusaTool
from modules.network.service_tools import (
    FTPCheckTool,
    LDAPEnumTool,
    RDPCheckTool,
    SNMPWalkTool,
    SSHAuditTool,
)
from modules.network.smb_tools import SMBClientTool, SMBEnumTool

# TYPE_CHECKING imports removed (legacy)


def register_network_tools(server: "MCPServer"):
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


__all__ = ["register_network_tools", "HydraTool", "CrackMapExecTool", "SMBEnumTool"]
