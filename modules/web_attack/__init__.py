"""
Web攻击模块 - Web Attack Tools
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.mcp_server import MCPServer

from modules.web_attack.sqli_tools import SQLMapTool, SQLiPayloadTool
from modules.web_attack.xss_tools import XSStrikeTool, DalfoxTool
from modules.web_attack.dir_tools import DirbTool, GobusterTool, FeroxbusterTool
from modules.web_attack.fuzzing_tools import FfufTool, WfuzzTool


def register_web_tools(server: 'MCPServer'):
    """注册Web攻击工具"""
    tools = [
        SQLMapTool(),
        SQLiPayloadTool(),
        XSStrikeTool(),
        DalfoxTool(),
        DirbTool(),
        GobusterTool(),
        FeroxbusterTool(),
        FfufTool(),
        WfuzzTool(),
    ]
    
    for tool in tools:
        server.register_tool(tool)


__all__ = [
    "register_web_tools",
    "SQLMapTool",
    "XSStrikeTool",
    "GobusterTool",
    "FfufTool"
]
