"""
AI Red Team MCP - Modules
"""

from typing import TYPE_CHECKING

# TYPE_CHECKING imports removed (legacy)


def register_all_modules(server: 'MCPServer'):
    """注册所有模块

    注意: 此函数目前未被使用，项目使用 handlers/register_all_handlers 代替。
    保留此函数用于向后兼容和未来可能的重构。
    """
    from modules.recon import register_recon_tools
    from modules.vuln_scan import register_vuln_tools
    from modules.network import register_network_tools
    from modules.exploit import register_exploit_tools
    from modules.post_exploit import register_post_tools
    from modules.cloud import register_cloud_tools

    register_recon_tools(server)
    register_vuln_tools(server)
    register_network_tools(server)
    register_exploit_tools(server)
    register_post_tools(server)
    register_cloud_tools(server)

    # 记录已注册的工具数量
    import logging
    logger = logging.getLogger(__name__)
    stats = server.tool_registry.get_stats()
    logger.info(f"已注册 {stats['total_tools']} 个工具")
