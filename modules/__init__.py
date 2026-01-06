"""
AI Red Team MCP - Modules
"""

from typing import TYPE_CHECKING

# TYPE_CHECKING imports removed (legacy)


def register_all_modules(server: 'MCPServer'):
    """注册所有模块"""
    from modules.recon import register_recon_tools
    from modules.vuln_scan import register_vuln_tools
    from modules.web_attack import register_web_tools
    from modules.network import register_network_tools
    from modules.exploit import register_exploit_tools
    from modules.post_exploit import register_post_tools
    from modules.cloud import register_cloud_tools
    
    register_recon_tools(server)
    register_vuln_tools(server)
    register_web_tools(server)
    register_network_tools(server)
    register_exploit_tools(server)
    register_post_tools(server)
    register_cloud_tools(server)
    
    # 记录已注册的工具数量
    import logging
    logger = logging.getLogger(__name__)
    stats = server.tool_registry.get_stats()
    logger.info(f"已注册 {stats['total_tools']} 个工具")
