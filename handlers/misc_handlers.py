"""
杂项工具处理器
包含: registry_stats, health_check, js_analyze
"""

import platform
from typing import Any, Dict
from .tooling import tool


def register_misc_tools(mcp, counter, logger):
    """注册杂项工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    async def registry_stats() -> Dict[str, Any]:
        """工具统计 - 获取已注册工具的统计信息

        Returns:
            工具统计
        """
        return {
            'success': True,
            'total': counter.total,
            'by_category': counter.counts,
            'version': '3.0.0'
        }

    @tool(mcp)
    async def health_check() -> Dict[str, Any]:
        """健康检查 - 检查MCP服务器状态

        Returns:
            服务器状态
        """
        return {
            'success': True,
            'status': 'healthy',
            'version': '3.0.0',
            'python_version': platform.python_version(),
            'platform': platform.system(),
            'tools_registered': counter.total
        }

    @tool(mcp)
    async def js_analyze(url: str) -> Dict[str, Any]:
        """JS代码分析 - 分析JavaScript代码中的敏感信息

        提取: API端点、密钥、令牌、内部路径

        Args:
            url: 目标URL或JS文件URL

        Returns:
            分析结果
        """
        try:
            from modules.js_analyzer import JSAnalyzer

            analyzer = JSAnalyzer()
            results = analyzer.analyze(url)

            return {
                'success': True,
                'url': url,
                'findings': results
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    counter.add('misc', 3)
    logger.info("[Misc] 已注册 3 个杂项工具")