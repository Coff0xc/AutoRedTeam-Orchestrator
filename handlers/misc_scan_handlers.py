"""Scan-profile misc surfaces. Imported only when the profile allows them."""

from typing import Any, Dict

from .error_handling import ErrorCategory, extract_url, handle_errors, validate_inputs
from .tooling import tool


def register_js_analyze(mcp, logger) -> int:
    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.MISC, context_extractor=extract_url)
    async def js_analyze(url: str) -> Dict[str, Any]:
        """JS代码分析 - 分析JavaScript代码中的敏感信息

        提取: API端点、密钥、令牌、内部路径

        Args:
            url: 目标URL或JS文件URL

        Returns:
            分析结果
        """
        from core.recon.js_analyzer import JSAnalyzer

        analyzer = JSAnalyzer()
        results = analyzer.analyze(url)

        return {"success": True, "url": url, "findings": results}

    return 1
