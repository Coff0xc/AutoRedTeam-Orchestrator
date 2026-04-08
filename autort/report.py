"""报告生成 — 封装 utils.report_generator

提供渗透测试报告的生成和导出功能。

Usage:
    reporter = Reporter("session_id_here")
    html_path = await reporter.generate(format="html")
    findings = await reporter.export_findings(format="json")
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class Reporter:
    """报告生成接口

    封装 ReportGenerator，提供多种格式的报告生成。

    Args:
        session_id: 渗透测试会话 ID，用于加载报告数据源
        config: 可选配置
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.session_id = session_id
        self._config = config or {}

    async def generate(self, format: str = "html") -> str:
        """生成渗透报告

        支持格式: html, json, markdown, executive

        Args:
            format: 报告格式

        Returns:
            报告文件路径或内容字符串
        """
        try:
            from utils.report_generator import ReportGenerator

            generator = ReportGenerator()
            if not self.session_id:
                return ""
            result = generator.generate(
                session_id=self.session_id,
                format_type=format,
            )
            return result
        except Exception as e:
            logger.error("generate 失败: %s", e)
            return f"报告生成失败: {e}"

    async def export_findings(self, format: str = "json") -> Dict[str, Any]:
        """导出渗透发现

        Args:
            format: 导出格式 (json/csv)

        Returns:
            导出结果字典
        """
        try:
            from utils.report_generator import ReportGenerator

            generator = ReportGenerator()
            if not self.session_id:
                return {"success": False, "error": "未指定 session_id"}

            source = generator.load_source(self.session_id)
            if not source:
                return {"success": False, "error": f"会话不存在: {self.session_id}"}

            # 使用 generator 内部方法准备数据
            report_data = generator._prepare_report_data(source)
            return {"success": True, "format": format, "data": report_data}
        except Exception as e:
            logger.error("export_findings 失败: %s", e)
            return {"success": False, "error": str(e)}
