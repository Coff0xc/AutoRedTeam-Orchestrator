"""
报告工具处理器
包含: generate_report, export_findings
"""

from typing import Any, Dict
from .tooling import tool


def register_report_tools(mcp, counter, logger):
    """注册报告生成工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    async def generate_report(
        session_id: str,
        format: str = "json",
        output_path: str = None
    ) -> Dict[str, Any]:
        """生成渗透测试报告 - 生成详细的安全评估报告

        Args:
            session_id: 会话ID
            format: 报告格式 (json, html, markdown, executive)
            output_path: 输出路径 (可选)

        Returns:
            报告内容或路径
        """
        try:
            from utils.report_generator import ReportGenerator

            generator = ReportGenerator()
            source = generator.load_source(session_id)
            fmt = (format or "json").lower()

            if fmt == 'json':
                report = generator.to_dict(source)
            elif fmt == 'html':
                report = generator.to_html(source)
            elif fmt == 'markdown':
                report = generator.to_markdown(source)
            elif fmt == 'executive':
                report = generator.to_executive(source)
            else:
                return {'success': False, 'error': f'不支持的报告格式: {format}'}

            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    if isinstance(report, dict):
                        import json
                        json.dump(report, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(report)

                return {
                    'success': True,
                    'session_id': session_id,
                    'format': fmt,
                    'output_path': output_path
                }

            return {
                'success': True,
                'session_id': session_id,
                'format': fmt,
                'report': report
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @tool(mcp)
    async def export_findings(
        session_id: str,
        severity: str = None,
        format: str = "json"
    ) -> Dict[str, Any]:
        """导出漏洞发现 - 导出会话中发现的漏洞

        Args:
            session_id: 会话ID
            severity: 按严重程度过滤 (critical, high, medium, low)
            format: 输出格式

        Returns:
            漏洞列表
        """
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            context = manager.get_session(session_id)

            if not context:
                return {'success': False, 'error': f'会话不存在: {session_id}'}

            vulns = context.vulnerabilities

            if severity:
                vulns = [v for v in vulns if v.severity.value.lower() == severity.lower()]

            return {
                'success': True,
                'session_id': session_id,
                'vulnerabilities': [v.to_dict() for v in vulns],
                'count': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    counter.add('report', 2)
    logger.info("[Report] 已注册 2 个报告工具")
