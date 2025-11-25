"""
Report Generator - 报告生成器
支持JSON、HTML、Markdown格式
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from string import Template

logger = logging.getLogger(__name__)


class ReportGenerator:
    """渗透测试报告生成器"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir = Path(__file__).parent.parent / "templates"
    
    def generate(self, data: Dict, format: str = "json", filename: str = None) -> str:
        """生成报告"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = data.get("meta", {}).get("target", "unknown").replace(".", "_")
        
        if format == "json":
            return self._generate_json(data, filename or f"report_{target}_{timestamp}.json")
        elif format == "html":
            return self._generate_html(data, filename or f"report_{target}_{timestamp}.html")
        elif format == "markdown":
            return self._generate_markdown(data, filename or f"report_{target}_{timestamp}.md")
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, data: Dict, filename: str) -> str:
        """生成JSON报告"""
        output_path = self.output_dir / filename
        output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        logger.info(f"JSON report saved: {output_path}")
        return str(output_path)
    
    def _generate_html(self, data: Dict, filename: str) -> str:
        """生成HTML报告"""
        template_path = self.template_dir / "report_template.html"
        
        # 准备模板数据
        summary = data.get("summary", {})
        severity = summary.get("severity_breakdown", {})
        assets_data = data.get("assets", {})
        
        template_data = {
            "target": data.get("meta", {}).get("target", "Unknown"),
            "scan_time": data.get("meta", {}).get("scan_time", datetime.now().isoformat()),
            "critical_count": severity.get("critical", 0),
            "high_count": severity.get("high", 0),
            "medium_count": severity.get("medium", 0),
            "subdomains_count": assets_data.get("subdomains_discovered", 0),
            "assets_count": assets_data.get("assets_mapped", 0),
            "http_services": assets_data.get("http_services", 0),
            "total_vulns": summary.get("total_findings", 0),
            "false_positives": summary.get("false_positives_filtered", 0),
        }
        
        # 简单模板替换（不使用Jinja2以减少依赖）
        if template_path.exists():
            html = template_path.read_text()
            for key, value in template_data.items():
                html = html.replace("{{ " + key + " }}", str(value))
            
            # 处理漏洞列表
            vulns_html = ""
            for v in data.get("vulnerabilities", []):
                vulns_html += f'''
                <div class="vuln-item {v.get('severity', 'medium')}">
                    <div class="vuln-header">
                        <span class="vuln-name">{v.get('name', 'Unknown')}</span>
                        <span class="severity-badge {v.get('severity', 'medium')}">{v.get('severity', 'medium')}</span>
                    </div>
                    <div class="vuln-details">
                        <p><strong>目标:</strong> {v.get('target', '')}</p>
                        <p><strong>置信度:</strong> {int(v.get('confidence', 0) * 100)}%</p>
                        <p><strong>模板ID:</strong> {v.get('id', '')}</p>
                    </div>
                </div>'''
            
            html = html.replace("{% for vuln in vulnerabilities %}{% endfor %}", vulns_html)
        else:
            html = self._generate_simple_html(data, template_data)
        
        output_path = self.output_dir / filename
        output_path.write_text(html)
        logger.info(f"HTML report saved: {output_path}")
        return str(output_path)
    
    def _generate_simple_html(self, data: Dict, template_data: Dict) -> str:
        """生成简单HTML报告（模板不存在时）"""
        vulns_rows = ""
        for v in data.get("vulnerabilities", []):
            vulns_rows += f"<tr><td>{v.get('name')}</td><td>{v.get('severity')}</td><td>{v.get('target')}</td></tr>"
        
        return f"""<!DOCTYPE html>
<html><head><title>渗透测试报告 - {template_data['target']}</title>
<style>body{{font-family:sans-serif;margin:40px;background:#1a1a2e;color:#ccc}}
h1{{color:#e94560}}table{{width:100%;border-collapse:collapse}}
th,td{{padding:10px;border:1px solid #333;text-align:left}}th{{background:#333}}</style></head>
<body><h1>渗透测试报告</h1>
<p><strong>目标:</strong> {template_data['target']}</p>
<p><strong>时间:</strong> {template_data['scan_time']}</p>
<h2>漏洞统计</h2>
<p>严重: {template_data['critical_count']} | 高危: {template_data['high_count']} | 中危: {template_data['medium_count']}</p>
<h2>漏洞详情</h2>
<table><tr><th>漏洞名称</th><th>等级</th><th>目标</th></tr>{vulns_rows}</table>
</body></html>"""
    
    def _generate_markdown(self, data: Dict, filename: str) -> str:
        """生成Markdown报告"""
        summary = data.get("summary", {})
        severity = summary.get("severity_breakdown", {})
        meta = data.get("meta", {})
        
        md = f"""# 🎯 渗透测试报告

## 基本信息
- **目标**: {meta.get('target', 'Unknown')}
- **扫描时间**: {meta.get('scan_time', '')}
- **工具**: AutoRedTeam-Orchestrator

## 📊 概览

| 指标 | 数值 |
|------|------|
| 严重漏洞 | {severity.get('critical', 0)} |
| 高危漏洞 | {severity.get('high', 0)} |
| 中危漏洞 | {severity.get('medium', 0)} |
| 低危漏洞 | {severity.get('low', 0)} |
| 误报过滤 | {summary.get('false_positives_filtered', 0)} |

## 🔥 漏洞详情

"""
        for v in data.get("vulnerabilities", []):
            md += f"""### [{v.get('severity', 'medium').upper()}] {v.get('name', 'Unknown')}
- **目标**: {v.get('target', '')}
- **置信度**: {int(v.get('confidence', 0) * 100)}%
- **ID**: {v.get('id', '')}

"""
        
        md += """---
*由 AutoRedTeam-Orchestrator 生成*
"""
        
        output_path = self.output_dir / filename
        output_path.write_text(md)
        logger.info(f"Markdown report saved: {output_path}")
        return str(output_path)
