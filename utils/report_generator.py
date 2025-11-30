#!/usr/bin/env python3
"""
报告生成器 - 生成渗透测试报告
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List
from jinja2 import Template


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        self.reports_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "reports"
        )
        os.makedirs(self.reports_dir, exist_ok=True)
        
        self.templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "templates"
        )
    
    def generate(self, session_id: str, format_type: str = "html") -> str:
        """生成报告"""
        # 加载会话数据
        from core.session_manager import SessionManager
        session_manager = SessionManager()
        
        try:
            session = session_manager.load_session(session_id)
        except FileNotFoundError:
            session = session_manager.get_session(session_id)
        
        if not session:
            raise ValueError(f"会话不存在: {session_id}")
        
        # 准备报告数据
        report_data = self._prepare_report_data(session)
        
        # 生成报告
        if format_type == "html":
            return self._generate_html(report_data, session_id)
        elif format_type == "json":
            return self._generate_json(report_data, session_id)
        elif format_type == "markdown":
            return self._generate_markdown(report_data, session_id)
        else:
            raise ValueError(f"不支持的报告格式: {format_type}")
    
    def _prepare_report_data(self, session) -> Dict[str, Any]:
        """准备报告数据"""
        return {
            "session_id": session.id,
            "session_name": session.name,
            "created_at": session.created_at.isoformat(),
            "status": session.status.value,
            "targets": [
                {"value": t.value, "type": t.type}
                for t in session.targets
            ],
            "findings": session.findings,
            "findings_summary": self._summarize_findings(session.findings),
            "results_count": len(session.results),
            "notes": session.notes,
            "generated_at": datetime.now().isoformat()
        }
    
    def _summarize_findings(self, findings: List[Dict]) -> Dict[str, int]:
        """汇总发现"""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _generate_html(self, data: Dict, session_id: str) -> str:
        """生成HTML报告"""
        template = Template(self._get_html_template())
        html_content = template.render(**data)
        
        filename = f"report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def _generate_json(self, data: Dict, session_id: str) -> str:
        """生成JSON报告"""
        filename = f"report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return filepath
    
    def _generate_markdown(self, data: Dict, session_id: str) -> str:
        """生成Markdown报告"""
        template = Template(self._get_markdown_template())
        md_content = template.render(**data)
        
        filename = f"report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return filepath
    
    def _get_html_template(self) -> str:
        """HTML报告模板"""
        return '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>渗透测试报告 - {{ session_name }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 40px; 
                 border-radius: 10px; margin-bottom: 30px; border: 1px solid #333; }
        h1 { color: #00ff88; font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #00d4ff; margin: 30px 0 15px; padding-bottom: 10px; border-bottom: 2px solid #333; }
        h3 { color: #ff6b6b; margin: 20px 0 10px; }
        .meta { color: #888; font-size: 0.9em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
                   gap: 15px; margin: 20px 0; }
        .summary-card { background: #1a1a1a; padding: 20px; border-radius: 8px; text-align: center;
                        border: 1px solid #333; }
        .summary-card.critical { border-color: #ff4757; }
        .summary-card.high { border-color: #ff6b6b; }
        .summary-card.medium { border-color: #ffa502; }
        .summary-card.low { border-color: #2ed573; }
        .summary-card .count { font-size: 2em; font-weight: bold; }
        .summary-card.critical .count { color: #ff4757; }
        .summary-card.high .count { color: #ff6b6b; }
        .summary-card.medium .count { color: #ffa502; }
        .summary-card.low .count { color: #2ed573; }
        .finding { background: #1a1a1a; padding: 20px; border-radius: 8px; margin: 15px 0;
                   border-left: 4px solid #333; }
        .finding.critical { border-left-color: #ff4757; }
        .finding.high { border-left-color: #ff6b6b; }
        .finding.medium { border-left-color: #ffa502; }
        .finding.low { border-left-color: #2ed573; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; 
                 text-transform: uppercase; font-weight: bold; }
        .badge.critical { background: #ff4757; color: white; }
        .badge.high { background: #ff6b6b; color: white; }
        .badge.medium { background: #ffa502; color: black; }
        .badge.low { background: #2ed573; color: black; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #1a1a1a; color: #00d4ff; }
        code { background: #2a2a2a; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
        footer { text-align: center; padding: 30px; color: #666; margin-top: 40px; 
                 border-top: 1px solid #333; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 渗透测试报告</h1>
            <p class="meta">会话: {{ session_name }} | ID: {{ session_id }}</p>
            <p class="meta">生成时间: {{ generated_at }}</p>
        </header>
        
        <section>
            <h2>📊 发现汇总</h2>
            <div class="summary">
                <div class="summary-card critical">
                    <div class="count">{{ findings_summary.critical }}</div>
                    <div>严重</div>
                </div>
                <div class="summary-card high">
                    <div class="count">{{ findings_summary.high }}</div>
                    <div>高危</div>
                </div>
                <div class="summary-card medium">
                    <div class="count">{{ findings_summary.medium }}</div>
                    <div>中危</div>
                </div>
                <div class="summary-card low">
                    <div class="count">{{ findings_summary.low }}</div>
                    <div>低危</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>🎯 测试目标</h2>
            <table>
                <tr><th>目标</th><th>类型</th></tr>
                {% for target in targets %}
                <tr><td><code>{{ target.value }}</code></td><td>{{ target.type }}</td></tr>
                {% endfor %}
            </table>
        </section>
        
        <section>
            <h2>🔍 安全发现</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.severity }}">
                <span class="badge {{ finding.severity }}">{{ finding.severity }}</span>
                <h3>{{ finding.title }}</h3>
                <p>{{ finding.description }}</p>
                {% if finding.recommendations %}
                <h4>修复建议:</h4>
                <ul>
                    {% for rec in finding.recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </section>
        
        <footer>
            <p>AI Red Team MCP - 自动化渗透测试报告</p>
            <p>⚠️ 仅用于授权的安全测试</p>
        </footer>
    </div>
</body>
</html>'''
    
    def _get_markdown_template(self) -> str:
        """Markdown报告模板"""
        return '''# 渗透测试报告

## 基本信息
- **会话名称**: {{ session_name }}
- **会话ID**: {{ session_id }}
- **创建时间**: {{ created_at }}
- **报告生成**: {{ generated_at }}
- **状态**: {{ status }}

## 发现汇总

| 严重性 | 数量 |
|--------|------|
| 严重 | {{ findings_summary.critical }} |
| 高危 | {{ findings_summary.high }} |
| 中危 | {{ findings_summary.medium }} |
| 低危 | {{ findings_summary.low }} |
| 信息 | {{ findings_summary.info }} |

## 测试目标

{% for target in targets %}
- `{{ target.value }}` ({{ target.type }})
{% endfor %}

## 安全发现

{% for finding in findings %}
### [{{ finding.severity|upper }}] {{ finding.title }}

{{ finding.description }}

{% if finding.recommendations %}
**修复建议:**
{% for rec in finding.recommendations %}
- {{ rec }}
{% endfor %}
{% endif %}

---
{% endfor %}

## 备注

{% for note in notes %}
- {{ note.content }} ({{ note.timestamp }})
{% endfor %}

---
*AI Red Team MCP - 自动化渗透测试报告*
*⚠️ 仅用于授权的安全测试*
'''
