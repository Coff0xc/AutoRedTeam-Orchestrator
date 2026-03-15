#!/usr/bin/env python3
"""
报告生成器 - 生成渗透测试报告
支持HTML、JSON、Markdown格式，含攻击链可视化和详细统计
"""

import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from jinja2 import Template

logger = logging.getLogger(__name__)


class ReportGenerator:
    """报告生成器"""

    def __init__(self):
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

        self.templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")

    def load_source(self, session_id: str) -> Any:
        """按session_id加载报告来源对象（兼容新旧会话系统）"""
        return self._load_report_source(session_id)

    def _load_report_source(self, session_id: str) -> Any:
        """加载报告源数据"""
        from core.session import get_session_manager

        manager = get_session_manager()

        # 优先获取扫描结果
        result = manager.get_result(session_id)
        if result:
            return result

        # 尝试获取会话上下文
        context = manager.get_session(session_id)
        if context:
            return context

        # 尝试从存储加载
        try:
            session = manager.load_session(session_id)
            if session:
                return session
        except FileNotFoundError:
            pass

        raise ValueError(f"会话不存在: {session_id}")

    def generate(self, session_id: str, format_type: str = "html") -> str:
        """生成报告"""
        source = self._load_report_source(session_id)
        report_data = self._prepare_report_data(source)
        format_type = (format_type or "html").lower()

        if format_type == "html":
            return self._generate_html(report_data, session_id)
        if format_type == "json":
            return self._generate_json(report_data, session_id)
        if format_type == "markdown":
            return self._generate_markdown(report_data, session_id)
        if format_type == "executive":
            return self._generate_executive_summary(report_data, session_id)
        raise ValueError(f"不支持的报告格式: {format_type}")

    def _prepare_report_data(self, source) -> Dict[str, Any]:
        """准备报告数据（兼容多种会话/结果对象）"""
        if self._is_legacy_session(source):
            return self._prepare_report_data_from_legacy_session(source)
        return self._prepare_report_data_from_scan_source(source)

    def _prepare_report_data_from_legacy_session(self, session) -> Dict[str, Any]:
        """准备旧版会话报告数据"""
        findings = self._normalize_findings(session.findings)

        return {
            "session_id": session.id,
            "session_name": session.name,
            "created_at": session.created_at.isoformat(),
            "status": (
                session.status.value if hasattr(session.status, "value") else str(session.status)
            ),
            "targets": [{"value": t.value, "type": t.type} for t in session.targets],
            "findings": findings,
            "findings_summary": self._summarize_findings(findings),
            "findings_by_type": self._group_findings_by_type(findings),
            "findings_by_target": self._group_findings_by_target(findings),
            "attack_chains": self._analyze_attack_chains(findings),
            "cvss_distribution": self._calculate_cvss_distribution(findings),
            "remediation_priority": self._prioritize_remediation(findings),
            "results_count": len(session.results),
            "notes": self._normalize_notes(session.notes),
            "scan_statistics": self._calculate_scan_stats(session),
            "generated_at": datetime.now().isoformat(),
        }

    def _prepare_report_data_from_scan_source(self, source) -> Dict[str, Any]:
        """准备新版扫描上下文或结果对象的报告数据"""
        session_id = getattr(source, "session_id", "unknown")
        target_value = getattr(source, "target", None)
        if hasattr(target_value, "value"):
            target_value = target_value.value
        metadata = getattr(source, "metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        if not target_value:
            target_value = metadata.get("target")

        findings = []
        vulnerabilities = getattr(source, "vulnerabilities", [])
        if vulnerabilities:
            findings = [v.to_dict() if hasattr(v, "to_dict") else v for v in vulnerabilities]
        if not findings:
            metadata_findings = metadata.get("findings", [])
            if isinstance(metadata_findings, list):
                findings = metadata_findings

        findings = self._normalize_findings(findings)

        status = getattr(source, "status", "unknown")
        status_value = status.value if hasattr(status, "value") else str(status)
        created_at = getattr(source, "started_at", None)
        created_at_value = created_at.isoformat() if created_at else datetime.now().isoformat()

        session_name = getattr(source, "session_name", None) or target_value or session_id
        targets = self._build_targets(target_value)

        return {
            "session_id": session_id,
            "session_name": session_name,
            "created_at": created_at_value,
            "status": status_value,
            "targets": targets,
            "findings": findings,
            "findings_summary": self._summarize_findings(findings),
            "findings_by_type": self._group_findings_by_type(findings),
            "findings_by_target": self._group_findings_by_target(findings),
            "attack_chains": self._analyze_attack_chains(findings),
            "cvss_distribution": self._calculate_cvss_distribution(findings),
            "remediation_priority": self._prioritize_remediation(findings),
            "results_count": getattr(source, "total_requests", len(findings)),
            "notes": self._normalize_notes(getattr(source, "notes", [])),
            "scan_statistics": self._calculate_scan_stats(source),
            "generated_at": datetime.now().isoformat(),
        }

    def to_dict(self, source) -> Dict[str, Any]:
        """将会话或结果对象转换为报告字典"""
        return self._prepare_report_data(source)

    def to_html(self, source) -> str:
        """将会话或结果对象渲染为HTML字符串"""
        data = self._prepare_report_data(source)
        return self._render_html(data)

    def to_markdown(self, source) -> str:
        """将会话或结果对象渲染为Markdown字符串"""
        data = self._prepare_report_data(source)
        return self._render_markdown(data)

    def to_executive(self, source) -> str:
        """将会话或结果对象渲染为执行摘要HTML字符串"""
        data = self._prepare_report_data(source)
        return self._render_executive_summary(data)

    def _is_legacy_session(self, source: Any) -> bool:
        """判断是否为旧版会话对象"""
        return hasattr(source, "targets") and hasattr(source, "findings")

    def _infer_target_type(self, target: Optional[str]) -> str:
        """粗略推断目标类型"""
        if not target:
            return "unknown"
        if target.startswith(("http://", "https://")):
            return "url"
        if "/" in target:
            return "network"
        return "host"

    def _build_targets(self, target_value: Optional[str]) -> List[Dict[str, str]]:
        """构建统一的目标列表结构"""
        if not target_value:
            return []
        return [{"value": target_value, "type": self._infer_target_type(target_value)}]

    def _normalize_notes(self, notes: List[Any]) -> List[Dict[str, Any]]:
        """统一备注结构"""
        normalized = []
        for note in notes or []:
            if isinstance(note, dict) and "content" in note:
                normalized.append(note)
            elif isinstance(note, str):
                normalized.append({"content": note, "timestamp": ""})
        return normalized

    def _normalize_findings(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """统一发现结构，补齐模板所需字段"""
        normalized = []
        for finding in findings or []:
            if isinstance(finding, dict):
                data = dict(finding)
            elif hasattr(finding, "to_dict"):
                data = finding.to_dict()
            else:
                continue

            raw_severity = data.get("severity", "info")
            if hasattr(raw_severity, "value"):
                raw_severity = raw_severity.value
            severity = str(raw_severity).lower()
            description = (
                data.get("description") or data.get("evidence") or data.get("detail") or ""
            )
            recommendations = data.get("recommendations")
            if recommendations is None and data.get("remediation"):
                recommendations = [data.get("remediation")]
            if recommendations is None:
                recommendations = []

            data.setdefault("title", data.get("name") or data.get("type") or "未知漏洞")
            data.setdefault("severity", severity)
            data.setdefault("description", description)
            data.setdefault("recommendations", recommendations)
            if "target" not in data:
                data["target"] = data.get("url")
            normalized.append(data)

        return normalized

    def _summarize_findings(self, findings: List[Dict]) -> Dict[str, int]:
        """汇总发现"""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": len(findings),
        }

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in summary:
                summary[severity] += 1

        return summary

    def _group_findings_by_type(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """按漏洞类型分组"""
        grouped = defaultdict(list)
        for finding in findings:
            vuln_type = finding.get("type", finding.get("category", "other"))
            grouped[vuln_type].append(finding)
        return dict(grouped)

    def _group_findings_by_target(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """按目标分组"""
        grouped = defaultdict(list)
        for finding in findings:
            target = finding.get("target", finding.get("url", "unknown"))
            grouped[target].append(finding)
        return dict(grouped)

    def _analyze_attack_chains(self, findings: List[Dict]) -> List[Dict]:
        """分析可能的攻击链"""
        chains = []

        # 查找可组合的漏洞
        sqli_findings = [f for f in findings if "sql" in f.get("type", "").lower()]
        ssrf_findings = [f for f in findings if "ssrf" in f.get("type", "").lower()]
        lfi_findings = [
            f
            for f in findings
            if "lfi" in f.get("type", "").lower() or "file" in f.get("type", "").lower()
        ]
        auth_findings = [f for f in findings if "auth" in f.get("type", "").lower()]

        # SSRF → 内网探测 → 数据库访问
        if ssrf_findings:
            chains.append(
                {
                    "name": "SSRF到内网渗透",
                    "steps": ["SSRF漏洞利用", "内网服务探测", "敏感服务访问"],
                    "findings": ssrf_findings[:3],
                    "risk": "critical",
                }
            )

        # SQLi → 数据泄露 → 权限提升
        if sqli_findings:
            chains.append(
                {
                    "name": "SQL注入到数据泄露",
                    "steps": ["SQL注入利用", "数据库枚举", "敏感数据提取"],
                    "findings": sqli_findings[:3],
                    "risk": "critical",
                }
            )

        # LFI → 配置泄露 → RCE
        if lfi_findings:
            chains.append(
                {
                    "name": "文件包含到远程执行",
                    "steps": ["本地文件包含", "配置文件读取", "凭据获取"],
                    "findings": lfi_findings[:3],
                    "risk": "high",
                }
            )

        # 认证绕过 → 后台访问 → 系统控制
        if auth_findings:
            chains.append(
                {
                    "name": "认证绕过到系统控制",
                    "steps": ["认证绕过", "后台功能访问", "敏感操作执行"],
                    "findings": auth_findings[:3],
                    "risk": "critical",
                }
            )

        return chains

    def _calculate_cvss_distribution(self, findings: List[Dict]) -> Dict[str, int]:
        """计算CVSS分数分布"""
        distribution = {"9.0-10.0": 0, "7.0-8.9": 0, "4.0-6.9": 0, "0.1-3.9": 0, "未评分": 0}

        for finding in findings:
            cvss = finding.get("cvss", finding.get("cvss_score"))
            if cvss is None:
                distribution["未评分"] += 1
            elif cvss >= 9.0:
                distribution["9.0-10.0"] += 1
            elif cvss >= 7.0:
                distribution["7.0-8.9"] += 1
            elif cvss >= 4.0:
                distribution["4.0-6.9"] += 1
            else:
                distribution["0.1-3.9"] += 1

        return distribution

    def _prioritize_remediation(self, findings: List[Dict]) -> List[Dict]:
        """优先级排序的修复建议"""
        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                priority_map.get(f.get("severity", "info").lower(), 5),
                -f.get("cvss", 0) if f.get("cvss") else 0,
            ),
        )

        return sorted_findings[:20]  # 返回前20个优先修复项

    def _calculate_scan_stats(self, session) -> Dict[str, Any]:
        """计算扫描统计"""
        if hasattr(session, "total_requests") or hasattr(session, "requests_sent"):
            total_requests = (
                getattr(session, "total_requests", None)
                if getattr(session, "total_requests", None) is not None
                else getattr(session, "requests_sent", 0)
            )
            vulnerabilities = getattr(session, "vulnerabilities", [])
            unique_endpoints = len(
                {
                    getattr(v, "url", None) or (v.get("url") if isinstance(v, dict) else None)
                    for v in vulnerabilities
                    if getattr(v, "url", None) or (isinstance(v, dict) and v.get("url"))
                }
            )

            return {
                "total_requests": total_requests or 0,
                "unique_endpoints": unique_endpoints,
                "scan_duration": self._calculate_duration(session),
                "success_rate": self._calculate_success_rate_from_scan_source(session),
            }

        results = session.results if hasattr(session, "results") else []
        unique_endpoints = len(
            {url for url in (self._extract_result_url(r) for r in results) if url}
        )

        return {
            "total_requests": len(results),
            "unique_endpoints": unique_endpoints,
            "scan_duration": self._calculate_duration(session),
            "success_rate": self._calculate_success_rate(results),
        }

    def _calculate_duration(self, session) -> str:
        """计算扫描持续时间"""
        try:
            if hasattr(session, "started_at") and hasattr(session, "ended_at"):
                if session.started_at and session.ended_at:
                    delta = session.ended_at - session.started_at
                    return self._format_duration(delta.total_seconds())
            if hasattr(session, "duration") and session.duration is not None:
                return self._format_duration(float(session.duration))
            if hasattr(session, "updated_at") and hasattr(session, "created_at"):
                if session.updated_at and session.created_at:
                    delta = session.updated_at - session.created_at
                    return self._format_duration(delta.total_seconds())
        except (TypeError, AttributeError):
            # 时间计算失败时返回默认值
            pass
        return "N/A"

    def _calculate_success_rate(self, results: List) -> float:
        """计算请求成功率"""
        if not results:
            return 0.0
        success = 0
        for result in results:
            if isinstance(result, dict):
                status_code = result.get("status_code")
                if status_code is not None:
                    success += 1 if status_code < 400 else 0
                elif result.get("success") is True:
                    success += 1
                continue
            if hasattr(result, "success"):
                success += 1 if result.success else 0
                continue
            if hasattr(result, "result") and isinstance(result.result, dict):
                status_code = result.result.get("status_code")
                if status_code is not None and status_code < 400:
                    success += 1
        return round(success / len(results) * 100, 2)

    def _calculate_success_rate_from_scan_source(self, session) -> float:
        """计算扫描成功率（基于总请求与错误计数）"""
        total = getattr(session, "requests_sent", None)
        if total is None:
            total = getattr(session, "total_requests", 0)
        errors = getattr(session, "errors_count", None)
        if not total:
            return 0.0
        if errors is None:
            return 0.0
        success = max(total - errors, 0)
        return round(success / total * 100, 2)

    def _extract_result_url(self, result: Any) -> Optional[str]:
        """从执行结果中提取URL"""
        if isinstance(result, dict):
            return result.get("url") or result.get("target")
        if hasattr(result, "result") and isinstance(result.result, dict):
            return result.result.get("url") or result.result.get("target")
        return None

    def _format_duration(self, seconds: float) -> str:
        """将秒数格式化为可读时长"""
        if seconds < 0:
            return "N/A"
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{int(hours)}h {int(minutes)}m {int(secs)}s"

    def _generate_executive_summary(self, data: Dict, session_id: str) -> str:
        """生成执行摘要报告"""
        content = self._render_executive_summary(data)

        filename = f"executive_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        return filepath

    def _render_executive_summary(self, data: Dict) -> str:
        """渲染执行摘要HTML内容"""
        template = Template(self._get_executive_template())
        return template.render(**data)

    def _get_executive_template(self) -> str:
        """执行摘要模板"""
        return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>安全评估执行摘要</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #fff; color: #333; padding: 40px; }
        .header { border-bottom: 3px solid #1a73e8; padding-bottom: 20px; margin-bottom: 30px; }
        h1 { color: #1a73e8; }
        .risk-meter { display: flex; height: 40px; border-radius: 8px; overflow: hidden; margin: 20px 0; }
        .risk-critical { background: #d32f2f; }
        .risk-high { background: #f57c00; }
        .risk-medium { background: #fbc02d; }
        .risk-low { background: #388e3c; }
        .key-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 30px 0; }
        .metric { text-align: center; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .metric .value { font-size: 2.5em; font-weight: bold; color: #1a73e8; }
        .attack-chain { background: #f5f5f5; padding: 20px; margin: 15px 0; border-radius: 8px; }
        .chain-steps { display: flex; align-items: center; gap: 10px; margin-top: 10px; }
        .chain-step { background: #1a73e8; color: white; padding: 8px 15px; border-radius: 4px; }
        .chain-arrow { color: #666; font-size: 1.5em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ 安全评估执行摘要</h1>
        <p>评估目标: {{ session_name }} | 报告日期: {{ generated_at[:10] }}</p>
    </div>
    
    <h2>风险概览</h2>
    <div class="risk-meter">
        {% set total = findings_summary.total or 1 %}
        <div class="risk-critical" style="width: {{ (findings_summary.critical / total * 100)|int }}%"></div>
        <div class="risk-high" style="width: {{ (findings_summary.high / total * 100)|int }}%"></div>
        <div class="risk-medium" style="width: {{ (findings_summary.medium / total * 100)|int }}%"></div>
        <div class="risk-low" style="width: {{ (findings_summary.low / total * 100)|int }}%"></div>
    </div>
    
    <div class="key-metrics">
        <div class="metric">
            <div class="value" style="color: #d32f2f;">{{ findings_summary.critical }}</div>
            <div>严重漏洞</div>
        </div>
        <div class="metric">
            <div class="value" style="color: #f57c00;">{{ findings_summary.high }}</div>
            <div>高危漏洞</div>
        </div>
        <div class="metric">
            <div class="value">{{ findings_summary.total }}</div>
            <div>总发现数</div>
        </div>
        <div class="metric">
            <div class="value">{{ targets|length }}</div>
            <div>测试目标</div>
        </div>
    </div>
    
    {% if attack_chains %}
    <h2>潜在攻击链</h2>
    {% for chain in attack_chains %}
    <div class="attack-chain">
        <strong>{{ chain.name }}</strong> <span style="color: #d32f2f;">[{{ chain.risk|upper }}]</span>
        <div class="chain-steps">
            {% for step in chain.steps %}
            <span class="chain-step">{{ step }}</span>
            {% if not loop.last %}<span class="chain-arrow">→</span>{% endif %}
            {% endfor %}
        </div>
    </div>
    {% endfor %}
    {% endif %}
    
    <h2>优先修复建议</h2>
    <ol>
    {% for finding in remediation_priority[:5] %}
        <li><strong>[{{ finding.severity|upper }}]</strong> {{ finding.title }} - {{ finding.target|default(finding.url)|default('N/A') }}</li>
    {% endfor %}
    </ol>
</body>
</html>"""

    def _generate_html(self, data: Dict, session_id: str) -> str:
        """生成HTML报告"""
        html_content = self._render_html(data)

        filename = f"report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath

    def _render_html(self, data: Dict) -> str:
        """渲染HTML报告内容"""
        template = Template(self._get_html_template())
        return template.render(**data)

    def _generate_json(self, data: Dict, session_id: str) -> str:
        """生成JSON报告"""
        filename = f"report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        return filepath

    def _generate_markdown(self, data: Dict, session_id: str) -> str:
        """生成Markdown报告"""
        md_content = self._render_markdown(data)

        filename = f"report_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)

        return filepath

    def _render_markdown(self, data: Dict) -> str:
        """渲染Markdown报告内容"""
        template = Template(self._get_markdown_template())
        return template.render(**data)

    def _get_html_template(self) -> str:
        """HTML报告模板"""
        return """<!DOCTYPE html>
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
</html>"""

    def _get_markdown_template(self) -> str:
        """Markdown报告模板"""
        return """# 渗透测试报告

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
"""
