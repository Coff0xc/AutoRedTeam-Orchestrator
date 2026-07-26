"""SARIF 2.1.0 输出格式生成器

将漏洞检测结果转换为 SARIF (Static Analysis Results Interchange Format) 格式，
供 GitHub Security tab / Code Scanning alerts 直接展示。

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF level 与内部 severity 的映射
_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# severity 的数值权重（用于阈值比较）
SEVERITY_ORDER: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "moderate": 2,  # SurfaceRiskLevel 使用 moderate，与 medium 同级
    "high": 3,
    "critical": 4,
}


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    tool_name: str = "AutoRedTeam",
    tool_version: str = "3.1.0",
) -> Dict[str, Any]:
    """将检测结果转换为 SARIF 2.1.0 格式

    Args:
        findings: 检测结果列表 (来自 Scanner.detect_vulns)
        tool_name: 工具名称
        tool_version: 工具版本

    Returns:
        SARIF JSON 字典
    """
    sarif: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/Coff0xc/AutoRedTeam-Orchestrator",
                        "rules": _extract_rules(findings),
                    }
                },
                "results": [_convert_finding(f, idx) for idx, f in enumerate(findings)],
            }
        ],
    }
    return sarif


def _normalize_severity(finding: Dict[str, Any]) -> str:
    """兼容动态漏洞的 severity 与静态表面 finding 的 risk_level。

    SurfaceRiskLevel 使用 "moderate"，SARIF level 映射按 "medium" 处理。
    """
    raw = str(finding.get("severity") or finding.get("risk_level") or "medium").lower()
    return "medium" if raw == "moderate" else raw


def _rule_id(finding: Dict[str, Any], index: int) -> str:
    """统一 result.ruleId 与 rule.id 的取值，兼容两类 finding。"""
    return (
        finding.get("type")
        or finding.get("finding_type")
        or finding.get("tool_name")
        or f"vuln-{index}"
    )


def _physical_location(finding: Dict[str, Any]) -> Dict[str, Any]:
    """静态分析优先用代码位置 (file_path + line)，动态扫描回退到 URL。"""
    file_path = finding.get("file_path")
    if file_path:
        location: Dict[str, Any] = {"artifactLocation": {"uri": str(file_path)}}
        line = finding.get("line")
        if isinstance(line, int) and line > 0:
            location["region"] = {"startLine": line}
        return location
    return {"artifactLocation": {"uri": finding.get("url", "unknown")}}


def _convert_finding(finding: Dict[str, Any], index: int) -> Dict[str, Any]:
    """转换单个发现为 SARIF result"""
    level = _SEVERITY_TO_LEVEL.get(_normalize_severity(finding), "warning")

    # 优先使用 evidence，回退到 description
    message_text = finding.get("evidence", finding.get("description", "Vulnerability detected"))

    result: Dict[str, Any] = {
        "ruleId": _rule_id(finding, index),
        "level": level,
        "message": {"text": str(message_text)},
        "locations": [{"physicalLocation": _physical_location(finding)}],
        "properties": {
            "confidence": finding.get("confidence", 0),
            "verified": finding.get("verified", False),
            "param": finding.get("param", ""),
            "payload": finding.get("payload", ""),
        },
    }
    return result


def _extract_rules(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """从 findings 中提取唯一的规则定义"""
    seen: set = set()
    rules: List[Dict[str, Any]] = []
    for index, f in enumerate(findings):
        rule_id = _rule_id(f, index)
        if rule_id not in seen:
            seen.add(rule_id)
            level = _SEVERITY_TO_LEVEL.get(_normalize_severity(f), "warning")
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {
                        "text": f.get("description", rule_id),
                    },
                    "defaultConfiguration": {"level": level},
                }
            )
    return rules


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    """判断 severity 是否达到阈值

    Args:
        severity: 漏洞严重程度 (info/low/medium/high/critical)
        threshold: 阈值 (info/low/medium/high/critical)

    Returns:
        severity >= threshold 时返回 True
    """
    sev_val = SEVERITY_ORDER.get(severity.lower(), 0)
    thr_val = SEVERITY_ORDER.get(threshold.lower(), 3)
    return sev_val >= thr_val


def write_sarif(sarif_data: Dict[str, Any], output_path: str) -> None:
    """将 SARIF 数据写入文件

    Args:
        sarif_data: SARIF 格式字典
        output_path: 输出文件路径
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(sarif_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
