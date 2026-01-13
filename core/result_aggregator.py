#!/usr/bin/env python3
"""
结果聚合器 - 统一的结果收集和聚合
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityResult:
    """漏洞结果数据类"""
    vuln_type: str
    severity: str
    url: str
    param: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    confidence: float = 0.0
    verified: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = "unknown"  # 来源检测器


class ResultAggregator:
    """
    结果聚合器 - 统一的结果收集和聚合

    特性:
    - 结果去重
    - 按严重程度分类
    - 统计分析
    - 导出多种格式
    """

    def __init__(self):
        """初始化结果聚合器"""
        self.results: List[VulnerabilityResult] = []
        self._result_hash_set = set()  # 用于去重

    def add_result(self, result: Dict[str, Any], source: str = "unknown"):
        """
        添加单个结果

        Args:
            result: 结果字典
            source: 来源标识
        """
        vuln = VulnerabilityResult(
            vuln_type=result.get("type", "unknown"),
            severity=result.get("severity", "MEDIUM"),
            url=result.get("url", ""),
            param=result.get("param"),
            payload=result.get("payload"),
            evidence=result.get("evidence"),
            confidence=result.get("confidence", 0.0),
            verified=result.get("verified", False),
            source=source
        )

        # 去重
        result_hash = self._hash_result(vuln)
        if result_hash not in self._result_hash_set:
            self.results.append(vuln)
            self._result_hash_set.add(result_hash)
            logger.debug(f"添加结果: {vuln.vuln_type} - {vuln.url}")
        else:
            logger.debug(f"跳过重复结果: {vuln.vuln_type} - {vuln.url}")

    def add_batch(self, results: List[Dict[str, Any]], source: str = "unknown"):
        """
        批量添加结果

        Args:
            results: 结果列表
            source: 来源标识
        """
        for result in results:
            self.add_result(result, source)

    def _hash_result(self, vuln: VulnerabilityResult) -> str:
        """生成结果哈希用于去重"""
        return f"{vuln.vuln_type}:{vuln.url}:{vuln.param}:{vuln.payload}"

    def get_all(self) -> List[VulnerabilityResult]:
        """获取所有结果"""
        return self.results

    def get_by_severity(self, severity: str) -> List[VulnerabilityResult]:
        """按严重程度筛选"""
        return [r for r in self.results if r.severity == severity]

    def get_by_type(self, vuln_type: str) -> List[VulnerabilityResult]:
        """按漏洞类型筛选"""
        return [r for r in self.results if r.vuln_type == vuln_type]

    def get_verified_only(self) -> List[VulnerabilityResult]:
        """只获取已验证的结果"""
        return [r for r in self.results if r.verified]

    def get_high_confidence(self, threshold: float = 0.7) -> List[VulnerabilityResult]:
        """获取高置信度结果"""
        return [r for r in self.results if r.confidence >= threshold]

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        if not self.results:
            return {
                "total": 0,
                "by_severity": {},
                "by_type": {},
                "verified_count": 0,
                "high_confidence_count": 0
            }

        # 按严重程度统计
        by_severity = defaultdict(int)
        for r in self.results:
            by_severity[r.severity] += 1

        # 按类型统计
        by_type = defaultdict(int)
        for r in self.results:
            by_type[r.vuln_type] += 1

        # 验证统计
        verified_count = sum(1 for r in self.results if r.verified)
        high_confidence_count = sum(1 for r in self.results if r.confidence >= 0.7)

        return {
            "total": len(self.results),
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "verified_count": verified_count,
            "verified_rate": verified_count / len(self.results) if self.results else 0,
            "high_confidence_count": high_confidence_count,
            "high_confidence_rate": high_confidence_count / len(self.results) if self.results else 0
        }

    def export_json(self, output_file: str):
        """导出为 JSON 格式"""
        data = {
            "scan_time": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "vulnerabilities": [
                {
                    "type": r.vuln_type,
                    "severity": r.severity,
                    "url": r.url,
                    "param": r.param,
                    "payload": r.payload,
                    "evidence": r.evidence,
                    "confidence": r.confidence,
                    "verified": r.verified,
                    "source": r.source,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in self.results
            ]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"结果已导出到: {output_file}")

    def export_csv(self, output_file: str):
        """导出为 CSV 格式"""
        import csv

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # 写入表头
            writer.writerow([
                "Type", "Severity", "URL", "Param", "Payload",
                "Evidence", "Confidence", "Verified", "Source", "Timestamp"
            ])

            # 写入数据
            for r in self.results:
                writer.writerow([
                    r.vuln_type,
                    r.severity,
                    r.url,
                    r.param or "",
                    r.payload or "",
                    r.evidence or "",
                    r.confidence,
                    r.verified,
                    r.source,
                    r.timestamp.isoformat()
                ])

        logger.info(f"结果已导出到: {output_file}")

    def export_markdown(self, output_file: str):
        """导出为 Markdown 格式"""
        stats = self.get_statistics()

        with open(output_file, 'w', encoding='utf-8') as f:
            # 标题
            f.write("# 漏洞扫描报告\n\n")
            f.write(f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # 统计信息
            f.write("## 统计信息\n\n")
            f.write(f"- 总漏洞数: {stats['total']}\n")
            f.write(f"- 已验证: {stats['verified_count']} ({stats['verified_rate']:.1%})\n")
            f.write(f"- 高置信度: {stats['high_confidence_count']} ({stats['high_confidence_rate']:.1%})\n\n")

            # 按严重程度
            f.write("### 按严重程度\n\n")
            for severity, count in sorted(stats['by_severity'].items()):
                f.write(f"- {severity}: {count}\n")
            f.write("\n")

            # 按类型
            f.write("### 按漏洞类型\n\n")
            for vuln_type, count in sorted(stats['by_type'].items()):
                f.write(f"- {vuln_type}: {count}\n")
            f.write("\n")

            # 详细列表
            f.write("## 漏洞详情\n\n")

            # 按严重程度分组
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                vulns = self.get_by_severity(severity)
                if not vulns:
                    continue

                f.write(f"### {severity}\n\n")
                for i, vuln in enumerate(vulns, 1):
                    f.write(f"#### {i}. {vuln.vuln_type}\n\n")
                    f.write(f"- **URL**: {vuln.url}\n")
                    if vuln.param:
                        f.write(f"- **参数**: {vuln.param}\n")
                    if vuln.payload:
                        f.write(f"- **Payload**: `{vuln.payload}`\n")
                    if vuln.evidence:
                        f.write(f"- **证据**: {vuln.evidence}\n")
                    f.write(f"- **置信度**: {vuln.confidence:.2f}\n")
                    f.write(f"- **已验证**: {'是' if vuln.verified else '否'}\n")
                    f.write(f"- **来源**: {vuln.source}\n\n")

        logger.info(f"结果已导出到: {output_file}")

    def clear(self):
        """清空所有结果"""
        self.results.clear()
        self._result_hash_set.clear()


# 使用示例
if __name__ == "__main__":
    aggregator = ResultAggregator()

    # 添加结果
    aggregator.add_result({
        "type": "SQL Injection",
        "severity": "CRITICAL",
        "url": "https://example.com/page?id=1",
        "param": "id",
        "payload": "' OR '1'='1",
        "confidence": 0.9,
        "verified": True
    }, source="sqli_detector")

    aggregator.add_result({
        "type": "XSS",
        "severity": "HIGH",
        "url": "https://example.com/search?q=test",
        "param": "q",
        "payload": "<script>alert(1)</script>",
        "confidence": 0.8,
        "verified": False
    }, source="xss_detector")

    # 统计信息
    stats = aggregator.get_statistics()
    print(f"统计: {json.dumps(stats, indent=2, ensure_ascii=False)}")

    # 导出
    aggregator.export_json("results.json")
    aggregator.export_markdown("report.md")
