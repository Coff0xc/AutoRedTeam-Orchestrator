#!/usr/bin/env python3
"""
依赖漏洞扫描器
数据源: OSV (Open Source Vulnerabilities), PyPI Advisory
作者: AutoRedTeam
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

# 统一 HTTP 客户端工厂
try:
    from core.http import get_sync_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


class VulnSeverity(Enum):
    """漏洞严重性"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class DependencyVuln:
    """依赖漏洞"""
    package_name: str
    installed_version: str
    vuln_id: str  # CVE-XXXX-XXXX 或 GHSA-XXXX
    severity: VulnSeverity
    title: str
    description: str
    fixed_version: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    ecosystem: str = ""


class DependencyScanner:
    """依赖漏洞扫描器"""

    # OSV API
    OSV_API = "https://api.osv.dev/v1"

    # 严重性映射
    SEVERITY_MAP = {
        "CRITICAL": VulnSeverity.CRITICAL,
        "HIGH": VulnSeverity.HIGH,
        "MEDIUM": VulnSeverity.MEDIUM,
        "LOW": VulnSeverity.LOW,
    }

    # CVSS到严重性映射
    CVSS_SEVERITY = [
        (9.0, VulnSeverity.CRITICAL),
        (7.0, VulnSeverity.HIGH),
        (4.0, VulnSeverity.MEDIUM),
        (0.1, VulnSeverity.LOW),
    ]

    def __init__(self, timeout: float = 30.0):
        """
        初始化扫描器

        Args:
            timeout: API请求超时时间
        """
        self.timeout = timeout
        # 优先使用统一 HTTP 客户端工厂
        if HAS_HTTP_FACTORY:
            self._session = get_sync_client(force_new=True)
        else:
            self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "AutoRedTeam-DependencyScanner/1.0",
            "Content-Type": "application/json"
        })
        self._cache: Dict[str, List[DependencyVuln]] = {}

    def _cvss_to_severity(self, score: float) -> VulnSeverity:
        """CVSS分数转换为严重性"""
        for threshold, severity in self.CVSS_SEVERITY:
            if score >= threshold:
                return severity
        return VulnSeverity.UNKNOWN

    def _parse_osv_response(self, data: Dict,
                            package: str, version: str,
                            ecosystem: str) -> List[DependencyVuln]:
        """解析OSV响应"""
        vulns = []

        for vuln_data in data.get("vulns", []):
            vuln_id = vuln_data.get("id", "")

            # 获取严重性
            severity = VulnSeverity.UNKNOWN
            cvss_score = 0.0

            for severity_item in vuln_data.get("severity", []):
                if severity_item.get("type") == "CVSS_V3":
                    cvss_score = float(severity_item.get("score", 0))
                    severity = self._cvss_to_severity(cvss_score)
                    break

            # 获取修复版本
            fixed_version = ""
            for affected in vuln_data.get("affected", []):
                for range_item in affected.get("ranges", []):
                    for event in range_item.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break

            # 获取引用
            references = [
                ref.get("url", "")
                for ref in vuln_data.get("references", [])
                if ref.get("url")
            ][:5]  # 限制数量

            vuln = DependencyVuln(
                package_name=package,
                installed_version=version,
                vuln_id=vuln_id,
                severity=severity,
                title=vuln_data.get("summary", vuln_id),
                description=vuln_data.get("details", "")[:500],
                fixed_version=fixed_version,
                references=references,
                cvss_score=cvss_score,
                ecosystem=ecosystem
            )
            vulns.append(vuln)

        return vulns

    def check_osv(self, package: str, version: str,
                  ecosystem: str = "PyPI") -> List[DependencyVuln]:
        """
        通过OSV API检查漏洞

        Args:
            package: 包名
            version: 版本号
            ecosystem: 生态系统 (PyPI, npm, Go, Maven, etc.)

        Returns:
            漏洞列表
        """
        cache_key = f"{ecosystem}:{package}:{version}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            response = self._session.post(
                f"{self.OSV_API}/query",
                json={
                    "package": {
                        "name": package,
                        "ecosystem": ecosystem
                    },
                    "version": version
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                vulns = self._parse_osv_response(data, package, version, ecosystem)
                self._cache[cache_key] = vulns
                return vulns

        except requests.RequestException as e:
            logger.error(f"OSV查询失败 ({package}): {e}")

        return []

    def check_batch_osv(self, packages: List[Dict[str, str]]) -> Dict[str, List[DependencyVuln]]:
        """
        批量检查OSV

        Args:
            packages: [{"name": "...", "version": "...", "ecosystem": "..."}]

        Returns:
            {package_name: [vulns]}
        """
        results = {}

        # OSV支持批量查询
        queries = []
        for pkg in packages:
            queries.append({
                "package": {
                    "name": pkg["name"],
                    "ecosystem": pkg.get("ecosystem", "PyPI")
                },
                "version": pkg["version"]
            })

        try:
            response = self._session.post(
                f"{self.OSV_API}/querybatch",
                json={"queries": queries},
                timeout=self.timeout * 2  # 批量查询给更多时间
            )

            if response.status_code == 200:
                data = response.json()

                for i, result in enumerate(data.get("results", [])):
                    pkg = packages[i]
                    vulns = self._parse_osv_response(
                        result, pkg["name"], pkg["version"],
                        pkg.get("ecosystem", "PyPI")
                    )
                    if vulns:
                        results[pkg["name"]] = vulns

        except requests.RequestException as e:
            logger.error(f"OSV批量查询失败: {e}")

            # 回退到单个查询
            for pkg in packages:
                vulns = self.check_osv(
                    pkg["name"], pkg["version"],
                    pkg.get("ecosystem", "PyPI")
                )
                if vulns:
                    results[pkg["name"]] = vulns

        return results

    def scan_sbom(self, sbom: Dict) -> Dict[str, Any]:
        """
        扫描SBOM中的所有依赖

        Args:
            sbom: SBOM文档 (CycloneDX或Simple格式)

        Returns:
            扫描结果
        """
        result = {
            "scanned": 0,
            "vulnerable": 0,
            "vulnerabilities": [],
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "packages": {}
        }

        # 解析SBOM获取依赖列表
        packages = []

        # CycloneDX格式
        if "components" in sbom:
            for comp in sbom["components"]:
                pkg = {
                    "name": comp.get("name", ""),
                    "version": comp.get("version", ""),
                    "ecosystem": self._detect_ecosystem_from_purl(comp.get("purl", ""))
                }
                if pkg["name"] and pkg["version"]:
                    packages.append(pkg)

        # Simple格式
        elif "dependencies" in sbom:
            for dep in sbom["dependencies"]:
                pkg = {
                    "name": dep.get("name", ""),
                    "version": dep.get("version", ""),
                    "ecosystem": self._ecosystem_to_osv(dep.get("ecosystem", "pypi"))
                }
                if pkg["name"] and pkg["version"]:
                    packages.append(pkg)

        result["scanned"] = len(packages)

        # 批量查询
        vuln_results = self.check_batch_osv(packages)

        for pkg_name, vulns in vuln_results.items():
            result["packages"][pkg_name] = []

            for vuln in vulns:
                result["vulnerable"] += 1
                severity = vuln.severity.value
                result["by_severity"][severity] = result["by_severity"].get(severity, 0) + 1

                vuln_info = {
                    "package": vuln.package_name,
                    "version": vuln.installed_version,
                    "id": vuln.vuln_id,
                    "severity": severity,
                    "title": vuln.title,
                    "fixed_version": vuln.fixed_version,
                    "cvss": vuln.cvss_score
                }

                result["vulnerabilities"].append(vuln_info)
                result["packages"][pkg_name].append(vuln_info)

        # 按严重性排序
        result["vulnerabilities"].sort(
            key=lambda x: ["critical", "high", "medium", "low"].index(x["severity"])
        )

        return result

    def scan_project(self, project_path: str) -> Dict[str, Any]:
        """
        扫描项目依赖漏洞

        Args:
            project_path: 项目路径

        Returns:
            扫描结果
        """
        from .sbom_generator import SBOMGenerator, SBOMFormat

        # 生成SBOM
        generator = SBOMGenerator(project_path)
        sbom = generator.generate(SBOMFormat.SIMPLE)

        # 扫描SBOM
        result = self.scan_sbom(sbom)
        result["project_path"] = project_path
        result["sbom_summary"] = generator.get_summary()

        return result

    def _detect_ecosystem_from_purl(self, purl: str) -> str:
        """从PURL检测生态系统"""
        if purl.startswith("pkg:pypi/"):
            return "PyPI"
        elif purl.startswith("pkg:npm/"):
            return "npm"
        elif purl.startswith("pkg:golang/"):
            return "Go"
        elif purl.startswith("pkg:maven/"):
            return "Maven"
        elif purl.startswith("pkg:cargo/"):
            return "crates.io"
        return "PyPI"

    def _ecosystem_to_osv(self, ecosystem: str) -> str:
        """转换生态系统名称为OSV格式"""
        mapping = {
            "pypi": "PyPI",
            "npm": "npm",
            "go": "Go",
            "maven": "Maven",
            "cargo": "crates.io"
        }
        return mapping.get(ecosystem.lower(), "PyPI")

    def generate_report(self, scan_result: Dict) -> str:
        """
        生成漏洞报告

        Args:
            scan_result: scan_project或scan_sbom的结果

        Returns:
            文本格式报告
        """
        lines = [
            "=" * 60,
            "依赖漏洞扫描报告",
            "=" * 60,
            f"扫描依赖数: {scan_result.get('scanned', 0)}",
            f"发现漏洞数: {scan_result.get('vulnerable', 0)}",
            "",
            "严重性分布:",
            f"  CRITICAL: {scan_result['by_severity'].get('critical', 0)}",
            f"  HIGH:     {scan_result['by_severity'].get('high', 0)}",
            f"  MEDIUM:   {scan_result['by_severity'].get('medium', 0)}",
            f"  LOW:      {scan_result['by_severity'].get('low', 0)}",
            "",
            "-" * 60,
            "漏洞详情:",
            "-" * 60,
        ]

        for vuln in scan_result.get("vulnerabilities", []):
            severity_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢"
            }.get(vuln["severity"], "⚪")

            lines.extend([
                f"{severity_icon} {vuln['id']}",
                f"   包: {vuln['package']} @ {vuln['version']}",
                f"   严重性: {vuln['severity'].upper()} (CVSS: {vuln.get('cvss', 'N/A')})",
                f"   标题: {vuln['title'][:60]}...",
                f"   修复版本: {vuln.get('fixed_version', '未知')}",
                ""
            ])

        lines.append("=" * 60)

        return "\n".join(lines)


# 便捷函数
def scan_dependencies(project_path: str) -> Dict[str, Any]:
    """快速扫描项目依赖漏洞"""
    scanner = DependencyScanner()
    return scanner.scan_project(project_path)


if __name__ == "__main__":
    # 测试示例
    scanner = DependencyScanner()

    # 测试单个包
    vulns = scanner.check_osv("requests", "2.25.0", "PyPI")
    print(f"requests 2.25.0 漏洞数: {len(vulns)}")

    for v in vulns:
        print(f"  - {v.vuln_id}: {v.title}")
