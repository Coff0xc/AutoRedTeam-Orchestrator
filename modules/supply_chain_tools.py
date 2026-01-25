#!/usr/bin/env python3
"""
供应链安全MCP工具注册模块
注册: SBOM生成、依赖漏洞扫描、CI/CD安全检测
"""

import logging
from typing import Optional

from utils.mcp_tooling import patch_mcp_tool

logger = logging.getLogger(__name__)


def register_supply_chain_tools(mcp):
    """注册供应链安全工具到MCP Server"""
    patch_mcp_tool(mcp)

    registered_tools = []

    # ========== SBOM生成工具 ==========

    @mcp.tool()
    def sbom_generate(project_path: str, format: str = "cyclonedx") -> dict:
        """SBOM生成 - 生成软件物料清单

        扫描项目依赖并生成SBOM (Software Bill of Materials)

        支持格式:
            - cyclonedx: CycloneDX 1.4格式 (推荐)
            - spdx: SPDX 2.3格式
            - simple: 简单JSON格式

        支持依赖文件:
            - Python: requirements.txt, pyproject.toml, Pipfile
            - Node.js: package.json, package-lock.json
            - Go: go.mod, go.sum

        Args:
            project_path: 项目根目录路径
            format: 输出格式 (cyclonedx/spdx/simple)

        Returns:
            {
                "format": str,
                "total_dependencies": int,
                "ecosystems": [...],
                "sbom": {...}  # 完整SBOM文档
            }
        """
        try:
            from modules.supply_chain.sbom_generator import SBOMGenerator, SBOMFormat

            # 格式映射
            format_map = {
                "cyclonedx": SBOMFormat.CYCLONEDX,
                "spdx": SBOMFormat.SPDX,
                "simple": SBOMFormat.SIMPLE
            }

            fmt = format_map.get(format.lower(), SBOMFormat.CYCLONEDX)

            generator = SBOMGenerator(project_path)
            sbom = generator.generate(fmt)
            summary = generator.get_summary()

            return {
                "success": True,
                "format": format,
                "total_dependencies": summary["total_dependencies"],
                "production_dependencies": summary["production_dependencies"],
                "dev_dependencies": summary["dev_dependencies"],
                "ecosystems": summary["ecosystems"],
                "sbom": sbom
            }

        except ImportError as e:
            return {"success": False, "error": f"模块导入失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("sbom_generate")

    @mcp.tool()
    def sbom_summary(project_path: str) -> dict:
        """SBOM摘要 - 快速获取项目依赖统计

        Args:
            project_path: 项目根目录路径

        Returns:
            {
                "total_dependencies": int,
                "production_dependencies": int,
                "dev_dependencies": int,
                "ecosystems": {"pypi": N, "npm": N, ...}
            }
        """
        try:
            from modules.supply_chain.sbom_generator import SBOMGenerator

            generator = SBOMGenerator(project_path)
            generator.scan_all()

            return {
                "success": True,
                **generator.get_summary()
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("sbom_summary")

    # ========== 依赖漏洞扫描工具 ==========

    @mcp.tool()
    def dependency_audit(project_path: str) -> dict:
        """依赖漏洞扫描 - 检查项目依赖中的已知漏洞

        使用OSV (Open Source Vulnerabilities) API扫描依赖漏洞

        Args:
            project_path: 项目根目录路径

        Returns:
            {
                "scanned": int,
                "vulnerable": int,
                "by_severity": {"critical": N, "high": N, ...},
                "vulnerabilities": [
                    {
                        "package": str,
                        "version": str,
                        "id": str,  # CVE-XXXX 或 GHSA-XXXX
                        "severity": str,
                        "title": str,
                        "fixed_version": str
                    }
                ]
            }
        """
        try:
            from modules.supply_chain.dependency_scanner import DependencyScanner

            scanner = DependencyScanner()
            result = scanner.scan_project(project_path)

            return {
                "success": True,
                **result
            }

        except ImportError as e:
            return {"success": False, "error": f"模块导入失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("dependency_audit")

    @mcp.tool()
    def dependency_check_package(package: str, version: str,
                                  ecosystem: str = "PyPI") -> dict:
        """单包漏洞检查 - 检查单个依赖包的漏洞

        Args:
            package: 包名
            version: 版本号
            ecosystem: 生态系统 (PyPI/npm/Go/Maven/crates.io)

        Returns:
            {
                "package": str,
                "version": str,
                "vulnerable": bool,
                "vulnerabilities": [...]
            }
        """
        try:
            from modules.supply_chain.dependency_scanner import DependencyScanner

            scanner = DependencyScanner()
            vulns = scanner.check_osv(package, version, ecosystem)

            return {
                "success": True,
                "package": package,
                "version": version,
                "ecosystem": ecosystem,
                "vulnerable": len(vulns) > 0,
                "vulnerability_count": len(vulns),
                "vulnerabilities": [
                    {
                        "id": v.vuln_id,
                        "severity": v.severity.value,
                        "title": v.title,
                        "cvss": v.cvss_score,
                        "fixed_version": v.fixed_version
                    }
                    for v in vulns
                ]
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("dependency_check_package")

    @mcp.tool()
    def dependency_report(project_path: str) -> dict:
        """依赖漏洞报告 - 生成详细的漏洞扫描报告

        Args:
            project_path: 项目根目录路径

        Returns:
            {
                "report": str,  # 文本格式报告
                "summary": {...}
            }
        """
        try:
            from modules.supply_chain.dependency_scanner import DependencyScanner

            scanner = DependencyScanner()
            result = scanner.scan_project(project_path)
            report = scanner.generate_report(result)

            return {
                "success": True,
                "report": report,
                "summary": {
                    "scanned": result["scanned"],
                    "vulnerable": result["vulnerable"],
                    "by_severity": result["by_severity"]
                }
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("dependency_report")

    # ========== CI/CD安全工具 ==========

    @mcp.tool()
    def cicd_security_scan(project_path: str) -> dict:
        """CI/CD安全扫描 - 检测CI/CD配置安全问题

        扫描范围:
            - GitHub Actions (.github/workflows/*.yml)
            - GitLab CI (.gitlab-ci.yml)
            - Jenkins (Jenkinsfile)

        检测类型:
            - 命令注入风险
            - Secrets暴露
            - 不受信任输入使用
            - 特权工作流
            - 硬编码敏感信息
            - 供应链风险 (未固定版本)

        Args:
            project_path: 项目根目录路径

        Returns:
            {
                "total_findings": int,
                "by_severity": {"critical": N, "high": N, ...},
                "by_platform": {"github_actions": N, ...},
                "findings": [...]
            }
        """
        try:
            from modules.supply_chain.cicd_security import CICDSecurityScanner

            scanner = CICDSecurityScanner(project_path)
            result = scanner.scan_all()

            return {
                "success": True,
                **result
            }

        except ImportError as e:
            return {"success": False, "error": f"模块导入失败: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("cicd_security_scan")

    @mcp.tool()
    def cicd_github_actions_scan(project_path: str) -> dict:
        """GitHub Actions安全扫描 - 专门扫描GitHub Actions配置

        Args:
            project_path: 项目根目录路径

        Returns:
            {
                "findings": [...],
                "workflow_count": int
            }
        """
        try:
            from modules.supply_chain.cicd_security import CICDSecurityScanner

            scanner = CICDSecurityScanner(project_path)
            findings = scanner.scan_github_actions()

            return {
                "success": True,
                "finding_count": len(findings),
                "findings": [
                    {
                        "file": f.file_path,
                        "line": f.line_number,
                        "severity": f.severity,
                        "type": f.vuln_type.value,
                        "title": f.title,
                        "description": f.description,
                        "remediation": f.remediation
                    }
                    for f in findings
                ]
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("cicd_github_actions_scan")

    @mcp.tool()
    def cicd_security_report(project_path: str) -> dict:
        """CI/CD安全报告 - 生成详细的CI/CD安全扫描报告

        Args:
            project_path: 项目根目录路径

        Returns:
            {
                "report": str,  # 文本格式报告
                "summary": {...}
            }
        """
        try:
            from modules.supply_chain.cicd_security import CICDSecurityScanner

            scanner = CICDSecurityScanner(project_path)
            result = scanner.scan_all()
            report = scanner.generate_report()

            return {
                "success": True,
                "report": report,
                "summary": {
                    "total_findings": result["total_findings"],
                    "by_severity": result["by_severity"],
                    "by_platform": result["by_platform"]
                }
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("cicd_security_report")

    # ========== 综合供应链安全扫描 ==========

    @mcp.tool()
    def supply_chain_full_scan(project_path: str) -> dict:
        """供应链完整安全扫描 - 一键执行所有供应链安全检测

        包含:
            1. SBOM生成
            2. 依赖漏洞扫描
            3. CI/CD安全扫描

        Args:
            project_path: 项目根目录路径

        Returns:
            {
                "sbom": {...},
                "dependency_vulns": {...},
                "cicd_findings": {...},
                "summary": {
                    "total_dependencies": int,
                    "vulnerable_packages": int,
                    "cicd_issues": int,
                    "risk_level": str
                }
            }
        """
        try:
            from modules.supply_chain.sbom_generator import SBOMGenerator, SBOMFormat
            from modules.supply_chain.dependency_scanner import DependencyScanner
            from modules.supply_chain.cicd_security import CICDSecurityScanner

            results = {
                "success": True,
                "project_path": project_path
            }

            # 1. SBOM生成
            try:
                sbom_gen = SBOMGenerator(project_path)
                sbom = sbom_gen.generate(SBOMFormat.SIMPLE)
                sbom_summary = sbom_gen.get_summary()
                results["sbom"] = {
                    "total": sbom_summary["total_dependencies"],
                    "ecosystems": sbom_summary["ecosystems"]
                }
            except Exception as e:
                results["sbom"] = {"error": str(e)}

            # 2. 依赖漏洞扫描
            try:
                dep_scanner = DependencyScanner()
                dep_result = dep_scanner.scan_project(project_path)
                results["dependency_vulns"] = {
                    "scanned": dep_result["scanned"],
                    "vulnerable": dep_result["vulnerable"],
                    "by_severity": dep_result["by_severity"],
                    "top_vulns": dep_result["vulnerabilities"][:10]  # 限制数量
                }
            except Exception as e:
                results["dependency_vulns"] = {"error": str(e)}

            # 3. CI/CD安全扫描
            try:
                cicd_scanner = CICDSecurityScanner(project_path)
                cicd_result = cicd_scanner.scan_all()
                results["cicd_findings"] = {
                    "total": cicd_result["total_findings"],
                    "by_severity": cicd_result["by_severity"],
                    "by_platform": cicd_result["by_platform"]
                }
            except Exception as e:
                results["cicd_findings"] = {"error": str(e)}

            # 计算风险等级
            risk_score = 0
            if "dependency_vulns" in results and "by_severity" in results["dependency_vulns"]:
                severity = results["dependency_vulns"]["by_severity"]
                risk_score += severity.get("critical", 0) * 10
                risk_score += severity.get("high", 0) * 5
                risk_score += severity.get("medium", 0) * 2
                risk_score += severity.get("low", 0) * 1

            if "cicd_findings" in results and "by_severity" in results["cicd_findings"]:
                severity = results["cicd_findings"]["by_severity"]
                risk_score += severity.get("critical", 0) * 8
                risk_score += severity.get("high", 0) * 4
                risk_score += severity.get("medium", 0) * 2

            if risk_score >= 50:
                risk_level = "critical"
            elif risk_score >= 30:
                risk_level = "high"
            elif risk_score >= 15:
                risk_level = "medium"
            elif risk_score > 0:
                risk_level = "low"
            else:
                risk_level = "none"

            results["summary"] = {
                "total_dependencies": results.get("sbom", {}).get("total", 0),
                "vulnerable_packages": results.get("dependency_vulns", {}).get("vulnerable", 0),
                "cicd_issues": results.get("cicd_findings", {}).get("total", 0),
                "risk_score": risk_score,
                "risk_level": risk_level
            }

            return results

        except Exception as e:
            return {"success": False, "error": str(e)}

    registered_tools.append("supply_chain_full_scan")

    logger.info(f"已注册 {len(registered_tools)} 个供应链安全工具")
    return registered_tools
