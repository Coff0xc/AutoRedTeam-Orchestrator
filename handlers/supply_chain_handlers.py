"""
供应链安全工具处理器
包含: sbom_generate, dependency_audit, cicd_scan
"""

from typing import Any, Dict
from .tooling import tool


def register_supply_chain_tools(mcp, counter, logger):
    """注册供应链安全工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    async def sbom_generate(project_path: str, output_format: str = "cyclonedx") -> Dict[str, Any]:
        """生成SBOM - 生成软件物料清单

        支持格式: CycloneDX, SPDX

        Args:
            project_path: 项目路径
            output_format: 输出格式 (cyclonedx, spdx)

        Returns:
            SBOM数据
        """
        try:
            from modules.supply_chain.sbom_generator import SBOMGenerator

            generator = SBOMGenerator()
            sbom = generator.generate(project_path, format=output_format)

            return {
                'success': True,
                'project': project_path,
                'format': output_format,
                'sbom': sbom if isinstance(sbom, dict) else sbom.to_dict()
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'project': project_path}

    @tool(mcp)
    async def dependency_audit(project_path: str) -> Dict[str, Any]:
        """依赖审计 - 检查项目依赖的已知漏洞

        支持: npm, pip, maven, go.mod

        Args:
            project_path: 项目路径

        Returns:
            依赖漏洞报告
        """
        try:
            from modules.supply_chain.dependency_scanner import DependencyScanner

            scanner = DependencyScanner()
            results = scanner.scan(project_path)

            return {
                'success': True,
                'project': project_path,
                'vulnerabilities': results if isinstance(results, list) else [results],
                'total': len(results) if isinstance(results, list) else 1
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'project': project_path}

    @tool(mcp)
    async def cicd_scan(config_path: str) -> Dict[str, Any]:
        """CI/CD配置扫描 - 检测CI/CD配置安全问题

        支持: GitHub Actions, GitLab CI, Jenkins

        Args:
            config_path: CI/CD配置文件路径

        Returns:
            安全发现
        """
        try:
            from modules.supply_chain.cicd_security import CICDScanner

            scanner = CICDScanner()
            findings = scanner.scan(config_path)

            return {
                'success': True,
                'config': config_path,
                'findings': findings if isinstance(findings, list) else [findings],
                'total': len(findings) if isinstance(findings, list) else 1
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'config': config_path}

    counter.add('supply_chain', 3)
    logger.info("[Supply Chain] 已注册 3 个供应链安全工具")