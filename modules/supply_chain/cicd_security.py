#!/usr/bin/env python3
"""
CI/CD安全检测模块
检测: GitHub Actions, GitLab CI, Jenkinsfile安全配置问题
作者: AutoRedTeam
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class CICDPlatform(Enum):
    """CI/CD平台"""

    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_PIPELINES = "azure_pipelines"


class CICDVulnType(Enum):
    """CI/CD漏洞类型"""

    COMMAND_INJECTION = "command_injection"
    SECRET_EXPOSURE = "secret_exposure"
    UNTRUSTED_INPUT = "untrusted_input"
    PRIVILEGED_WORKFLOW = "privileged_workflow"
    ARTIFACT_POISONING = "artifact_poisoning"
    SELF_HOSTED_RUNNER = "self_hosted_runner"
    INSECURE_PERMISSION = "insecure_permission"
    HARDCODED_SECRET = "hardcoded_secret"
    SUPPLY_CHAIN_RISK = "supply_chain_risk"


@dataclass
class CICDFinding:
    """CI/CD安全发现"""

    platform: CICDPlatform
    vuln_type: CICDVulnType
    file_path: str
    line_number: int
    severity: str
    title: str
    description: str
    code_snippet: str
    remediation: str


class CICDSecurityScanner:
    """CI/CD安全扫描器"""

    # GitHub Actions危险模式
    GITHUB_DANGEROUS_PATTERNS = [
        # 直接使用不受信任的输入 (命令注入)
        {
            "pattern": r"\$\{\{\s*github\.event\.(issue|pull_request|comment|discussion)\.(title|body|head\.ref)",
            "type": CICDVulnType.UNTRUSTED_INPUT,
            "severity": "high",
            "title": "直接使用不受信任的GitHub事件输入",
            "description": "直接使用github.event中的用户输入可能导致命令注入",
            "remediation": "将用户输入存储到环境变量,并使用引号包裹",
        },
        # pull_request_target触发器
        {
            "pattern": r"on:\s*(pull_request_target|workflow_run)",
            "type": CICDVulnType.PRIVILEGED_WORKFLOW,
            "severity": "high",
            "title": "使用特权工作流触发器",
            "description": "pull_request_target和workflow_run在特权上下文运行,可能导致权限提升",
            "remediation": "避免在特权工作流中检出不受信任的代码",
        },
        # 在日志中暴露secrets
        {
            "pattern": r"(echo|print|cat|printf).*\$\{\{\s*secrets\.",
            "type": CICDVulnType.SECRET_EXPOSURE,
            "severity": "high",
            "title": "可能在日志中暴露Secrets",
            "description": "将secrets输出到标准输出可能导致泄露",
            "remediation": "避免将secrets输出到日志",
        },
        # 使用自托管runner
        {
            "pattern": r"runs-on:\s*self-hosted",
            "type": CICDVulnType.SELF_HOSTED_RUNNER,
            "severity": "medium",
            "title": "使用自托管Runner",
            "description": "自托管runner可能存在持久化和隔离问题",
            "remediation": "确保自托管runner安全配置,使用临时环境",
        },
        # 过度权限
        {
            "pattern": r"permissions:\s*write-all",
            "type": CICDVulnType.INSECURE_PERMISSION,
            "severity": "high",
            "title": "工作流使用过度权限",
            "description": "write-all权限可能导致仓库被篡改",
            "remediation": "遵循最小权限原则,仅申请必要权限",
        },
        # 使用第三方action而不固定版本
        {
            "pattern": r"uses:\s*[^@]+@(master|main|latest)",
            "type": CICDVulnType.SUPPLY_CHAIN_RISK,
            "severity": "medium",
            "title": "使用未固定版本的第三方Action",
            "description": "使用master/main分支可能导致供应链攻击",
            "remediation": "使用commit SHA固定Action版本",
        },
        # 禁用安全检查
        {
            "pattern": r"--no-verify|--skip-ci|continue-on-error:\s*true",
            "type": CICDVulnType.INSECURE_PERMISSION,
            "severity": "low",
            "title": "禁用安全检查",
            "description": "禁用验证可能允许恶意代码通过",
            "remediation": "避免禁用安全检查",
        },
    ]

    # 硬编码敏感信息模式
    HARDCODED_SECRET_PATTERNS = [
        (r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']', "密码"),
        (r'(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']+["\']', "API密钥"),
        (r'(secret[_-]?key|secretkey)\s*[=:]\s*["\'][^"\']+["\']', "Secret密钥"),
        (r'(access[_-]?token|accesstoken)\s*[=:]\s*["\'][^"\']+["\']', "Access Token"),
        (r'(private[_-]?key|privatekey)\s*[=:]\s*["\'][^"\']+["\']', "私钥"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Token"),
        (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
        (r"glpat-[a-zA-Z0-9\-_]{20}", "GitLab Personal Token"),
    ]

    # GitLab CI危险模式
    GITLAB_DANGEROUS_PATTERNS = [
        {
            "pattern": r"when:\s*manual",
            "type": CICDVulnType.INSECURE_PERMISSION,
            "severity": "low",
            "title": "手动触发任务",
            "description": "手动任务可能被未授权人员触发",
            "remediation": "限制手动任务的执行权限",
        },
        {
            "pattern": r"allow_failure:\s*true",
            "type": CICDVulnType.INSECURE_PERMISSION,
            "severity": "low",
            "title": "允许任务失败",
            "description": "允许失败可能让恶意代码通过",
            "remediation": "评估是否真正需要允许失败",
        },
    ]

    def __init__(self, project_path: str):
        """
        初始化扫描器

        Args:
            project_path: 项目根目录路径
        """
        self.project_path = Path(project_path)
        self._findings: List[CICDFinding] = []

    def _read_file(self, file_path: Path) -> str:
        """安全读取文件"""
        try:
            return file_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return ""

    def _extract_context(self, content: str, match_start: int, context_lines: int = 2) -> tuple:
        """提取匹配上下文"""
        lines = content[:match_start].split("\n")
        line_number = len(lines)

        # 获取代码片段
        all_lines = content.split("\n")
        start = max(0, line_number - context_lines - 1)
        end = min(len(all_lines), line_number + context_lines)
        snippet = "\n".join(all_lines[start:end])

        return line_number, snippet

    def scan_github_actions(self) -> List[CICDFinding]:
        """扫描GitHub Actions配置"""
        findings = []
        workflows_dir = self.project_path / ".github" / "workflows"

        if not workflows_dir.exists():
            return findings

        for yaml_file in workflows_dir.glob("*.yml"):
            findings.extend(self._scan_github_workflow(yaml_file))

        for yaml_file in workflows_dir.glob("*.yaml"):
            findings.extend(self._scan_github_workflow(yaml_file))

        return findings

    def _scan_github_workflow(self, file_path: Path) -> List[CICDFinding]:
        """扫描单个GitHub Workflow文件"""
        findings = []
        content = self._read_file(file_path)

        if not content:
            return findings

        # 检查危险模式
        for pattern_info in self.GITHUB_DANGEROUS_PATTERNS:
            pattern = pattern_info["pattern"]

            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num, snippet = self._extract_context(content, match.start())

                finding = CICDFinding(
                    platform=CICDPlatform.GITHUB_ACTIONS,
                    vuln_type=pattern_info["type"],
                    file_path=str(file_path.relative_to(self.project_path)),
                    line_number=line_num,
                    severity=pattern_info["severity"],
                    title=pattern_info["title"],
                    description=pattern_info["description"],
                    code_snippet=snippet,
                    remediation=pattern_info["remediation"],
                )
                findings.append(finding)

        # 检查硬编码敏感信息
        findings.extend(
            self._scan_hardcoded_secrets(content, file_path, CICDPlatform.GITHUB_ACTIONS)
        )

        return findings

    def scan_gitlab_ci(self) -> List[CICDFinding]:
        """扫描GitLab CI配置"""
        findings = []
        ci_file = self.project_path / ".gitlab-ci.yml"

        if not ci_file.exists():
            return findings

        content = self._read_file(ci_file)

        if not content:
            return findings

        # 检查危险模式
        for pattern_info in self.GITLAB_DANGEROUS_PATTERNS:
            pattern = pattern_info["pattern"]

            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num, snippet = self._extract_context(content, match.start())

                finding = CICDFinding(
                    platform=CICDPlatform.GITLAB_CI,
                    vuln_type=pattern_info["type"],
                    file_path=".gitlab-ci.yml",
                    line_number=line_num,
                    severity=pattern_info["severity"],
                    title=pattern_info["title"],
                    description=pattern_info["description"],
                    code_snippet=snippet,
                    remediation=pattern_info["remediation"],
                )
                findings.append(finding)

        # 检查硬编码敏感信息
        findings.extend(self._scan_hardcoded_secrets(content, ci_file, CICDPlatform.GITLAB_CI))

        return findings

    def scan_jenkinsfile(self) -> List[CICDFinding]:
        """扫描Jenkinsfile"""
        findings = []

        # 查找Jenkinsfile
        jenkinsfiles = [
            self.project_path / "Jenkinsfile",
            self.project_path / "jenkinsfile",
            self.project_path / "jenkins" / "Jenkinsfile",
        ]

        for jf in jenkinsfiles:
            if jf.exists():
                findings.extend(self._scan_jenkinsfile(jf))

        return findings

    def _scan_jenkinsfile(self, file_path: Path) -> List[CICDFinding]:
        """扫描单个Jenkinsfile"""
        findings = []
        content = self._read_file(file_path)

        if not content:
            return findings

        # Jenkins特定危险模式
        jenkins_patterns = [
            {
                "pattern": r'sh\s*["\'].*\$\{.*\}',
                "type": CICDVulnType.COMMAND_INJECTION,
                "severity": "high",
                "title": "可能的Shell命令注入",
                "description": "在sh步骤中使用变量插值可能导致命令注入",
                "remediation": "使用参数化方式传递变量",
            },
            {
                "pattern": r"environment\s*\{[^}]*password\s*=",
                "type": CICDVulnType.SECRET_EXPOSURE,
                "severity": "high",
                "title": "环境变量中可能包含密码",
                "description": "密码不应在Jenkinsfile中硬编码",
                "remediation": "使用Jenkins credentials管理密码",
            },
        ]

        for pattern_info in jenkins_patterns:
            pattern = pattern_info["pattern"]

            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num, snippet = self._extract_context(content, match.start())

                finding = CICDFinding(
                    platform=CICDPlatform.JENKINS,
                    vuln_type=pattern_info["type"],
                    file_path=str(file_path.relative_to(self.project_path)),
                    line_number=line_num,
                    severity=pattern_info["severity"],
                    title=pattern_info["title"],
                    description=pattern_info["description"],
                    code_snippet=snippet,
                    remediation=pattern_info["remediation"],
                )
                findings.append(finding)

        # 检查硬编码敏感信息
        findings.extend(self._scan_hardcoded_secrets(content, file_path, CICDPlatform.JENKINS))

        return findings

    def _scan_hardcoded_secrets(
        self, content: str, file_path: Path, platform: CICDPlatform
    ) -> List[CICDFinding]:
        """扫描硬编码的敏感信息"""
        findings = []

        for pattern, secret_type in self.HARDCODED_SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num, snippet = self._extract_context(content, match.start())

                finding = CICDFinding(
                    platform=platform,
                    vuln_type=CICDVulnType.HARDCODED_SECRET,
                    file_path=str(file_path.relative_to(self.project_path)),
                    line_number=line_num,
                    severity="critical",
                    title=f"硬编码的{secret_type}",
                    description=f"在CI/CD配置文件中发现硬编码的{secret_type}",
                    code_snippet=snippet,
                    remediation="使用环境变量或密钥管理服务存储敏感信息",
                )
                findings.append(finding)

        return findings

    def scan_all(self) -> Dict[str, Any]:
        """
        扫描所有CI/CD配置

        Returns:
            扫描结果
        """
        all_findings = []

        # GitHub Actions
        all_findings.extend(self.scan_github_actions())

        # GitLab CI
        all_findings.extend(self.scan_gitlab_ci())

        # Jenkins
        all_findings.extend(self.scan_jenkinsfile())

        self._findings = all_findings

        # 统计
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        by_platform = {}
        by_type = {}

        for finding in all_findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            platform = finding.platform.value
            by_platform[platform] = by_platform.get(platform, 0) + 1
            vuln_type = finding.vuln_type.value
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1

        return {
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "by_platform": by_platform,
            "by_type": by_type,
            "findings": [
                {
                    "platform": f.platform.value,
                    "type": f.vuln_type.value,
                    "file": f.file_path,
                    "line": f.line_number,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in all_findings
            ],
        }

    def generate_report(self) -> str:
        """生成扫描报告"""
        if not self._findings:
            self.scan_all()

        lines = [
            "=" * 60,
            "CI/CD安全扫描报告",
            "=" * 60,
            f"项目路径: {self.project_path}",
            f"发现问题数: {len(self._findings)}",
            "",
            "-" * 60,
            "问题详情:",
            "-" * 60,
        ]

        for finding in self._findings:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                finding.severity, "⚪"
            )

            lines.extend(
                [
                    f"{severity_icon} [{finding.severity.upper()}] {finding.title}",
                    f"   平台: {finding.platform.value}",
                    f"   文件: {finding.file_path}:{finding.line_number}",
                    f"   描述: {finding.description}",
                    f"   修复: {finding.remediation}",
                    "",
                ]
            )

        lines.append("=" * 60)

        return "\n".join(lines)


# 便捷函数
def scan_cicd(project_path: str) -> Dict[str, Any]:
    """快速扫描CI/CD配置"""
    scanner = CICDSecurityScanner(project_path)
    return scanner.scan_all()


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        path = "."

    scanner = CICDSecurityScanner(path)
    result = scanner.scan_all()

    logger.info(f"发现问题数: {result['total_findings']}")
    logger.info(f"严重性分布: {result['by_severity']}")
