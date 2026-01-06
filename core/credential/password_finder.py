# -*- coding: utf-8 -*-
"""
敏感信息搜索模块 (Password/Secret Finder)
ATT&CK Technique: T1552 - Unsecured Credentials

搜索文件系统中的敏感信息:
- 密码/凭证
- API密钥
- 私钥/证书
- 数据库连接字符串
- 配置文件中的机密

注意: 仅用于授权的渗透测试和安全研究
"""

import os
import re
import json
import mimetypes
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Generator
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class SecretType(Enum):
    """敏感信息类型"""
    PASSWORD = "password"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    AWS_KEY = "aws_key"
    DATABASE_URL = "database_url"
    JWT_TOKEN = "jwt_token"
    OAUTH_TOKEN = "oauth_token"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    ENCRYPTION_KEY = "encryption_key"
    WEBHOOK_URL = "webhook_url"
    GENERIC_SECRET = "generic_secret"


@dataclass
class SecretFinding:
    """发现的敏感信息"""
    secret_type: SecretType
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    confidence: str  # high, medium, low
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.secret_type.value,
            "file": self.file_path,
            "line": self.line_number,
            "content": self.line_content[:200] + "..." if len(self.line_content) > 200 else self.line_content,
            "match": self.matched_text[:100] + "..." if len(self.matched_text) > 100 else self.matched_text,
            "confidence": self.confidence,
            "context": self.context
        }


class PasswordFinder:
    """
    敏感信息搜索器

    使用正则表达式和启发式规则搜索文件中的敏感信息
    """

    # 默认忽略的目录
    DEFAULT_IGNORE_DIRS: Set[str] = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__',
        'venv', '.venv', 'env', '.env', 'vendor', 'target',
        'build', 'dist', 'bin', 'obj', '.idea', '.vscode',
        'logs', 'log', 'tmp', 'temp', 'cache', '.cache'
    }

    # 默认忽略的文件扩展名
    DEFAULT_IGNORE_EXTENSIONS: Set[str] = {
        '.exe', '.dll', '.so', '.dylib', '.bin', '.pyc',
        '.pyo', '.class', '.jar', '.war', '.ear',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.jpg', '.jpeg', '.png', '.gif', '.ico', '.bmp',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt',
        '.mp3', '.mp4', '.avi', '.mkv', '.mov',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.min.js', '.min.css', '.map'
    }

    # 敏感文件名模式
    SENSITIVE_FILENAMES: List[str] = [
        '.env', '.env.local', '.env.production', '.env.development',
        'config.json', 'config.yaml', 'config.yml', 'config.ini',
        'settings.py', 'settings.json', 'settings.yaml',
        'secrets.json', 'secrets.yaml', 'secrets.yml',
        'credentials.json', 'credentials.yaml',
        'database.yml', 'database.json',
        'application.properties', 'application.yml',
        'wp-config.php', 'configuration.php',
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        '.htpasswd', '.netrc', '.pgpass',
        'docker-compose.yml', 'docker-compose.yaml',
        'Dockerfile', 'kubernetes.yaml', 'k8s.yaml',
        'terraform.tfvars', '*.tfstate',
        'ansible.cfg', 'vault.yml',
        'travis.yml', '.travis.yml', 'circle.yml',
        'jenkins.xml', 'Jenkinsfile',
        'gitlab-ci.yml', '.gitlab-ci.yml',
        'github-actions.yml', 'workflows/*.yml'
    ]

    # 敏感信息正则表达式
    SECRET_PATTERNS: Dict[SecretType, List[tuple]] = {
        SecretType.PASSWORD: [
            (r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']?([^"\'\s\n]{4,})["\']?', 'high'),
            (r'(?i)(secret|token|key)\s*[=:]\s*["\']?([^"\'\s\n]{8,})["\']?', 'medium'),
        ],
        SecretType.API_KEY: [
            # Generic API keys
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', 'high'),
            # Slack tokens
            (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'high'),
            # Google API
            (r'AIza[0-9A-Za-z_-]{35}', 'high'),
            # GitHub tokens
            (r'ghp_[0-9a-zA-Z]{36}', 'high'),
            (r'gho_[0-9a-zA-Z]{36}', 'high'),
            (r'ghu_[0-9a-zA-Z]{36}', 'high'),
            (r'ghs_[0-9a-zA-Z]{36}', 'high'),
            (r'ghr_[0-9a-zA-Z]{36}', 'high'),
            # Stripe
            (r'sk_live_[0-9a-zA-Z]{24,}', 'high'),
            (r'pk_live_[0-9a-zA-Z]{24,}', 'high'),
            # Twilio
            (r'SK[0-9a-fA-F]{32}', 'medium'),
            # SendGrid
            (r'SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}', 'high'),
        ],
        SecretType.AWS_KEY: [
            (r'AKIA[0-9A-Z]{16}', 'high'),  # AWS Access Key ID
            (r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'high'),
        ],
        SecretType.PRIVATE_KEY: [
            (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'high'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'high'),
        ],
        SecretType.DATABASE_URL: [
            (r'(?i)(mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s\n"\']+', 'high'),
            (r'(?i)(database_url|db_url|connection_string)\s*[=:]\s*["\']?([^\s\n"\']+)["\']?', 'high'),
            (r'Server=.+;Database=.+;User Id=.+;Password=.+;', 'high'),
        ],
        SecretType.JWT_TOKEN: [
            (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'high'),
        ],
        SecretType.OAUTH_TOKEN: [
            (r'(?i)(oauth|bearer)\s*(token)?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', 'medium'),
            (r'(?i)(access_token|refresh_token)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', 'high'),
        ],
        SecretType.SSH_KEY: [
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'high'),
            (r'ssh-rsa\s+AAAA[0-9A-Za-z+/]+', 'medium'),  # Public key (有时也有用)
        ],
        SecretType.WEBHOOK_URL: [
            (r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', 'high'),
            (r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', 'high'),
            (r'https://outlook\.office\.com/webhook/[A-Za-z0-9-]+', 'high'),
        ],
        SecretType.GENERIC_SECRET: [
            (r'(?i)(secret|token|credential|auth)\s*[=:]\s*["\']([^"\']{8,})["\']', 'low'),
        ],
    }

    def __init__(
        self,
        ignore_dirs: Set[str] = None,
        ignore_extensions: Set[str] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        verbose: bool = False
    ):
        self.ignore_dirs = ignore_dirs or self.DEFAULT_IGNORE_DIRS
        self.ignore_extensions = ignore_extensions or self.DEFAULT_IGNORE_EXTENSIONS
        self.max_file_size = max_file_size
        self.verbose = verbose
        self.findings: List[SecretFinding] = []

    def _log(self, message: str):
        """日志输出"""
        if self.verbose:
            print(f"[SecretFinder] {message}")

    def _should_skip_file(self, file_path: Path) -> bool:
        """判断是否跳过文件"""
        # 检查扩展名
        suffix = file_path.suffix.lower()
        if suffix in self.ignore_extensions:
            return True

        # 检查是否为压缩的JS/CSS
        if file_path.name.endswith('.min.js') or file_path.name.endswith('.min.css'):
            return True

        # 检查文件大小
        try:
            if file_path.stat().st_size > self.max_file_size:
                return True
        except Exception:
            return True

        # 检查是否为二进制文件
        try:
            mime_type = mimetypes.guess_type(str(file_path))[0]
            if mime_type and not mime_type.startswith('text/') and \
               not mime_type.startswith('application/json') and \
               not mime_type.startswith('application/xml') and \
               not mime_type.startswith('application/javascript'):
                # 尝试读取前512字节判断
                with open(file_path, 'rb') as f:
                    chunk = f.read(512)
                    if b'\x00' in chunk:  # 包含null字节,可能是二进制
                        return True
        except Exception:
            pass

        return False

    def _should_skip_dir(self, dir_path: Path) -> bool:
        """判断是否跳过目录"""
        return dir_path.name in self.ignore_dirs

    def _is_sensitive_filename(self, filename: str) -> bool:
        """检查是否为敏感文件名"""
        filename_lower = filename.lower()
        for pattern in self.SENSITIVE_FILENAMES:
            if '*' in pattern:
                # 通配符匹配
                import fnmatch
                if fnmatch.fnmatch(filename_lower, pattern.lower()):
                    return True
            elif filename_lower == pattern.lower():
                return True
        return False

    def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """
        扫描单个文件

        Args:
            file_path: 文件路径

        Returns:
            发现的敏感信息列表
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            self._log(f"Cannot read {file_path}: {e}")
            return findings

        # 检查文件名是否敏感
        is_sensitive_file = self._is_sensitive_filename(file_path.name)

        for line_num, line in enumerate(lines, 1):
            # 跳过注释行 (简单启发式)
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                # 即使是注释也可能包含敏感信息
                pass

            # 检查各种敏感模式
            for secret_type, patterns in self.SECRET_PATTERNS.items():
                for pattern, confidence in patterns:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        matched_text = match.group(0)

                        # 过滤假阳性
                        if self._is_false_positive(matched_text, line, file_path):
                            continue

                        # 如果在敏感文件中发现,提高置信度
                        actual_confidence = confidence
                        if is_sensitive_file and confidence == 'medium':
                            actual_confidence = 'high'

                        finding = SecretFinding(
                            secret_type=secret_type,
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.strip(),
                            matched_text=matched_text,
                            confidence=actual_confidence,
                            context=f"Line {max(1, line_num-2)}-{min(len(lines), line_num+2)}"
                        )
                        findings.append(finding)
                        self._log(f"Found {secret_type.value} in {file_path}:{line_num}")

        return findings

    def _is_false_positive(self, matched_text: str, line: str, file_path: Path) -> bool:
        """
        检测假阳性

        Args:
            matched_text: 匹配到的文本
            line: 所在行
            file_path: 文件路径

        Returns:
            是否为假阳性
        """
        # 常见假阳性值
        false_positive_values = {
            'password', 'passwd', 'pwd', 'your_password', 'your-password',
            'example', 'xxx', 'placeholder', 'changeme', 'todo',
            'password123', '12345678', 'test', 'testing', 'secret',
            'none', 'null', 'undefined', 'empty', 'default',
            '<password>', '{password}', '${password}', '%password%',
            'password_here', 'your_api_key', 'your-api-key',
            'xxxxxxxx', '********', '........'
        }

        matched_lower = matched_text.lower()

        # 检查是否为示例值
        for fp in false_positive_values:
            if fp in matched_lower:
                return True

        # 检查是否为变量引用
        if '${' in matched_text or '#{' in matched_text or '{{' in matched_text:
            return True

        # 检查是否在测试/示例文件中
        path_lower = str(file_path).lower()
        if any(x in path_lower for x in ['test', 'example', 'sample', 'mock', 'demo', 'spec']):
            # 测试文件中的发现降低优先级,但不完全排除
            pass

        # 检查是否为文档注释
        if 'example:' in line.lower() or 'e.g.' in line.lower():
            return True

        return False

    def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        file_patterns: List[str] = None
    ) -> List[SecretFinding]:
        """
        扫描目录

        Args:
            directory: 目录路径
            recursive: 是否递归扫描
            file_patterns: 文件名模式过滤 (如 ['*.py', '*.js'])

        Returns:
            发现的敏感信息列表
        """
        self.findings = []
        dir_path = Path(directory)

        if not dir_path.exists():
            self._log(f"Directory not found: {directory}")
            return self.findings

        def walk_directory(path: Path) -> Generator[Path, None, None]:
            try:
                for item in path.iterdir():
                    if item.is_dir():
                        if not self._should_skip_dir(item):
                            if recursive:
                                yield from walk_directory(item)
                    elif item.is_file():
                        if not self._should_skip_file(item):
                            # 检查文件模式过滤
                            if file_patterns:
                                import fnmatch
                                if not any(fnmatch.fnmatch(item.name, p) for p in file_patterns):
                                    continue
                            yield item
            except PermissionError:
                self._log(f"Permission denied: {path}")

        # 扫描文件
        file_count = 0
        for file_path in walk_directory(dir_path):
            file_count += 1
            if file_count % 100 == 0:
                self._log(f"Scanned {file_count} files...")

            file_findings = self.scan_file(file_path)
            self.findings.extend(file_findings)

        self._log(f"Scan complete. Scanned {file_count} files, found {len(self.findings)} secrets.")
        return self.findings

    def scan_git_history(self, repo_path: str, max_commits: int = 100) -> List[SecretFinding]:
        """
        扫描Git历史中的敏感信息

        Args:
            repo_path: Git仓库路径
            max_commits: 最大扫描提交数

        Returns:
            发现的敏感信息列表
        """
        import subprocess

        findings = []
        repo_path = Path(repo_path)

        if not (repo_path / '.git').exists():
            self._log(f"Not a git repository: {repo_path}")
            return findings

        try:
            # 获取提交历史
            result = subprocess.run(
                ['git', 'log', '--pretty=format:%H', f'-{max_commits}'],
                cwd=str(repo_path),
                capture_output=True, text=True, timeout=60
            )

            commits = result.stdout.strip().split('\n')

            for commit in commits:
                if not commit:
                    continue

                # 获取该提交的diff
                diff_result = subprocess.run(
                    ['git', 'show', commit, '--format=', '--unified=0'],
                    cwd=str(repo_path),
                    capture_output=True, text=True, timeout=60
                )

                # 扫描diff内容
                diff_content = diff_result.stdout
                current_file = ""

                for line_num, line in enumerate(diff_content.split('\n'), 1):
                    # 提取文件名
                    if line.startswith('+++ b/'):
                        current_file = line[6:]
                        continue

                    # 只检查添加的行
                    if not line.startswith('+') or line.startswith('+++'):
                        continue

                    line_content = line[1:]  # 移除 + 号

                    # 检查敏感模式
                    for secret_type, patterns in self.SECRET_PATTERNS.items():
                        for pattern, confidence in patterns:
                            matches = re.finditer(pattern, line_content)
                            for match in matches:
                                matched_text = match.group(0)

                                if self._is_false_positive(matched_text, line_content, Path(current_file)):
                                    continue

                                finding = SecretFinding(
                                    secret_type=secret_type,
                                    file_path=f"{current_file} (commit: {commit[:8]})",
                                    line_number=line_num,
                                    line_content=line_content.strip(),
                                    matched_text=matched_text,
                                    confidence=confidence,
                                    context=f"Git commit: {commit}"
                                )
                                findings.append(finding)
                                self._log(f"Found {secret_type.value} in git history: {commit[:8]}")

            self.findings.extend(findings)
            return findings

        except Exception as e:
            self._log(f"Git scan error: {e}")
            return findings

    def get_summary(self) -> Dict[str, Any]:
        """获取扫描摘要"""
        summary = {
            "total_findings": len(self.findings),
            "by_type": {},
            "by_confidence": {"high": 0, "medium": 0, "low": 0},
            "files_affected": set()
        }

        for finding in self.findings:
            # 按类型统计
            type_name = finding.secret_type.value
            if type_name not in summary["by_type"]:
                summary["by_type"][type_name] = 0
            summary["by_type"][type_name] += 1

            # 按置信度统计
            summary["by_confidence"][finding.confidence] += 1

            # 受影响文件
            summary["files_affected"].add(finding.file_path)

        summary["files_affected"] = list(summary["files_affected"])
        return summary

    def export_json(self, output_path: str = None) -> str:
        """
        导出结果为JSON

        Args:
            output_path: 输出文件路径,None则返回JSON字符串
        """
        data = {
            "timestamp": datetime.now().isoformat(),
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings]
        }

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return output_path
        else:
            return json.dumps(data, indent=2, ensure_ascii=False)

    def export_sarif(self, output_path: str) -> str:
        """
        导出为SARIF格式 (GitHub/GitLab安全报告兼容)
        """
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecretFinder",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        # 添加规则
        rules_added = set()
        for finding in self.findings:
            rule_id = finding.secret_type.value
            if rule_id not in rules_added:
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": finding.secret_type.value.replace('_', ' ').title(),
                    "shortDescription": {"text": f"Detected {rule_id}"},
                    "defaultConfiguration": {
                        "level": "error" if finding.confidence == "high" else "warning"
                    }
                })
                rules_added.add(rule_id)

            # 添加结果
            sarif["runs"][0]["results"].append({
                "ruleId": rule_id,
                "level": "error" if finding.confidence == "high" else "warning",
                "message": {"text": f"Found {rule_id} with {finding.confidence} confidence"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path},
                        "region": {"startLine": finding.line_number}
                    }
                }]
            })

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)

        return output_path


# 便捷函数
def find_secrets(
    path: str,
    recursive: bool = True,
    include_git: bool = False,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    敏感信息搜索便捷函数

    Args:
        path: 扫描路径
        recursive: 是否递归
        include_git: 是否扫描Git历史
        verbose: 是否输出详细日志

    Returns:
        扫描结果字典
    """
    finder = PasswordFinder(verbose=verbose)
    finder.scan_directory(path, recursive=recursive)

    if include_git:
        finder.scan_git_history(path)

    return {
        "summary": finder.get_summary(),
        "findings": [f.to_dict() for f in finder.findings]
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    else:
        target_path = "."

    print(f"=== Secret Finder - Scanning: {target_path} ===")
    finder = PasswordFinder(verbose=True)
    findings = finder.scan_directory(target_path)

    print(f"\n=== Summary ===")
    summary = finder.get_summary()
    print(f"Total findings: {summary['total_findings']}")
    print(f"By type: {summary['by_type']}")
    print(f"By confidence: {summary['by_confidence']}")
    print(f"Files affected: {len(summary['files_affected'])}")
