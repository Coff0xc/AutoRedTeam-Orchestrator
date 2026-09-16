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

import logging

logger = logging.getLogger(__name__)

import json
import mimetypes
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Set, Tuple, Union


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
            "content": (
                self.line_content[:200] + "..."
                if len(self.line_content) > 200
                else self.line_content
            ),
            "match": (
                self.matched_text[:100] + "..."
                if len(self.matched_text) > 100
                else self.matched_text
            ),
            "confidence": self.confidence,
            "context": self.context,
        }


class PasswordFinder:
    """
    敏感信息搜索器

    使用正则表达式和启发式规则搜索文件中的敏感信息
    """

    # 默认忽略的目录
    DEFAULT_IGNORE_DIRS: Set[str] = {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "__pycache__",
        "venv",
        ".venv",
        "env",
        ".env",
        "vendor",
        "target",
        "build",
        "dist",
        "bin",
        "obj",
        ".idea",
        ".vscode",
        "logs",
        "log",
        "tmp",
        "temp",
        "cache",
        ".cache",
    }

    # 默认忽略的文件扩展名
    DEFAULT_IGNORE_EXTENSIONS: Set[str] = {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".pyc",
        ".pyo",
        ".class",
        ".jar",
        ".war",
        ".ear",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".ico",
        ".bmp",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".mp3",
        ".mp4",
        ".avi",
        ".mkv",
        ".mov",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".min.js",
        ".min.css",
        ".map",
    }

    # 敏感文件名模式
    SENSITIVE_FILENAMES: List[str] = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "config.json",
        "config.yaml",
        "config.yml",
        "config.ini",
        "settings.py",
        "settings.json",
        "settings.yaml",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
        "credentials.json",
        "credentials.yaml",
        "database.yml",
        "database.json",
        "application.properties",
        "application.yml",
        "wp-config.php",
        "configuration.php",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".htpasswd",
        ".netrc",
        ".pgpass",
        "docker-compose.yml",
        "docker-compose.yaml",
        "Dockerfile",
        "kubernetes.yaml",
        "k8s.yaml",
        "terraform.tfvars",
        "*.tfstate",
        "ansible.cfg",
        "vault.yml",
        "travis.yml",
        ".travis.yml",
        "circle.yml",
        "jenkins.xml",
        "Jenkinsfile",
        "gitlab-ci.yml",
        ".gitlab-ci.yml",
        "github-actions.yml",
        "workflows/*.yml",
    ]

    # 敏感信息正则表达式
    SECRET_PATTERNS: Dict[SecretType, List[tuple]] = {
        SecretType.PASSWORD: [
            # (?<![A-Za-z]) 而非 \b：下划线是 word 字符，db_pass 这类命名必须仍能命中
            (
                r"(?i)(password|passwd|pwd|(?<![A-Za-z])pass)\s*[=:]\s*"
                r'["\']?([^"\'\s\n]{4,})["\']?',
                "high",
            ),
            (r'(?i)(secret|token|key)\s*[=:]\s*["\']?([^"\'\s\n]{8,})["\']?', "medium"),
        ],
        SecretType.API_KEY: [
            # Generic API keys
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', "high"),
            # Slack tokens
            (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", "high"),
            # Google API
            (r"AIza[0-9A-Za-z_-]{35}", "high"),
            # GitHub tokens
            (r"ghp_[0-9a-zA-Z]{36}", "high"),
            (r"gho_[0-9a-zA-Z]{36}", "high"),
            (r"ghu_[0-9a-zA-Z]{36}", "high"),
            (r"ghs_[0-9a-zA-Z]{36}", "high"),
            (r"ghr_[0-9a-zA-Z]{36}", "high"),
            # Stripe
            (r"sk_live_[0-9a-zA-Z]{24,}", "high"),
            (r"pk_live_[0-9a-zA-Z]{24,}", "high"),
            # Twilio
            (r"SK[0-9a-fA-F]{32}", "medium"),
            # SendGrid
            (r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}", "high"),
        ],
        SecretType.AWS_KEY: [
            (r"AKIA[0-9A-Z]{16}", "high"),  # AWS Access Key ID
            (
                r'(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\']?'  # noqa: E501
                r'([A-Za-z0-9/+=]{40})["\']?',
                "high",
            ),
        ],
        SecretType.PRIVATE_KEY: [
            (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "high"),
            (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "high"),
        ],
        SecretType.DATABASE_URL: [
            # 协议名不捕获：捕获组在这里表示密钥值，整个连接串才是值
            (r'(?i)(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s\n"\']+', "high"),
            (
                r'(?i)(database_url|db_url|connection_string)\s*[=:]\s*["\']?([^\s\n"\']+)["\']?',
                "high",
            ),
            (r"(?i)Server=.+;Database=.+;User Id=.+;Password=(.+?);", "high"),
        ],
        SecretType.JWT_TOKEN: [
            (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "high"),
        ],
        SecretType.OAUTH_TOKEN: [
            (r'(?i)(oauth|bearer)\s*(token)?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', "medium"),
            (r'(?i)(access_token|refresh_token)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?', "high"),
        ],
        SecretType.SSH_KEY: [
            (r"-----BEGIN OPENSSH PRIVATE KEY-----", "high"),
            (r"ssh-rsa\s+AAAA[0-9A-Za-z+/]+", "medium"),  # Public key (有时也有用)
        ],
        SecretType.WEBHOOK_URL: [
            (r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "high"),
            (r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", "high"),
            (r"https://outlook\.office\.com/webhook/[A-Za-z0-9-]+", "high"),
        ],
        SecretType.GENERIC_SECRET: [
            (r'(?i)(secret|token|credential|auth)\s*[=:]\s*["\']([^"\']{8,})["\']', "low"),
        ],
    }

    def __init__(
        self,
        ignore_dirs: Optional[Set[str]] = None,
        ignore_extensions: Optional[Set[str]] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        verbose: bool = False,
    ):
        self.ignore_dirs = ignore_dirs or self.DEFAULT_IGNORE_DIRS
        self.ignore_extensions = ignore_extensions or self.DEFAULT_IGNORE_EXTENSIONS
        self.max_file_size = max_file_size
        self.verbose = verbose
        self.findings: List[SecretFinding] = []

    def _log(self, message: str):
        """日志输出"""
        if self.verbose:
            logger.debug("[SecretFinder] %s", message)

    def _should_skip_file(self, file_path: Path) -> bool:
        """判断是否跳过文件"""
        # 检查扩展名
        suffix = file_path.suffix.lower()
        if suffix in self.ignore_extensions:
            return True

        # 检查是否为压缩的JS/CSS
        if file_path.name.endswith(".min.js") or file_path.name.endswith(".min.css"):
            return True

        # 检查文件大小
        try:
            if file_path.stat().st_size > self.max_file_size:
                return True
        except (OSError, FileNotFoundError):
            return True

        # 检查是否为二进制文件
        try:
            mime_type = mimetypes.guess_type(str(file_path))[0]
            if (
                mime_type
                and not mime_type.startswith("text/")
                and not mime_type.startswith("application/json")
                and not mime_type.startswith("application/xml")
                and not mime_type.startswith("application/javascript")
            ):
                # 尝试读取前512字节判断
                with open(file_path, "rb") as f:
                    chunk = f.read(512)
                    if b"\x00" in chunk:  # 包含null字节,可能是二进制
                        return True
        except Exception:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return False

    def _should_skip_dir(self, dir_path: Path) -> bool:
        """判断是否跳过目录"""
        return dir_path.name in self.ignore_dirs

    def _is_sensitive_filename(self, filename: str) -> bool:
        """检查是否为敏感文件名"""
        filename_lower = filename.lower()
        for pattern in self.SENSITIVE_FILENAMES:
            if "*" in pattern:
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
        findings: List[SecretFinding] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            self._log(f"Cannot read {file_path}: {e}")
            return findings

        # 检查文件名是否敏感
        is_sensitive_file = self._is_sensitive_filename(file_path.name)

        for line_num, line in enumerate(lines, 1):
            # 跳过注释行 (简单启发式)
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                # 即使是注释也可能包含敏感信息
                pass

            # 检查各种敏感模式
            for secret_type, patterns in self.SECRET_PATTERNS.items():
                for pattern, confidence in patterns:
                    matches = re.finditer(pattern, line)
                    for match in matches:
                        # 报出去的是值本身，不是含关键字的整段匹配
                        matched_text, from_group = self._captured_value(match)

                        # 过滤假阳性
                        if self._is_false_positive(matched_text, from_group, line, file_path):
                            continue

                        # 如果在敏感文件中发现,提高置信度
                        actual_confidence = confidence
                        if is_sensitive_file and confidence == "medium":
                            actual_confidence = "high"

                        finding = SecretFinding(
                            secret_type=secret_type,
                            file_path=str(file_path),
                            line_number=line_num,
                            line_content=line.strip(),
                            matched_text=matched_text,
                            confidence=actual_confidence,
                            context=f"Line {max(1, line_num - 2)}-{min(len(lines), line_num + 2)}",
                        )
                        findings.append(finding)
                        self._log(f"Found {secret_type.value} in {file_path}:{line_num}")

        return findings

    @staticmethod
    def _captured_value(match: "re.Match[str]") -> Tuple[str, bool]:
        """取匹配里的密钥值，以及它是不是从捕获组里取出来的

        约定：最后一个非空捕获组是密钥值（``password = "x"`` 的值是 ``x``）；
        整个匹配即密钥的模式（私钥头、``ghp_`` token、连接串）没有捕获组，退回 group(0)。
        关键字和分隔符都在 group(0) 里，拿它当值去比对会把真实密钥整条滤掉。
        """
        groups = [group for group in match.groups() if group]
        if groups:
            return groups[-1], True
        return match.group(0), False

    @staticmethod
    def _looks_like_secret_value(value: str) -> bool:
        """值的形状像密钥，而不是代码或文档片段

        只对捕获组取值的情况用：``password: str,`` 是类型注解、``os.environ.get(`` 是调用、
        ``password[:2]`` 是表达式，抠出来的值形状就不对。签名类模式（私钥头、token、
        连接串）的整段匹配本身就带这些字符，不能按同一把尺子量。
        """
        if any(char in value for char in "()[]{}<>=|`"):
            return False
        # 以逗号结尾的值是代码里的参数或字面量，配置文件不用逗号收尾
        if value.endswith(","):
            return False
        return bool(re.search(r"[A-Za-z0-9]", value))

    def _is_false_positive(self, value: str, from_group: bool, line: str, file_path: Path) -> bool:
        """
        检测假阳性

        Args:
            value: 密钥值（_captured_value 取出，也是最终报出去的内容）
            from_group: 值是否来自捕获组，决定要不要按密钥形状要求它
            line: 所在行
            file_path: 文件路径

        Returns:
            是否为假阳性
        """
        # 常见假阳性值
        false_positive_values = {
            "password",
            "passwd",
            "pwd",
            "your_password",
            "your-password",
            "example",
            "xxx",
            "placeholder",
            "changeme",
            "todo",
            "password123",
            "12345678",
            "test",
            "testing",
            "secret",
            "none",
            "null",
            "undefined",
            "empty",
            "default",
            "<password>",
            "{password}",
            "${password}",
            "%password%",
            "password_here",
            "your_api_key",
            "your-api-key",
            "xxxxxxxx",
            "********",
            "........",
        }

        # 占位符按整值比对：子串命中会连真实密钥一起吞掉
        # （hunter2SuperSecret 含 secret，MyTestPassw0rd! 含 test）
        # 逗号分号是 ini/properties 的行尾分隔符，比对前去掉
        if value.strip().strip(",;").lower() in false_positive_values:
            return True

        # 掩码值不按整值比，长度随意 (xxxxxx / ********)
        if re.fullmatch(r"[x*.]+", value, re.IGNORECASE):
            return True

        # 明说是假值的标记按子串比对，形状判不出来：AKIA...EXAMPLE、AIza...FAKE_TEST_KEY
        # 名单故意只有这几个词：test、secret、password 在真实密钥里也会出现，放进来就是误杀
        if any(
            marker in value.lower()
            for marker in (
                "example",
                "fake",
                "dummy",
                "placeholder",
                "not_real",
                "your_",
                "your-",
                "changeme",
                "xxxx",
                "****",
            )
        ):
            return True

        # 检查是否为变量引用
        if "${" in value or "#{" in value or "{{" in value:
            return True

        if from_group and not self._looks_like_secret_value(value):
            return True

        # 检查是否在测试/示例文件中
        path_lower = str(file_path).lower()
        if any(x in path_lower for x in ["test", "example", "sample", "mock", "demo", "spec"]):
            # 测试文件中的发现降低优先级,但不完全排除
            pass

        # 检查是否为文档注释
        if "example:" in line.lower() or "e.g." in line.lower():
            return True

        return False

    def scan_directory(
        self, directory: str, recursive: bool = True, file_patterns: Optional[List[str]] = None
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

    def scan_git_history(
        self, repo_path: Union[str, Path], max_commits: int = 100
    ) -> List[SecretFinding]:
        """
        扫描Git历史中的敏感信息

        Args:
            repo_path: Git仓库路径
            max_commits: 最大扫描提交数

        Returns:
            发现的敏感信息列表
        """
        import subprocess

        findings: List[SecretFinding] = []
        repo_path = Path(repo_path)

        if not (repo_path / ".git").exists():
            self._log(f"Not a git repository: {repo_path}")
            return findings

        try:
            # 获取提交历史
            result = subprocess.run(
                ["git", "log", "--pretty=format:%H", f"-{max_commits}"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=60,
            )

            commits = result.stdout.strip().split("\n")

            for commit in commits:
                if not commit:
                    continue

                # 获取该提交的diff
                diff_result = subprocess.run(
                    ["git", "show", commit, "--format=", "--unified=0"],
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                # 扫描diff内容
                diff_content = diff_result.stdout
                current_file = ""

                for line_num, line in enumerate(diff_content.split("\n"), 1):
                    # 提取文件名
                    if line.startswith("+++ b/"):
                        current_file = line[6:]
                        continue

                    # 只检查添加的行
                    if not line.startswith("+") or line.startswith("+++"):
                        continue

                    line_content = line[1:]  # 移除 + 号

                    # 检查敏感模式
                    for secret_type, patterns in self.SECRET_PATTERNS.items():
                        for pattern, confidence in patterns:
                            matches = re.finditer(pattern, line_content)
                            for match in matches:
                                matched_text, from_group = self._captured_value(match)

                                if self._is_false_positive(
                                    matched_text, from_group, line_content, Path(current_file)
                                ):
                                    continue

                                finding = SecretFinding(
                                    secret_type=secret_type,
                                    file_path=f"{current_file} (commit: {commit[:8]})",
                                    line_number=line_num,
                                    line_content=line_content.strip(),
                                    matched_text=matched_text,
                                    confidence=confidence,
                                    context=f"Git commit: {commit}",
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
        summary: Dict[str, Any] = {
            "total_findings": len(self.findings),
            "by_type": {},
            "by_confidence": {"high": 0, "medium": 0, "low": 0},
            "files_affected": set(),
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

    def export_json(self, output_path: Optional[str] = None) -> str:
        """
        导出结果为JSON

        Args:
            output_path: 输出文件路径,None则返回JSON字符串
        """
        data = {
            "timestamp": datetime.now().isoformat(),
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return output_path
        else:
            return json.dumps(data, indent=2, ensure_ascii=False)

    def export_sarif(self, output_path: str) -> str:
        """
        导出为SARIF格式 (GitHub/GitLab安全报告兼容)
        """
        sarif: Dict[str, Any] = {
            "version": "2.1.0",
            "$schema": (  # noqa: E501
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master"
                "/Schemata/sarif-schema-2.1.0.json"
            ),
            "runs": [
                {
                    "tool": {"driver": {"name": "SecretFinder", "version": "1.0.0", "rules": []}},
                    "results": [],
                }
            ],
        }

        # 添加规则
        rules_added = set()
        for finding in self.findings:
            rule_id = finding.secret_type.value
            if rule_id not in rules_added:
                sarif["runs"][0]["tool"]["driver"]["rules"].append(
                    {
                        "id": rule_id,
                        "name": finding.secret_type.value.replace("_", " ").title(),
                        "shortDescription": {"text": f"Detected {rule_id}"},
                        "defaultConfiguration": {
                            "level": "error" if finding.confidence == "high" else "warning"
                        },
                    }
                )
                rules_added.add(rule_id)

            # 添加结果
            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "level": "error" if finding.confidence == "high" else "warning",
                    "message": {"text": f"Found {rule_id} with {finding.confidence} confidence"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file_path},
                                "region": {"startLine": finding.line_number},
                            }
                        }
                    ],
                }
            )

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)

        return output_path


# 便捷函数
def find_secrets(
    path: str, recursive: bool = True, include_git: bool = False, verbose: bool = False
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

    return {"summary": finder.get_summary(), "findings": [f.to_dict() for f in finder.findings]}


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    else:
        target_path = "."

    logger.info("=== Secret Finder - Scanning: %s ===", target_path)
    finder = PasswordFinder(verbose=True)
    findings = finder.scan_directory(target_path)

    logger.info("=== Summary ===")
    summary = finder.get_summary()
    logger.info("Total findings: %s", summary["total_findings"])
    logger.info("By type: %s", summary["by_type"])
    logger.info("By confidence: %s", summary["by_confidence"])
    logger.info("Files affected: %s", len(summary["files_affected"]))
