"""
暴露面检测器

检测真实互联网中常见的非注入型高价值暴露：工具目录、凭证文件、历史记录、配置和代码仓库元数据。
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity


@register_detector("exposure")
class ExposureDetector(BaseDetector):
    """敏感暴露检测器"""

    name = "exposure"
    description = "敏感文件、攻击工具痕迹和管理数据暴露检测器"
    vuln_type = "exposure"
    severity = Severity.HIGH
    detector_type = DetectorType.MISC
    version = "1.0.0"

    EXPOSURE_PATHS = {
        "/.msf4/": (Severity.HIGH, "metasploit_home"),
        "/.msf4/history": (Severity.CRITICAL, "metasploit_history"),
        "/.msf4/logs/": (Severity.HIGH, "metasploit_logs"),
        "/.sliver/": (Severity.HIGH, "sliver_home"),
        "/.sliver/sliver.db": (Severity.CRITICAL, "sliver_database"),
        "/.sliver/configs/": (Severity.HIGH, "sliver_configs"),
        "/.git/HEAD": (Severity.HIGH, "git_metadata"),
        "/.git/config": (Severity.HIGH, "git_config"),
        "/.env": (Severity.HIGH, "env_file"),
        "/.bash_history": (Severity.CRITICAL, "shell_history"),
        "/.zsh_history": (Severity.CRITICAL, "shell_history"),
        "/id_rsa": (Severity.CRITICAL, "private_key"),
        "/.ssh/id_rsa": (Severity.CRITICAL, "private_key"),
        "/credentials": (Severity.HIGH, "credentials_file"),
        "/credentials.txt": (Severity.HIGH, "credentials_file"),
        "/config.json": (Severity.MEDIUM, "config_file"),
    }

    DIRECTORY_LISTING_PATTERNS = [
        re.compile(r"<title>Index of /", re.IGNORECASE),
        re.compile(r"<h1>Index of /", re.IGNORECASE),
        re.compile(r"\bParent Directory\b", re.IGNORECASE),
    ]

    CONTENT_PATTERNS = {
        "sliver_database": [b"SQLite format 3", b"beacons", b"operators"],
        "metasploit_history": ["use exploit/", "set RHOST", "setg RHOST", "run", "exploit"],
        "shell_history": ["ssh ", "mysql ", "psql ", "password", "token", "curl "],
        "private_key": ["-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----"],
        "git_metadata": ["ref: refs/heads/"],
        "git_config": ["[core]", "repositoryformatversion"],
        "env_file": ["=", "SECRET", "TOKEN", "PASSWORD", "DATABASE_URL"],
        "credentials_file": ["password", "username", "token", "secret", "access_key"],
    }

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        custom_paths = self.config.get("custom_paths", {})
        self.exposure_paths = {**self.EXPOSURE_PATHS, **custom_paths}

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        self._log_detection_start(url)
        headers = kwargs.get("headers", {})
        results: List[DetectionResult] = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, (severity, exposure_type) in self.exposure_paths.items():
            test_url = urljoin(base_url, path)
            response = self._safe_request("GET", test_url, headers=headers)
            if response is None or getattr(response, "status_code", 0) != 200:
                continue

            body = getattr(response, "text", "") or ""
            content = getattr(response, "content", b"") or b""
            if not self._is_real_exposure(path, exposure_type, body, content):
                continue

            result = self._create_result(
                url=test_url,
                vulnerable=True,
                payload=path,
                evidence=f"发现敏感暴露: {path} ({exposure_type})",
                confidence=0.95,
                verified=True,
                request=self._build_request_info(method="GET", url=test_url, headers=headers),
                response=self._build_response_info(response),
                remediation="移除公开访问、关闭目录列表，并将敏感文件迁出 Web 根目录",
                extra={
                    "exposure_type": exposure_type,
                    "path": path,
                    "content_preview": body[:200],
                },
            )
            result.severity = severity
            results.append(result)

            if self.config.get("early_stop", True) and severity == Severity.CRITICAL:
                break

        self._log_detection_end(url, results)
        return results

    def _is_real_exposure(self, path: str, exposure_type: str, body: str, content: bytes) -> bool:
        if not body and not content:
            return False

        if path.endswith("/"):
            return any(pattern.search(body) for pattern in self.DIRECTORY_LISTING_PATTERNS)

        patterns = self.CONTENT_PATTERNS.get(exposure_type, [])
        if exposure_type == "sliver_database":
            return any(isinstance(p, bytes) and p in content for p in patterns)

        body_lower = body.lower()
        return any(str(pattern).lower() in body_lower for pattern in patterns)

    def get_payloads(self) -> List[str]:
        return list(self.exposure_paths.keys())
