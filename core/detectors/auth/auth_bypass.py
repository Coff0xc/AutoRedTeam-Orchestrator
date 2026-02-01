"""
认证绕过检测器

检测各种认证绕过漏洞
"""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)


@register_detector("auth_bypass")
class AuthBypassDetector(BaseDetector):
    """认证绕过检测器

    检测多种认证绕过技术:
    - HTTP 方法绕过
    - 路径绕过
    - 参数污染绕过
    - 头部注入绕过
    - 默认/后门路径

    使用示例:
        detector = AuthBypassDetector()
        results = detector.detect("https://example.com/admin/dashboard")
    """

    name = "auth_bypass"
    description = "认证绕过漏洞检测器"
    vuln_type = "auth_bypass"
    severity = Severity.CRITICAL
    detector_type = DetectorType.AUTH
    version = "1.0.0"

    # HTTP 方法绕过测试
    HTTP_METHODS = [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
    ]

    # 路径绕过 payload
    PATH_BYPASS_PAYLOADS = [
        # 大小写变体
        "{path}",
        "{PATH}",
        "{Path}",
        # 路径遍历
        "/{path}/",
        "//{path}",
        "/./{path}",
        "/{path}/.",
        "/{path}/./",
        "/{path}/./.",
        # URL 编码
        "/%2e/{path}",
        "/{path}%2f",
        "/{path}%20",
        "/{path}%09",
        "/{path}%00",
        # 扩展名绕过
        "/{path}.json",
        "/{path}.html",
        "/{path}.php",
        "/{path}.asp",
        "/{path}.aspx",
        "/{path};.js",
        "/{path}..;/",
        # 特殊字符
        "/{path}?",
        "/{path}#",
        "/{path}%23",
        "/{path}%3f",
        # 双重编码
        "/%252e/{path}",
        "/{path}%252f",
    ]

    # 认证绕过头部
    AUTH_BYPASS_HEADERS = [
        {"X-Original-URL": "{path}"},
        {"X-Rewrite-URL": "{path}"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Host": "localhost"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Cluster-Client-IP": "127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Forwarded": "for=127.0.0.1"},
    ]

    # 后门/调试路径
    BACKDOOR_PATHS = [
        "/admin",
        "/administrator",
        "/admin.php",
        "/admin.asp",
        "/manager",
        "/console",
        "/debug",
        "/test",
        "/backup",
        "/config",
        "/api/admin",
        "/api/debug",
        "/api/test",
        "/.git",
        "/.svn",
        "/.env",
        "/phpinfo.php",
        "/info.php",
        "/server-status",
        "/server-info",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - check_method_bypass: 是否检测方法绕过
                - check_path_bypass: 是否检测路径绕过
                - check_header_bypass: 是否检测头部绕过
                - check_backdoor: 是否检测后门路径
        """
        super().__init__(config)

        self.check_method_bypass = self.config.get("check_method_bypass", True)
        self.check_path_bypass = self.config.get("check_path_bypass", True)
        self.check_header_bypass = self.config.get("check_header_bypass", True)
        self.check_backdoor = self.config.get("check_backdoor", True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测认证绕过漏洞

        Args:
            url: 目标 URL（通常是受保护资源）
            **kwargs:
                headers: 请求头
                expected_status: 预期的认证失败状态码

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        headers = kwargs.get("headers", {})
        expected_status = kwargs.get("expected_status", [401, 403])

        # 获取基线响应（未认证）
        baseline = self._get_baseline(url, headers)
        if not baseline:
            logger.warning("无法获取基线响应")
            self._log_detection_end(url, results)
            return results

        # HTTP 方法绕过
        if self.check_method_bypass:
            method_results = self._test_method_bypass(url, headers, baseline)
            results.extend(method_results)

        # 路径绕过
        if self.check_path_bypass:
            path_results = self._test_path_bypass(url, headers, baseline)
            results.extend(path_results)

        # 头部绕过
        if self.check_header_bypass:
            header_results = self._test_header_bypass(url, headers, baseline)
            results.extend(header_results)

        # 后门路径检测
        if self.check_backdoor:
            backdoor_results = self._test_backdoor_paths(url, headers)
            results.extend(backdoor_results)

        self._log_detection_end(url, results)
        return results

    def _test_method_bypass(
        self, url: str, headers: Dict[str, str], baseline: Any
    ) -> List[DetectionResult]:
        """测试 HTTP 方法绕过

        Args:
            url: 目标 URL
            headers: 请求头
            baseline: 基线响应

        Returns:
            检测结果列表
        """
        results = []

        for method in self.HTTP_METHODS:
            if method == "GET":
                continue

            try:
                response = self.http_client.request(method, url, headers=headers)

                if self._is_bypass_success(response, baseline):
                    results.append(
                        self._create_result(
                            url=url,
                            vulnerable=True,
                            payload=f"HTTP 方法: {method}",
                            evidence=f"使用 {method} 方法绕过认证，状态码: {response.status_code}",
                            confidence=0.85,
                            verified=True,
                            remediation="确保所有 HTTP 方法都经过认证检查",
                            extra={"bypass_type": "method", "method": method},
                        )
                    )
                    break

            except Exception as e:
                logger.debug(f"方法绕过测试失败 ({method}): {e}")

        return results

    def _test_path_bypass(
        self, url: str, headers: Dict[str, str], baseline: Any
    ) -> List[DetectionResult]:
        """测试路径绕过

        Args:
            url: 目标 URL
            headers: 请求头
            baseline: 基线响应

        Returns:
            检测结果列表
        """
        results = []
        parsed = urlparse(url)
        path = parsed.path

        for payload_template in self.PATH_BYPASS_PAYLOADS:
            # 构造测试 URL
            test_path = payload_template.replace("{path}", path.strip("/"))
            test_path = payload_template.replace("{PATH}", path.strip("/").upper())
            test_path = payload_template.replace("{Path}", path.strip("/").capitalize())

            test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"
            if parsed.query:
                test_url += f"?{parsed.query}"

            try:
                response = self.http_client.get(test_url, headers=headers)

                if self._is_bypass_success(response, baseline):
                    results.append(
                        self._create_result(
                            url=url,
                            vulnerable=True,
                            payload=test_path,
                            evidence=f"路径绕过成功，状态码: {response.status_code}",
                            confidence=0.80,
                            verified=True,
                            remediation="规范化 URL 路径处理，避免路径解析差异",
                            extra={"bypass_type": "path", "test_url": test_url},
                        )
                    )
                    return results  # 发现一个就返回

            except Exception as e:
                logger.debug(f"路径绕过测试失败: {e}")

        return results

    def _test_header_bypass(
        self, url: str, headers: Dict[str, str], baseline: Any
    ) -> List[DetectionResult]:
        """测试头部绕过

        Args:
            url: 目标 URL
            headers: 请求头
            baseline: 基线响应

        Returns:
            检测结果列表
        """
        results = []
        parsed = urlparse(url)

        for bypass_header in self.AUTH_BYPASS_HEADERS:
            test_headers = headers.copy()

            for key, value in bypass_header.items():
                test_headers[key] = value.replace("{path}", parsed.path)

            try:
                response = self.http_client.get(url, headers=test_headers)

                if self._is_bypass_success(response, baseline):
                    results.append(
                        self._create_result(
                            url=url,
                            vulnerable=True,
                            payload=str(bypass_header),
                            evidence=f"头部绕过成功，状态码: {response.status_code}",
                            confidence=0.85,
                            verified=True,
                            remediation="不要信任客户端提供的 IP 或路径头部",
                            extra={"bypass_type": "header", "headers": bypass_header},
                        )
                    )
                    return results

            except Exception as e:
                logger.debug(f"头部绕过测试失败: {e}")

        return results

    def _test_backdoor_paths(self, url: str, headers: Dict[str, str]) -> List[DetectionResult]:
        """测试后门路径

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果列表
        """
        results = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.BACKDOOR_PATHS:
            test_url = urljoin(base_url, path)

            try:
                response = self.http_client.get(test_url, headers=headers)

                # 检查是否可访问（200 且有内容）
                if response.status_code == 200 and len(response.text) > 100:
                    # 检查是否是有意义的内容
                    if self._is_sensitive_content(response.text):
                        results.append(
                            self._create_result(
                                url=test_url,
                                vulnerable=True,
                                payload=path,
                                evidence=f"发现可访问的敏感路径",
                                confidence=0.75,
                                verified=False,
                                remediation="禁用或保护敏感路径",
                                extra={"bypass_type": "backdoor", "path": path},
                            )
                        )

            except Exception as e:
                logger.debug(f"后门路径测试失败 ({path}): {e}")

        return results

    def _get_baseline(self, url: str, headers: Dict[str, str]) -> Optional[Any]:
        """获取基线响应"""
        try:
            return self.http_client.get(url, headers=headers)
        except Exception as e:
            logger.debug(f"获取基线失败: {e}")
            return None

    def _is_bypass_success(self, response: Any, baseline: Any) -> bool:
        """判断是否绕过成功

        Args:
            response: 测试响应
            baseline: 基线响应

        Returns:
            是否绕过成功
        """
        # 基线是 401/403，测试是 200
        if baseline.status_code in (401, 403) and response.status_code == 200:
            return True

        # 响应内容明显不同
        if baseline.status_code in (401, 403):
            if response.status_code == 200 and len(response.text) > len(baseline.text) * 2:
                return True

        return False

    def _is_sensitive_content(self, content: str) -> bool:
        """判断是否是敏感内容"""
        sensitive_patterns = [
            r"<title>.*admin.*</title>",
            r"<title>.*dashboard.*</title>",
            r"<title>.*console.*</title>",
            r"password",
            r"secret",
            r"api[_-]?key",
            r"phpinfo",
            r"git config",
            r"\.env",
            r"database",
        ]

        content_lower = content.lower()
        for pattern in sensitive_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True

        return False

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.PATH_BYPASS_PAYLOADS + [str(h) for h in self.AUTH_BYPASS_HEADERS]
