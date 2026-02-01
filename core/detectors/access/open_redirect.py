"""
开放重定向检测器

检测不安全的 URL 重定向漏洞
"""

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)


@register_detector("open_redirect")
class OpenRedirectDetector(BaseDetector):
    """开放重定向检测器

    检测不安全的 URL 重定向漏洞，可能导致钓鱼攻击

    使用示例:
        detector = OpenRedirectDetector()
        results = detector.detect("https://example.com/login", params={"redirect": "/dashboard"})
    """

    name = "open_redirect"
    description = "开放重定向漏洞检测器"
    vuln_type = "open_redirect"
    severity = Severity.MEDIUM
    detector_type = DetectorType.ACCESS
    version = "1.0.0"

    # 重定向参数名
    REDIRECT_PARAMS = [
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "return",
        "return_url",
        "return_uri",
        "returnto",
        "next",
        "next_url",
        "next_page",
        "target",
        "dest",
        "destination",
        "goto",
        "go",
        "continue",
        "callback",
        "rurl",
        "out",
        "checkout_url",
        "success_url",
        "fail_url",
        "link",
        "forward",
        "ref",
        "redir",
    ]

    # 测试域名
    TEST_DOMAIN = "evil.com"

    # 开放重定向 payload
    REDIRECT_PAYLOADS = [
        # 基础重定向
        "https://evil.com",
        "http://evil.com",
        "//evil.com",
        "///evil.com",
        "////evil.com",
        # 协议相对 URL
        "//evil.com/",
        "///evil.com/",
        # 反斜杠绕过
        "/\\evil.com",
        "\\/evil.com",
        "//evil.com\\@trusted.com",
        # @ 符号绕过
        "https://trusted.com@evil.com",
        "//trusted.com@evil.com",
        "https://evil.com#trusted.com",
        "https://evil.com?trusted.com",
        # 编码绕过
        "//evil%00.com",
        "//evil%E3%80%82com",
        "//%0d%0aevil.com",
        "//evil.com%2f%2f",
        "//evil.com%09",
        # JavaScript 协议
        "javascript:alert(1)",
        "javascript://comment%0aalert(1)",
        # 数据 URI
        "data:text/html,<script>alert(1)</script>",
        # 特殊格式
        "https:evil.com",
        "https:/evil.com",
        "https:\\\\evil.com",
        # Unicode 绕过
        "//ⓔⓥⓘⓛ.ⓒⓞⓜ",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - test_domain: 测试域名
                - follow_redirects: 是否跟踪重定向
        """
        super().__init__(config)

        self.test_domain = self.config.get("test_domain", self.TEST_DOMAIN)
        self.follow_redirects = self.config.get("follow_redirects", False)

        # 更新 payload 中的测试域名
        self.payloads = [p.replace("evil.com", self.test_domain) for p in self.REDIRECT_PAYLOADS]

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测开放重定向漏洞

        Args:
            url: 目标 URL
            **kwargs:
                params: GET 参数字典
                data: POST 数据字典
                method: HTTP 方法
                headers: 请求头

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        params = kwargs.get("params", {})
        data = kwargs.get("data", {})
        method = kwargs.get("method", "GET").upper()
        headers = kwargs.get("headers", {})

        # 解析 URL 参数
        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # 识别重定向参数
        redirect_params = self._identify_redirect_params(params)

        for param_name in redirect_params:
            result = self._test_open_redirect(url, params, param_name, method, headers)
            if result:
                results.append(result)

        self._log_detection_end(url, results)
        return results

    def _test_open_redirect(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str],
    ) -> Optional[DetectionResult]:
        """测试开放重定向

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        for payload in self.payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == "GET":
                    response = self.http_client.get(
                        url,
                        params=test_params,
                        headers=headers,
                        allow_redirects=self.follow_redirects,
                    )
                else:
                    response = self.http_client.post(
                        url,
                        data=test_params,
                        headers=headers,
                        allow_redirects=self.follow_redirects,
                    )

                # 检查重定向
                is_vulnerable, evidence = self._check_redirect(response, payload)

                if is_vulnerable:
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        param=param_name,
                        payload=payload,
                        evidence=evidence,
                        confidence=0.90,
                        verified=True,
                        remediation="使用白名单验证重定向目标，避免使用用户提供的完整 URL",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                        ],
                        extra={"redirect_type": self._classify_redirect_type(payload)},
                    )

            except Exception as e:
                logger.debug(f"开放重定向检测失败: {e}")

        return None

    def _check_redirect(self, response: Any, payload: str) -> tuple:
        """检查响应是否存在开放重定向

        Args:
            response: HTTP 响应
            payload: 测试 payload

        Returns:
            (是否存在漏洞, 证据)
        """
        # 检查 3xx 重定向
        if 300 <= response.status_code < 400:
            location = response.headers.get("Location", "")

            if self._is_external_redirect(location):
                return (True, f"重定向到外部地址: {location}")

        # 检查响应中的重定向
        if hasattr(response, "history") and response.history:
            for r in response.history:
                location = r.headers.get("Location", "")
                if self._is_external_redirect(location):
                    return (True, f"重定向链包含外部地址: {location}")

        # 检查 JavaScript 重定向
        if response.status_code == 200:
            js_redirect_patterns = [
                rf'location\s*[=\.]\s*["\'].*{re.escape(self.test_domain)}',
                rf'window\.location\s*[=\.]\s*["\'].*{re.escape(self.test_domain)}',
                rf'location\.href\s*=\s*["\'].*{re.escape(self.test_domain)}',
            ]
            for pattern in js_redirect_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return (True, f"检测到 JavaScript 重定向到外部地址")

            # 检查 meta 刷新标签
            meta_pattern = (
                rf'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=.*{re.escape(self.test_domain)}'
            )
            if re.search(meta_pattern, response.text, re.IGNORECASE):
                return (True, f"检测到 meta 刷新重定向到外部地址")

        return (False, None)

    def _is_external_redirect(self, location: str) -> bool:
        """判断是否重定向到外部地址

        Args:
            location: Location 头值

        Returns:
            是否是外部重定向
        """
        if not location:
            return False

        # 检查测试域名
        if self.test_domain in location.lower():
            return True

        # 检查协议相对 URL
        if location.startswith("//"):
            return True

        # 检查完整 URL（非当前域名）
        parsed = urlparse(location)
        if parsed.netloc and parsed.netloc != "":
            # 这里简化判断，实际应该比较当前域名
            return True

        return False

    def _classify_redirect_type(self, payload: str) -> str:
        """分类重定向类型

        Args:
            payload: payload

        Returns:
            重定向类型
        """
        if payload.startswith("javascript:"):
            return "javascript_protocol"
        elif payload.startswith("data:"):
            return "data_uri"
        elif payload.startswith("//"):
            return "protocol_relative"
        elif "@" in payload:
            return "url_confusion"
        elif payload.startswith("http://") or payload.startswith("https://"):
            return "absolute_url"
        else:
            return "other"

    def _identify_redirect_params(self, params: Dict[str, str]) -> List[str]:
        """识别重定向参数

        Args:
            params: 参数字典

        Returns:
            重定向参数名列表
        """
        redirect_params = []

        for param_name, value in params.items():
            param_lower = param_name.lower()

            # 检查参数名
            if any(rp in param_lower for rp in self.REDIRECT_PARAMS):
                redirect_params.append(param_name)
                continue

            # 检查值是否像 URL 或路径
            if self._looks_like_redirect(value):
                redirect_params.append(param_name)

        return redirect_params

    def _looks_like_redirect(self, value: str) -> bool:
        """判断值是否像重定向目标

        Args:
            value: 参数值

        Returns:
            是否像重定向目标
        """
        if not value:
            return False

        # 以斜杠开头（相对路径）
        if value.startswith("/"):
            return True

        # URL 格式
        if value.startswith(("http://", "https://", "//")):
            return True

        return False

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads
