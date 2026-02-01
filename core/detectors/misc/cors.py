"""
CORS 配置检测器

检测跨域资源共享的安全配置问题
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)


@register_detector("cors")
class CORSDetector(BaseDetector):
    """CORS 配置检测器

    检测 CORS 配置问题:
    - 通配符 Origin
    - 任意 Origin 反射
    - Null Origin 允许
    - 凭证配置问题
    - 子域名绕过

    使用示例:
        detector = CORSDetector()
        results = detector.detect("https://api.example.com/users")
    """

    name = "cors"
    description = "CORS 跨域配置检测器"
    vuln_type = "cors_misconfiguration"
    severity = Severity.MEDIUM
    detector_type = DetectorType.MISC
    version = "1.0.0"

    # 测试 Origin 列表
    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://evil.{domain}",
        "https://{domain}.evil.com",
        "https://{subdomain}.{domain}",
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - test_origins: 自定义测试 Origin 列表
                - check_credentials: 是否检测凭证配置
        """
        super().__init__(config)

        custom_origins = self.config.get("test_origins", [])
        self.test_origins = list(self.TEST_ORIGINS) + custom_origins
        self.check_credentials = self.config.get("check_credentials", True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 CORS 配置问题

        Args:
            url: 目标 URL
            **kwargs:
                headers: 请求头
                method: HTTP 方法

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        headers = kwargs.get("headers", {})
        parsed = urlparse(url)
        domain = parsed.netloc

        # 测试通配符 CORS
        wildcard_result = self._test_wildcard_cors(url, headers)
        if wildcard_result:
            results.append(wildcard_result)

        # 测试 Origin 反射
        reflection_result = self._test_origin_reflection(url, headers)
        if reflection_result:
            results.append(reflection_result)

        # 测试 Null Origin
        null_result = self._test_null_origin(url, headers)
        if null_result:
            results.append(null_result)

        # 测试子域名绕过
        subdomain_result = self._test_subdomain_bypass(url, domain, headers)
        if subdomain_result:
            results.append(subdomain_result)

        # 测试凭证配置
        if self.check_credentials and results:
            credential_results = self._test_credentials_exposure(url, headers, results)
            results.extend(credential_results)

        self._log_detection_end(url, results)
        return results

    def _test_wildcard_cors(self, url: str, headers: Dict[str, str]) -> Optional[DetectionResult]:
        """测试通配符 CORS

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        try:
            response = self.http_client.get(url, headers=headers)

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                severity = Severity.MEDIUM
                evidence = "CORS 配置允许任意 Origin (*)"

                # 如果同时允许凭证，严重程度提升
                if acac.lower() == "true":
                    severity = Severity.HIGH
                    evidence += "，且允许发送凭证"

                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload="Origin: *",
                    evidence=evidence,
                    confidence=0.95,
                    verified=True,
                    remediation="使用白名单而非通配符配置允许的 Origin",
                    extra={"cors_type": "wildcard", "acao": acao, "acac": acac},
                )

        except Exception as e:
            logger.debug(f"通配符 CORS 测试失败: {e}")

        return None

    def _test_origin_reflection(
        self, url: str, headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试 Origin 反射

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        test_origin = "https://evil.com"
        test_headers = headers.copy()
        test_headers["Origin"] = test_origin

        try:
            response = self.http_client.get(url, headers=test_headers)

            acao = response.headers.get("Access-Control-Allow-Origin", "")

            if acao == test_origin:
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload=f"Origin: {test_origin}",
                    evidence=f"服务器反射任意 Origin: {acao}",
                    confidence=0.90,
                    verified=True,
                    remediation="验证 Origin 头而非直接反射",
                    references=["https://portswigger.net/web-security/cors"],
                    extra={"cors_type": "reflection", "reflected_origin": acao},
                )

        except Exception as e:
            logger.debug(f"Origin 反射测试失败: {e}")

        return None

    def _test_null_origin(self, url: str, headers: Dict[str, str]) -> Optional[DetectionResult]:
        """测试 Null Origin

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        test_headers = headers.copy()
        test_headers["Origin"] = "null"

        try:
            response = self.http_client.get(url, headers=test_headers)

            acao = response.headers.get("Access-Control-Allow-Origin", "")

            if acao == "null":
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload="Origin: null",
                    evidence="服务器接受 null Origin",
                    confidence=0.85,
                    verified=True,
                    remediation="不要在白名单中包含 null Origin",
                    extra={"cors_type": "null_origin"},
                )

        except Exception as e:
            logger.debug(f"Null Origin 测试失败: {e}")

        return None

    def _test_subdomain_bypass(
        self, url: str, domain: str, headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试子域名绕过

        Args:
            url: 目标 URL
            domain: 目标域名
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 提取基础域名
        parts = domain.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])
        else:
            base_domain = domain

        bypass_origins = [
            f"https://evil.{base_domain}",
            f"https://{base_domain}.evil.com",
            f"https://attack.{base_domain}",
        ]

        for test_origin in bypass_origins:
            test_headers = headers.copy()
            test_headers["Origin"] = test_origin

            try:
                response = self.http_client.get(url, headers=test_headers)

                acao = response.headers.get("Access-Control-Allow-Origin", "")

                if acao == test_origin:
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=f"Origin: {test_origin}",
                        evidence=f"子域名绕过成功: {acao}",
                        confidence=0.85,
                        verified=True,
                        remediation="使用严格的 Origin 白名单验证",
                        extra={"cors_type": "subdomain_bypass", "bypass_origin": test_origin},
                    )

            except Exception as e:
                logger.debug(f"子域名绕过测试失败: {e}")

        return None

    def _test_credentials_exposure(
        self, url: str, headers: Dict[str, str], existing_results: List[DetectionResult]
    ) -> List[DetectionResult]:
        """测试凭证暴露风险

        Args:
            url: 目标 URL
            headers: 请求头
            existing_results: 已发现的 CORS 问题

        Returns:
            检测结果列表
        """
        results = []

        for result in existing_results:
            if result.extra.get("cors_type") in ("reflection", "subdomain_bypass", "null_origin"):
                # 使用相同的恶意 Origin 测试凭证
                test_origin = result.payload.replace("Origin: ", "")
                test_headers = headers.copy()
                test_headers["Origin"] = test_origin

                try:
                    response = self.http_client.get(url, headers=test_headers)
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")

                    if acac.lower() == "true":
                        results.append(
                            self._create_result(
                                url=url,
                                vulnerable=True,
                                payload=result.payload,
                                evidence=f"CORS 配置允许凭证发送到恶意 Origin",
                                confidence=0.95,
                                verified=True,
                                remediation="当允许凭证时，必须严格验证 Origin",
                                extra={
                                    "cors_type": "credentials_exposure",
                                    "origin": test_origin,
                                    "acac": acac,
                                },
                            )
                        )
                        result.severity = Severity.HIGH

                except Exception as e:
                    logger.debug(f"凭证暴露测试失败: {e}")

        return results

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.test_origins
