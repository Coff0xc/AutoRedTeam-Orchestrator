"""
Host Header Injection 检测器

检测 Host 头注入漏洞，包括:
- 密码重置投毒: 通过注入恶意 Host 影响密码重置链接
- Web 缓存投毒: 通过 Host 头影响缓存内容
- SSRF via Host: 通过 Host 头将请求路由到内部服务
- 访问控制绕过: 通过 Host 头绕过基于 host 的访问控制

技术原理:
1. 应用使用 Host header 生成绝对 URL (如密码重置链接)
2. Web 服务器/反向代理可能将请求路由到 Host 指定的后端
3. 缓存可能基于 Host 缓存不同内容

参考:
- https://portswigger.net/web-security/host-header
- https://portswigger.net/research/practical-host-header-attacks
"""

import hashlib
import logging
import time
from typing import List, Optional
from urllib.parse import urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)


@register_detector("host_header_injection")
class HostHeaderInjectionDetector(BaseDetector):
    """Host Header Injection 检测器

    通过发送含修改 Host 头的请求，检测应用是否信任并使用 Host 头生成内容。

    使用示例:
        detector = HostHeaderInjectionDetector()
        results = detector.detect("https://example.com/")
    """

    name = "host_header_injection"
    description = "Host Header Injection 主机头注入检测器"
    vuln_type = "host_header_injection"
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS
    version = "1.0.0"

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 Host Header Injection 漏洞

        Args:
            url: 目标 URL
            **kwargs: 额外参数

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        parsed = urlparse(url)
        if not parsed.hostname:
            logger.warning("[%s] 无效URL: %s", self.name, url)
            return results

        original_host = parsed.hostname
        nonce = hashlib.md5(f"{url}{time.time()}".encode(), usedforsecurity=False).hexdigest()[:10]

        # 获取基线响应
        baseline_resp = self._safe_request("GET", url)
        if baseline_resp is None:
            return results
        baseline_body = getattr(baseline_resp, "text", "") or ""

        # 1. 直接替换 Host 头
        result = self._test_host_override(url, original_host, nonce, baseline_body)
        if result:
            results.append(result)

        # 2. X-Forwarded-Host 注入
        result = self._test_x_forwarded_host(url, nonce, baseline_body)
        if result:
            results.append(result)

        # 3. 双 Host 头
        result = self._test_duplicate_host(url, original_host, nonce, baseline_body)
        if result:
            results.append(result)

        # 4. Host 头端口注入
        result = self._test_host_port_injection(url, original_host, nonce, baseline_body)
        if result:
            results.append(result)

        # 5. 绝对 URL 覆盖
        result = self._test_absolute_url_override(url, original_host, nonce, baseline_body)
        if result:
            results.append(result)

        self._log_detection_end(url, results)
        return results

    def _test_host_override(
        self,
        url: str,
        _original_host: str,
        nonce: str,
        baseline_body: str,
    ) -> Optional[DetectionResult]:
        """测试直接替换 Host 头"""
        evil_host = f"evil-{nonce}.example.com"

        resp = self._safe_request("GET", url, headers={"Host": evil_host})
        if resp is None:
            return None

        body = getattr(resp, "text", "") or ""
        status = getattr(resp, "status_code", 0)

        if evil_host in body and evil_host not in baseline_body:
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=f"Host: {evil_host}",
                evidence=(
                    f"Host 头注入: 替换 Host 为 '{evil_host}' 后，"
                    f"该值被反射到响应 body 中 (可能用于链接生成)。"
                ),
                confidence=0.85,
                verified=True,
                remediation=self._get_remediation(),
                references=self._get_references(),
                extra={
                    "attack_type": "host_override",
                    "evil_host": evil_host,
                    "status_code": status,
                },
            )
        return None

    def _test_x_forwarded_host(
        self,
        url: str,
        nonce: str,
        baseline_body: str,
    ) -> Optional[DetectionResult]:
        """测试 X-Forwarded-Host 注入"""
        evil_host = f"xfh-{nonce}.example.com"

        forwarded_headers = [
            ("X-Forwarded-Host", evil_host),
            ("X-Host", evil_host),
            ("X-Forwarded-Server", evil_host),
            ("Forwarded", f"host={evil_host}"),
        ]

        for header_name, header_value in forwarded_headers:
            resp = self._safe_request("GET", url, headers={header_name: header_value})
            if resp is None:
                continue

            body = getattr(resp, "text", "") or ""
            status = getattr(resp, "status_code", 0)

            if evil_host in body and evil_host not in baseline_body:
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload=f"{header_name}: {header_value}",
                    evidence=(
                        f"X-Forwarded-Host 注入: {header_name} 设置为 "
                        f"'{evil_host}' 后被反射到响应中。"
                    ),
                    confidence=0.80,
                    verified=True,
                    remediation=self._get_remediation(),
                    references=self._get_references(),
                    extra={
                        "attack_type": "x_forwarded_host",
                        "header_name": header_name,
                        "evil_host": evil_host,
                        "status_code": status,
                    },
                )

        return None

    def _test_duplicate_host(
        self,
        url: str,
        original_host: str,
        nonce: str,
        baseline_body: str,
    ) -> Optional[DetectionResult]:
        """测试双 Host 头注入

        某些代理会传递两个 Host 头，后端可能使用第二个。
        注意: Python requests 库不支持真正的重复 header，
        这里通过 Host header 与 X-Forwarded-Host 组合模拟。
        """
        evil_host = f"dup-{nonce}.example.com"

        # 保持原 Host 但添加覆盖 header
        resp = self._safe_request(
            "GET",
            url,
            headers={
                "X-Forwarded-Host": evil_host,
                "X-Original-Host": original_host,
            },
        )
        if resp is None:
            return None

        body = getattr(resp, "text", "") or ""
        if evil_host in body and evil_host not in baseline_body:
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=f"X-Forwarded-Host: {evil_host} (duplicate host simulation)",
                evidence=(
                    f"双 Host 头注入: 通过 X-Forwarded-Host 覆盖原始 Host，"
                    f"'{evil_host}' 被反射到响应中。"
                ),
                confidence=0.75,
                verified=True,
                remediation=self._get_remediation(),
                references=self._get_references(),
                extra={
                    "attack_type": "duplicate_host",
                    "evil_host": evil_host,
                },
            )
        return None

    def _test_host_port_injection(
        self,
        url: str,
        original_host: str,
        nonce: str,
        baseline_body: str,
    ) -> Optional[DetectionResult]:
        """测试 Host 头端口注入

        在 Host 头中追加端口信息，检查是否被用于 URL 生成。
        """
        evil_port = f"{original_host}:1337/{nonce}"

        resp = self._safe_request("GET", url, headers={"Host": evil_port})
        if resp is None:
            return None

        body = getattr(resp, "text", "") or ""
        if nonce in body and nonce not in baseline_body:
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=f"Host: {evil_port}",
                evidence=(
                    f"Host 端口注入: Host 设置为 '{evil_port}' 后，"
                    f"注入内容被反射到响应中。可用于链接劫持。"
                ),
                confidence=0.70,
                verified=False,
                remediation=self._get_remediation(),
                references=self._get_references(),
                extra={
                    "attack_type": "host_port_injection",
                    "evil_host": evil_port,
                },
            )
        return None

    def _test_absolute_url_override(
        self,
        url: str,
        _original_host: str,
        nonce: str,
        baseline_body: str,
    ) -> Optional[DetectionResult]:
        """测试绝对 URL 覆盖"""
        evil_host = f"abs-{nonce}.example.com"

        resp = self._safe_request(
            "GET",
            url,
            headers={
                "X-Original-URL": f"http://{evil_host}/",
                "X-Rewrite-URL": f"http://{evil_host}/",
            },
        )
        if resp is None:
            return None

        body = getattr(resp, "text", "") or ""
        status = getattr(resp, "status_code", 0)

        if evil_host in body and evil_host not in baseline_body:
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=f"X-Original-URL: http://{evil_host}/",
                evidence=(
                    f"URL 覆盖注入: X-Original-URL/X-Rewrite-URL 中的 "
                    f"'{evil_host}' 被反射到响应中。"
                ),
                confidence=0.75,
                verified=True,
                remediation=self._get_remediation(),
                references=self._get_references(),
                extra={
                    "attack_type": "absolute_url_override",
                    "evil_host": evil_host,
                    "status_code": status,
                },
            )
        return None

    @staticmethod
    def _get_remediation() -> str:
        return (
            "1. 不要信任 Host header 来生成 URL，使用配置中的固定域名\n"
            "2. 配置 Web 服务器验证 Host 头，拒绝非预期的 Host 值\n"
            "3. 忽略 X-Forwarded-Host 等代理 header (除非来自可信代理)\n"
            "4. 使用 allowlist 限制有效的 Host 值\n"
            "5. 在 Nginx/Apache 中配置 server_name 严格匹配"
        )

    @staticmethod
    def _get_references() -> list:
        return [
            "https://portswigger.net/web-security/host-header",
            "https://cwe.mitre.org/data/definitions/644.html",
        ]
