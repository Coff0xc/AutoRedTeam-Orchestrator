"""
Web Cache Poisoning 检测器

检测 Web 缓存投毒漏洞，包括:
- Unkeyed Header 投毒: 利用缓存不跟踪的请求头注入恶意内容
- Unkeyed Query Parameter 投毒: 利用缓存忽略的查询参数
- Fat GET 投毒: 在 GET 请求中附加 body 影响响应
- Cache Key 规范化差异: 前端/缓存对 URL 编码处理不一致

技术原理:
1. 缓存以 cache key (通常是 Host + Path + 部分参数) 标识响应
2. 如果某些输入影响响应但不在 cache key 中 → 可投毒
3. 攻击者发送含恶意 header 的请求 → 响应被缓存 → 其他用户命中被投毒的缓存

参考:
- https://portswigger.net/research/practical-web-cache-poisoning
- James Kettle, "Web Cache Entanglement" (2020)
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

# 用于测试 unkeyed header 的候选 header 列表
# 这些 header 常被缓存忽略但可能影响后端响应
UNKEYED_HEADERS = [
    ("X-Forwarded-Host", "cache-poison-{nonce}.example.com"),
    ("X-Forwarded-Scheme", "nothttps"),
    ("X-Forwarded-Proto", "nothttps"),
    ("X-Original-URL", "/{nonce}"),
    ("X-Rewrite-URL", "/{nonce}"),
    ("X-Forwarded-Port", "1337"),
    ("X-Host", "cache-poison-{nonce}.example.com"),
    ("X-Forwarded-Server", "cache-poison-{nonce}.example.com"),
    ("X-HTTP-Method-Override", "POST"),
    ("X-Amz-Website-Redirect-Location", "https://evil.com/{nonce}"),
    ("Fastly-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
]

# 用于检测缓存行为的参数
CACHE_BUSTER_PARAM = "_cb"


@register_detector("cache_poisoning")
class CachePoisoningDetector(BaseDetector):
    """Web Cache Poisoning 检测器

    通过发送含 unkeyed header 的请求，检测响应是否被缓存投毒。
    使用安全的检测方法：仅使用无害的 nonce 值验证反射，不注入恶意代码。

    使用示例:
        detector = CachePoisoningDetector()
        results = detector.detect("https://example.com")
    """

    name = "cache_poisoning"
    description = "Web Cache Poisoning 缓存投毒检测器"
    vuln_type = "cache_poisoning"
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS
    version = "1.0.0"

    # 缓存探测重试次数
    CACHE_PROBE_RETRIES = 3
    # 两次请求之间的间隔 (秒)
    PROBE_DELAY = 0.5

    def detect(self, url: str, **_kwargs) -> List[DetectionResult]:
        """检测 Web Cache Poisoning 漏洞

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

        # 生成本次检测的唯一 nonce
        nonce = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12]

        # 1. 检测是否存在缓存层
        has_cache = self._detect_cache_layer(url)
        if not has_cache:
            logger.info("[%s] 未检测到缓存层: %s", self.name, url)
            # 即使没检测到缓存层也继续，因为可能有隐式缓存

        # 2. Unkeyed Header 投毒检测
        header_results = self._detect_unkeyed_headers(url, nonce)
        results.extend(header_results)

        # 3. Unkeyed Query Parameter 检测
        param_result = self._detect_unkeyed_params(url, nonce)
        if param_result:
            results.append(param_result)

        # 4. Fat GET 检测
        fat_get_result = self._detect_fat_get(url, nonce)
        if fat_get_result:
            results.append(fat_get_result)

        self._log_detection_end(url, results)
        return results

    def _generate_cache_buster(self) -> str:
        """生成唯一的 cache buster 参数值"""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def _add_cache_buster(self, url: str) -> str:
        """给 URL 添加 cache buster 参数以避免命中已有缓存"""
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{CACHE_BUSTER_PARAM}={self._generate_cache_buster()}"

    def _detect_cache_layer(self, url: str) -> bool:
        """检测目标是否存在缓存层

        通过发送两次相同请求，比较响应头中的缓存指示来判断。
        """
        test_url = self._add_cache_buster(url)

        # 第一次请求 (可能是 MISS)
        resp1 = self._safe_request("GET", test_url)
        if resp1 is None:
            return False

        headers1 = {k.lower(): v for k, v in resp1.headers.items()} if resp1.headers else {}

        # 缓存指示 header
        cache_indicators = [
            "x-cache",
            "cf-cache-status",
            "x-cache-status",
            "x-varnish",
            "x-drupal-cache",
            "x-proxy-cache",
            "x-fastly-request-id",
            "x-served-by",
            "age",
            "x-cdn",
            "via",
        ]

        for indicator in cache_indicators:
            if indicator in headers1:
                logger.info("[%s] 发现缓存指示: %s=%s", self.name, indicator, headers1[indicator])
                return True

        # 检查 Cache-Control
        cc = headers1.get("cache-control", "")
        if any(d in cc for d in ["max-age=", "s-maxage=", "public"]):
            return True

        # 第二次请求，检查是否有 HIT
        time.sleep(self.PROBE_DELAY)
        resp2 = self._safe_request("GET", test_url)
        if resp2 is None:
            return False

        headers2 = {k.lower(): v for k, v in resp2.headers.items()} if resp2.headers else {}
        x_cache = headers2.get("x-cache", "").upper()
        cf_cache = headers2.get("cf-cache-status", "").upper()

        if "HIT" in x_cache or "HIT" in cf_cache:
            return True

        # 检查 Age header 是否增加
        age1 = headers1.get("age", "0")
        age2 = headers2.get("age", "0")
        try:
            if int(age2) > int(age1):
                return True
        except (ValueError, TypeError):
            pass

        return False

    def _detect_unkeyed_headers(self, url: str, nonce: str) -> List[DetectionResult]:
        """检测 Unkeyed Header 投毒

        对每个候选 header，发送含该 header 的请求，检查 nonce 是否在响应中反射。
        如果反射存在，再发送不含该 header 的请求验证缓存是否被投毒。
        """
        results = []

        for header_name, header_template in UNKEYED_HEADERS:
            header_value = header_template.format(nonce=nonce)
            cb = self._generate_cache_buster()
            test_url = f"{url}{'&' if '?' in url else '?'}{CACHE_BUSTER_PARAM}={cb}"

            # 步骤1: 带 unkeyed header 发送请求（投毒请求）
            resp = self._safe_request("GET", test_url, headers={header_name: header_value})
            if resp is None:
                continue

            body = getattr(resp, "text", "") or ""
            status = getattr(resp, "status_code", 0)

            # 检查 nonce 是否在响应中反射
            if nonce not in body:
                continue

            logger.info(
                "[%s] Header %s 的值在响应中反射，验证缓存投毒...",
                self.name,
                header_name,
            )

            # 步骤2: 不带该 header 再次请求同一 URL（验证缓存是否被投毒）
            time.sleep(self.PROBE_DELAY)
            verify_resp = self._safe_request("GET", test_url)
            if verify_resp is None:
                continue

            verify_body = getattr(verify_resp, "text", "") or ""

            # 如果不带 header 的请求也返回了包含 nonce 的响应 → 缓存已被投毒
            if nonce in verify_body:
                confidence = 0.85
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=f"{header_name}: {header_value}",
                        evidence=(
                            f"Unkeyed Header 投毒: {header_name} 的值 "
                            f"'{header_value}' 被反射并缓存。"
                            f"验证请求(无该header)也返回了投毒内容。"
                        ),
                        confidence=confidence,
                        verified=True,
                        remediation=(
                            "1. 将影响响应的所有 header 加入 cache key (Vary header)\n"
                            "2. 过滤/忽略非标准 header (X-Forwarded-Host 等)\n"
                            "3. 使用 Cache-Control: private 避免共享缓存\n"
                            "4. 配置 CDN/缓存层的 cache key 策略"
                        ),
                        references=[
                            "https://portswigger.net/research/practical-web-cache-poisoning",
                            "https://cwe.mitre.org/data/definitions/444.html",
                        ],
                        extra={
                            "poison_type": "unkeyed_header",
                            "header_name": header_name,
                            "header_value": header_value,
                            "cached": True,
                            "status_code": status,
                        },
                    )
                )
            else:
                # nonce 反射但未被缓存 — 仍有风险 (header 注入)
                confidence = 0.50
                results.append(
                    self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=f"{header_name}: {header_value}",
                        evidence=(
                            f"Header 反射: {header_name} 的值被反射到响应中，"
                            f"但未确认被缓存。存在潜在缓存投毒风险。"
                        ),
                        confidence=confidence,
                        verified=False,
                        remediation=(
                            "1. 过滤/清理 X-Forwarded-* 等 header 的值\n"
                            "2. 确保 Vary header 包含所有影响响应的请求头\n"
                            "3. 对反射内容进行 HTML 编码"
                        ),
                        references=[
                            "https://portswigger.net/research/practical-web-cache-poisoning",
                        ],
                        extra={
                            "poison_type": "header_reflection",
                            "header_name": header_name,
                            "header_value": header_value,
                            "cached": False,
                            "status_code": status,
                        },
                    )
                )

        return results

    def _detect_unkeyed_params(self, url: str, nonce: str) -> Optional[DetectionResult]:
        """检测 Unkeyed Query Parameter 投毒

        某些缓存可能忽略特定查询参数（如 UTM 参数），
        但后端仍然处理它们并影响响应。
        """
        # 常见被缓存忽略的参数
        unkeyed_params = [
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_content",
            "utm_term",
            "fbclid",
            "gclid",
            "mc_cid",
            "mc_eid",
            "msclkid",
            "_ga",
            "ref",
            "callback",
        ]

        for param_name in unkeyed_params:
            cb = self._generate_cache_buster()
            base_url = f"{url}{'&' if '?' in url else '?'}{CACHE_BUSTER_PARAM}={cb}"

            # 带参数请求
            test_url = f"{base_url}&{param_name}={nonce}"
            resp = self._safe_request("GET", test_url)
            if resp is None:
                continue

            body = getattr(resp, "text", "") or ""
            if nonce not in body:
                continue

            # 验证: 不带该参数请求同一 cache key
            time.sleep(self.PROBE_DELAY)
            verify_resp = self._safe_request("GET", base_url)
            if verify_resp is None:
                continue

            verify_body = getattr(verify_resp, "text", "") or ""
            if nonce in verify_body:
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    param=param_name,
                    payload=f"{param_name}={nonce}",
                    evidence=(
                        f"Unkeyed Parameter 投毒: 参数 '{param_name}' "
                        f"的值被反射并缓存。验证请求(无该参数)也返回了投毒内容。"
                    ),
                    confidence=0.80,
                    verified=True,
                    remediation=(
                        "1. 将所有影响响应的参数加入 cache key\n"
                        "2. 配置缓存忽略参数时确保后端也忽略\n"
                        "3. 对反射内容进行编码/过滤"
                    ),
                    references=[
                        "https://portswigger.net/research/practical-web-cache-poisoning",
                    ],
                    extra={
                        "poison_type": "unkeyed_param",
                        "param_name": param_name,
                        "cached": True,
                    },
                )

        return None

    def _detect_fat_get(self, url: str, nonce: str) -> Optional[DetectionResult]:
        """检测 Fat GET 投毒

        某些框架允许 GET 请求携带 body，如果 body 内容影响响应但不在 cache key 中，
        则可以通过 Fat GET 投毒缓存。
        """
        cb = self._generate_cache_buster()
        test_url = f"{url}{'&' if '?' in url else '?'}{CACHE_BUSTER_PARAM}={cb}"

        # 发送带 body 的 GET 请求
        # 一些框架会从 body 中解析参数（如 Rails, Express）
        # 尝试在 body 中覆盖 URL 中的参数
        body_data = f"callback={nonce}&_method=GET"
        resp = self._safe_request(
            "GET",
            test_url,
            data=body_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp is None:
            return None

        body = getattr(resp, "text", "") or ""
        if nonce not in body:
            return None

        # 验证缓存
        time.sleep(self.PROBE_DELAY)
        verify_resp = self._safe_request("GET", test_url)
        if verify_resp is None:
            return None

        verify_body = getattr(verify_resp, "text", "") or ""
        if nonce in verify_body:
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=f"GET body: {body_data}",
                evidence=(
                    "Fat GET 投毒: GET 请求的 body 内容被反射并缓存。"
                    "正常 GET 请求也返回了投毒内容。"
                ),
                confidence=0.75,
                verified=True,
                remediation=(
                    "1. 禁止 GET 请求解析 body 内容\n"
                    "2. 配置 Web 框架忽略 GET 请求的 body\n"
                    "3. 在缓存层拒绝带 body 的 GET 请求"
                ),
                references=[
                    "https://portswigger.net/research/web-cache-entanglement",
                ],
                extra={
                    "poison_type": "fat_get",
                    "body_data": body_data,
                    "cached": True,
                },
            )

        return None
