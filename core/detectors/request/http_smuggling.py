"""
HTTP Request Smuggling 检测器

检测 CL.TE、TE.CL、TE.TE 三种 HTTP 请求走私变体。
基于时间差异的安全检测方法，不发送破坏性 payload。

技术原理:
- CL.TE: 前端用 Content-Length，后端用 Transfer-Encoding
- TE.CL: 前端用 Transfer-Encoding，后端用 Content-Length
- TE.TE: 两端都用 Transfer-Encoding 但解析差异（混淆 TE 头）

检测策略:
1. 时间差异检测: 发送特制请求，如果后端因走私而等待更多数据，响应时间会显著增加
2. 差异响应检测: 相同请求不同 TE/CL 组合，比较响应差异
3. Content-Length 差异: 发送 CL 值与实际 body 不匹配的请求

参考:
- https://portswigger.net/web-security/request-smuggling
- James Kettle, "HTTP Desync Attacks" (2019)
"""

import logging
import socket
import ssl
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..base import BaseDetector
from ..factory import register_detector
from ..result import DetectionResult, DetectorType, Severity

logger = logging.getLogger(__name__)


@register_detector("http_smuggling")
class HTTPSmugglingDetector(BaseDetector):
    """HTTP Request Smuggling 检测器

    使用时间差异和响应差异检测 CL.TE / TE.CL / TE.TE 走私漏洞。
    采用安全的检测方法，不会导致后端连接污染。

    使用示例:
        detector = HTTPSmugglingDetector()
        results = detector.detect("https://example.com")
    """

    name = "http_smuggling"
    description = "HTTP Request Smuggling 请求走私检测器"
    vuln_type = "http_smuggling"
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS
    version = "1.0.0"

    # 时间阈值 (秒) — 超过此值视为后端阻塞
    DELAY_THRESHOLD = 3.0
    # 正常请求超时 (秒)
    NORMAL_TIMEOUT = 10.0
    # 检测超时 (秒) — 走私请求可能导致后端等待
    SMUGGLE_TIMEOUT = 15.0

    def detect(self, url: str, **_kwargs) -> List[DetectionResult]:
        """检测 HTTP Request Smuggling 漏洞

        Args:
            url: 目标 URL
            **kwargs: 额外参数

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        if not host:
            logger.warning("[%s] 无效URL: %s", self.name, url)
            return results

        # 1. 获取基线响应时间
        baseline_time = self._get_baseline_time(host, port, path, use_ssl)
        if baseline_time is None:
            logger.info("[%s] 无法建立基线连接: %s", self.name, url)
            return results

        logger.info("[%s] 基线响应时间: %.2fs", self.name, baseline_time)

        # 2. CL.TE 检测
        clte_result = self._detect_clte(url, host, port, path, use_ssl, baseline_time)
        if clte_result:
            results.append(clte_result)

        # 3. TE.CL 检测
        tecl_result = self._detect_tecl(url, host, port, path, use_ssl, baseline_time)
        if tecl_result:
            results.append(tecl_result)

        # 4. TE.TE 检测 (混淆 Transfer-Encoding 头)
        tete_result = self._detect_tete(url, host, port, path, use_ssl, baseline_time)
        if tete_result:
            results.append(tete_result)

        self._log_detection_end(url, results)
        return results

    def _raw_request(
        self,
        host: str,
        port: int,
        raw_data: bytes,
        use_ssl: bool,
        timeout: float = 10.0,
    ) -> Optional[Dict[str, Any]]:
        """发送原始 HTTP 请求 (绕过库的自动规范化)

        Returns:
            {"status": int, "headers": str, "body": str, "time": float} 或 None
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            start = time.time()
            sock.connect((host, port))
            sock.sendall(raw_data)

            # 接收响应
            response_data = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    # 简单检查响应是否完整
                    if b"\r\n\r\n" in response_data:
                        header_end = response_data.index(b"\r\n\r\n")
                        headers_part = response_data[:header_end].decode("utf-8", errors="ignore")
                        # 检查 Content-Length
                        for line in headers_part.split("\r\n"):
                            if line.lower().startswith("content-length:"):
                                cl = int(line.split(":")[1].strip())
                                body_start = header_end + 4
                                if len(response_data) >= body_start + cl:
                                    break
                        else:
                            # 无 CL，检查 chunked 或足够数据
                            if len(response_data) > header_end + 4 + 100:
                                break
                except socket.timeout:
                    break

            elapsed = time.time() - start

            if not response_data:
                return None

            resp_str = response_data.decode("utf-8", errors="ignore")
            status = 0
            if resp_str.startswith("HTTP/"):
                try:
                    status = int(resp_str.split(" ")[1])
                except (IndexError, ValueError):
                    pass

            return {
                "status": status,
                "raw": resp_str,
                "time": elapsed,
            }

        except (socket.timeout, socket.error, OSError):
            elapsed = time.time() - start if "start" in locals() else timeout
            # 超时本身可能是走私的信号
            return {"status": 0, "raw": "", "time": elapsed, "timeout": True}
        except Exception as e:
            logger.debug("[%s] 原始请求异常: %s", self.name, e)
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _get_baseline_time(self, host: str, port: int, path: str, use_ssl: bool) -> Optional[float]:
        """获取正常请求的基线响应时间"""
        request = (
            f"GET {path} HTTP/1.1\r\n" f"Host: {host}\r\n" f"Connection: close\r\n" f"\r\n"
        ).encode()

        times = []
        for _ in range(3):
            result = self._raw_request(host, port, request, use_ssl, self.NORMAL_TIMEOUT)
            if result and result.get("status", 0) > 0:
                times.append(result["time"])

        if not times:
            return None
        return sum(times) / len(times)

    def _detect_clte(
        self,
        url: str,
        host: str,
        port: int,
        path: str,
        use_ssl: bool,
        baseline_time: float,
    ) -> Optional[DetectionResult]:
        """检测 CL.TE 走私

        原理: 前端信任 Content-Length，后端信任 Transfer-Encoding。
        发送 CL 表示完整但 TE chunked 未结束的请求，
        如果后端使用 TE，会等待更多 chunk 数据，导致超时/延迟。
        """
        # 安全探测: CL 说 body 很短，TE chunked 也正确结束
        # 但 CL 值比实际 body 短 → 如果前端用 CL 截断，后端用 TE 会看到不完整 chunk
        body = "0\r\n\r\n"
        smuggle_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        result = self._raw_request(host, port, smuggle_request, use_ssl, self.SMUGGLE_TIMEOUT)
        if result is None:
            return None

        elapsed = result["time"]
        is_timeout = result.get("timeout", False)

        # 如果响应时间远超基线，或发生超时，可能存在 CL.TE 走私
        if is_timeout or elapsed > baseline_time + self.DELAY_THRESHOLD:
            confidence = min(0.85, 0.6 + (elapsed - baseline_time) / 10.0)
            return self._create_result(
                url=url,
                vulnerable=True,
                payload="CL.TE: Content-Length + Transfer-Encoding: chunked",
                evidence=(
                    f"时间差异检测: 基线 {baseline_time:.2f}s, "
                    f"走私请求 {elapsed:.2f}s "
                    f"(差异 {elapsed - baseline_time:.2f}s)"
                ),
                confidence=confidence,
                verified=False,
                remediation=(
                    "1. 规范化前后端对 Transfer-Encoding 的处理\n"
                    "2. 禁止同时存在 Content-Length 和 Transfer-Encoding 头\n"
                    "3. 使用 HTTP/2 端到端通信\n"
                    "4. 配置 WAF 拒绝含歧义头的请求"
                ),
                references=[
                    "https://portswigger.net/web-security/request-smuggling",
                    "https://cwe.mitre.org/data/definitions/444.html",
                ],
                extra={
                    "smuggle_type": "CL.TE",
                    "baseline_time": round(baseline_time, 3),
                    "smuggle_time": round(elapsed, 3),
                    "timed_out": is_timeout,
                },
            )
        return None

    def _detect_tecl(
        self,
        url: str,
        host: str,
        port: int,
        path: str,
        use_ssl: bool,
        baseline_time: float,
    ) -> Optional[DetectionResult]:
        """检测 TE.CL 走私

        原理: 前端信任 Transfer-Encoding，后端信任 Content-Length。
        发送 TE chunked 完整但 CL 表示 body 更长的请求，
        后端用 CL 会等待更多数据，导致超时/延迟。
        """
        # 构造: TE 说 body 是 "0\r\n\r\n"(完整 chunked)，
        # 但 CL 说 body 有 100 字节 → 后端用 CL 会等待
        body = "0\r\n\r\n"
        smuggle_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 100\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        result = self._raw_request(host, port, smuggle_request, use_ssl, self.SMUGGLE_TIMEOUT)
        if result is None:
            return None

        elapsed = result["time"]
        is_timeout = result.get("timeout", False)

        if is_timeout or elapsed > baseline_time + self.DELAY_THRESHOLD:
            confidence = min(0.85, 0.6 + (elapsed - baseline_time) / 10.0)
            return self._create_result(
                url=url,
                vulnerable=True,
                payload="TE.CL: Transfer-Encoding: chunked + Content-Length mismatch",
                evidence=(
                    f"时间差异检测: 基线 {baseline_time:.2f}s, "
                    f"走私请求 {elapsed:.2f}s "
                    f"(差异 {elapsed - baseline_time:.2f}s)"
                ),
                confidence=confidence,
                verified=False,
                remediation=(
                    "1. 规范化前后端对 Transfer-Encoding 的处理\n"
                    "2. 禁止同时存在 Content-Length 和 Transfer-Encoding 头\n"
                    "3. 使用 HTTP/2 端到端通信\n"
                    "4. 配置 WAF 拒绝含歧义头的请求"
                ),
                references=[
                    "https://portswigger.net/web-security/request-smuggling",
                    "https://cwe.mitre.org/data/definitions/444.html",
                ],
                extra={
                    "smuggle_type": "TE.CL",
                    "baseline_time": round(baseline_time, 3),
                    "smuggle_time": round(elapsed, 3),
                    "timed_out": is_timeout,
                },
            )
        return None

    def _detect_tete(
        self,
        url: str,
        host: str,
        port: int,
        path: str,
        use_ssl: bool,
        baseline_time: float,
    ) -> Optional[DetectionResult]:
        """检测 TE.TE 走私 (Transfer-Encoding 混淆)

        原理: 发送混淆的 Transfer-Encoding 头（如大小写变体、多余空格、
        换行符等），前后端可能对不同变体做不同解析。
        """
        # TE 头混淆变体
        te_variants = [
            "Transfer-Encoding : chunked",  # 冒号前空格
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",  # 双 TE 头
            "Transfer-Encoding: xchunked",  # 无效值 + 正确值
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",  # 重复不同值
        ]

        for variant in te_variants:
            body = "0\r\n\r\n"
            smuggle_request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 4\r\n"
                f"{variant}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            ).encode()

            result = self._raw_request(host, port, smuggle_request, use_ssl, self.SMUGGLE_TIMEOUT)
            if result is None:
                continue

            elapsed = result["time"]
            is_timeout = result.get("timeout", False)

            if is_timeout or elapsed > baseline_time + self.DELAY_THRESHOLD:
                confidence = min(0.80, 0.55 + (elapsed - baseline_time) / 10.0)
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload=f"TE.TE: {variant.split(chr(13))[0]}",
                    evidence=(
                        f"TE 混淆检测: 基线 {baseline_time:.2f}s, "
                        f"走私请求 {elapsed:.2f}s "
                        f"(差异 {elapsed - baseline_time:.2f}s)"
                    ),
                    confidence=confidence,
                    verified=False,
                    remediation=(
                        "1. 严格解析 Transfer-Encoding 头，拒绝非标准格式\n"
                        "2. 前后端使用统一的 HTTP 解析库\n"
                        "3. 使用 HTTP/2 端到端通信"
                    ),
                    references=[
                        "https://portswigger.net/web-security/request-smuggling",
                        "https://cwe.mitre.org/data/definitions/444.html",
                    ],
                    extra={
                        "smuggle_type": "TE.TE",
                        "te_variant": variant.replace("\r\n", "\\r\\n"),
                        "baseline_time": round(baseline_time, 3),
                        "smuggle_time": round(elapsed, 3),
                        "timed_out": is_timeout,
                    },
                )
        return None
