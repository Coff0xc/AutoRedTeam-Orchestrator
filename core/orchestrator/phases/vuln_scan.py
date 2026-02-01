#!/usr/bin/env python3
"""
phases/vuln_scan.py - 漏洞扫描阶段执行器

负责漏洞扫描与检测，包括误报过滤和统计验证。
"""

import asyncio
import ipaddress
import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .base import BasePhaseExecutor, PhaseResult

# SSRF 防护常量
_ALLOWED_SCHEMES = frozenset(("http", "https"))
_BLOCKED_IP_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918 Class A
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918 Class B
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918 Class C
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
)

if TYPE_CHECKING:
    from core.detectors.false_positive_filter import FalsePositiveFilter, ResponseBaseline
    from core.detectors.result import DetectionResult
    from core.http.client import HTTPClient
    from modules.vuln_verifier import StatisticalVerifier

    from ..state import PentestPhase, PentestState

logger = logging.getLogger(__name__)


class VulnScanPhaseExecutor(BasePhaseExecutor):
    """漏洞扫描阶段执行器"""

    name = "vuln_scan"
    description = "漏洞扫描与检测"

    @property
    def phase(self):
        from ..state import PentestPhase

        return PentestPhase.VULN_SCAN

    @property
    def required_phases(self):
        from ..state import PentestPhase

        return (PentestPhase.RECON,)

    async def execute(self) -> PhaseResult:
        from ..state import PentestPhase

        errors: List[str] = []
        findings: List[Dict[str, Any]] = []

        try:
            from core.detectors import DetectorFactory
            from core.detectors.false_positive_filter import FalsePositiveFilter
            from core.evasion import normalize_waf_type
            from core.http import HTTPClient, HTTPConfig
            from modules.vuln_verifier import StatisticalVerifier

            targets = self._get_scan_targets()
            detector_types = self.config.get(
                "detectors",
                [
                    "sqli",
                    "xss",
                    "ssrf",
                    "ssti",
                    "xxe",
                    "rce",
                    "path_traversal",
                    "idor",
                    "open_redirect",
                ],
            )

            waf_name = self.state.recon_data.get("waf_detected")
            waf_type = normalize_waf_type(waf_name)

            detector_config = {
                "timeout": self.config.get("timeout", 30),
                "verify_ssl": self.config.get("verify_ssl", False),
                "follow_redirects": self.config.get("follow_redirects", True),
                "enable_smart_payload": self.config.get("enable_smart_payload", True),
                "smart_payload_source": self.config.get("smart_payload_source", "adaptive"),
                "waf_type": waf_type.value if waf_type else None,
                "max_payload_variants": self.config.get("max_payload_variants"),
            }
            detector_config = {k: v for k, v in detector_config.items() if v is not None}

            detector = DetectorFactory.create_composite(detector_types, detector_config)

            enable_fp_filter = self.config.get("enable_false_positive_filter", True)
            enable_verifier = self.config.get("enable_verifier", True)
            verifier_rounds = self._clamp_config_int("verification_rounds", 3, 1, 10)
            baseline_requests = self._clamp_config_int("baseline_requests", 3, 1, 10)

            http_config = HTTPConfig()
            http_config.timeout = self.config.get("timeout", 30)
            http_config.verify_ssl = self.config.get("verify_ssl", False)
            http_config.follow_redirects = self.config.get("follow_redirects", True)
            http_client = HTTPClient(config=http_config)

            fp_filter = FalsePositiveFilter() if enable_fp_filter else None
            verifier = StatisticalVerifier() if enable_verifier else None

            def _baseline_request(url: str):
                resp = http_client.get(url)
                return resp.text, resp.status_code, resp.elapsed, resp.headers

            for idx, target_url in enumerate(targets):
                self.state.add_checkpoint(step=idx, data={"current_target": target_url})

                try:
                    baseline = None
                    if fp_filter:
                        try:
                            baseline = fp_filter.establish_baseline(
                                target_url, _baseline_request, num_requests=baseline_requests
                            )
                        except (OSError, ConnectionError) as e:
                            self.logger.debug(f"基线构建失败 {target_url}: {e}")

                    results = await detector.async_detect(target_url)

                    for result in results:
                        if result.vulnerable:
                            fp_result = None
                            if fp_filter and baseline:
                                fp_result = self._apply_false_positive_filter(
                                    fp_filter, baseline, http_client, result
                                )
                                if fp_result and fp_result.is_false_positive:
                                    continue

                            verification = None
                            if (
                                verifier
                                and result.param
                                and (not result.verified or result.confidence < 0.9)
                            ):
                                verification = await self._apply_statistical_verification(
                                    verifier, result, rounds=verifier_rounds
                                )
                                if verification.get("filtered_out"):
                                    continue
                                if verification.get("confirmed"):
                                    result.verified = True
                                    result.confidence = max(
                                        result.confidence, verification.get("confidence_score", 0.0)
                                    )

                            cve_id = self._extract_cve_id(result)
                            finding = {
                                "type": result.vuln_type,
                                "severity": (
                                    result.severity.value
                                    if hasattr(result.severity, "value")
                                    else str(result.severity)
                                ),
                                "title": f"{result.vuln_type.upper()} 漏洞",
                                "url": result.url,
                                "param": result.param,
                                "payload": result.payload,
                                "evidence": result.evidence,
                                "verified": result.verified,
                                "confidence": result.confidence,
                                "phase": "vuln_scan",
                                "remediation": getattr(result, "remediation", None),
                                "references": getattr(result, "references", []) or [],
                            }
                            if fp_result:
                                finding["false_positive_filter"] = {
                                    "reason": fp_result.reason.value,
                                    "confidence": fp_result.confidence,
                                    "evidence": fp_result.evidence,
                                }
                            if verification:
                                finding["verification"] = verification
                            if cve_id:
                                finding["cve_id"] = cve_id
                            findings.append(finding)
                            self.state.add_finding(finding)

                except (OSError, ConnectionError, asyncio.TimeoutError) as e:
                    self.logger.exception(f"扫描 {target_url} 失败: {e}")
                    errors.append(f"扫描 {target_url} 失败: {e}")
                    continue

            return PhaseResult(
                success=len(errors) == 0,
                phase=PentestPhase.VULN_SCAN,
                data={
                    "targets_scanned": len(targets),
                    "vulns_found": len(findings),
                    "waf_detected": waf_name,
                    "waf_type": waf_type.value if waf_type else None,
                    "false_positive_filter": enable_fp_filter,
                    "verifier_enabled": enable_verifier,
                },
                findings=findings,
                errors=errors,
            )

        except ImportError as e:
            self.logger.exception(f"漏洞扫描模块导入失败: {e}")
            errors.append(f"模块导入失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.VULN_SCAN,
                data={},
                findings=findings,
                errors=errors,
            )
        except (OSError, ConnectionError, asyncio.TimeoutError) as e:
            self.logger.exception(f"漏洞扫描阶段失败: {e}")
            errors.append(str(e))
            return PhaseResult(
                success=False,
                phase=PentestPhase.VULN_SCAN,
                data={},
                findings=findings,
                errors=errors,
            )

    def _get_scan_targets(self) -> List[str]:
        """获取扫描目标URL列表 - 带完整 SSRF 防护

        使用规范化后的目标URL，确保与Recon阶段保持一致。

        安全措施:
        - URL Scheme 白名单 (仅 http/https)
        - 内部 IP 地址黑名单 (RFC 1918, loopback, link-local)
        - 主机名范围校验

        Returns:
            规范化后的目标URL列表
        """
        normalized_target = self.get_normalized_target()
        targets = [normalized_target]

        parsed_target = urlparse(normalized_target)
        allowed_hosts = {parsed_target.netloc}

        # 安全校验: 仅允许列表类型的 allowed_hosts 配置
        extra_allowed = self.config.get("allowed_hosts")
        if isinstance(extra_allowed, (list, tuple)):
            # 过滤掉非字符串和空值
            for host in extra_allowed:
                if isinstance(host, str) and host.strip():
                    allowed_hosts.add(host.strip())

        recon_data = self.state.recon_data
        max_directories = self._clamp_config_int("max_scan_directories", 50, 1, 200)

        for directory in recon_data.get("directories", [])[:max_directories]:
            if not directory.startswith("http"):
                url = f"{normalized_target}/{directory.lstrip('/')}"
            else:
                url = directory

            # SSRF 安全校验
            if not self._is_safe_url(url, allowed_hosts):
                continue

            targets.append(url)
        return targets

    def _is_safe_url(self, url: str, allowed_hosts: set) -> bool:
        """验证 URL 是否安全 (SSRF 防护)

        Args:
            url: 待验证的 URL
            allowed_hosts: 允许的主机名集合

        Returns:
            True 如果 URL 安全，False 否则
        """
        try:
            parsed = urlparse(url)

            # 1. Scheme 白名单检查
            if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
                self.logger.warning(f"SSRF 防护: 拒绝非 HTTP(S) URL: {url}")
                return False

            # 2. 主机名范围检查
            hostname = parsed.hostname or ""
            if not hostname:
                self.logger.warning(f"SSRF 防护: URL 缺少主机名: {url}")
                return False

            if parsed.netloc not in allowed_hosts:
                self.logger.warning(f"SSRF 防护: 主机名越界: {url} (不在允许范围内)")
                return False

            # 3. 内部 IP 地址黑名单检查
            if self._is_internal_address(hostname):
                self.logger.warning(f"SSRF 防护: 拒绝内部地址: {url}")
                return False

            return True

        except (ValueError, TypeError) as e:
            self.logger.warning(f"SSRF 防护: URL 解析失败 {url}: {e}")
            return False

    @staticmethod
    def _is_internal_address(hostname: str) -> bool:
        """检查主机名是否为内部 IP 地址字面量

        注意: 此方法仅检查 IP 地址字面量，不进行 DNS 解析。
        域名通过 allowed_hosts 检查确保范围，无需 DNS 解析。

        Args:
            hostname: 主机名或 IP 地址

        Returns:
            True 如果是内部 IP 地址字面量，False 否则
        """
        try:
            # 仅检查 IP 地址字面量
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            # 不是 IP 地址字面量（是域名），不做内部地址检查
            # 域名已通过 allowed_hosts 校验
            return False

        # 检查是否在阻止的 IP 范围内
        for blocked_range in _BLOCKED_IP_RANGES:
            if ip in blocked_range:
                return True

        # 检查其他特殊地址
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True

        return False

    def _build_param_url(self, url: str, param: str, value: str) -> str:
        """构造带参数的URL"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[param] = [value]
        new_query = urlencode(query, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _build_request_context(
        self, result: "DetectionResult"
    ) -> Tuple[str, str, Dict[str, Any], Dict[str, Any], Any, Any]:
        """从检测结果构建请求上下文"""
        method = "GET"
        url = result.url or self.get_normalized_target()
        headers: Dict[str, Any] = {}
        params: Dict[str, Any] = {}
        data = None
        json_data = None

        request = getattr(result, "request", None)
        if request:
            method = (request.method or method).upper()
            if request.url:
                url = request.url
            headers = request.headers or {}
            params = request.params or {}
            body = request.body
            if body:
                body_str = (
                    body.decode("utf-8", errors="ignore")
                    if isinstance(body, (bytes, bytearray))
                    else str(body)
                )
                content_type = str(
                    headers.get("content-type") or headers.get("Content-Type") or ""
                ).lower()
                if "application/json" in content_type or body_str.strip().startswith(("{", "[")):
                    try:
                        json_data = json.loads(body_str)
                    except (json.JSONDecodeError, ValueError):
                        data = body_str
                elif "application/x-www-form-urlencoded" in content_type or "=" in body_str:
                    parsed = parse_qs(body_str, keep_blank_values=True)
                    data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                else:
                    data = body_str

        return method, url, headers, params, data, json_data

    def _apply_false_positive_filter(
        self,
        fp_filter: "FalsePositiveFilter",
        baseline: "ResponseBaseline",
        http_client: "HTTPClient",
        result: "DetectionResult",
    ):
        """最小可用误报过滤"""
        try:
            method, url, headers, params, data, json_data = self._build_request_context(result)
            payload = result.payload or "1"
            request_baseline = baseline if method == "GET" else None

            if method == "GET":
                if result.param:
                    if params:
                        test_params = dict(params)
                        test_params[result.param] = payload
                        resp = http_client.get(url, params=test_params, headers=headers)
                    else:
                        test_url = self._build_param_url(url, result.param, payload)
                        resp = http_client.get(test_url, headers=headers)
                else:
                    resp = http_client.get(url, params=params or None, headers=headers)
            else:
                if result.param:
                    if isinstance(data, dict):
                        data = {**data, result.param: payload}
                    elif isinstance(json_data, dict):
                        json_data = {**json_data, result.param: payload}
                    else:
                        return None
                if data is None and json_data is None:
                    return None
                resp = http_client.request(
                    method, url, headers=headers, params=params or None, data=data, json=json_data
                )
            return fp_filter.check(
                body=resp.text,
                status_code=resp.status_code,
                response_time=resp.elapsed,
                headers=resp.headers,
                baseline=request_baseline,
                url=resp.url,
            )
        except (OSError, ConnectionError) as e:
            self.logger.debug(f"误报过滤失败 {result.url}: {e}")
            return None

    async def _apply_statistical_verification(
        self, verifier: "StatisticalVerifier", result: "DetectionResult", rounds: int = 3
    ) -> Dict[str, Any]:
        """统计验证并返回结构化结果"""
        method, url, headers, params, data, json_data = self._build_request_context(result)
        if not result.param:
            return {
                "confirmed": False,
                "confidence_score": 0.0,
                "positive_count": 0,
                "rounds": rounds,
                "recommendation": "缺少参数，无法进行统计验证",
                "filtered_out": False,
                "skipped": True,
            }

        summary = await asyncio.to_thread(
            verifier.verify_with_statistics,
            vuln_type=result.vuln_type,
            url=url,
            param=result.param or "",
            payload=result.payload or "",
            rounds=rounds,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data,
        )

        confidence_score = float(summary.confidence_score)
        filtered_out = (
            confidence_score < verifier.CONFIDENCE_THRESHOLDS["medium"] and not summary.is_confirmed
        )

        return {
            "confirmed": summary.is_confirmed,
            "confidence_score": confidence_score,
            "positive_count": summary.positive_count,
            "rounds": summary.rounds,
            "recommendation": summary.recommendation,
            "filtered_out": filtered_out,
            "skipped": False,
        }


__all__ = ["VulnScanPhaseExecutor"]
