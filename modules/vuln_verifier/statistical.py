#!/usr/bin/env python3
"""
统计学验证模块

包含:
- StatisticalVerifier: 基于统计学方法的漏洞验证
  - 多次采样
  - 置信区间计算
  - 异常值检测
- verify_vuln_statistically: 便捷函数
"""

import logging
import math
from typing import Callable, List, Tuple

from .models import StatisticalVerification

logger = logging.getLogger(__name__)


class StatisticalVerifier:
    """统计学验证器 - 通过多次采样和统计分析减少误报"""

    def __init__(
        self,
        sample_size: int = 10,
        confidence_level: float = 0.95,
        timeout: int = 10,
    ):
        """初始化统计验证器

        Args:
            sample_size: 每次验证的采样次数
            confidence_level: 置信水平 (0-1)
            timeout: 请求超时时间
        """
        self.sample_size = sample_size
        self.confidence_level = confidence_level
        self.timeout = timeout

    def verify_time_based(
        self,
        url: str,
        param: str,
        payload: str,
        request_func: Callable[[bool], float],
        expected_delay: float = 5.0,
    ) -> StatisticalVerification:
        """基于时间的统计验证

        Args:
            url: 目标 URL
            param: 注入参数
            payload: 测试 payload
            request_func: 发送请求的回调函数，接受 inject 参数，返回响应时间
            expected_delay: 预期延迟时间

        Returns:
            StatisticalVerification: 统计验证结果
        """
        # 采集基准样本
        base_samples: List[float] = []
        for _ in range(self.sample_size):
            try:
                elapsed = request_func(False)
                base_samples.append(elapsed)
            except Exception as e:
                logger.warning("Base sample request failed: %s", e)

        if len(base_samples) < 3:
            return StatisticalVerification(
                vuln_type="Time-based",
                url=url,
                param=param,
                payload=payload,
                rounds=len(base_samples),
                positive_count=0,
                confidence_score=0.0,
                is_confirmed=False,
                details=[{"error": "Insufficient baseline samples"}],
                recommendation="Need at least 3 baseline samples",
            )

        # 采集注入后样本
        payload_samples: List[float] = []
        positive_count = 0
        for _ in range(self.sample_size):
            try:
                elapsed = request_func(True)
                payload_samples.append(elapsed)
                # 判断是否为正向结果（延迟超过预期）
                if elapsed >= expected_delay * 0.8:
                    positive_count += 1
            except Exception as e:
                logger.warning("Payload sample request failed: %s", e)

        if len(payload_samples) < 3:
            return StatisticalVerification(
                vuln_type="Time-based",
                url=url,
                param=param,
                payload=payload,
                rounds=len(base_samples) + len(payload_samples),
                positive_count=0,
                confidence_score=0.0,
                is_confirmed=False,
                details=[{"error": "Insufficient payload samples"}],
                recommendation="Need at least 3 payload samples",
            )

        # 计算统计量
        mean_base = self._mean(base_samples)
        std_base = self._std(base_samples)
        mean_payload = self._mean(payload_samples)
        std_payload = self._std(payload_samples)

        # Welch's t-test（不假设方差相等）
        t_stat, p_value = self._welch_ttest(base_samples, payload_samples)

        # 计算置信区间
        diff_mean = mean_payload - mean_base
        ci = self._confidence_interval(base_samples, payload_samples)

        # 判断是否显著
        # 条件：p值显著 且 差异大于预期延迟的80%
        is_significant = p_value < (1 - self.confidence_level) and diff_mean >= expected_delay * 0.8

        # 置信度评分：基于 p 值和正向比例
        positive_ratio = positive_count / len(payload_samples) if payload_samples else 0
        confidence_score = (1 - p_value) * positive_ratio if is_significant else p_value * 0.1

        # 详细信息
        details = [
            {"mean_base": mean_base, "std_base": std_base},
            {"mean_payload": mean_payload, "std_payload": std_payload},
            {"t_statistic": t_stat, "p_value": p_value},
            {"confidence_interval": ci, "diff_mean": diff_mean},
        ]

        # 生成结论
        if is_significant:
            recommendation = (
                f"Confirmed! Mean diff: {diff_mean:.2f}s (expected ~{expected_delay}s), "
                f"p-value: {p_value:.4f}"
            )
        else:
            recommendation = f"Not confirmed. Mean diff: {diff_mean:.2f}s, p-value: {p_value:.4f}"

        return StatisticalVerification(
            vuln_type="Time-based Injection",
            url=url,
            param=param,
            payload=payload,
            rounds=len(base_samples) + len(payload_samples),
            positive_count=positive_count,
            confidence_score=min(1.0, max(0.0, confidence_score)),
            is_confirmed=is_significant,
            details=details,
            recommendation=recommendation,
        )

    def verify_boolean_diff(
        self,
        url: str,
        param: str,
        true_payload: str,
        false_payload: str,
        true_responses: List[str],
        false_responses: List[str],
    ) -> StatisticalVerification:
        """布尔差异的统计验证

        Args:
            url: 目标 URL
            param: 注入参数
            true_payload: TRUE 条件 payload
            false_payload: FALSE 条件 payload
            true_responses: TRUE 条件下的响应列表
            false_responses: FALSE 条件下的响应列表

        Returns:
            StatisticalVerification: 统计验证结果
        """
        if len(true_responses) < 3 or len(false_responses) < 3:
            return StatisticalVerification(
                vuln_type="Boolean-based",
                url=url,
                param=param,
                payload=f"T:{true_payload} | F:{false_payload}",
                rounds=len(true_responses) + len(false_responses),
                positive_count=0,
                confidence_score=0.0,
                is_confirmed=False,
                details=[{"error": "Insufficient samples"}],
                recommendation="Need at least 3 samples for each condition",
            )

        # 计算响应长度
        true_lengths = [len(r) for r in true_responses]
        false_lengths = [len(r) for r in false_responses]

        mean_true = self._mean(true_lengths)
        std_true = self._std(true_lengths)
        mean_false = self._mean(false_lengths)
        std_false = self._std(false_lengths)

        # t-test
        t_stat, p_value = self._welch_ttest(true_lengths, false_lengths)

        # 内容差异分析
        content_diffs: List[float] = []
        for tr, fr in zip(true_responses, false_responses):
            min_len = min(len(tr), len(fr))
            if min_len > 0:
                diff_count = sum(1 for i in range(min_len) if tr[i] != fr[i])
                content_diffs.append(diff_count / min_len)

        avg_content_diff = self._mean(content_diffs) if content_diffs else 0

        # 判断显著性
        length_diff_ratio = abs(mean_true - mean_false) / max(mean_true, mean_false, 1)
        is_significant = p_value < (1 - self.confidence_level) and (
            length_diff_ratio > 0.1 or avg_content_diff > 0.05
        )

        # 正向计数：差异明显的次数
        positive_count = sum(
            1 for tl, fl in zip(true_lengths, false_lengths) if abs(tl - fl) / max(tl, fl, 1) > 0.05
        )

        confidence_score = (1 - p_value) * (length_diff_ratio + avg_content_diff) / 2

        details = [
            {"mean_true": mean_true, "std_true": std_true},
            {"mean_false": mean_false, "std_false": std_false},
            {"t_statistic": t_stat, "p_value": p_value},
            {"length_diff_ratio": length_diff_ratio, "content_diff": avg_content_diff},
        ]

        recommendation = (
            f"Length diff: {length_diff_ratio:.2%}, "
            f"Content diff: {avg_content_diff:.2%}, "
            f"p-value: {p_value:.4f}"
        )

        return StatisticalVerification(
            vuln_type="Boolean-based Injection",
            url=url,
            param=param,
            payload=f"T:{true_payload} | F:{false_payload}",
            rounds=len(true_responses) + len(false_responses),
            positive_count=positive_count,
            confidence_score=min(1.0, max(0.0, confidence_score)),
            is_confirmed=is_significant,
            details=details,
            recommendation=recommendation,
        )

    def _mean(self, data: List[float]) -> float:
        """计算均值"""
        if not data:
            return 0.0
        return sum(data) / len(data)

    def _std(self, data: List[float]) -> float:
        """计算标准差"""
        if len(data) < 2:
            return 0.0
        mean = self._mean(data)
        variance = sum((x - mean) ** 2 for x in data) / (len(data) - 1)
        return math.sqrt(variance)

    def _welch_ttest(self, sample1: List[float], sample2: List[float]) -> Tuple[float, float]:
        """Welch's t-test (不假设方差相等)

        Returns:
            Tuple[float, float]: (t统计量, p值估算)
        """
        n1 = len(sample1)
        n2 = len(sample2)

        if n1 < 2 or n2 < 2:
            return 0.0, 1.0

        mean1 = self._mean(sample1)
        mean2 = self._mean(sample2)
        var1 = self._std(sample1) ** 2
        var2 = self._std(sample2) ** 2

        # Welch's t-statistic
        se = math.sqrt(var1 / n1 + var2 / n2)
        if se == 0:
            return 0.0, 1.0

        t_stat = (mean1 - mean2) / se

        # Welch-Satterthwaite 自由度
        if var1 == 0 and var2 == 0:
            pass  # df 不需要
        else:
            numerator = (var1 / n1 + var2 / n2) ** 2
            denominator = (var1 / n1) ** 2 / (n1 - 1) + (var2 / n2) ** 2 / (n2 - 1)
            _ = numerator / denominator if denominator > 0 else 1  # df

        # 简化的 p 值估算（使用正态分布近似）
        z = abs(t_stat)
        p_value = 2 * (1 - self._norm_cdf(z))

        return t_stat, p_value

    def _norm_cdf(self, x: float) -> float:
        """标准正态分布 CDF 的近似"""
        # Abramowitz and Stegun 近似
        a1 = 0.254829592
        a2 = -0.284496736
        a3 = 1.421413741
        a4 = -1.453152027
        a5 = 1.061405429
        p = 0.3275911

        sign = 1 if x >= 0 else -1
        x = abs(x)

        t = 1.0 / (1.0 + p * x)
        y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * math.exp(-x * x)

        return 0.5 * (1.0 + sign * y)

    def _confidence_interval(
        self, sample1: List[float], sample2: List[float]
    ) -> Tuple[float, float]:
        """计算差异的置信区间"""
        mean_diff = self._mean(sample2) - self._mean(sample1)
        n1, n2 = len(sample1), len(sample2)

        if n1 < 2 or n2 < 2:
            return (mean_diff, mean_diff)

        var1 = self._std(sample1) ** 2
        var2 = self._std(sample2) ** 2
        se = math.sqrt(var1 / n1 + var2 / n2)

        # 对于 95% 置信水平，z ≈ 1.96
        z_scores = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
        z = z_scores.get(self.confidence_level, 1.96)

        margin = z * se
        return (mean_diff - margin, mean_diff + margin)


def verify_vuln_statistically(
    url: str,
    param: str,
    payload: str,
    request_func: Callable[[bool], float],
    vuln_type: str = "Time-based",
    expected_delay: float = 5.0,
    sample_size: int = 10,
) -> StatisticalVerification:
    """便捷函数：统计学验证漏洞

    Args:
        url: 目标 URL
        param: 注入参数
        payload: 测试 payload
        request_func: 请求函数
        vuln_type: 漏洞类型
        expected_delay: 预期延迟
        sample_size: 样本大小

    Returns:
        StatisticalVerification: 验证结果
    """
    verifier = StatisticalVerifier(sample_size=sample_size)
    return verifier.verify_time_based(
        url=url,
        param=param,
        payload=payload,
        request_func=request_func,
        expected_delay=expected_delay,
    )
