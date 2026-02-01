"""
反馈循环引擎 - 失败自动调整重试引擎

功能:
- 执行操作并捕获失败
- 分析失败原因
- 自动选择调整策略
- 应用策略并重试
- 记录学习历史
"""

import asyncio
import inspect
import logging
import random
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, TypeVar

from .failure_analyzer import FailureAnalysis, FailureAnalyzer
from .strategies import (
    AdjustmentAction,
    AdjustmentStrategy,
    AdjustmentType,
    FailureReason,
    StrategyRegistry,
    get_strategy_registry,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class RetryContext:
    """重试上下文 - 跟踪重试状态"""

    attempt: int = 0  # 当前尝试次数
    max_retries: int = 3  # 最大重试次数
    total_time_ms: float = 0.0  # 总耗时
    failures: List[FailureAnalysis] = field(default_factory=list)  # 失败历史
    adjustments: List[AdjustmentAction] = field(default_factory=list)  # 应用的调整
    current_delay: float = 0.0  # 当前延迟
    proxy: Optional[str] = None  # 当前代理
    headers: Dict[str, str] = field(default_factory=dict)  # 修改的请求头
    encoding: Optional[str] = None  # 当前编码方式


@dataclass
class FeedbackResult:
    """反馈循环执行结果"""

    success: bool  # 是否成功
    result: Optional[Any] = None  # 成功时的结果
    final_error: Optional[Exception] = None  # 最终错误
    retry_context: Optional[RetryContext] = None  # 重试上下文
    adjustments_applied: List[Dict[str, Any]] = field(default_factory=list)
    total_attempts: int = 0
    total_time_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "result": self.result if not isinstance(self.result, Exception) else str(self.result),
            "final_error": str(self.final_error) if self.final_error else None,
            "adjustments_applied": self.adjustments_applied,
            "total_attempts": self.total_attempts,
            "total_time_ms": self.total_time_ms,
            "timestamp": self.timestamp,
        }


class PayloadMutator:
    """Payload变异器 - 根据策略变异Payload"""

    @staticmethod
    def mutate(payload: str, strategy: AdjustmentStrategy) -> str:
        """应用变异策略"""
        mutation_type = strategy.params.get("mutation", "")
        encoding = strategy.params.get("encoding", "")

        if encoding:
            return PayloadMutator._apply_encoding(payload, encoding)

        if mutation_type:
            return PayloadMutator._apply_mutation(payload, mutation_type)

        return payload

    @staticmethod
    def _apply_encoding(payload: str, encoding: str) -> str:
        """应用编码"""
        if encoding == "double_url":
            # 双重URL编码
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

        if encoding == "unicode":
            # Unicode编码 (仅对非ASCII字符和特殊字符)
            result = []
            for char in payload:
                if char.isalnum() or char in " .,":
                    result.append(char)
                else:
                    result.append(f"\\u{ord(char):04x}")
            return "".join(result)

        if encoding == "hex":
            # 十六进制编码
            return "".join(f"%{ord(c):02x}" for c in payload)

        if encoding == "base64":
            import base64

            return base64.b64encode(payload.encode()).decode()

        return payload

    @staticmethod
    def _apply_mutation(payload: str, mutation_type: str) -> str:
        """应用变异"""
        if mutation_type == "case_toggle":
            # 随机大小写
            return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

        if mutation_type == "inline_comment":
            # 添加内联注释 (SQL)
            keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
            result = payload
            for kw in keywords:
                result = result.replace(kw, f"{kw}/**/").replace(kw.lower(), f"{kw.lower()}/**/")
            return result

        if mutation_type == "space_substitute":
            # 空格替换
            substitutes = ["/**/", "%09", "%0a", "%0d", "+"]
            sub = random.choice(substitutes)
            return payload.replace(" ", sub)

        if mutation_type == "concat_break":
            # 字符串拼接断开
            # 例如: 'admin' -> 'ad'+'min'
            if len(payload) > 4:
                mid = len(payload) // 2
                return f"'{payload[:mid]}'+'{payload[mid:]}'"

        return payload


class FeedbackLoopEngine:
    """反馈循环引擎 - 失败自动调整重试"""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        strategy_registry: Optional[StrategyRegistry] = None,
        failure_analyzer: Optional[FailureAnalyzer] = None,
        proxy_pool: Optional[List[str]] = None,
        user_agent_pool: Optional[List[str]] = None,
    ):
        """
        初始化反馈循环引擎

        Args:
            max_retries: 最大重试次数
            base_delay: 基础延迟(秒)
            max_delay: 最大延迟(秒)
            strategy_registry: 策略注册表
            failure_analyzer: 失败分析器
            proxy_pool: 代理池
            user_agent_pool: User-Agent池
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.strategy_registry = strategy_registry or get_strategy_registry()
        self.failure_analyzer = failure_analyzer or FailureAnalyzer()
        self.proxy_pool = proxy_pool or []
        self.user_agent_pool = user_agent_pool or self._default_user_agents()

        # 学习历史
        self._success_strategies: Dict[str, int] = {}  # 成功策略计数
        self._failed_strategies: Dict[str, int] = {}  # 失败策略计数
        self._stats_lock = Lock()  # 线程安全锁

    def _default_user_agents(self) -> List[str]:
        """默认User-Agent池"""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
        ]

    async def execute_with_feedback(
        self,
        operation: Callable[..., Any],
        detection_result: Optional[Any] = None,
        max_retries: Optional[int] = None,
        **operation_kwargs,
    ) -> FeedbackResult:
        """
        带反馈循环执行操作

        Args:
            operation: 要执行的操作 (同步或异步函数)
            detection_result: 漏洞检测结果 (提供上下文)
            max_retries: 最大重试次数 (覆盖默认值)
            **operation_kwargs: 传递给操作的参数

        Returns:
            FeedbackResult 执行结果
        """
        max_retries = max_retries if max_retries is not None else self.max_retries
        context = RetryContext(max_retries=max_retries)

        start_time = time.time()

        while context.attempt <= max_retries:
            context.attempt += 1
            attempt_start = time.time()

            try:
                # 应用当前调整到操作参数
                adjusted_kwargs = self._apply_adjustments(operation_kwargs, context)

                # 执行操作
                if inspect.iscoroutinefunction(operation):
                    result = await operation(**adjusted_kwargs)
                else:
                    result = await asyncio.to_thread(operation, **adjusted_kwargs)

                # 检查结果是否表示失败
                if self._is_operation_failed(result):
                    raise OperationFailedError(result)

                # 成功 - 记录成功的策略
                self._record_success(context)

                return FeedbackResult(
                    success=True,
                    result=result,
                    retry_context=context,
                    adjustments_applied=[a.to_dict() for a in context.adjustments],
                    total_attempts=context.attempt,
                    total_time_ms=(time.time() - start_time) * 1000,
                )

            except Exception as e:
                attempt_time = (time.time() - attempt_start) * 1000
                context.total_time_ms += attempt_time

                # 分析失败原因
                analysis = self._analyze_failure(e, operation_kwargs, detection_result)
                context.failures.append(analysis)

                logger.warning(
                    f"尝试 {context.attempt}/{max_retries + 1} 失败: "
                    f"{analysis.reason.name} (置信度: {analysis.confidence:.2f})"
                )

                # 如果还有重试机会
                if context.attempt <= max_retries:
                    # 选择调整策略
                    adjustment = self._select_adjustment(analysis, context)
                    if adjustment:
                        context.adjustments.append(adjustment)
                        logger.info(f"应用调整策略: {adjustment.strategy.name}")

                    # 计算延迟
                    delay = self._calculate_delay(context, analysis)
                    if delay > 0:
                        logger.debug(f"等待 {delay:.2f} 秒后重试")
                        await asyncio.sleep(delay)
                else:
                    # 记录失败的策略
                    self._record_failure(context)

                    return FeedbackResult(
                        success=False,
                        final_error=e,
                        retry_context=context,
                        adjustments_applied=[a.to_dict() for a in context.adjustments],
                        total_attempts=context.attempt,
                        total_time_ms=(time.time() - start_time) * 1000,
                    )

        # 不应该到达这里
        return FeedbackResult(
            success=False,
            retry_context=context,
            total_attempts=context.attempt,
            total_time_ms=(time.time() - start_time) * 1000,
        )

    def execute_with_feedback_sync(
        self,
        operation: Callable[..., Any],
        detection_result: Optional[Any] = None,
        max_retries: Optional[int] = None,
        **operation_kwargs,
    ) -> FeedbackResult:
        """同步版本的反馈循环执行"""
        return asyncio.run(
            self.execute_with_feedback(operation, detection_result, max_retries, **operation_kwargs)
        )

    def _is_operation_failed(self, result: Any) -> bool:
        """判断操作结果是否表示失败"""
        if result is None:
            return True

        # 检查字典类型的结果
        if isinstance(result, dict):
            # 检查常见的失败标志
            if result.get("success") is False:
                return True
            if result.get("status") in ["FAILED", "ERROR", "failed", "error"]:
                return True
            if result.get("error"):
                return True

        # 检查是否有 status 属性
        if hasattr(result, "status"):
            status = result.status
            if hasattr(status, "name"):
                status = status.name
            if status in ["FAILED", "ERROR", "NOT_APPLICABLE"]:
                return True

        return False

    def _analyze_failure(
        self, error: Exception, operation_kwargs: Dict[str, Any], detection_result: Optional[Any]
    ) -> FailureAnalysis:
        """分析失败原因"""
        # 构建上下文
        context = {
            "payload": operation_kwargs.get("payload", ""),
            "url": operation_kwargs.get("url", ""),
            "detection_result": detection_result,
        }

        # 提取响应 (如果有)
        response = None
        if isinstance(error, OperationFailedError) and error.result:
            result = error.result
            if isinstance(result, dict):
                response = result.get("response")
            elif hasattr(result, "response"):
                response = result.response

        return self.failure_analyzer.analyze(error, response, context)

    def _select_adjustment(
        self, analysis: FailureAnalysis, context: RetryContext
    ) -> Optional[AdjustmentAction]:
        """选择调整策略"""
        # 获取适用于该失败原因的策略
        strategies = self.strategy_registry.get_strategies(analysis.reason)

        if not strategies:
            return None

        # 过滤已使用的策略
        used_strategy_names = {a.strategy.name for a in context.adjustments}
        available = [s for s in strategies if s.name not in used_strategy_names]

        if not available:
            # 如果所有策略都用过了，重新尝试优先级最高的
            available = strategies[:1]

        # 根据学习历史调整优先级
        sorted_strategies = sorted(
            available,
            key=lambda s: (
                self._success_strategies.get(s.name, 0)
                - self._failed_strategies.get(s.name, 0) * 0.5,
                s.priority,
            ),
            reverse=True,
        )

        selected = sorted_strategies[0]

        # 构建调整参数
        params = self._build_adjustment_params(selected, context, analysis)

        return AdjustmentAction(strategy=selected, params=params, attempt=context.attempt)

    def _build_adjustment_params(
        self, strategy: AdjustmentStrategy, context: RetryContext, analysis: FailureAnalysis
    ) -> Dict[str, Any]:
        """构建调整参数"""
        params = dict(strategy.params)

        # 根据策略类型添加特定参数
        if strategy.adjustment_type == AdjustmentType.PROXY:
            if self.proxy_pool:
                params["proxy"] = random.choice(self.proxy_pool)

        elif strategy.adjustment_type == AdjustmentType.USER_AGENT:
            if self.user_agent_pool:
                params["user_agent"] = random.choice(self.user_agent_pool)

        elif strategy.adjustment_type == AdjustmentType.DELAY:
            # 指数退避
            base = strategy.params.get("base_delay", self.base_delay)
            multiplier = strategy.params.get("multiplier", 2.0)
            max_delay = strategy.params.get("max_delay", self.max_delay)
            params["delay"] = min(base * (multiplier ** (context.attempt - 1)), max_delay)

        elif strategy.adjustment_type == AdjustmentType.HEADER:
            # 随机IP头
            if params.get("value_type") == "random_ip":
                params["value"] = (
                    f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                )

        return params

    def _apply_adjustments(self, kwargs: Dict[str, Any], context: RetryContext) -> Dict[str, Any]:
        """应用所有调整到操作参数"""
        result = dict(kwargs)

        for adjustment in context.adjustments:
            strategy = adjustment.strategy
            params = adjustment.params

            if strategy.adjustment_type == AdjustmentType.ENCODING:
                # 对payload应用编码
                if "payload" in result:
                    result["payload"] = PayloadMutator.mutate(result["payload"], strategy)
                context.encoding = params.get("encoding")

            elif strategy.adjustment_type == AdjustmentType.PAYLOAD:
                # Payload变异
                if "payload" in result:
                    result["payload"] = PayloadMutator.mutate(result["payload"], strategy)

            elif strategy.adjustment_type == AdjustmentType.PROXY:
                # 代理切换
                if "proxy" in params:
                    result["proxies"] = {"http": params["proxy"], "https": params["proxy"]}
                    context.proxy = params["proxy"]

            elif strategy.adjustment_type == AdjustmentType.USER_AGENT:
                # UA切换
                if "user_agent" in params:
                    headers = result.get("headers", {})
                    headers["User-Agent"] = params["user_agent"]
                    result["headers"] = headers
                    context.headers["User-Agent"] = params["user_agent"]

            elif strategy.adjustment_type == AdjustmentType.HEADER:
                # 请求头修改
                headers = result.get("headers", {})
                header_name = params.get("header", "")
                header_value = params.get("value", "")
                if header_name and header_value:
                    headers[header_name] = header_value
                    result["headers"] = headers
                    context.headers[header_name] = header_value

            elif strategy.adjustment_type == AdjustmentType.DELAY:
                # 延迟 (保存到context，在主循环中应用)
                context.current_delay = params.get("delay", 0)

            elif strategy.adjustment_type == AdjustmentType.METHOD:
                # HTTP方法切换
                if "method" in result and params.get("methods"):
                    current = result["method"].upper()
                    available = [m for m in params["methods"] if m.upper() != current]
                    if available:
                        result["method"] = random.choice(available)

        return result

    def _calculate_delay(self, context: RetryContext, analysis: FailureAnalysis) -> float:
        """计算重试延迟"""
        # 基础指数退避
        delay = self.base_delay * (2 ** (context.attempt - 1))

        # 根据失败原因调整
        if analysis.reason == FailureReason.RATE_LIMITED:
            # 限速时增加延迟
            delay *= 2
            # 如果有 Retry-After 信息
            retry_after = analysis.raw_data.get("retry_after", "")
            if retry_after and retry_after.isdigit():
                delay = max(delay, int(retry_after))

        elif analysis.reason == FailureReason.WAF_BLOCKED:
            # WAF拦截添加随机抖动
            delay += random.uniform(0.5, 2.0)

        elif analysis.reason == FailureReason.TIMEOUT:
            # 超时时适度增加
            delay *= 1.5

        # 应用context中保存的延迟
        if context.current_delay > 0:
            delay = max(delay, context.current_delay)

        # 添加随机抖动
        jitter = random.uniform(0, delay * 0.2)
        delay += jitter

        # 限制最大延迟
        return min(delay, self.max_delay)

    def _record_success(self, context: RetryContext) -> None:
        """记录成功的策略"""
        with self._stats_lock:
            for adjustment in context.adjustments:
                name = adjustment.strategy.name
                self._success_strategies[name] = self._success_strategies.get(name, 0) + 1

    def _record_failure(self, context: RetryContext) -> None:
        """记录失败的策略"""
        with self._stats_lock:
            for adjustment in context.adjustments:
                name = adjustment.strategy.name
                self._failed_strategies[name] = self._failed_strategies.get(name, 0) + 1

    def get_strategy_stats(self) -> Dict[str, Dict[str, int]]:
        """获取策略统计"""
        with self._stats_lock:
            all_names = set(self._success_strategies.keys()) | set(self._failed_strategies.keys())
            return {
                name: {
                    "success": self._success_strategies.get(name, 0),
                    "failure": self._failed_strategies.get(name, 0),
                }
                for name in all_names
            }


class OperationFailedError(Exception):
    """操作失败异常 - 用于包装非异常类型的失败结果"""

    def __init__(self, result: Any):
        self.result = result
        super().__init__(f"Operation failed with result: {result}")


# 便捷函数
async def execute_with_retry(
    operation: Callable[..., Any], max_retries: int = 3, **kwargs
) -> FeedbackResult:
    """便捷函数 - 带重试执行操作"""
    engine = FeedbackLoopEngine(max_retries=max_retries)
    return await engine.execute_with_feedback(operation, **kwargs)
