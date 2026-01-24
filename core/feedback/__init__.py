"""
反馈循环引擎模块

提供失败自动调整重试能力:
- FeedbackLoopEngine: 主引擎，执行操作并在失败时自动调整重试
- FailureAnalyzer: 失败原因分析器
- StrategyRegistry: 调整策略注册表
- PayloadMutator: Payload变异器

示例用法:
    from core.feedback import FeedbackLoopEngine, execute_with_retry

    # 创建引擎
    engine = FeedbackLoopEngine(max_retries=3)

    # 执行带反馈循环的操作
    async def my_operation(url, payload):
        # ... 实际操作
        pass

    result = await engine.execute_with_feedback(
        my_operation,
        detection_result=detection,  # 可选，提供上下文
        url='http://target.com',
        payload="' OR 1=1--"
    )

    if result.success:
        print("成功:", result.result)
    else:
        print("失败:", result.final_error)
        print("尝试次数:", result.total_attempts)
        print("应用的调整:", result.adjustments_applied)
"""

from .engine import (
    FeedbackLoopEngine,
    FeedbackResult,
    OperationFailedError,
    PayloadMutator,
    RetryContext,
    execute_with_retry,
)
from .failure_analyzer import (
    FailureAnalysis,
    FailureAnalyzer,
    analyze_failure,
)
from .strategies import (
    AdjustmentAction,
    AdjustmentStrategy,
    AdjustmentType,
    FailureReason,
    StrategyRegistry,
    get_strategies_for_failure,
    get_strategy_registry,
)

__all__ = [
    # 主引擎
    'FeedbackLoopEngine',
    'FeedbackResult',
    'RetryContext',
    'execute_with_retry',

    # 失败分析
    'FailureAnalyzer',
    'FailureAnalysis',
    'analyze_failure',

    # 策略
    'StrategyRegistry',
    'AdjustmentStrategy',
    'AdjustmentAction',
    'AdjustmentType',
    'FailureReason',
    'get_strategy_registry',
    'get_strategies_for_failure',

    # 工具
    'PayloadMutator',
    'OperationFailedError',
]
