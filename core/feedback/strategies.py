"""
调整策略定义 - 定义失败后的自动调整策略

支持的调整策略:
- 编码绕过 (encoding bypass)
- 延迟调整 (delay adjustment)
- 代理切换 (proxy switching)
- Payload变异 (payload mutation)
- 协议切换 (protocol switching)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


class FailureReason(Enum):
    """失败原因枚举"""

    # 网络相关
    TIMEOUT = auto()  # 请求超时
    RATE_LIMITED = auto()  # 被限速
    CONNECTION_ERROR = auto()  # 连接错误
    DNS_ERROR = auto()  # DNS解析失败

    # 安全防护
    WAF_BLOCKED = auto()  # WAF拦截
    IDS_DETECTED = auto()  # IDS检测
    CAPTCHA_REQUIRED = auto()  # 需要验证码
    IP_BLOCKED = auto()  # IP被封

    # Payload相关
    PAYLOAD_FILTERED = auto()  # Payload被过滤
    ENCODING_ERROR = auto()  # 编码问题
    CONTENT_TYPE_MISMATCH = auto()  # Content-Type不匹配

    # 验证相关
    FALSE_POSITIVE = auto()  # 误报
    VERIFICATION_FAILED = auto()  # 验证失败

    # 服务端
    SERVER_ERROR = auto()  # 服务器错误 (5xx)
    NOT_FOUND = auto()  # 资源不存在 (404)
    AUTH_REQUIRED = auto()  # 需要认证

    # 其他
    UNKNOWN = auto()  # 未知原因


class AdjustmentType(Enum):
    """调整类型枚举"""

    ENCODING = auto()  # 编码调整
    DELAY = auto()  # 延迟调整
    PROXY = auto()  # 代理切换
    PAYLOAD = auto()  # Payload变异
    PROTOCOL = auto()  # 协议切换
    HEADER = auto()  # 请求头修改
    CONCURRENT = auto()  # 并发调整
    USER_AGENT = auto()  # UA切换
    METHOD = auto()  # HTTP方法切换
    CHUNK = auto()  # 分块传输


@dataclass
class AdjustmentStrategy:
    """调整策略定义"""

    name: str  # 策略名称
    adjustment_type: AdjustmentType  # 调整类型
    description: str  # 策略描述
    applicable_reasons: List[FailureReason]  # 适用的失败原因
    priority: int = 0  # 优先级 (越高越先尝试)
    max_attempts: int = 3  # 最大尝试次数

    # 策略参数
    params: Dict[str, Any] = field(default_factory=dict)

    def applies_to(self, reason: FailureReason) -> bool:
        """判断策略是否适用于指定失败原因"""
        return reason in self.applicable_reasons


@dataclass
class AdjustmentAction:
    """调整动作 - 具体的调整操作"""

    strategy: AdjustmentStrategy
    params: Dict[str, Any]
    attempt: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "strategy": self.strategy.name,
            "adjustment_type": self.strategy.adjustment_type.name,
            "params": self.params,
            "attempt": self.attempt,
        }


# ============== 预定义策略 ==============

# WAF绕过编码策略
WAF_ENCODING_STRATEGIES = [
    AdjustmentStrategy(
        name="url_double_encode",
        adjustment_type=AdjustmentType.ENCODING,
        description="URL双重编码绕过",
        applicable_reasons=[FailureReason.WAF_BLOCKED, FailureReason.PAYLOAD_FILTERED],
        priority=10,
        params={"encoding": "double_url"},
    ),
    AdjustmentStrategy(
        name="unicode_encode",
        adjustment_type=AdjustmentType.ENCODING,
        description="Unicode编码绕过",
        applicable_reasons=[FailureReason.WAF_BLOCKED, FailureReason.PAYLOAD_FILTERED],
        priority=9,
        params={"encoding": "unicode"},
    ),
    AdjustmentStrategy(
        name="hex_encode",
        adjustment_type=AdjustmentType.ENCODING,
        description="十六进制编码绕过",
        applicable_reasons=[FailureReason.WAF_BLOCKED, FailureReason.PAYLOAD_FILTERED],
        priority=8,
        params={"encoding": "hex"},
    ),
    AdjustmentStrategy(
        name="mixed_case",
        adjustment_type=AdjustmentType.PAYLOAD,
        description="大小写混合绕过",
        applicable_reasons=[FailureReason.WAF_BLOCKED, FailureReason.PAYLOAD_FILTERED],
        priority=7,
        params={"mutation": "case_toggle"},
    ),
    AdjustmentStrategy(
        name="comment_injection",
        adjustment_type=AdjustmentType.PAYLOAD,
        description="注释符注入绕过",
        applicable_reasons=[FailureReason.WAF_BLOCKED, FailureReason.PAYLOAD_FILTERED],
        priority=6,
        params={"mutation": "inline_comment"},
    ),
]

# 延迟和限速策略
RATE_LIMIT_STRATEGIES = [
    AdjustmentStrategy(
        name="exponential_backoff",
        adjustment_type=AdjustmentType.DELAY,
        description="指数退避延迟",
        applicable_reasons=[FailureReason.RATE_LIMITED, FailureReason.TIMEOUT],
        priority=10,
        params={"base_delay": 1.0, "max_delay": 30.0, "multiplier": 2.0},
    ),
    AdjustmentStrategy(
        name="reduce_concurrency",
        adjustment_type=AdjustmentType.CONCURRENT,
        description="降低并发数",
        applicable_reasons=[FailureReason.RATE_LIMITED, FailureReason.SERVER_ERROR],
        priority=8,
        params={"factor": 0.5, "min_concurrent": 1},
    ),
    AdjustmentStrategy(
        name="add_jitter",
        adjustment_type=AdjustmentType.DELAY,
        description="添加随机抖动延迟",
        applicable_reasons=[FailureReason.RATE_LIMITED, FailureReason.IDS_DETECTED],
        priority=7,
        params={"min_jitter": 0.5, "max_jitter": 3.0},
    ),
]

# 代理切换策略
PROXY_STRATEGIES = [
    AdjustmentStrategy(
        name="switch_proxy",
        adjustment_type=AdjustmentType.PROXY,
        description="切换代理服务器",
        applicable_reasons=[
            FailureReason.IP_BLOCKED,
            FailureReason.RATE_LIMITED,
            FailureReason.WAF_BLOCKED,
        ],
        priority=10,
        params={"rotate": True},
    ),
    AdjustmentStrategy(
        name="use_tor",
        adjustment_type=AdjustmentType.PROXY,
        description="使用Tor网络",
        applicable_reasons=[FailureReason.IP_BLOCKED],
        priority=5,
        params={"proxy_type": "tor"},
    ),
]

# 请求头修改策略
HEADER_STRATEGIES = [
    AdjustmentStrategy(
        name="rotate_user_agent",
        adjustment_type=AdjustmentType.USER_AGENT,
        description="轮换User-Agent",
        applicable_reasons=[FailureReason.WAF_BLOCKED, FailureReason.IP_BLOCKED],
        priority=8,
        params={"pool": "browser"},
    ),
    AdjustmentStrategy(
        name="add_forwarded_for",
        adjustment_type=AdjustmentType.HEADER,
        description="添加X-Forwarded-For头",
        applicable_reasons=[FailureReason.IP_BLOCKED],
        priority=7,
        params={"header": "X-Forwarded-For", "value_type": "random_ip"},
    ),
    AdjustmentStrategy(
        name="content_type_change",
        adjustment_type=AdjustmentType.HEADER,
        description="修改Content-Type",
        applicable_reasons=[FailureReason.CONTENT_TYPE_MISMATCH, FailureReason.WAF_BLOCKED],
        priority=6,
        params={
            "content_types": [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            ]
        },
    ),
    AdjustmentStrategy(
        name="add_origin_header",
        adjustment_type=AdjustmentType.HEADER,
        description="添加Origin/Referer头",
        applicable_reasons=[FailureReason.WAF_BLOCKED],
        priority=5,
        params={"headers": ["Origin", "Referer"]},
    ),
]

# HTTP方法切换策略
METHOD_STRATEGIES = [
    AdjustmentStrategy(
        name="method_override",
        adjustment_type=AdjustmentType.METHOD,
        description="使用X-HTTP-Method-Override",
        applicable_reasons=[FailureReason.WAF_BLOCKED],
        priority=5,
        params={"methods": ["POST", "PUT", "PATCH"]},
    ),
    AdjustmentStrategy(
        name="chunked_transfer",
        adjustment_type=AdjustmentType.CHUNK,
        description="使用分块传输编码",
        applicable_reasons=[FailureReason.WAF_BLOCKED, FailureReason.PAYLOAD_FILTERED],
        priority=6,
        params={"chunk_size": 10},
    ),
]

# 验证相关策略
VERIFICATION_STRATEGIES = [
    AdjustmentStrategy(
        name="statistical_verification",
        adjustment_type=AdjustmentType.PAYLOAD,
        description="统计学验证降低误报",
        applicable_reasons=[FailureReason.FALSE_POSITIVE, FailureReason.VERIFICATION_FAILED],
        priority=10,
        params={"sample_size": 5, "threshold": 0.8},
    ),
    AdjustmentStrategy(
        name="oob_verification",
        adjustment_type=AdjustmentType.PAYLOAD,
        description="带外(OOB)验证",
        applicable_reasons=[FailureReason.FALSE_POSITIVE, FailureReason.VERIFICATION_FAILED],
        priority=9,
        params={"oob_type": "dns"},
    ),
    AdjustmentStrategy(
        name="time_based_verification",
        adjustment_type=AdjustmentType.PAYLOAD,
        description="时间延迟验证",
        applicable_reasons=[FailureReason.FALSE_POSITIVE],
        priority=8,
        params={"delay_seconds": 5},
    ),
]


class StrategyRegistry:
    """策略注册表 - 管理所有调整策略"""

    def __init__(self):
        self._strategies: Dict[FailureReason, List[AdjustmentStrategy]] = {}
        self._register_default_strategies()

    def _register_default_strategies(self) -> None:
        """注册默认策略"""
        all_strategies = (
            WAF_ENCODING_STRATEGIES
            + RATE_LIMIT_STRATEGIES
            + PROXY_STRATEGIES
            + HEADER_STRATEGIES
            + METHOD_STRATEGIES
            + VERIFICATION_STRATEGIES
        )

        for strategy in all_strategies:
            self.register(strategy)

    def register(self, strategy: AdjustmentStrategy) -> None:
        """注册策略"""
        for reason in strategy.applicable_reasons:
            if reason not in self._strategies:
                self._strategies[reason] = []

            # 避免重复注册
            if not any(s.name == strategy.name for s in self._strategies[reason]):
                self._strategies[reason].append(strategy)
                # 按优先级排序
                self._strategies[reason].sort(key=lambda s: s.priority, reverse=True)

    def get_strategies(
        self, reason: FailureReason, max_count: Optional[int] = None
    ) -> List[AdjustmentStrategy]:
        """获取适用于指定失败原因的策略列表"""
        strategies = self._strategies.get(reason, [])
        if max_count:
            return strategies[:max_count]
        return strategies

    def get_all_strategies(self) -> Dict[FailureReason, List[AdjustmentStrategy]]:
        """获取所有策略"""
        return self._strategies.copy()

    def get_strategy_by_name(self, name: str) -> Optional[AdjustmentStrategy]:
        """根据名称获取策略"""
        for strategies in self._strategies.values():
            for strategy in strategies:
                if strategy.name == name:
                    return strategy
        return None


# 全局策略注册表实例
_strategy_registry = StrategyRegistry()


def get_strategy_registry() -> StrategyRegistry:
    """获取全局策略注册表"""
    return _strategy_registry


def get_strategies_for_failure(
    reason: FailureReason, max_count: Optional[int] = None
) -> List[AdjustmentStrategy]:
    """根据失败原因获取调整策略列表"""
    return _strategy_registry.get_strategies(reason, max_count)
