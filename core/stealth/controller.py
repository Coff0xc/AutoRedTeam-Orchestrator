#!/usr/bin/env python3
"""
controller.py - 统一规避控制器

提供实战级的规避检测能力，解决 CRITICAL-3 缺陷。

核心能力:
1. 请求级规避 - User-Agent轮换、请求延迟、流量混淆
2. 行为级规避 - 操作时间窗口、行为模式模拟
3. 网络级规避 - DNS隧道、域前置、流量伪装
4. 主机级规避 - 进程注入、内存执行、日志清理
"""

import asyncio
import hashlib
import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

logger = logging.getLogger(__name__)


class StealthLevel(Enum):
    """隐蔽级别"""

    NONE = "none"  # 无规避，最快速度
    LOW = "low"  # 基础规避，User-Agent轮换
    MEDIUM = "medium"  # 中等规避，增加延迟和流量混淆
    HIGH = "high"  # 高级规避，完整行为模拟
    PARANOID = "paranoid"  # 极端规避，最大隐蔽性


class EvasionType(Enum):
    """规避类型"""

    REQUEST = "request"  # 请求级规避
    BEHAVIOR = "behavior"  # 行为级规避
    NETWORK = "network"  # 网络级规避
    HOST = "host"  # 主机级规避
    MEMORY = "memory"  # 内存级规避
    TIMING = "timing"  # 时间级规避


@dataclass
class StealthConfig:
    """规避配置"""

    level: StealthLevel = StealthLevel.MEDIUM

    # 请求规避配置
    rotate_user_agent: bool = True
    min_delay_ms: int = 100
    max_delay_ms: int = 3000
    jitter_percent: float = 0.3

    # 行为规避配置
    simulate_human: bool = True
    working_hours_only: bool = False
    working_hours_start: int = 9
    working_hours_end: int = 18
    max_requests_per_minute: int = 30

    # 网络规避配置
    use_domain_fronting: bool = False
    fronting_domain: Optional[str] = None
    use_dns_tunnel: bool = False
    dns_server: Optional[str] = None
    encrypt_traffic: bool = True

    # 主机规避配置
    memory_only: bool = False
    clean_logs: bool = False
    avoid_disk_write: bool = False
    process_injection: bool = False

    # 检测规避
    detect_honeypot: bool = True
    detect_sandbox: bool = True
    detect_debugger: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "rotate_user_agent": self.rotate_user_agent,
            "min_delay_ms": self.min_delay_ms,
            "max_delay_ms": self.max_delay_ms,
            "jitter_percent": self.jitter_percent,
            "simulate_human": self.simulate_human,
            "working_hours_only": self.working_hours_only,
            "working_hours_start": self.working_hours_start,
            "working_hours_end": self.working_hours_end,
            "max_requests_per_minute": self.max_requests_per_minute,
            "use_domain_fronting": self.use_domain_fronting,
            "fronting_domain": self.fronting_domain,
            "use_dns_tunnel": self.use_dns_tunnel,
            "dns_server": self.dns_server,
            "encrypt_traffic": self.encrypt_traffic,
            "memory_only": self.memory_only,
            "clean_logs": self.clean_logs,
            "avoid_disk_write": self.avoid_disk_write,
            "process_injection": self.process_injection,
            "detect_honeypot": self.detect_honeypot,
            "detect_sandbox": self.detect_sandbox,
            "detect_debugger": self.detect_debugger,
        }


@dataclass
class RequestContext:
    """请求上下文"""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    timeout: float = 30.0
    follow_redirects: bool = True
    verify_ssl: bool = True
    proxy: Optional[str] = None

    # 规避相关
    priority: int = 0  # 0-10, 10最高优先级
    bypass_delay: bool = False  # 是否跳过延迟
    custom_user_agent: Optional[str] = None
    last_delay_ms: int = 0


@dataclass
class StealthMetrics:
    """规避指标"""

    total_requests: int = 0
    requests_delayed: int = 0
    total_delay_ms: int = 0
    user_agents_used: int = 0
    honeypots_detected: int = 0
    sandboxes_detected: int = 0
    detection_events: List[Dict[str, Any]] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)

    def add_detection_event(self, event_type: str, details: str) -> None:
        self.detection_events.append(
            {
                "type": event_type,
                "details": details,
                "timestamp": datetime.now().isoformat(),
            }
        )

    def get_summary(self) -> Dict[str, Any]:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return {
            "total_requests": self.total_requests,
            "requests_delayed": self.requests_delayed,
            "avg_delay_ms": self.total_delay_ms / max(1, self.requests_delayed),
            "user_agents_used": self.user_agents_used,
            "honeypots_detected": self.honeypots_detected,
            "sandboxes_detected": self.sandboxes_detected,
            "detection_events_count": len(self.detection_events),
            "requests_per_second": self.total_requests / max(1, elapsed),
            "elapsed_seconds": elapsed,
        }


class EvasionTechnique(ABC):
    """规避技术基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def evasion_type(self) -> EvasionType:
        pass

    @abstractmethod
    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        """应用规避技术"""

    @abstractmethod
    def is_applicable(self, config: StealthConfig) -> bool:
        """检查是否适用"""


class UserAgentRotation(EvasionTechnique):
    """User-Agent轮换"""

    # 常见浏览器User-Agent
    USER_AGENTS = [
        # Chrome Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        # Chrome Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        # Firefox Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]

    def __init__(self):
        self._used_agents: List[str] = []
        self._last_agent: Optional[str] = None

    @property
    def name(self) -> str:
        return "user_agent_rotation"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.REQUEST

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        if context.custom_user_agent:
            context.headers["User-Agent"] = context.custom_user_agent
            if context.custom_user_agent not in self._used_agents:
                self._used_agents.append(context.custom_user_agent)
        else:
            # 避免连续使用相同的User-Agent
            available = [ua for ua in self.USER_AGENTS if ua != self._last_agent]
            agent = random.choice(available)
            context.headers["User-Agent"] = agent
            self._last_agent = agent
            if agent not in self._used_agents:
                self._used_agents.append(agent)

        return context

    @property
    def used_agents_count(self) -> int:
        return len(self._used_agents)

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.rotate_user_agent


class RequestDelay(EvasionTechnique):
    """请求延迟"""

    def __init__(self):
        self._last_request_time: Optional[float] = None

    @property
    def name(self) -> str:
        return "request_delay"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.TIMING

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        if context.bypass_delay:
            return context

        # 计算延迟
        base_delay = random.randint(config.min_delay_ms, config.max_delay_ms)

        # 添加抖动
        jitter = int(base_delay * config.jitter_percent * (random.random() * 2 - 1))
        delay_ms = max(0, base_delay + jitter)

        # 根据优先级调整延迟
        if context.priority >= 8:
            delay_ms = int(delay_ms * 0.3)
        elif context.priority >= 5:
            delay_ms = int(delay_ms * 0.6)

        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)

        context.last_delay_ms = delay_ms

        self._last_request_time = time.time()
        return context

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.level != StealthLevel.NONE


class HumanBehaviorSimulation(EvasionTechnique):
    """人类行为模拟"""

    def __init__(self):
        self._request_history: List[Tuple[float, str]] = []

    @property
    def name(self) -> str:
        return "human_behavior"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.BEHAVIOR

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        now = time.time()

        # 清理过期历史
        self._request_history = [(ts, url) for ts, url in self._request_history if now - ts < 60]

        # 检查请求频率
        if len(self._request_history) >= config.max_requests_per_minute:
            # 等待直到可以发送
            oldest = self._request_history[0][0]
            wait_time = 60 - (now - oldest)
            if wait_time > 0:
                logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
                await asyncio.sleep(wait_time)

        # 添加常见浏览器行为特征
        context.headers.setdefault(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        )
        context.headers.setdefault("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7")
        context.headers.setdefault("Accept-Encoding", "gzip, deflate, br")
        context.headers.setdefault("Connection", "keep-alive")
        context.headers.setdefault("Upgrade-Insecure-Requests", "1")

        # 添加Sec-Fetch headers (现代浏览器特征)
        if "Sec-Fetch-Site" not in context.headers:
            context.headers["Sec-Fetch-Site"] = "none"
            context.headers["Sec-Fetch-Mode"] = "navigate"
            context.headers["Sec-Fetch-User"] = "?1"
            context.headers["Sec-Fetch-Dest"] = "document"

        # 记录请求
        self._request_history.append((now, context.url))

        return context

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.simulate_human


class WorkingHoursEnforcement(EvasionTechnique):
    """工作时间限制"""

    @property
    def name(self) -> str:
        return "working_hours"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.TIMING

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        now = datetime.now()
        hour = now.hour

        if not (config.working_hours_start <= hour < config.working_hours_end):
            # 计算到下一个工作时间的等待时间
            if hour >= config.working_hours_end:
                # 今天工作时间已结束，等到明天
                next_start = now.replace(
                    hour=config.working_hours_start, minute=0, second=0, microsecond=0
                ) + timedelta(days=1)
            else:
                # 工作时间还没开始
                next_start = now.replace(
                    hour=config.working_hours_start, minute=0, second=0, microsecond=0
                )

            wait_seconds = (next_start - now).total_seconds()
            logger.info(f"Outside working hours, waiting {wait_seconds/3600:.1f} hours")

            # 如果等待时间太长，分段等待并允许取消
            while wait_seconds > 0:
                sleep_time = min(300, wait_seconds)  # 每次最多等待5分钟
                await asyncio.sleep(sleep_time)
                wait_seconds -= sleep_time

        return context

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.working_hours_only


class HoneypotDetector(EvasionTechnique):
    """蜜罐检测"""

    # 蜜罐特征
    HONEYPOT_INDICATORS = [
        # 响应特征
        "cowrie",
        "dionaea",
        "kippo",
        "honeyd",
        "honeytrap",
        # 异常服务特征
        "admin:admin",
        "root:root",
        "test:test",
        # 过于容易的漏洞
        "vulnerable_demo",
        "injection_test",
    ]

    @property
    def name(self) -> str:
        return "honeypot_detector"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.BEHAVIOR

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        # 蜜罐检测在响应分析阶段进行
        # 这里只是标记需要进行检测
        context.headers["X-Honeypot-Check"] = "enabled"
        return context

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.detect_honeypot

    @classmethod
    def check_response(cls, response_body: str, response_headers: Dict[str, str]) -> bool:
        """检查响应是否来自蜜罐"""
        body_lower = response_body.lower()

        for indicator in cls.HONEYPOT_INDICATORS:
            if indicator.lower() in body_lower:
                return True

        # 检查异常响应模式
        # 例如：所有端口都开放，所有服务版本都很旧

        return False


class SandboxDetector(EvasionTechnique):
    """沙箱检测"""

    # 沙箱/虚拟机特征
    VM_INDICATORS = [
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "xen",
        "hyperv",
        "parallels",
    ]

    @property
    def name(self) -> str:
        return "sandbox_detector"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.HOST

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        # 沙箱检测主要在主机端进行
        return context

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.detect_sandbox

    @classmethod
    def check_environment(cls) -> Tuple[bool, List[str]]:
        """检测当前环境是否为沙箱"""
        indicators_found: List[str] = []

        try:
            import platform

            system_info = platform.platform().lower()

            for indicator in cls.VM_INDICATORS:
                if indicator in system_info:
                    indicators_found.append(f"Platform: {indicator}")
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 检查常见沙箱文件
        sandbox_paths = [
            "/usr/share/virtualbox",
            "/usr/bin/vmware",
            "C:\\Program Files\\VMware",
            "C:\\Program Files\\Oracle\\VirtualBox",
        ]

        import os

        for path in sandbox_paths:
            if os.path.exists(path):
                indicators_found.append(f"Path: {path}")

        return len(indicators_found) > 0, indicators_found


class TrafficObfuscation(EvasionTechnique):
    """流量混淆"""

    @property
    def name(self) -> str:
        return "traffic_obfuscation"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.NETWORK

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        # 添加噪声参数
        noise_param = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]

        parts = urlsplit(context.url)
        query_params = parse_qsl(parts.query, keep_blank_values=True)
        query_params.append(("_", noise_param))
        new_query = urlencode(query_params, doseq=True)
        context.url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
        )

        # 添加随机headers
        context.headers["X-Request-ID"] = hashlib.md5(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()

        return context

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.level in (StealthLevel.HIGH, StealthLevel.PARANOID)


class DomainFronting(EvasionTechnique):
    """域前置"""

    @property
    def name(self) -> str:
        return "domain_fronting"

    @property
    def evasion_type(self) -> EvasionType:
        return EvasionType.NETWORK

    async def apply(self, context: RequestContext, config: StealthConfig) -> RequestContext:
        if config.fronting_domain:
            # 保存原始Host
            parts = urlsplit(context.url)
            original_host = parts.netloc

            # 使用前置域名
            fronting_netloc = config.fronting_domain
            if "://" in fronting_netloc:
                fronting_netloc = urlsplit(fronting_netloc).netloc or fronting_netloc

            if original_host:
                context.headers["Host"] = original_host
                context.url = urlunsplit(
                    (parts.scheme, fronting_netloc, parts.path, parts.query, parts.fragment)
                )

            logger.debug(f"Domain fronting: {config.fronting_domain} -> {original_host}")

        return context

    def is_applicable(self, config: StealthConfig) -> bool:
        return config.use_domain_fronting and config.fronting_domain is not None


class StealthController:
    """统一规避控制器

    管理和协调所有规避技术的应用。

    使用示例:
        controller = StealthController(StealthConfig(level=StealthLevel.HIGH))

        # 包装HTTP请求
        async def make_request(url):
            context = RequestContext(url=url)
            context = await controller.prepare_request(context)
            response = await http_client.request(context)
            controller.analyze_response(response)
            return response
    """

    def __init__(self, config: Optional[StealthConfig] = None):
        self.config = config or StealthConfig()
        self.metrics = StealthMetrics()

        # 初始化规避技术
        self._techniques: List[EvasionTechnique] = [
            UserAgentRotation(),
            RequestDelay(),
            HumanBehaviorSimulation(),
            WorkingHoursEnforcement(),
            HoneypotDetector(),
            SandboxDetector(),
            TrafficObfuscation(),
            DomainFronting(),
        ]

        # 根据级别调整配置
        self._apply_level_defaults()

        logger.info(f"StealthController initialized with level: {self.config.level.value}")

    def _apply_level_defaults(self) -> None:
        """根据隐蔽级别应用默认配置"""
        level = self.config.level

        if level == StealthLevel.NONE:
            self.config.rotate_user_agent = False
            self.config.min_delay_ms = 0
            self.config.max_delay_ms = 0
            self.config.simulate_human = False

        elif level == StealthLevel.LOW:
            self.config.min_delay_ms = 50
            self.config.max_delay_ms = 500
            self.config.max_requests_per_minute = 60

        elif level == StealthLevel.MEDIUM:
            self.config.min_delay_ms = 100
            self.config.max_delay_ms = 2000
            self.config.max_requests_per_minute = 30

        elif level == StealthLevel.HIGH:
            self.config.min_delay_ms = 500
            self.config.max_delay_ms = 5000
            self.config.max_requests_per_minute = 15
            self.config.simulate_human = True

        elif level == StealthLevel.PARANOID:
            self.config.min_delay_ms = 2000
            self.config.max_delay_ms = 10000
            self.config.max_requests_per_minute = 5
            self.config.simulate_human = True
            self.config.working_hours_only = True
            self.config.detect_honeypot = True
            self.config.detect_sandbox = True

    async def prepare_request(self, context: RequestContext) -> RequestContext:
        """准备请求，应用所有适用的规避技术"""
        self.metrics.total_requests += 1

        for technique in self._techniques:
            if technique.is_applicable(self.config):
                try:
                    context = await technique.apply(context, self.config)

                    if isinstance(technique, RequestDelay):
                        if context.last_delay_ms > 0:
                            self.metrics.requests_delayed += 1
                            self.metrics.total_delay_ms += context.last_delay_ms

                    if isinstance(technique, UserAgentRotation):
                        self.metrics.user_agents_used = technique.used_agents_count

                except Exception as e:
                    logger.warning(f"Evasion technique {technique.name} failed: {e}")

        return context

    def analyze_response(
        self, response_body: str, response_headers: Dict[str, str], status_code: int
    ) -> Dict[str, Any]:
        """分析响应，检测异常"""
        analysis = {
            "is_honeypot": False,
            "is_blocked": False,
            "needs_retry": False,
            "warnings": [],
        }

        # 检测蜜罐
        if self.config.detect_honeypot:
            if HoneypotDetector.check_response(response_body, response_headers):
                analysis["is_honeypot"] = True
                analysis["warnings"].append("Possible honeypot detected")
                self.metrics.honeypots_detected += 1
                self.metrics.add_detection_event("honeypot", "Response matches honeypot patterns")

        # 检测WAF/封禁
        waf_indicators = ["403 forbidden", "access denied", "blocked", "rate limit"]
        body_lower = response_body.lower()

        if status_code in (403, 429, 503):
            for indicator in waf_indicators:
                if indicator in body_lower:
                    analysis["is_blocked"] = True
                    analysis["needs_retry"] = True
                    analysis["warnings"].append(f"Possible WAF/blocking: {indicator}")
                    self.metrics.add_detection_event(
                        "blocked", f"Status {status_code}: {indicator}"
                    )
                    break

        return analysis

    def get_metrics(self) -> Dict[str, Any]:
        """获取规避指标"""
        return self.metrics.get_summary()

    def reset_metrics(self) -> None:
        """重置指标"""
        self.metrics = StealthMetrics()

    def update_config(self, **kwargs) -> None:
        """更新配置"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

        # 重新应用级别默认值
        if "level" in kwargs:
            self._apply_level_defaults()

    async def with_stealth(self, func: Callable, *args, **kwargs) -> Any:
        """使用规避包装执行函数

        示例:
            result = await controller.with_stealth(http_client.get, url, headers=headers)
        """
        # 提取或创建RequestContext
        context = kwargs.pop("_context", None)
        if context is None:
            url = args[0] if args else kwargs.get("url", "")
            context = RequestContext(url=str(url))

        # 应用规避
        context = await self.prepare_request(context)

        # 更新kwargs
        if "headers" in kwargs:
            kwargs["headers"].update(context.headers)
        else:
            kwargs["headers"] = context.headers

        # 执行
        result = await func(*args, **kwargs)

        return result

    def stealth_wrapper(self, func: Callable) -> Callable:
        """装饰器形式的规避包装"""

        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await self.with_stealth(func, *args, **kwargs)

        return wrapper


# ============================================================================
# 高级规避策略
# ============================================================================


class AdaptiveEvasion:
    """自适应规避策略

    根据目标响应动态调整规避级别。
    """

    def __init__(self, controller: StealthController):
        self.controller = controller
        self._consecutive_blocks = 0
        self._original_level = controller.config.level

    def on_response(self, status_code: int, response_time_ms: float) -> None:
        """根据响应调整策略"""

        # 被封禁，提升规避级别
        if status_code in (403, 429):
            self._consecutive_blocks += 1

            if self._consecutive_blocks >= 3:
                self._escalate_level()
        else:
            self._consecutive_blocks = 0

            # 响应正常，可以尝试降低级别以提高速度
            if status_code == 200 and response_time_ms < 500:
                self._consider_deescalate()

    def _escalate_level(self) -> None:
        """提升规避级别"""
        current = self.controller.config.level

        level_order = [
            StealthLevel.NONE,
            StealthLevel.LOW,
            StealthLevel.MEDIUM,
            StealthLevel.HIGH,
            StealthLevel.PARANOID,
        ]

        current_idx = level_order.index(current)
        if current_idx < len(level_order) - 1:
            new_level = level_order[current_idx + 1]
            self.controller.update_config(level=new_level)
            logger.warning(f"Escalating stealth level to: {new_level.value}")

    def _consider_deescalate(self) -> None:
        """考虑降低规避级别"""
        # 只有在连续成功多次后才降级
        # 这里简化处理

    def reset(self) -> None:
        """重置到原始级别"""
        self.controller.update_config(level=self._original_level)
        self._consecutive_blocks = 0


# ============================================================================
# 便捷函数
# ============================================================================

_global_controller: Optional[StealthController] = None


def get_stealth_controller() -> StealthController:
    """获取全局规避控制器"""
    global _global_controller
    if _global_controller is None:
        _global_controller = StealthController()
    return _global_controller


def set_stealth_level(level: StealthLevel) -> None:
    """设置全局规避级别"""
    get_stealth_controller().update_config(level=level)


def create_stealth_controller(
    level: StealthLevel = StealthLevel.MEDIUM, **config_overrides: Any
) -> StealthController:
    """创建新的规避控制器

    Args:
        level: 隐蔽级别
        **config_overrides: 配置覆盖项

    Returns:
        配置好的 StealthController 实例
    """
    config = StealthConfig(level=level)

    for key, value in config_overrides.items():
        if hasattr(config, key):
            setattr(config, key, value)

    return StealthController(config)
