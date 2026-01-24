#!/usr/bin/env python3
"""
phases.py - 侦察阶段定义

定义侦察工作流的各个阶段、阶段结果和默认执行顺序。

使用方式:
    from core.recon.phases import ReconPhase, PhaseResult, DEFAULT_PHASE_ORDER

    # 遍历所有阶段
    for phase in DEFAULT_PHASE_ORDER:
        result = engine.run_phase(phase)
        if not result.success:
            break
"""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Any, Dict
from datetime import datetime


class ReconPhase(Enum):
    """侦察阶段枚举

    定义完整侦察流程的10个阶段，按执行顺序排列。
    """
    INIT = auto()           # 初始化: 解析目标URL，提取主机名
    DNS = auto()            # DNS解析: 获取A/AAAA/MX/NS/TXT记录
    PORT_SCAN = auto()      # 端口扫描: 扫描开放端口和服务
    FINGERPRINT = auto()    # 指纹识别: 识别服务器、框架、CMS
    TECH_DETECT = auto()    # 技术栈识别: 基于Wappalyzer规则识别
    WAF_DETECT = auto()     # WAF检测: 识别常见WAF/CDN
    SUBDOMAIN = auto()      # 子域名枚举: 字典暴破+DNS解析
    DIRECTORY = auto()      # 目录扫描: 目录和文件暴破
    SENSITIVE = auto()      # 敏感信息: 敏感文件、配置泄露
    COMPLETE = auto()       # 完成: 汇总结果，生成报告

    def __str__(self) -> str:
        """返回阶段名称"""
        return self.name

    @property
    def display_name(self) -> str:
        """返回阶段显示名称（中文）"""
        names = {
            ReconPhase.INIT: "初始化",
            ReconPhase.DNS: "DNS解析",
            ReconPhase.PORT_SCAN: "端口扫描",
            ReconPhase.FINGERPRINT: "指纹识别",
            ReconPhase.TECH_DETECT: "技术栈识别",
            ReconPhase.WAF_DETECT: "WAF检测",
            ReconPhase.SUBDOMAIN: "子域名枚举",
            ReconPhase.DIRECTORY: "目录扫描",
            ReconPhase.SENSITIVE: "敏感信息",
            ReconPhase.COMPLETE: "完成",
        }
        return names.get(self, self.name)

    @property
    def is_critical(self) -> bool:
        """判断是否为关键阶段（失败则中止）"""
        return self in [ReconPhase.INIT, ReconPhase.DNS]


class PhaseStatus(Enum):
    """阶段执行状态"""
    PENDING = "pending"         # 待执行
    RUNNING = "running"         # 执行中
    SUCCESS = "success"         # 成功
    FAILED = "failed"           # 失败
    SKIPPED = "skipped"         # 跳过
    TIMEOUT = "timeout"         # 超时


@dataclass
class PhaseResult:
    """阶段执行结果

    记录单个侦察阶段的执行情况和数据。

    Attributes:
        phase: 阶段类型
        success: 是否成功
        status: 执行状态
        data: 收集的数据
        duration: 执行耗时(秒)
        errors: 错误信息列表
        start_time: 开始时间
        end_time: 结束时间
        metadata: 额外元数据
    """
    phase: ReconPhase
    success: bool
    status: PhaseStatus = PhaseStatus.SUCCESS
    data: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理"""
        if self.start_time is None:
            self.start_time = datetime.now().isoformat()
        # 根据 success 设置 status
        if not self.success and self.status == PhaseStatus.SUCCESS:
            self.status = PhaseStatus.FAILED

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "phase": self.phase.name,
            "phase_display": self.phase.display_name,
            "success": self.success,
            "status": self.status.value,
            "duration": round(self.duration, 3),
            "errors": self.errors,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "data_keys": list(self.data.keys()),
            "metadata": self.metadata,
        }

    @classmethod
    def create_success(
        cls,
        phase: ReconPhase,
        data: Dict[str, Any],
        duration: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "PhaseResult":
        """创建成功结果"""
        return cls(
            phase=phase,
            success=True,
            status=PhaseStatus.SUCCESS,
            data=data,
            duration=duration,
            metadata=metadata or {},
            end_time=datetime.now().isoformat()
        )

    @classmethod
    def create_failure(
        cls,
        phase: ReconPhase,
        errors: List[str],
        duration: float = 0.0,
        data: Optional[Dict[str, Any]] = None
    ) -> "PhaseResult":
        """创建失败结果"""
        return cls(
            phase=phase,
            success=False,
            status=PhaseStatus.FAILED,
            data=data or {},
            duration=duration,
            errors=errors,
            end_time=datetime.now().isoformat()
        )

    @classmethod
    def create_skipped(
        cls,
        phase: ReconPhase,
        reason: str = "Skipped by configuration"
    ) -> "PhaseResult":
        """创建跳过结果"""
        return cls(
            phase=phase,
            success=True,
            status=PhaseStatus.SKIPPED,
            data={},
            duration=0.0,
            metadata={"skip_reason": reason},
            end_time=datetime.now().isoformat()
        )

    @classmethod
    def create_timeout(
        cls,
        phase: ReconPhase,
        timeout: float,
        partial_data: Optional[Dict[str, Any]] = None
    ) -> "PhaseResult":
        """创建超时结果"""
        return cls(
            phase=phase,
            success=False,
            status=PhaseStatus.TIMEOUT,
            data=partial_data or {},
            duration=timeout,
            errors=[f"Phase timed out after {timeout}s"],
            end_time=datetime.now().isoformat()
        )


# 默认阶段执行顺序
DEFAULT_PHASE_ORDER: List[ReconPhase] = [
    ReconPhase.INIT,
    ReconPhase.DNS,
    ReconPhase.PORT_SCAN,
    ReconPhase.FINGERPRINT,
    ReconPhase.TECH_DETECT,
    ReconPhase.WAF_DETECT,
    ReconPhase.SUBDOMAIN,
    ReconPhase.DIRECTORY,
    ReconPhase.SENSITIVE,
    ReconPhase.COMPLETE,
]

# 快速模式阶段顺序（跳过耗时阶段）
QUICK_PHASE_ORDER: List[ReconPhase] = [
    ReconPhase.INIT,
    ReconPhase.DNS,
    ReconPhase.PORT_SCAN,
    ReconPhase.FINGERPRINT,
    ReconPhase.TECH_DETECT,
    ReconPhase.WAF_DETECT,
    ReconPhase.COMPLETE,
]

# 最小模式阶段顺序（仅基础信息）
MINIMAL_PHASE_ORDER: List[ReconPhase] = [
    ReconPhase.INIT,
    ReconPhase.DNS,
    ReconPhase.FINGERPRINT,
    ReconPhase.COMPLETE,
]


# 阶段处理器类型
PhaseHandler = Callable[[], PhaseResult]


@dataclass
class PhaseConfig:
    """阶段配置

    用于自定义单个阶段的执行行为。

    Attributes:
        enabled: 是否启用
        timeout: 超时时间(秒)
        retries: 重试次数
        on_error: 错误处理策略 (continue/abort)
        custom_handler: 自定义处理器
    """
    enabled: bool = True
    timeout: float = 60.0
    retries: int = 0
    on_error: str = "continue"  # continue, abort
    custom_handler: Optional[PhaseHandler] = None

    def should_abort_on_error(self) -> bool:
        """判断错误时是否中止"""
        return self.on_error == "abort"


class PhaseManager:
    """阶段管理器

    管理侦察阶段的配置和执行顺序。

    使用方式:
        manager = PhaseManager()
        manager.disable_phase(ReconPhase.SUBDOMAIN)
        manager.set_timeout(ReconPhase.PORT_SCAN, 120.0)

        for phase in manager.get_phase_order():
            if manager.is_enabled(phase):
                result = execute_phase(phase)
    """

    def __init__(self, phase_order: Optional[List[ReconPhase]] = None):
        """初始化阶段管理器

        Args:
            phase_order: 自定义阶段顺序，默认使用 DEFAULT_PHASE_ORDER
        """
        self._phase_order = phase_order or DEFAULT_PHASE_ORDER.copy()
        self._configs: Dict[ReconPhase, PhaseConfig] = {
            phase: PhaseConfig() for phase in ReconPhase
        }

    def get_phase_order(self) -> List[ReconPhase]:
        """获取阶段执行顺序"""
        return [p for p in self._phase_order if self._configs[p].enabled]

    def set_phase_order(self, order: List[ReconPhase]) -> None:
        """设置阶段执行顺序"""
        self._phase_order = order.copy()

    def get_config(self, phase: ReconPhase) -> PhaseConfig:
        """获取阶段配置"""
        return self._configs[phase]

    def set_config(self, phase: ReconPhase, config: PhaseConfig) -> None:
        """设置阶段配置"""
        self._configs[phase] = config

    def enable_phase(self, phase: ReconPhase) -> None:
        """启用阶段"""
        self._configs[phase].enabled = True

    def disable_phase(self, phase: ReconPhase) -> None:
        """禁用阶段"""
        self._configs[phase].enabled = False

    def is_enabled(self, phase: ReconPhase) -> bool:
        """判断阶段是否启用"""
        return self._configs[phase].enabled

    def set_timeout(self, phase: ReconPhase, timeout: float) -> None:
        """设置阶段超时时间"""
        self._configs[phase].timeout = timeout

    def get_timeout(self, phase: ReconPhase) -> float:
        """获取阶段超时时间"""
        return self._configs[phase].timeout

    def set_custom_handler(
        self,
        phase: ReconPhase,
        handler: PhaseHandler
    ) -> None:
        """设置自定义阶段处理器"""
        self._configs[phase].custom_handler = handler

    def use_quick_mode(self) -> None:
        """使用快速模式（跳过耗时阶段）"""
        self._phase_order = QUICK_PHASE_ORDER.copy()

    def use_minimal_mode(self) -> None:
        """使用最小模式（仅基础信息）"""
        self._phase_order = MINIMAL_PHASE_ORDER.copy()

    def use_full_mode(self) -> None:
        """使用完整模式"""
        self._phase_order = DEFAULT_PHASE_ORDER.copy()


# 导出
__all__ = [
    "ReconPhase",
    "PhaseStatus",
    "PhaseResult",
    "PhaseConfig",
    "PhaseHandler",
    "PhaseManager",
    "DEFAULT_PHASE_ORDER",
    "QUICK_PHASE_ORDER",
    "MINIMAL_PHASE_ORDER",
]
