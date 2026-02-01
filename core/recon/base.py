#!/usr/bin/env python3
"""
base.py - 侦察引擎基类

定义统一的侦察引擎接口，所有侦察引擎都应继承此类。

架构说明:
- BaseReconEngine: 抽象基类，定义标准接口
- ReconConfig: 侦察配置数据类
- ReconResult: 侦察结果数据类

使用方式:
    from core.recon.base import BaseReconEngine, ReconConfig, ReconResult

    class CustomReconEngine(BaseReconEngine):
        def run(self) -> ReconResult:
            # 实现侦察逻辑
            pass
"""

import logging
import ssl
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .phases import (
    PhaseManager,
    PhaseResult,
    PhaseStatus,
    ReconPhase,
)

logger = logging.getLogger(__name__)


class Severity(Enum):
    """漏洞严重级别"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "Severity") -> bool:
        """支持比较排序"""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class ReconConfig:
    """侦察配置

    控制侦察引擎的各种行为参数。

    Attributes:
        timeout: 默认请求超时时间(秒)
        max_threads: 最大并发线程数
        rate_limit: 请求速率限制(请求/秒)
        verify_ssl: 是否验证SSL证书
        user_agent: 自定义User-Agent

        enable_port_scan: 是否启用端口扫描
        enable_subdomain: 是否启用子域名枚举
        enable_directory: 是否启用目录扫描
        enable_waf_detect: 是否启用WAF检测

        port_range: 端口扫描范围
        top_ports: 扫描Top N常用端口
        port_timeout: 端口扫描超时(秒)

        wordlist: 目录扫描字典路径
        extensions: 目录扫描文件扩展名
        max_directories: 最大目录数量

        subdomain_wordlist: 子域名字典路径
        max_subdomains: 最大子域名数量

        proxy: 代理设置 (http://host:port)
        headers: 自定义请求头
    """

    # 基础配置
    timeout: float = 30.0
    max_threads: int = 10
    rate_limit: float = 10.0
    verify_ssl: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # 功能开关
    enable_port_scan: bool = True
    enable_subdomain: bool = True
    enable_directory: bool = True
    enable_waf_detect: bool = True
    enable_fingerprint: bool = True
    enable_tech_detect: bool = True
    enable_sensitive: bool = True

    # 端口扫描配置
    port_range: str = "1-1000"
    top_ports: int = 100
    port_timeout: float = 3.0
    port_concurrency: int = 100

    # 目录扫描配置
    wordlist: Optional[str] = None
    extensions: List[str] = field(
        default_factory=lambda: [".php", ".asp", ".aspx", ".jsp", ".html", ".js"]
    )
    max_directories: int = 500
    directory_timeout: float = 10.0

    # 子域名配置
    subdomain_wordlist: Optional[str] = None
    max_subdomains: int = 1000
    subdomain_timeout: float = 5.0

    # 网络配置
    proxy: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)

    # 模式配置
    quick_mode: bool = False
    stealth_mode: bool = False

    def __post_init__(self):
        """初始化后处理"""
        # 快速模式下调整配置
        if self.quick_mode:
            self.enable_subdomain = False
            self.enable_directory = False
            self.top_ports = 20

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReconConfig":
        """从字典创建配置"""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "timeout": self.timeout,
            "max_threads": self.max_threads,
            "rate_limit": self.rate_limit,
            "verify_ssl": self.verify_ssl,
            "enable_port_scan": self.enable_port_scan,
            "enable_subdomain": self.enable_subdomain,
            "enable_directory": self.enable_directory,
            "enable_waf_detect": self.enable_waf_detect,
            "port_range": self.port_range,
            "top_ports": self.top_ports,
            "quick_mode": self.quick_mode,
            "stealth_mode": self.stealth_mode,
        }


@dataclass
class Finding:
    """发现结果

    记录侦察过程中发现的问题或信息。

    Attributes:
        type: 发现类型 (port, subdomain, sensitive_file, etc.)
        severity: 严重级别
        title: 标题
        description: 描述
        evidence: 证据
        recommendation: 修复建议
        confidence: 置信度 (0-1)
        cve_id: CVE编号
        url: 相关URL
        metadata: 额外元数据
    """

    type: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    confidence: float = 0.8
    cve_id: Optional[str] = None
    url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "type": self.type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "cve_id": self.cve_id,
            "url": self.url,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class ReconResult:
    """侦察结果

    存储完整侦察的所有结果数据。

    Attributes:
        target: 目标URL
        success: 是否成功完成
        ip_addresses: IP地址列表
        open_ports: 开放端口列表
        technologies: 识别的技术栈
        fingerprints: 指纹信息
        subdomains: 子域名列表
        directories: 发现的目录列表
        waf_detected: 检测到的WAF
        findings: 发现列表
        duration: 总耗时
        phase_results: 各阶段结果
        errors: 错误列表
        metadata: 元数据
    """

    target: str
    success: bool = False

    # 收集的信息
    ip_addresses: List[str] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None

    # 发现和问题
    findings: List[Finding] = field(default_factory=list)

    # 元数据
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    duration: float = 0.0
    phase_results: List[PhaseResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        """添加发现"""
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        """添加错误"""
        self.errors.append(error)

    def add_phase_result(self, result: PhaseResult) -> None:
        """添加阶段结果"""
        self.phase_results.append(result)

    def get_phase_result(self, phase: ReconPhase) -> Optional[PhaseResult]:
        """获取指定阶段的结果"""
        for pr in self.phase_results:
            if pr.phase == phase:
                return pr
        return None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "target": self.target,
            "success": self.success,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": round(self.duration, 3),
            # 资产信息
            "ip_addresses": self.ip_addresses,
            "open_ports": self.open_ports,
            "technologies": self.technologies,
            "fingerprints": self.fingerprints,
            "subdomains": self.subdomains[:100],  # 限制数量
            "directories": self.directories[:100],
            "sensitive_files": self.sensitive_files,
            "waf_detected": self.waf_detected,
            # 发现
            "findings": [f.to_dict() for f in self.findings],
            # 摘要
            "summary": self._generate_summary(),
            # 错误
            "errors": self.errors,
            # 阶段结果
            "phase_results": [pr.to_dict() for pr in self.phase_results],
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """生成摘要"""
        severity_count = {s.value: 0 for s in Severity}
        for f in self.findings:
            severity_count[f.severity.value] += 1

        # 计算风险等级
        if severity_count["critical"] > 0:
            risk_level = "critical"
        elif severity_count["high"] > 0:
            risk_level = "high"
        elif severity_count["medium"] > 0:
            risk_level = "medium"
        elif severity_count["low"] > 0:
            risk_level = "low"
        else:
            risk_level = "info"

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_count,
            "risk_level": risk_level,
            "open_ports_count": len(self.open_ports),
            "subdomains_count": len(self.subdomains),
            "directories_count": len(self.directories),
            "technologies": self.technologies[:10],
            "phases_completed": len(
                [pr for pr in self.phase_results if pr.status == PhaseStatus.SUCCESS]
            ),
            "phases_failed": len(
                [pr for pr in self.phase_results if pr.status == PhaseStatus.FAILED]
            ),
        }


# 进度回调类型
ProgressCallback = Callable[[ReconPhase, int, str], None]


class BaseReconEngine(ABC):
    """侦察引擎抽象基类

    定义所有侦察引擎的标准接口。

    使用方式:
        class CustomEngine(BaseReconEngine):
            def run(self) -> ReconResult:
                # 实现侦察逻辑
                for phase in self._phase_manager.get_phase_order():
                    result = self._run_phase(phase)
                    if not result.success and phase.is_critical:
                        break
                return self.result

            async def async_run(self) -> ReconResult:
                # 异步实现
                pass
    """

    # 默认配置
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def __init__(self, target: str, config: Optional[ReconConfig] = None):
        """初始化侦察引擎

        Args:
            target: 目标URL或域名
            config: 侦察配置
        """
        self.target = self._normalize_target(target)
        self.config = config or ReconConfig()

        # 解析目标
        parsed = urlparse(self.target)
        self.hostname = parsed.hostname or ""
        self.scheme = parsed.scheme or "https"
        self.port = parsed.port
        self.base_url = f"{self.scheme}://{parsed.netloc}"

        # 初始化结果
        self.result = ReconResult(target=self.target)

        # 阶段管理
        self._phase_manager = PhaseManager()
        self._current_phase = ReconPhase.INIT

        # 线程安全
        self._lock = threading.Lock()
        self._stop_flag = threading.Event()

        # 进度回调
        self._progress_callback: Optional[ProgressCallback] = None

        # SSL上下文
        self._ssl_context = self._create_ssl_context()

        # 初始化日志
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def _normalize_target(self, target: str) -> str:
        """规范化目标URL"""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        return target.rstrip("/")

    def _create_ssl_context(self) -> ssl.SSLContext:
        """创建SSL上下文"""
        if self.config.verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @property
    def current_phase(self) -> ReconPhase:
        """获取当前阶段"""
        return self._current_phase

    @property
    def phase_manager(self) -> PhaseManager:
        """获取阶段管理器"""
        return self._phase_manager

    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """设置进度回调

        Args:
            callback: 回调函数，签名为 callback(phase, progress, message)
        """
        self._progress_callback = callback

    def _report_progress(self, phase: ReconPhase, progress: int, message: str = "") -> None:
        """报告进度"""
        self._current_phase = phase
        if self._progress_callback:
            try:
                self._progress_callback(phase, progress, message)
            except Exception as e:
                self._logger.warning(f"Progress callback error: {e}")

    def _add_finding(self, finding: Finding) -> None:
        """线程安全地添加发现"""
        with self._lock:
            self.result.add_finding(finding)

    def _add_error(self, error: str) -> None:
        """线程安全地添加错误"""
        with self._lock:
            self.result.add_error(error)

    def _add_phase_result(self, phase_result: PhaseResult) -> None:
        """线程安全地添加阶段结果"""
        with self._lock:
            self.result.add_phase_result(phase_result)

    def stop(self) -> None:
        """停止侦察"""
        self._stop_flag.set()
        self.result.success = False
        self.result.end_time = datetime.now().isoformat()
        self._logger.info(f"Recon stopped for target: {self.target}")

    def is_stopped(self) -> bool:
        """检查是否已停止"""
        return self._stop_flag.is_set()

    def get_result(self) -> ReconResult:
        """获取当前结果"""
        return self.result

    @abstractmethod
    def run(self) -> ReconResult:
        """运行侦察（同步）

        子类必须实现此方法。

        Returns:
            ReconResult 侦察结果
        """

    @abstractmethod
    async def async_run(self) -> ReconResult:
        """运行侦察（异步）

        子类必须实现此方法。

        Returns:
            ReconResult 侦察结果
        """

    def run_phase(self, phase: ReconPhase) -> PhaseResult:
        """运行单个阶段

        默认实现，子类可以覆盖。

        Args:
            phase: 要运行的阶段

        Returns:
            PhaseResult 阶段结果
        """
        import time

        start = time.time()

        if self.is_stopped():
            return PhaseResult.create_skipped(phase, "Engine stopped")

        if not self._phase_manager.is_enabled(phase):
            return PhaseResult.create_skipped(phase, "Phase disabled")

        self._current_phase = phase
        self._report_progress(phase, 0, f"Starting {phase.display_name}")

        try:
            # 子类应该覆盖此方法或提供 _phase_handlers
            handler = getattr(self, f"_phase_{phase.name.lower()}", None)
            if handler:
                result = handler()
            else:
                result = PhaseResult.create_skipped(phase, "No handler")

            duration = time.time() - start
            result.duration = duration
            return result

        except Exception as e:
            duration = time.time() - start
            self._logger.error(f"Phase {phase.name} error: {e}")
            return PhaseResult.create_failure(phase, [str(e)], duration)

    def export_json(self) -> str:
        """导出JSON格式结果"""
        import json

        return json.dumps(self.result.to_dict(), ensure_ascii=False, indent=2)

    def export_dict(self) -> Dict[str, Any]:
        """导出字典格式结果"""
        return self.result.to_dict()


# 导出
__all__ = [
    "Severity",
    "ReconConfig",
    "Finding",
    "ReconResult",
    "BaseReconEngine",
    "ProgressCallback",
]
