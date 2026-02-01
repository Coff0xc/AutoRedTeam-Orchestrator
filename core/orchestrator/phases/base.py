#!/usr/bin/env python3
"""
phases/base.py - 阶段执行器基类

定义 PhaseResult 和 BasePhaseExecutor 抽象基类。
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from ..state import PentestPhase, PentestState

logger = logging.getLogger(__name__)

# CVE ID 识别正则 (用于从 references/extra 中补充 cve_id)
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class PhaseResult:
    """阶段执行结果"""

    success: bool
    phase: "PentestPhase"
    data: Dict[str, Any]
    findings: List[Dict[str, Any]]
    errors: List[str]
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "phase": self.phase.value,
            "data": self.data,
            "findings_count": len(self.findings),
            "errors": self.errors,
            "duration": self.duration,
        }


class BasePhaseExecutor(ABC):
    """阶段执行器基类

    所有阶段执行器的抽象基类，提供通用功能：
    - URL规范化 (_normalize_url)
    - 前置阶段检查 (can_execute)
    - 检查点恢复 (resume)

    子类必须实现:
    - execute(): 阶段执行逻辑
    - phase: 阶段枚举值
    """

    phase: "PentestPhase"
    name: str = "base"
    description: str = "基础阶段执行器"
    required_phases: List["PentestPhase"] = []

    def __init__(self, state: "PentestState", config: Optional[Dict[str, Any]] = None):
        self.state = state
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
        # 缓存规范化后的目标URL，避免重复计算
        self._normalized_target: Optional[str] = None

    @abstractmethod
    async def execute(self) -> PhaseResult:
        """执行阶段"""
        pass

    async def resume(self, checkpoint_data: Dict[str, Any]) -> PhaseResult:
        """从检查点恢复执行"""
        return await self.execute()

    def can_execute(self) -> bool:
        """检查是否可以执行"""
        for required in self.required_phases:
            if not self.state.is_phase_completed(required):
                return False
        return True

    def get_missing_requirements(self) -> List["PentestPhase"]:
        """获取缺失的前置阶段"""
        return [phase for phase in self.required_phases if not self.state.is_phase_completed(phase)]

    def _normalize_url(self, url: str) -> str:
        """规范化URL - 确保包含协议

        与 core/recon/base.py 的 _normalize_target 保持一致的规范化逻辑。

        Args:
            url: 原始URL或域名

        Returns:
            规范化后的URL (带协议，无尾部斜杠)

        Examples:
            >>> _normalize_url("example.com")
            "https://example.com"
            >>> _normalize_url("http://example.com/")
            "http://example.com"
        """
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    def _extract_cve_id(self, detection_result: Any) -> Optional[str]:
        """从检测结果中提取 cve_id (优先 extra，其次 references/evidence)"""
        cve_id = None
        extra = getattr(detection_result, "extra", None)
        if isinstance(extra, dict):
            cve_id = (
                extra.get("cve_id") or extra.get("cve") or extra.get("cve-id") or extra.get("cveId")
            )

        if not cve_id:
            references = getattr(detection_result, "references", None)
            for ref in references or []:
                match = CVE_ID_PATTERN.search(str(ref))
                if match:
                    cve_id = match.group(0)
                    break

        if not cve_id:
            evidence = getattr(detection_result, "evidence", None)
            if evidence:
                match = CVE_ID_PATTERN.search(str(evidence))
                if match:
                    cve_id = match.group(0)

        return cve_id.upper() if isinstance(cve_id, str) and cve_id else None

    def get_normalized_target(self) -> str:
        """获取规范化后的目标URL (带缓存)

        Returns:
            规范化后的目标URL
        """
        if self._normalized_target is None:
            self._normalized_target = self._normalize_url(self.state.target)
        return self._normalized_target


__all__ = ["PhaseResult", "BasePhaseExecutor", "CVE_ID_PATTERN"]
