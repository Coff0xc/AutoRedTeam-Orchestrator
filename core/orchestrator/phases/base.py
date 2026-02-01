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
    # 注意: 子类必须重写此属性，不要直接修改基类的列表
    required_phases: tuple = ()

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

    # ============== 安全工具方法 ==============

    @staticmethod
    def _redact_credential(cred: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """脱敏凭证信息 - 仅保留类型和用户名，隐藏密码/令牌

        Args:
            cred: 原始凭证字典

        Returns:
            脱敏后的凭证字典
        """
        if not isinstance(cred, dict):
            return None
        redacted: Dict[str, Any] = {"source": cred.get("source", "unknown")}
        if cred.get("username"):
            redacted["username"] = str(cred["username"])
        if cred.get("password"):
            redacted["password"] = "***REDACTED***"
        if cred.get("token"):
            token = str(cred["token"])
            redacted["token"] = token[:4] + "***" if len(token) > 4 else "***"
        if cred.get("type"):
            redacted["type"] = cred["type"]
        return redacted

    @staticmethod
    def _sanitize_output(output: Optional[str], max_length: int = 200) -> str:
        """清洗命令输出 - 截断并移除潜在敏感行

        Args:
            output: 原始输出
            max_length: 最大保留长度

        Returns:
            清洗后的输出
        """
        if not output:
            return ""
        # 移除包含常见敏感关键字的行
        sensitive_patterns = ("password", "passwd", "secret", "token", "key=", "api_key")
        lines = output.split("\n")
        safe_lines = [
            line for line in lines if not any(p in line.lower() for p in sensitive_patterns)
        ]
        cleaned = "\n".join(safe_lines)
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length] + "...[truncated]"
        return cleaned

    @staticmethod
    def _sanitize_error(error: str) -> str:
        """清洗错误消息 - 移除路径和敏感信息"""
        # 移除文件路径 (Windows 和 Unix)
        sanitized = re.sub(r"[A-Z]:\\[\w\\/.]+", "[PATH]", error)
        sanitized = re.sub(r"/(?:home|root|tmp|var|etc)/[\w/.]+", "[PATH]", sanitized)
        # 移除 IP:Port 模式中的端口
        sanitized = re.sub(r"(\d+\.\d+\.\d+\.\d+):\d+", r"\1:[PORT]", sanitized)
        return sanitized

    def _create_error_result(
        self,
        error: str,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> PhaseResult:
        """创建错误阶段结果"""
        return PhaseResult(
            success=False,
            phase=self.phase,
            data={},
            findings=findings or [],
            errors=[self._sanitize_error(error)],
        )

    def _clamp_config_int(self, key: str, default: int, min_val: int, max_val: int) -> int:
        """获取配置整数值并限制范围

        Args:
            key: 配置键
            default: 默认值
            min_val: 最小值
            max_val: 最大值

        Returns:
            范围限制后的整数
        """
        try:
            value = int(self.config.get(key, default))
        except (ValueError, TypeError):
            value = default
        return max(min_val, min(value, max_val))


__all__ = ["PhaseResult", "BasePhaseExecutor", "CVE_ID_PATTERN"]
