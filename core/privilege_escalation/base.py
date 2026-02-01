#!/usr/bin/env python3
"""
权限提升基类 - Privilege Escalation Base Module
ATT&CK Tactic: TA0004 - Privilege Escalation

定义权限提升模块的基础接口和数据结构
仅用于授权渗透测试和安全研究
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PrivilegeLevel(Enum):
    """
    权限级别枚举

    定义系统中不同的权限层级
    """

    LOW = "low"  # 普通用户
    MEDIUM = "medium"  # 本地管理员(受限，如 UAC 未提升)
    HIGH = "high"  # 本地管理员(完整权限)
    SYSTEM = "system"  # SYSTEM/root 权限


class EscalationMethod(Enum):
    """
    提权方法枚举

    定义各种提权技术
    """

    # Windows 方法
    UAC_BYPASS = "uac_bypass"
    TOKEN_IMPERSONATION = "token_impersonation"
    POTATO = "potato"
    SERVICE_EXPLOIT = "service_exploit"
    REGISTRY_EXPLOIT = "registry_exploit"
    DLL_HIJACK = "dll_hijack"
    ALWAYS_INSTALL_ELEVATED = "always_install_elevated"
    UNQUOTED_SERVICE_PATH = "unquoted_service_path"

    # Linux 方法
    SUID = "suid"
    SUDO = "sudo"
    CAPABILITY = "capability"
    KERNEL = "kernel"
    CRON = "cron"
    LD_PRELOAD = "ld_preload"
    PATH_HIJACK = "path_hijack"
    NFS_ROOT_SQUASH = "nfs_root_squash"
    DOCKER_ESCAPE = "docker_escape"

    # 通用方法
    CREDENTIAL_ABUSE = "credential_abuse"
    MISCONFIGURATION = "misconfiguration"


class EscalationStatus(Enum):
    """提权状态"""

    IDLE = "idle"
    ENUMERATING = "enumerating"
    EXPLOITING = "exploiting"
    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"


@dataclass
class EscalationVector:
    """
    提权向量

    描述一个可能的提权路径
    """

    method: EscalationMethod
    name: str
    description: str
    success_probability: float = 0.5  # 0.0 - 1.0
    requires_interaction: bool = False
    requires_reboot: bool = False
    cleanup_required: bool = True
    detected_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "method": self.method.value,
            "name": self.name,
            "description": self.description,
            "success_probability": self.success_probability,
            "requires_interaction": self.requires_interaction,
            "requires_reboot": self.requires_reboot,
            "cleanup_required": self.cleanup_required,
            "detected_info": self.detected_info,
        }


@dataclass
class EscalationResult:
    """
    提权结果

    记录提权操作的结果
    """

    success: bool
    method: EscalationMethod
    from_level: PrivilegeLevel
    to_level: PrivilegeLevel
    output: str = ""
    error: str = ""
    duration: float = 0.0
    evidence: str = ""
    cleanup_command: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "success": self.success,
            "method": self.method.value,
            "from_level": self.from_level.value,
            "to_level": self.to_level.value,
            "output": self.output,
            "error": self.error,
            "duration": self.duration,
            "evidence": self.evidence,
            "cleanup_command": self.cleanup_command,
        }

    def __bool__(self) -> bool:
        return self.success


@dataclass
class EscalationConfig:
    """
    提权配置
    """

    # 通用配置
    timeout: float = 60.0
    cleanup: bool = True
    stealth: bool = False

    # 提权选项
    methods: List[EscalationMethod] = field(default_factory=list)
    auto_select: bool = True
    min_success_probability: float = 0.3

    # 安全选项
    safe_mode: bool = True  # 安全模式：避免破坏性操作
    backup_before: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "timeout": self.timeout,
            "cleanup": self.cleanup,
            "stealth": self.stealth,
            "methods": [m.value for m in self.methods],
            "auto_select": self.auto_select,
            "safe_mode": self.safe_mode,
        }


class BasePrivilegeEscalation(ABC):
    """
    权限提升基类

    所有权限提升模块必须继承此类并实现抽象方法

    Usage:
        class MyPrivEsc(BasePrivilegeEscalation):
            name = 'my_privesc'
            platform = 'windows'

            def check_current_privilege(self) -> PrivilegeLevel:
                ...

            def enumerate_vectors(self) -> List[Dict[str, Any]]:
                ...

            def escalate(self, method: Optional[EscalationMethod] = None) -> EscalationResult:
                ...

    Context Manager:
        with MyPrivEsc(config) as privesc:
            result = privesc.auto_escalate()
    """

    # 子类必须覆盖
    name: str = "base"
    description: str = "Base Privilege Escalation Module"
    platform: str = ""  # windows/linux
    supported_methods: List[EscalationMethod] = []

    def __init__(self, config: Optional[EscalationConfig] = None):
        """
        初始化权限提升模块

        Args:
            config: 配置选项
        """
        self.config = config or EscalationConfig()
        self.status = EscalationStatus.IDLE
        self._current_level: Optional[PrivilegeLevel] = None
        self._vectors: List[EscalationVector] = []
        self.logger = logging.getLogger(f"{__name__}.{self.name}")

    @property
    def current_level(self) -> PrivilegeLevel:
        """获取当前权限级别（缓存）"""
        if self._current_level is None:
            self._current_level = self.check_current_privilege()
        return self._current_level

    def _set_status(self, status: EscalationStatus) -> None:
        """设置状态"""
        old_status = self.status
        self.status = status
        self.logger.debug(f"Status: {old_status.value} -> {status.value}")

    @abstractmethod
    def check_current_privilege(self) -> PrivilegeLevel:
        """
        检查当前权限级别

        Returns:
            当前的权限级别
        """

    @abstractmethod
    def enumerate_vectors(self) -> List[Dict[str, Any]]:
        """
        枚举可用的提权向量

        Returns:
            提权向量列表（字典格式）
        """

    @abstractmethod
    def escalate(self, method: Optional[EscalationMethod] = None) -> EscalationResult:
        """
        执行权限提升

        Args:
            method: 指定提权方法，为 None 时自动选择

        Returns:
            提权结果
        """

    def auto_escalate(self) -> EscalationResult:
        """
        自动选择最佳方法进行提权

        按成功概率排序尝试所有可用向量

        Returns:
            提权结果
        """
        self._set_status(EscalationStatus.ENUMERATING)

        # 枚举向量
        vectors_data = self.enumerate_vectors()
        if not vectors_data:
            self._set_status(EscalationStatus.FAILED)
            return EscalationResult(
                success=False,
                method=EscalationMethod.MISCONFIGURATION,
                from_level=self.current_level,
                to_level=self.current_level,
                error="No suitable escalation vectors found",
            )

        # 按成功概率排序
        vectors_data.sort(key=lambda x: x.get("success_probability", 0), reverse=True)

        # 过滤低概率向量
        min_prob = self.config.min_success_probability
        filtered_vectors = [v for v in vectors_data if v.get("success_probability", 0) >= min_prob]

        if not filtered_vectors:
            filtered_vectors = vectors_data[:3]  # 至少尝试前3个

        self._set_status(EscalationStatus.EXPLOITING)

        # 依次尝试
        for vector in filtered_vectors:
            try:
                method = EscalationMethod(vector.get("method"))
                self.logger.info(f"Trying escalation method: {method.value}")

                result = self.escalate(method)
                if result.success:
                    self._set_status(EscalationStatus.SUCCESS)
                    return result

            except Exception as e:
                self.logger.warning(f"Method {vector.get('method')} failed: {e}")
                continue

        self._set_status(EscalationStatus.FAILED)
        return EscalationResult(
            success=False,
            method=EscalationMethod.MISCONFIGURATION,
            from_level=self.current_level,
            to_level=self.current_level,
            error="All escalation methods failed",
        )

    def cleanup(self) -> bool:
        """
        清理提权痕迹

        Returns:
            是否清理成功
        """
        return True

    def get_info(self) -> Dict[str, Any]:
        """获取模块信息"""
        return {
            "name": self.name,
            "description": self.description,
            "platform": self.platform,
            "status": self.status.value,
            "current_level": self.current_level.value if self._current_level else "unknown",
            "supported_methods": [m.value for m in self.supported_methods],
            "vectors_count": len(self._vectors),
        }

    def __enter__(self) -> "BasePrivilegeEscalation":
        """上下文管理器入口"""
        return self

    def __exit__(self, exc_type, _exc_val, _exc_tb) -> None:
        """上下文管理器出口"""
        if self.config.cleanup:
            self.cleanup()

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"platform={self.platform}, "
            f"status={self.status.value})"
        )


# 导出
__all__ = [
    "PrivilegeLevel",
    "EscalationMethod",
    "EscalationStatus",
    "EscalationVector",
    "EscalationResult",
    "EscalationConfig",
    "BasePrivilegeEscalation",
]
