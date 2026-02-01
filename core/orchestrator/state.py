#!/usr/bin/env python3
"""
state.py - 渗透测试状态管理

管理渗透测试过程中的状态、检查点和断点续传
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from threading import RLock
from typing import Any, Dict, List, Optional, Set


class PentestPhase(Enum):
    """渗透测试阶段枚举"""

    INIT = "init"
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    POC_EXEC = "poc_exec"
    EXPLOIT = "exploit"
    PRIVILEGE_ESC = "privilege_escalation"
    LATERAL_MOVE = "lateral_movement"
    EXFILTRATE = "exfiltrate"
    REPORT = "report"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class PhaseStatus(Enum):
    """阶段状态"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class Checkpoint:
    """检查点数据 - 用于断点续传"""

    phase: PentestPhase
    step: int
    timestamp: datetime
    data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "step": self.step,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Checkpoint":
        return cls(
            phase=PentestPhase(data["phase"]),
            step=data["step"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            data=data["data"],
        )


@dataclass
class AccessInfo:
    """访问信息 - 记录获取的访问权限"""

    host: str
    method: str
    privilege_level: str
    credentials: Optional[Dict[str, str]] = None
    session_token: Optional[str] = None
    notes: str = ""
    obtained_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "method": self.method,
            "privilege_level": self.privilege_level,
            "credentials": self.credentials,
            "session_token": self.session_token,
            "notes": self.notes,
            "obtained_at": self.obtained_at.isoformat(),
        }


@dataclass
class PentestState:
    """渗透测试状态 - 支持断点续传（线程安全）"""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)  # 完整32字符hex，提高熵值
    target: str = ""
    started_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None

    # 阶段状态
    current_phase: PentestPhase = PentestPhase.INIT
    phase_status: Dict[str, PhaseStatus] = field(default_factory=dict)
    phase_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # 检查点
    checkpoints: List[Checkpoint] = field(default_factory=list)
    last_checkpoint: Optional[Checkpoint] = None

    # 收集的信息
    findings: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    access_list: List[AccessInfo] = field(default_factory=list)
    loot: List[Dict[str, Any]] = field(default_factory=list)

    # 侦察结果缓存
    recon_data: Dict[str, Any] = field(default_factory=dict)
    discovered_hosts: Set[str] = field(default_factory=set)
    discovered_ports: Dict[str, List[int]] = field(default_factory=dict)

    # 配置
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 线程安全锁（不序列化）
    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)

    def set_phase(self, phase: PentestPhase, status: PhaseStatus = PhaseStatus.RUNNING) -> None:
        """设置当前阶段"""
        self.current_phase = phase
        self.phase_status[phase.value] = status
        self.updated_at = datetime.now()

    def complete_phase(self, phase: PentestPhase, result: Dict[str, Any]) -> None:
        """完成阶段"""
        self.phase_status[phase.value] = PhaseStatus.COMPLETED
        self.phase_results[phase.value] = result
        self.updated_at = datetime.now()

    def fail_phase(self, phase: PentestPhase, error: str) -> None:
        """标记阶段失败"""
        self.phase_status[phase.value] = PhaseStatus.FAILED
        self.phase_results[phase.value] = {"error": error, "failed_at": datetime.now().isoformat()}
        self.updated_at = datetime.now()

    def add_checkpoint(self, step: int, data: Dict[str, Any]) -> Checkpoint:
        """添加检查点"""
        checkpoint = Checkpoint(
            phase=self.current_phase, step=step, timestamp=datetime.now(), data=data
        )
        self.checkpoints.append(checkpoint)
        self.last_checkpoint = checkpoint
        self.updated_at = datetime.now()
        return checkpoint

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """添加漏洞发现（线程安全）"""
        with self._lock:
            # 使用字典索引提高查找效率
            key = (finding.get("url"), finding.get("type"), finding.get("param"))
            existing_idx = None

            for idx, existing in enumerate(self.findings):
                existing_key = (existing.get("url"), existing.get("type"), existing.get("param"))
                if key == existing_key:
                    if finding.get("confidence", 0) > existing.get("confidence", 0):
                        existing_idx = idx
                    else:
                        return  # 不添加低置信度结果
                    break

            if existing_idx is not None:
                self.findings[existing_idx] = finding
            else:
                finding["discovered_at"] = datetime.now().isoformat()
                self.findings.append(finding)

            self.updated_at = datetime.now()

    def add_credential(self, credential: Dict[str, Any]) -> None:
        """添加凭证（线程安全）"""
        with self._lock:
            credential["discovered_at"] = datetime.now().isoformat()
            self.credentials.append(credential)
            self.updated_at = datetime.now()

    def add_access(self, access: AccessInfo) -> None:
        """添加访问权限（线程安全）"""
        with self._lock:
            self.access_list.append(access)
            self.updated_at = datetime.now()

    def is_phase_completed(self, phase: PentestPhase) -> bool:
        """检查阶段是否完成"""
        return self.phase_status.get(phase.value) == PhaseStatus.COMPLETED

    def get_high_value_findings(self) -> List[Dict[str, Any]]:
        """获取高价值发现（Critical/High）"""
        return [f for f in self.findings if f.get("severity", "").lower() in ("critical", "high")]

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "current_phase": self.current_phase.value,
            "phase_status": {k: v.value for k, v in self.phase_status.items()},
            "phase_results": self.phase_results,
            "checkpoints": [cp.to_dict() for cp in self.checkpoints],
            "last_checkpoint": self.last_checkpoint.to_dict() if self.last_checkpoint else None,
            "findings": self.findings,
            "credentials": self.credentials,
            "access_list": [a.to_dict() for a in self.access_list],
            "loot": self.loot,
            "recon_data": self.recon_data,
            "discovered_hosts": list(self.discovered_hosts),
            "discovered_ports": self.discovered_ports,
            "config": self.config,
            "metadata": self.metadata,
        }

    def to_safe_dict(self) -> Dict[str, Any]:
        """转换为脱敏字典 - 用于持久化和回调，隐藏敏感信息"""
        data = self.to_dict()
        # 脱敏凭证信息
        data["credentials"] = (
            [
                {"type": c.get("type", "unknown"), "discovered_at": c.get("discovered_at")}
                for c in self.credentials
            ]
            if self.credentials
            else []
        )
        # 脱敏访问信息中的敏感字段
        safe_access_list = []
        for access in data.get("access_list", []):
            safe_access = {
                "host": access.get("host"),
                "method": access.get("method"),
                "privilege_level": access.get("privilege_level"),
                "notes": access.get("notes"),
                "obtained_at": access.get("obtained_at"),
                "credentials": "[REDACTED]" if access.get("credentials") else None,
                "session_token": "[REDACTED]" if access.get("session_token") else None,
            }
            safe_access_list.append(safe_access)
        data["access_list"] = safe_access_list
        # 脱敏loot数据
        data["loot"] = (
            [
                {"type": l.get("type", "unknown"), "size": len(str(l.get("data", "")))}
                for l in self.loot
            ]
            if self.loot
            else []
        )
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PentestState":
        """从字典创建状态"""
        state = cls(
            session_id=data.get("session_id", str(uuid.uuid4())[:16]),
            target=data.get("target", ""),
            started_at=(
                datetime.fromisoformat(data["started_at"])
                if data.get("started_at")
                else datetime.now()
            ),
            updated_at=(
                datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None
            ),
            current_phase=PentestPhase(data.get("current_phase", "init")),
            phase_status={k: PhaseStatus(v) for k, v in data.get("phase_status", {}).items()},
            phase_results=data.get("phase_results", {}),
            checkpoints=[Checkpoint.from_dict(cp) for cp in data.get("checkpoints", [])],
            findings=data.get("findings", []),
            credentials=data.get("credentials", []),
            loot=data.get("loot", []),
            recon_data=data.get("recon_data", {}),
            discovered_hosts=set(data.get("discovered_hosts", [])),
            discovered_ports=data.get("discovered_ports", {}),
            config=data.get("config", {}),
            metadata=data.get("metadata", {}),
        )
        if data.get("last_checkpoint"):
            state.last_checkpoint = Checkpoint.from_dict(data["last_checkpoint"])
        return state


__all__ = [
    "PentestPhase",
    "PhaseStatus",
    "Checkpoint",
    "AccessInfo",
    "PentestState",
]
