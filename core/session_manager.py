#!/usr/bin/env python3
"""
会话管理器 - 管理渗透测试会话 (legacy)

兼容旧版 SessionManager API，新实现请使用 core.session。
"""

import json
import logging
import os
import re
import uuid
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

# Session ID 安全正则
SESSION_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{8,64}$')


class SessionStatus(Enum):
    """会话状态"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Target:
    """目标信息"""
    value: str  # IP, 域名, URL等
    type: str   # ip, domain, url, network
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """执行结果"""
    tool_name: str
    params: Dict[str, Any]
    result: Dict[str, Any]
    timestamp: datetime
    duration: float  # 秒
    success: bool
    error: str = None


@dataclass
class Session:
    """渗透测试会话"""
    id: str
    name: str
    created_at: datetime
    status: SessionStatus = SessionStatus.ACTIVE
    targets: List[Target] = field(default_factory=list)
    results: List[ExecutionResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_target(self, value: str, target_type: str, metadata: Dict = None):
        """添加目标"""
        target = Target(
            value=value,
            type=target_type,
            metadata=metadata or {}
        )
        self.targets.append(target)
        logger.info(f"会话 {self.id}: 添加目标 {value}")
    
    def add_result(self, tool_name: str, params: Dict, result: Dict,
                   duration: float, success: bool, error: str = None):
        """添加执行结果"""
        exec_result = ExecutionResult(
            tool_name=tool_name,
            params=params,
            result=result,
            timestamp=datetime.now(),
            duration=duration,
            success=success,
            error=error
        )
        self.results.append(exec_result)
    
    def add_finding(self, title: str, severity: str, description: str,
                    evidence: Dict = None, recommendations: List[str] = None):
        """添加发现"""
        finding = {
            "id": str(uuid.uuid4())[:8],
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence or {},
            "recommendations": recommendations or [],
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        logger.info(f"会话 {self.id}: 添加发现 - {title} [{severity}]")
    
    def add_note(self, note: str):
        """添加备注"""
        self.notes.append({
            "content": note,
            "timestamp": datetime.now().isoformat()
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "targets": [
                {"value": t.value, "type": t.type, "metadata": t.metadata}
                for t in self.targets
            ],
            "results_count": len(self.results),
            "findings_count": len(self.findings),
            "findings": self.findings,
            "notes": self.notes,
            "metadata": self.metadata
        }
    
    def export_results(self) -> List[Dict[str, Any]]:
        """导出结果"""
        return [
            {
                "tool_name": r.tool_name,
                "params": r.params,
                "result": r.result,
                "timestamp": r.timestamp.isoformat(),
                "duration": r.duration,
                "success": r.success,
                "error": r.error
            }
            for r in self.results
        ]


class SessionManager:
    """会话管理器"""
    
    def __init__(self, storage_path: str = None):
        self._sessions: Dict[str, Session] = {}
        self._storage_path = storage_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "sessions"
        )
        os.makedirs(self._storage_path, exist_ok=True)
        logger.info("会话管理器初始化完成")
    
    def create_session(self, name: str = None) -> Session:
        """创建会话"""
        session_id = str(uuid.uuid4())[:12]
        name = name or f"session_{session_id}"
        
        session = Session(
            id=session_id,
            name=name,
            created_at=datetime.now()
        )
        self._sessions[session_id] = session
        
        logger.info(f"创建会话: {session_id} ({name})")
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """获取会话"""
        return self._sessions.get(session_id)
    
    def list_sessions(self, status: SessionStatus = None) -> List[Dict[str, Any]]:
        """列出会话"""
        sessions = self._sessions.values()
        if status:
            sessions = [s for s in sessions if s.status == status]
        return [s.to_dict() for s in sessions]
    
    def update_session_status(self, session_id: str, status: SessionStatus):
        """更新会话状态"""
        session = self.get_session(session_id)
        if session:
            session.status = status
            logger.info(f"会话 {session_id} 状态更新为: {status.value}")
    
    def delete_session(self, session_id: str):
        """删除会话"""
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info(f"会话已删除: {session_id}")
    
    def get_results(self, session_id: str) -> List[Dict[str, Any]]:
        """获取会话结果"""
        session = self.get_session(session_id)
        if session:
            return session.export_results()
        return []
    
    def _validate_session_id(self, session_id: str) -> bool:
        """验证 Session ID 格式，防止路径遍历"""
        if not session_id:
            return False
        if not SESSION_ID_PATTERN.match(session_id):
            return False
        # 额外检查危险字符
        if '..' in session_id or '/' in session_id or '\\' in session_id:
            return False
        return True

    def _get_safe_filepath(self, session_id: str) -> str:
        """获取安全的文件路径，防止路径遍历"""
        if not self._validate_session_id(session_id):
            raise ValueError(f"无效的 Session ID: {session_id}")

        # 构建路径并验证
        filepath = Path(self._storage_path) / f"{session_id}.json"
        resolved = filepath.resolve()
        storage_resolved = Path(self._storage_path).resolve()

        # 确保路径在存储目录内
        if not str(resolved).startswith(str(storage_resolved)):
            raise ValueError(f"路径遍历攻击检测: {session_id}")

        return str(resolved)

    def save_session(self, session_id: str):
        """保存会话到文件 - 安全版"""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"会话不存在: {session_id}")

        filepath = self._get_safe_filepath(session_id)
        data = {
            **session.to_dict(),
            "results": session.export_results()
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"会话已保存: {filepath}")

    def load_session(self, session_id: str) -> Session:
        """从文件加载会话 - 安全版"""
        filepath = self._get_safe_filepath(session_id)
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"会话文件不存在: {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        session = Session(
            id=data["id"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            status=SessionStatus(data["status"]),
            metadata=data.get("metadata", {})
        )
        
        # 恢复目标
        for t in data.get("targets", []):
            session.add_target(t["value"], t["type"], t.get("metadata"))
        
        # 恢复发现
        session.findings = data.get("findings", [])
        session.notes = data.get("notes", [])
        
        self._sessions[session_id] = session
        logger.info(f"会话已加载: {session_id}")
        
        return session
    
    def get_active_session_count(self) -> int:
        """获取活动会话数"""
        return sum(
            1 for s in self._sessions.values()
            if s.status == SessionStatus.ACTIVE
        )


# ========== HTTP会话管理器 (兼容导出) ==========
from core.session.http_manager import AuthContext, HTTPSessionManager, get_http_session_manager
