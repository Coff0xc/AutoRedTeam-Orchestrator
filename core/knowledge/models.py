#!/usr/bin/env python3
"""
知识图谱数据模型

定义知识图谱中的实体、关系和查询结果类型
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class EntityType(Enum):
    """实体类型"""

    TARGET = "target"  # 目标（IP/域名/URL）
    SERVICE = "service"  # 服务（HTTP/SSH/FTP等）
    VULNERABILITY = "vulnerability"  # 漏洞
    CREDENTIAL = "credential"  # 凭证
    TECHNIQUE = "technique"  # 攻击技术
    TOOL = "tool"  # 工具
    FINDING = "finding"  # 发现
    SESSION = "session"  # 会话


class RelationType(Enum):
    """关系类型"""

    # 目标关系
    HOSTS = "hosts"  # Target -> Service
    RESOLVES_TO = "resolves_to"  # Domain -> IP

    # 漏洞关系
    HAS_VULNERABILITY = "has_vulnerability"  # Service -> Vulnerability
    EXPLOITS = "exploits"  # Technique -> Vulnerability
    FIXED_BY = "fixed_by"  # Vulnerability -> Patch

    # 攻击关系
    LEADS_TO = "leads_to"  # Vulnerability -> Access
    REQUIRES = "requires"  # Technique -> Prerequisite
    USES = "uses"  # Technique -> Tool

    # 凭证关系
    GRANTS_ACCESS = "grants_access"  # Credential -> Target
    OBTAINED_FROM = "obtained_from"  # Credential -> Source

    # 会话关系
    DISCOVERED_IN = "discovered_in"  # Finding -> Session
    TARGETS = "targets"  # Session -> Target


class Severity(Enum):
    """严重程度"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class KnowledgeEntity:
    """知识实体"""

    id: str
    type: EntityType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    embeddings: Optional[List[float]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "properties": self.properties,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KnowledgeEntity":
        """从字典创建"""
        return cls(
            id=data["id"],
            type=EntityType(data["type"]),
            name=data["name"],
            properties=data.get("properties", {}),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"])
            if "updated_at" in data
            else datetime.now(),
            metadata=data.get("metadata", {}),
        )


@dataclass
class KnowledgeRelation:
    """知识关系"""

    id: str
    source_id: str
    target_id: str
    relation_type: RelationType
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "properties": self.properties,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KnowledgeRelation":
        """从字典创建"""
        return cls(
            id=data["id"],
            source_id=data["source_id"],
            target_id=data["target_id"],
            relation_type=RelationType(data["relation_type"]),
            properties=data.get("properties", {}),
            confidence=data.get("confidence", 1.0),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else datetime.now(),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AttackPath:
    """攻击路径"""

    id: str
    nodes: List[KnowledgeEntity]
    edges: List[KnowledgeRelation]
    success_rate: float = 0.0
    estimated_time: float = 0.0  # 分钟
    required_tools: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        """路径长度"""
        return len(self.nodes)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "success_rate": self.success_rate,
            "estimated_time": self.estimated_time,
            "required_tools": self.required_tools,
            "prerequisites": self.prerequisites,
            "length": self.length,
        }


@dataclass
class QueryResult:
    """查询结果"""

    entities: List[KnowledgeEntity] = field(default_factory=list)
    relations: List[KnowledgeRelation] = field(default_factory=list)
    paths: List[AttackPath] = field(default_factory=list)
    total_count: int = 0
    query_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "entities": [e.to_dict() for e in self.entities],
            "relations": [r.to_dict() for r in self.relations],
            "paths": [p.to_dict() for p in self.paths],
            "total_count": self.total_count,
            "query_time_ms": self.query_time_ms,
        }


@dataclass
class SimilarityMatch:
    """相似度匹配结果"""

    entity: KnowledgeEntity
    score: float
    matched_properties: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "entity": self.entity.to_dict(),
            "score": self.score,
            "matched_properties": self.matched_properties,
        }
