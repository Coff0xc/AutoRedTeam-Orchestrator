#!/usr/bin/env python3
"""
知识图谱模块

提供知识的存储、查询和攻击路径推理功能

Usage:
    from core.knowledge import KnowledgeManager

    km = KnowledgeManager()
    km.store_target("192.168.1.1", "ip")
    km.store_finding({"type": "vulnerability", "name": "SQLi", "severity": "critical"})
"""

from .manager import KnowledgeManager, InMemoryGraphStore
from .models import (
    AttackPath,
    EntityType,
    KnowledgeEntity,
    KnowledgeRelation,
    QueryResult,
    RelationType,
    Severity,
    SimilarityMatch,
)

__all__ = [
    "KnowledgeManager",
    "InMemoryGraphStore",
    "KnowledgeEntity",
    "KnowledgeRelation",
    "EntityType",
    "RelationType",
    "Severity",
    "AttackPath",
    "QueryResult",
    "SimilarityMatch",
]
