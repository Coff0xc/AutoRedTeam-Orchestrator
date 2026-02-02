#!/usr/bin/env python3
"""
知识图谱管理器

提供知识的存储、查询和推理功能
支持两种存储后端：
- 内存存储（默认，无外部依赖）
- Neo4j 存储（可选，需安装 neo4j 驱动）
"""

import json
import threading
import logging
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .models import (
    AttackPath,
    EntityType,
    KnowledgeEntity,
    KnowledgeRelation,
    QueryResult,
    RelationType,
    SimilarityMatch,
)

logger = logging.getLogger(__name__)


class InMemoryGraphStore:
    """内存图存储后端

    轻量级图存储，不依赖外部数据库。
    适用于单次会话或小规模数据。
    """

    def __init__(self):
        self._entities: Dict[str, KnowledgeEntity] = {}
        self._relations: Dict[str, KnowledgeRelation] = {}
        # 索引：type -> entity_ids
        self._type_index: Dict[EntityType, Set[str]] = defaultdict(set)
        # 索引：source_id -> relation_ids
        self._outgoing_index: Dict[str, Set[str]] = defaultdict(set)
        # 索引：target_id -> relation_ids
        self._incoming_index: Dict[str, Set[str]] = defaultdict(set)
        # 索引：property key:value -> entity_ids
        self._property_index: Dict[str, Set[str]] = defaultdict(set)
        # 线程锁
        self._lock = threading.RLock()

    def add_entity(self, entity: KnowledgeEntity) -> str:
        """添加实体"""
        with self._lock:
            self._entities[entity.id] = entity
            self._type_index[entity.type].add(entity.id)

            # 建立属性索引
            for key, value in entity.properties.items():
                idx_key = f"{key}:{value}"
                self._property_index[idx_key].add(entity.id)

            return entity.id

    def get_entity(self, entity_id: str) -> Optional[KnowledgeEntity]:
        """获取实体"""
        return self._entities.get(entity_id)

    def update_entity(self, entity_id: str, properties: Dict[str, Any]) -> bool:
        """更新实体属性"""
        with self._lock:
            entity = self._entities.get(entity_id)
            if not entity:
                return False

            # 清除旧的属性索引
            for key, value in entity.properties.items():
                idx_key = f"{key}:{value}"
                self._property_index[idx_key].discard(entity_id)

            entity.properties.update(properties)
            entity.updated_at = datetime.now()

            # 重建属性索引
            for key, value in entity.properties.items():
                idx_key = f"{key}:{value}"
                self._property_index[idx_key].add(entity_id)

            return True

    def delete_entity(self, entity_id: str) -> bool:
        """删除实体及其关联关系"""
        with self._lock:
            entity = self._entities.get(entity_id)
            if not entity:
                return False

            # 删除关联关系
            for rel_id in list(self._outgoing_index.get(entity_id, set())):
                self._delete_relation(rel_id)
            for rel_id in list(self._incoming_index.get(entity_id, set())):
                self._delete_relation(rel_id)

            # 清除索引
            self._type_index[entity.type].discard(entity_id)
            for key, value in entity.properties.items():
                idx_key = f"{key}:{value}"
                self._property_index[idx_key].discard(entity_id)

            del self._entities[entity_id]
            return True

    def add_relation(self, relation: KnowledgeRelation) -> str:
        """添加关系"""
        with self._lock:
            if relation.source_id not in self._entities:
                raise ValueError("源实体不存在: %s" % relation.source_id)
            if relation.target_id not in self._entities:
                raise ValueError("目标实体不存在: %s" % relation.target_id)
            self._relations[relation.id] = relation
            self._outgoing_index[relation.source_id].add(relation.id)
            self._incoming_index[relation.target_id].add(relation.id)
            return relation.id

    def get_relation(self, relation_id: str) -> Optional[KnowledgeRelation]:
        """获取关系"""
        return self._relations.get(relation_id)

    def _delete_relation(self, relation_id: str) -> bool:
        """删除关系"""
        relation = self._relations.get(relation_id)
        if not relation:
            return False

        self._outgoing_index[relation.source_id].discard(relation_id)
        self._incoming_index[relation.target_id].discard(relation_id)
        del self._relations[relation_id]
        return True

    def find_entities(
        self,
        entity_type: Optional[EntityType] = None,
        properties: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> List[KnowledgeEntity]:
        """查找实体"""
        candidates: Optional[Set[str]] = None

        # 按类型过滤
        if entity_type:
            candidates = self._type_index.get(entity_type, set()).copy()

        # 按属性过滤
        if properties:
            for key, value in properties.items():
                idx_key = f"{key}:{value}"
                prop_ids = self._property_index.get(idx_key, set())

                if candidates is None:
                    candidates = prop_ids.copy()
                else:
                    candidates &= prop_ids

        if candidates is None:
            candidates = set(self._entities.keys())

        entities = [self._entities[eid] for eid in list(candidates)[:limit] if eid in self._entities]
        return entities

    def find_relations(
        self,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        relation_type: Optional[RelationType] = None,
    ) -> List[KnowledgeRelation]:
        """查找关系"""
        if source_id:
            rel_ids = self._outgoing_index.get(source_id, set())
        elif target_id:
            rel_ids = self._incoming_index.get(target_id, set())
        else:
            rel_ids = set(self._relations.keys())

        relations = []
        for rid in rel_ids:
            rel = self._relations.get(rid)
            if rel is None:
                continue
            if relation_type and rel.relation_type != relation_type:
                continue
            if source_id and rel.source_id != source_id:
                continue
            if target_id and rel.target_id != target_id:
                continue
            relations.append(rel)

        return relations

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 5,
        min_confidence: float = 0.5,
    ) -> List[List[Tuple[str, str]]]:
        """查找两点之间的路径 (BFS)

        Returns:
            路径列表，每条路径是 [(entity_id, relation_id), ...] 的序列
        """
        with self._lock:
            if source_id not in self._entities or target_id not in self._entities:
                return []

            queue: deque = deque([[(source_id, "")]])
            found_paths: List[List[Tuple[str, str]]] = []

            while queue:
                path = queue.popleft()
                current_id = path[-1][0]

                # 已到达最大深度，不再扩展
                if len(path) > max_depth + 1:
                    continue

                if current_id == target_id and len(path) > 1:
                    found_paths.append(path)
                    continue  # 不继续扩展已到达目标的路径

                # 获取路径中已经访问过的节点（防止环）
                visited_in_path = {eid for eid, _ in path}

                for rel_id in self._outgoing_index.get(current_id, set()):
                    rel = self._relations.get(rel_id)
                    if rel and rel.confidence >= min_confidence:
                        next_id = rel.target_id
                        # 只检查当前路径内的节点避免环，允许不同路径到达同一节点
                        if next_id not in visited_in_path or next_id == target_id:
                            queue.append(path + [(next_id, rel_id)])

            return found_paths

    def get_neighbors(
        self,
        entity_id: str,
        direction: str = "both",
        relation_type: Optional[RelationType] = None,
    ) -> List[Tuple[KnowledgeEntity, KnowledgeRelation]]:
        """获取邻居节点"""
        neighbors = []

        if direction in ("out", "both"):
            for rel_id in self._outgoing_index.get(entity_id, set()):
                rel = self._relations.get(rel_id)
                if rel and (relation_type is None or rel.relation_type == relation_type):
                    target = self._entities.get(rel.target_id)
                    if target:
                        neighbors.append((target, rel))

        if direction in ("in", "both"):
            for rel_id in self._incoming_index.get(entity_id, set()):
                rel = self._relations.get(rel_id)
                if rel and (relation_type is None or rel.relation_type == relation_type):
                    source = self._entities.get(rel.source_id)
                    if source:
                        neighbors.append((source, rel))

        return neighbors

    @property
    def entity_count(self) -> int:
        """实体总数"""
        return len(self._entities)

    @property
    def relation_count(self) -> int:
        """关系总数"""
        return len(self._relations)

    def clear(self):
        """清空所有数据"""
        self._entities.clear()
        self._relations.clear()
        self._type_index.clear()
        self._outgoing_index.clear()
        self._incoming_index.clear()
        self._property_index.clear()

    def export_to_dict(self) -> Dict[str, Any]:
        """导出为字典（用于序列化）"""
        return {
            "entities": [e.to_dict() for e in self._entities.values()],
            "relations": [r.to_dict() for r in self._relations.values()],
        }


class KnowledgeManager:
    """知识图谱管理器

    提供高层知识管理接口，封装底层图存储操作。

    Usage:
        km = KnowledgeManager()

        # 存储发现
        entity_id = km.store_finding({
            "type": "vulnerability",
            "name": "SQL Injection",
            "target": "https://example.com",
            "severity": "critical"
        })

        # 查询相似目标
        similar = km.find_similar_targets("192.168.1.100")

        # 获取攻击路径
        paths = km.get_attack_paths("target_1", "credential_1")
    """

    MAX_ACTION_HISTORY = 10000

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._store = InMemoryGraphStore()
        self._action_history: List[Dict[str, Any]] = []

        logger.info("知识图谱管理器初始化完成 (内存存储)")

    def _generate_id(self, prefix: str = "e") -> str:
        """生成唯一 ID"""
        return f"{prefix}_{uuid.uuid4().hex[:12]}"

    # ==================== 实体操作 ====================

    def store_target(
        self,
        target: str,
        target_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """存储目标实体"""
        entity_id = self._generate_id("target")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.TARGET,
            name=target,
            properties={
                "target": target,
                "target_type": target_type,
                **(properties or {}),
            },
        )

        self._store.add_entity(entity)
        logger.debug("存储目标: %s (%s)", target, entity_id)
        return entity_id

    def store_service(
        self,
        target_id: str,
        service_name: str,
        port: int,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """存储服务实体并关联到目标"""
        entity_id = self._generate_id("svc")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.SERVICE,
            name=f"{service_name}:{port}",
            properties={
                "service": service_name,
                "port": port,
                **(properties or {}),
            },
        )

        self._store.add_entity(entity)

        # 建立 Target -> Service 关系
        rel_id = self._generate_id("rel")
        relation = KnowledgeRelation(
            id=rel_id,
            source_id=target_id,
            target_id=entity_id,
            relation_type=RelationType.HOSTS,
        )
        self._store.add_relation(relation)

        logger.debug("存储服务: %s:%d (%s)", service_name, port, entity_id)
        return entity_id

    def store_vulnerability(
        self,
        service_id: str,
        vuln_name: str,
        severity: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """存储漏洞实体并关联到服务"""
        entity_id = self._generate_id("vuln")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.VULNERABILITY,
            name=vuln_name,
            properties={
                "severity": severity,
                **(properties or {}),
            },
        )

        self._store.add_entity(entity)

        # 建立 Service -> Vulnerability 关系
        rel_id = self._generate_id("rel")
        relation = KnowledgeRelation(
            id=rel_id,
            source_id=service_id,
            target_id=entity_id,
            relation_type=RelationType.HAS_VULNERABILITY,
        )
        self._store.add_relation(relation)

        logger.debug("存储漏洞: %s (%s)", vuln_name, entity_id)
        return entity_id

    def store_credential(
        self,
        source_id: str,
        credential_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> str:
        """存储凭证实体"""
        entity_id = self._generate_id("cred")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.CREDENTIAL,
            name=f"credential_{credential_type}",
            properties={
                "credential_type": credential_type,
                **(properties or {}),
            },
        )

        self._store.add_entity(entity)

        # 建立来源关系
        rel_id = self._generate_id("rel")
        relation = KnowledgeRelation(
            id=rel_id,
            source_id=entity_id,
            target_id=source_id,
            relation_type=RelationType.OBTAINED_FROM,
        )
        self._store.add_relation(relation)

        logger.debug("存储凭证: %s (%s)", credential_type, entity_id)
        return entity_id

    # ==================== 通用发现存储 ====================

    def store_finding(self, finding: Dict[str, Any], session_id: Optional[str] = None) -> str:
        """存储通用发现

        根据 finding 类型自动选择存储方式

        Args:
            finding: 发现数据，需包含 'type' 字段
            session_id: 关联的会话 ID

        Returns:
            实体 ID
        """
        finding_type = finding.get("type", "unknown")

        if finding_type == "vulnerability":
            return self._store_vuln_finding(finding)
        elif finding_type == "open_port":
            return self._store_port_finding(finding)
        elif finding_type == "credential":
            return self._store_cred_finding(finding)
        else:
            return self._store_generic_finding(finding)

    def _store_vuln_finding(self, finding: Dict) -> str:
        """存储漏洞发现"""
        entity_id = self._generate_id("vuln")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.VULNERABILITY,
            name=finding.get("title", finding.get("name", "Unknown Vulnerability")),
            properties={
                "severity": finding.get("severity", "unknown"),
                "source": finding.get("source", ""),
                "url": finding.get("url", ""),
                "cve_id": finding.get("cve_id", ""),
                "confidence": finding.get("confidence", 0.0),
            },
        )

        self._store.add_entity(entity)
        return entity_id

    def _store_port_finding(self, finding: Dict) -> str:
        """存储端口发现"""
        entity_id = self._generate_id("svc")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.SERVICE,
            name=f"{finding.get('service', 'unknown')}:{finding.get('port', 0)}",
            properties={
                "port": finding.get("port"),
                "service": finding.get("service", ""),
                "state": finding.get("state", "open"),
                "version": finding.get("version", ""),
            },
        )

        self._store.add_entity(entity)
        return entity_id

    def _store_cred_finding(self, finding: Dict) -> str:
        """存储凭证发现"""
        entity_id = self._generate_id("cred")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.CREDENTIAL,
            name=f"credential_{finding.get('source', 'unknown')}",
            properties={
                "source": finding.get("source", ""),
                "credential_type": finding.get("credential_type", "password"),
            },
        )

        self._store.add_entity(entity)
        return entity_id

    def _store_generic_finding(self, finding: Dict) -> str:
        """存储通用发现"""
        entity_id = self._generate_id("find")

        entity = KnowledgeEntity(
            id=entity_id,
            type=EntityType.FINDING,
            name=finding.get("title", finding.get("type", "unknown")),
            properties=finding,
        )

        self._store.add_entity(entity)
        return entity_id

    # ==================== 查询操作 ====================

    def get_entity(self, entity_id: str) -> Optional[KnowledgeEntity]:
        """获取实体"""
        return self._store.get_entity(entity_id)

    def find_targets(self, **filters) -> List[KnowledgeEntity]:
        """查找目标"""
        return self._store.find_entities(
            entity_type=EntityType.TARGET,
            properties=filters if filters else None,
        )

    def find_vulnerabilities(
        self,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[KnowledgeEntity]:
        """查找漏洞"""
        props = {}
        if severity:
            props["severity"] = severity

        return self._store.find_entities(
            entity_type=EntityType.VULNERABILITY,
            properties=props if props else None,
            limit=limit,
        )

    def find_services_for_target(self, target_id: str) -> List[KnowledgeEntity]:
        """查找目标的所有服务"""
        neighbors = self._store.get_neighbors(
            target_id,
            direction="out",
            relation_type=RelationType.HOSTS,
        )
        return [entity for entity, _ in neighbors]

    def find_vulns_for_service(self, service_id: str) -> List[KnowledgeEntity]:
        """查找服务的所有漏洞"""
        neighbors = self._store.get_neighbors(
            service_id,
            direction="out",
            relation_type=RelationType.HAS_VULNERABILITY,
        )
        return [entity for entity, _ in neighbors]

    # ==================== 攻击路径分析 ====================

    def get_attack_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 5,
    ) -> List[AttackPath]:
        """获取攻击路径

        查找从源实体到目标实体的所有可能攻击路径

        Args:
            source_id: 起始实体 ID
            target_id: 目标实体 ID
            max_depth: 最大路径深度

        Returns:
            攻击路径列表
        """
        start_time = time.time()

        raw_paths = self._store.find_paths(source_id, target_id, max_depth)

        attack_paths = []
        for raw_path in raw_paths:
            nodes = []
            edges = []

            for entity_id, rel_id in raw_path:
                entity = self._store.get_entity(entity_id)
                if entity:
                    nodes.append(entity)
                if rel_id:
                    relation = self._store.get_relation(rel_id)
                    if relation:
                        edges.append(relation)

            if nodes:
                success_rate = self._calculate_path_success_rate(edges)
                path = AttackPath(
                    id=self._generate_id("path"),
                    nodes=nodes,
                    edges=edges,
                    success_rate=success_rate,
                )
                attack_paths.append(path)

        # 按成功率排序
        attack_paths.sort(key=lambda p: p.success_rate, reverse=True)

        elapsed = (time.time() - start_time) * 1000
        logger.debug("攻击路径查询: %d 条路径, %.1fms", len(attack_paths), elapsed)

        return attack_paths

    def _calculate_path_success_rate(self, edges: List[KnowledgeRelation]) -> float:
        """计算路径成功率（基于边的置信度）"""
        if not edges:
            return 0.0

        rate = 1.0
        for edge in edges:
            rate *= edge.confidence

        return rate

    # ==================== 相似度查询 ====================

    def find_similar_targets(
        self,
        target: str,
        top_k: int = 5,
    ) -> List[SimilarityMatch]:
        """查找相似目标

        基于属性匹配进行相似度比较

        Args:
            target: 目标标识（IP/域名/URL）
            top_k: 返回前 k 个结果
        """
        all_targets = self._store.find_entities(entity_type=EntityType.TARGET)

        matches = []
        for entity in all_targets:
            score = self._calculate_similarity(target, entity)
            if score > 0:
                matches.append(SimilarityMatch(
                    entity=entity,
                    score=score,
                    matched_properties=self._get_matched_props(target, entity),
                ))

        matches.sort(key=lambda m: m.score, reverse=True)
        return matches[:top_k]

    def _calculate_similarity(self, target: str, entity: KnowledgeEntity) -> float:
        """计算目标相似度"""
        score = 0.0
        entity_target = entity.properties.get("target", "")

        # 完全匹配
        if target == entity_target:
            return 1.0

        # IP 网段匹配
        if self._is_same_subnet(target, entity_target):
            score += 0.7

        # 域名后缀匹配
        if self._has_common_domain(target, entity_target):
            score += 0.5

        # 技术栈匹配
        if entity.properties.get("technologies"):
            score += 0.3

        return min(score, 1.0)

    def _is_same_subnet(self, ip1: str, ip2: str) -> bool:
        """检查是否在同一子网"""
        try:
            parts1 = ip1.split(".")
            parts2 = ip2.split(".")
            if len(parts1) == 4 and len(parts2) == 4:
                return parts1[:3] == parts2[:3]
        except (ValueError, AttributeError):
            pass
        return False

    def _has_common_domain(self, d1: str, d2: str) -> bool:
        """检查是否有共同的域名后缀"""
        try:
            # 提取域名
            for prefix in ("http://", "https://"):
                d1 = d1.replace(prefix, "")
                d2 = d2.replace(prefix, "")

            d1 = d1.split("/")[0]
            d2 = d2.split("/")[0]

            # 移除端口号
            d1 = d1.split(":")[0]
            d2 = d2.split(":")[0]

            # 比较后缀
            parts1 = d1.split(".")
            parts2 = d2.split(".")

            if len(parts1) >= 2 and len(parts2) >= 2:
                return parts1[-2:] == parts2[-2:]
        except (ValueError, AttributeError):
            pass
        return False

    def _get_matched_props(self, target: str, entity: KnowledgeEntity) -> List[str]:
        """获取匹配的属性"""
        matched = []
        if self._is_same_subnet(target, entity.properties.get("target", "")):
            matched.append("subnet")
        if self._has_common_domain(target, entity.properties.get("target", "")):
            matched.append("domain")
        return matched

    # ==================== 动作记录 ====================

    def record_action(
        self,
        action: str,
        state_hash: str,
        success: bool,
        result: Optional[Dict] = None,
    ):
        """记录动作执行结果（用于学习）"""
        if len(self._action_history) >= self.MAX_ACTION_HISTORY:
            self._action_history = self._action_history[-self.MAX_ACTION_HISTORY // 2:]
        self._action_history.append({
            "action": action,
            "state_hash": state_hash,
            "success": success,
            "result": result,
            "timestamp": datetime.now().isoformat(),
        })

    def query_action_success_rate(
        self,
        state_hash: str,
        actions: List[str],
    ) -> Dict[str, float]:
        """查询特定状态下各动作的成功率"""
        rates: Dict[str, float] = {}

        for action in actions:
            relevant = [
                h for h in self._action_history
                if h["action"] == action and h["state_hash"] == state_hash
            ]
            if relevant:
                success_count = sum(1 for h in relevant if h["success"])
                rates[action] = success_count / len(relevant)
            else:
                rates[action] = 0.5  # 无历史数据，默认 50%

        return rates

    # ==================== 统计和导出 ====================

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        entities_by_type = {}
        for entity_type in EntityType:
            count = len(self._store.find_entities(entity_type=entity_type))
            if count > 0:
                entities_by_type[entity_type.value] = count

        return {
            "total_entities": self._store.entity_count,
            "total_relations": self._store.relation_count,
            "entities_by_type": entities_by_type,
            "action_history_size": len(self._action_history),
        }

    def export_graph(self) -> Dict[str, Any]:
        """导出完整图数据"""
        return self._store.export_to_dict()

    def clear(self):
        """清空所有数据"""
        self._store.clear()
        self._action_history.clear()
        logger.info("知识图谱已清空")
