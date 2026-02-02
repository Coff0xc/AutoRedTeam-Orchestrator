#!/usr/bin/env python3
"""
知识图谱模块测试

测试 core/knowledge/ 的所有核心功能
"""

import pytest
from datetime import datetime

from core.knowledge import (
    KnowledgeManager,
    InMemoryGraphStore,
    KnowledgeEntity,
    KnowledgeRelation,
    EntityType,
    RelationType,
    Severity,
    AttackPath,
    QueryResult,
    SimilarityMatch,
)


# ==================== 数据模型测试 ====================


class TestEntityType:
    """EntityType 枚举测试"""

    def test_all_types_exist(self):
        assert EntityType.TARGET.value == "target"
        assert EntityType.SERVICE.value == "service"
        assert EntityType.VULNERABILITY.value == "vulnerability"
        assert EntityType.CREDENTIAL.value == "credential"
        assert EntityType.TECHNIQUE.value == "technique"
        assert EntityType.TOOL.value == "tool"
        assert EntityType.FINDING.value == "finding"
        assert EntityType.SESSION.value == "session"

    def test_type_count(self):
        assert len(EntityType) == 8


class TestRelationType:
    """RelationType 枚举测试"""

    def test_all_types_exist(self):
        assert RelationType.HOSTS.value == "hosts"
        assert RelationType.HAS_VULNERABILITY.value == "has_vulnerability"
        assert RelationType.LEADS_TO.value == "leads_to"
        assert RelationType.GRANTS_ACCESS.value == "grants_access"

    def test_type_count(self):
        assert len(RelationType) == 12


class TestSeverity:
    """Severity 枚举测试"""

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestKnowledgeEntity:
    """KnowledgeEntity 数据类测试"""

    def test_creation(self):
        entity = KnowledgeEntity(
            id="e_001",
            type=EntityType.TARGET,
            name="192.168.1.1",
            properties={"target_type": "ip"},
        )
        assert entity.id == "e_001"
        assert entity.type == EntityType.TARGET
        assert entity.name == "192.168.1.1"
        assert entity.properties["target_type"] == "ip"

    def test_defaults(self):
        entity = KnowledgeEntity(
            id="e_002", type=EntityType.SERVICE, name="http:80"
        )
        assert entity.properties == {}
        assert entity.metadata == {}
        assert entity.embeddings is None
        assert isinstance(entity.created_at, datetime)

    def test_to_dict(self):
        entity = KnowledgeEntity(
            id="e_003",
            type=EntityType.VULNERABILITY,
            name="SQLi",
            properties={"severity": "critical"},
        )
        d = entity.to_dict()
        assert d["id"] == "e_003"
        assert d["type"] == "vulnerability"
        assert d["name"] == "SQLi"
        assert d["properties"]["severity"] == "critical"
        assert "created_at" in d

    def test_from_dict(self):
        data = {
            "id": "e_004",
            "type": "target",
            "name": "example.com",
            "properties": {"target_type": "domain"},
            "created_at": "2026-01-15T10:00:00",
            "updated_at": "2026-01-15T10:00:00",
        }
        entity = KnowledgeEntity.from_dict(data)
        assert entity.id == "e_004"
        assert entity.type == EntityType.TARGET
        assert entity.name == "example.com"

    def test_from_dict_missing_timestamps(self):
        data = {"id": "e_005", "type": "service", "name": "ssh:22"}
        entity = KnowledgeEntity.from_dict(data)
        assert isinstance(entity.created_at, datetime)

    def test_roundtrip(self):
        original = KnowledgeEntity(
            id="e_006",
            type=EntityType.TOOL,
            name="nmap",
            properties={"version": "7.94"},
            metadata={"source": "recon"},
        )
        d = original.to_dict()
        restored = KnowledgeEntity.from_dict(d)
        assert restored.id == original.id
        assert restored.type == original.type
        assert restored.name == original.name
        assert restored.properties == original.properties


class TestKnowledgeRelation:
    """KnowledgeRelation 数据类测试"""

    def test_creation(self):
        rel = KnowledgeRelation(
            id="r_001",
            source_id="e_001",
            target_id="e_002",
            relation_type=RelationType.HOSTS,
        )
        assert rel.source_id == "e_001"
        assert rel.target_id == "e_002"
        assert rel.relation_type == RelationType.HOSTS
        assert rel.confidence == 1.0

    def test_to_dict(self):
        rel = KnowledgeRelation(
            id="r_002",
            source_id="s1",
            target_id="t1",
            relation_type=RelationType.HAS_VULNERABILITY,
            confidence=0.9,
        )
        d = rel.to_dict()
        assert d["relation_type"] == "has_vulnerability"
        assert d["confidence"] == 0.9

    def test_from_dict(self):
        data = {
            "id": "r_003",
            "source_id": "s2",
            "target_id": "t2",
            "relation_type": "leads_to",
            "confidence": 0.75,
            "created_at": "2026-01-15T10:00:00",
        }
        rel = KnowledgeRelation.from_dict(data)
        assert rel.relation_type == RelationType.LEADS_TO
        assert rel.confidence == 0.75

    def test_roundtrip(self):
        original = KnowledgeRelation(
            id="r_004",
            source_id="a",
            target_id="b",
            relation_type=RelationType.EXPLOITS,
            confidence=0.85,
            properties={"method": "rce"},
        )
        d = original.to_dict()
        restored = KnowledgeRelation.from_dict(d)
        assert restored.relation_type == original.relation_type
        assert restored.confidence == original.confidence


class TestAttackPath:
    """AttackPath 数据类测试"""

    def test_length_property(self):
        nodes = [
            KnowledgeEntity(id="n1", type=EntityType.TARGET, name="t1"),
            KnowledgeEntity(id="n2", type=EntityType.SERVICE, name="s1"),
            KnowledgeEntity(id="n3", type=EntityType.VULNERABILITY, name="v1"),
        ]
        path = AttackPath(id="p_001", nodes=nodes, edges=[])
        assert path.length == 3

    def test_empty_path(self):
        path = AttackPath(id="p_002", nodes=[], edges=[])
        assert path.length == 0
        assert path.success_rate == 0.0

    def test_to_dict(self):
        nodes = [
            KnowledgeEntity(id="n1", type=EntityType.TARGET, name="t1"),
        ]
        path = AttackPath(
            id="p_003",
            nodes=nodes,
            edges=[],
            success_rate=0.8,
            required_tools=["nmap"],
        )
        d = path.to_dict()
        assert d["success_rate"] == 0.8
        assert d["length"] == 1
        assert d["required_tools"] == ["nmap"]


class TestQueryResult:
    """QueryResult 数据类测试"""

    def test_defaults(self):
        result = QueryResult()
        assert result.entities == []
        assert result.relations == []
        assert result.paths == []
        assert result.total_count == 0

    def test_to_dict(self):
        result = QueryResult(total_count=5, query_time_ms=1.5)
        d = result.to_dict()
        assert d["total_count"] == 5
        assert d["query_time_ms"] == 1.5


class TestSimilarityMatch:
    """SimilarityMatch 数据类测试"""

    def test_creation(self):
        entity = KnowledgeEntity(id="e1", type=EntityType.TARGET, name="t1")
        match = SimilarityMatch(
            entity=entity, score=0.85, matched_properties=["subnet"]
        )
        assert match.score == 0.85
        assert "subnet" in match.matched_properties


# ==================== InMemoryGraphStore 测试 ====================


class TestInMemoryGraphStore:
    """内存图存储测试"""

    @pytest.fixture
    def store(self):
        return InMemoryGraphStore()

    @pytest.fixture
    def populated_store(self, store):
        """预填充的图存储"""
        e1 = KnowledgeEntity(
            id="t1", type=EntityType.TARGET, name="192.168.1.1",
            properties={"target_type": "ip"},
        )
        e2 = KnowledgeEntity(
            id="s1", type=EntityType.SERVICE, name="http:80",
            properties={"port": 80, "service": "http"},
        )
        e3 = KnowledgeEntity(
            id="v1", type=EntityType.VULNERABILITY, name="SQLi",
            properties={"severity": "critical"},
        )
        store.add_entity(e1)
        store.add_entity(e2)
        store.add_entity(e3)

        r1 = KnowledgeRelation(
            id="r1", source_id="t1", target_id="s1",
            relation_type=RelationType.HOSTS,
        )
        r2 = KnowledgeRelation(
            id="r2", source_id="s1", target_id="v1",
            relation_type=RelationType.HAS_VULNERABILITY,
        )
        store.add_relation(r1)
        store.add_relation(r2)
        return store

    # --- 实体操作 ---

    def test_add_and_get_entity(self, store):
        entity = KnowledgeEntity(
            id="e1", type=EntityType.TARGET, name="test"
        )
        store.add_entity(entity)
        retrieved = store.get_entity("e1")
        assert retrieved is not None
        assert retrieved.name == "test"

    def test_get_nonexistent_entity(self, store):
        assert store.get_entity("nonexistent") is None

    def test_update_entity(self, store):
        entity = KnowledgeEntity(
            id="e1", type=EntityType.TARGET, name="test",
            properties={"status": "pending"},
        )
        store.add_entity(entity)
        result = store.update_entity("e1", {"status": "done", "extra": "val"})
        assert result is True

        updated = store.get_entity("e1")
        assert updated.properties["status"] == "done"
        assert updated.properties["extra"] == "val"

    def test_update_nonexistent_entity(self, store):
        assert store.update_entity("nope", {"a": 1}) is False

    def test_delete_entity(self, populated_store):
        store = populated_store
        assert store.entity_count == 3
        result = store.delete_entity("v1")
        assert result is True
        assert store.entity_count == 2
        assert store.get_entity("v1") is None

    def test_delete_entity_removes_relations(self, populated_store):
        store = populated_store
        # s1 有入边 r1 和出边 r2
        store.delete_entity("s1")
        assert store.relation_count == 0  # r1 和 r2 都应被删除

    def test_delete_nonexistent_entity(self, store):
        assert store.delete_entity("nope") is False

    # --- 关系操作 ---

    def test_add_and_get_relation(self, store):
        # 先创建实体，因为add_relation会验证实体存在
        entity_a = KnowledgeEntity(id="a", type=EntityType.TARGET, name="A")
        entity_b = KnowledgeEntity(id="b", type=EntityType.SERVICE, name="B")
        store.add_entity(entity_a)
        store.add_entity(entity_b)
        
        rel = KnowledgeRelation(
            id="r1", source_id="a", target_id="b",
            relation_type=RelationType.HOSTS,
        )
        store.add_relation(rel)
        retrieved = store.get_relation("r1")
        assert retrieved is not None
        assert retrieved.source_id == "a"

    def test_get_nonexistent_relation(self, store):
        assert store.get_relation("nope") is None

    # --- 查找操作 ---

    def test_find_entities_by_type(self, populated_store):
        targets = populated_store.find_entities(entity_type=EntityType.TARGET)
        assert len(targets) == 1
        assert targets[0].id == "t1"

    def test_find_entities_by_property(self, populated_store):
        results = populated_store.find_entities(
            properties={"severity": "critical"}
        )
        assert len(results) == 1
        assert results[0].id == "v1"

    def test_find_entities_by_type_and_property(self, populated_store):
        results = populated_store.find_entities(
            entity_type=EntityType.SERVICE,
            properties={"port": 80},
        )
        assert len(results) == 1

    def test_find_entities_no_match(self, populated_store):
        results = populated_store.find_entities(
            properties={"severity": "low"}
        )
        assert len(results) == 0

    def test_find_entities_all(self, populated_store):
        all_entities = populated_store.find_entities()
        assert len(all_entities) == 3

    def test_find_entities_with_limit(self, populated_store):
        results = populated_store.find_entities(limit=1)
        assert len(results) == 1

    def test_find_relations_by_source(self, populated_store):
        rels = populated_store.find_relations(source_id="t1")
        assert len(rels) == 1
        assert rels[0].relation_type == RelationType.HOSTS

    def test_find_relations_by_target(self, populated_store):
        rels = populated_store.find_relations(target_id="v1")
        assert len(rels) == 1
        assert rels[0].relation_type == RelationType.HAS_VULNERABILITY

    def test_find_relations_by_type(self, populated_store):
        rels = populated_store.find_relations(
            relation_type=RelationType.HOSTS
        )
        assert len(rels) == 1

    def test_find_relations_all(self, populated_store):
        rels = populated_store.find_relations()
        assert len(rels) == 2

    # --- 路径查找 ---

    def test_find_paths_simple(self, populated_store):
        paths = populated_store.find_paths("t1", "v1")
        assert len(paths) == 1
        assert len(paths[0]) == 3  # t1 -> s1 -> v1

    def test_find_paths_no_path(self, populated_store):
        paths = populated_store.find_paths("v1", "t1")
        assert len(paths) == 0  # 反向无路径

    def test_find_paths_nonexistent_nodes(self, store):
        paths = store.find_paths("a", "b")
        assert len(paths) == 0

    def test_find_paths_with_max_depth(self, populated_store):
        paths = populated_store.find_paths("t1", "v1", max_depth=1)
        assert len(paths) == 0  # t1->v1 需要 2 步，depth=1 不够

    def test_find_paths_confidence_filter(self, store):
        e1 = KnowledgeEntity(id="a", type=EntityType.TARGET, name="a")
        e2 = KnowledgeEntity(id="b", type=EntityType.SERVICE, name="b")
        store.add_entity(e1)
        store.add_entity(e2)

        rel = KnowledgeRelation(
            id="r1", source_id="a", target_id="b",
            relation_type=RelationType.HOSTS, confidence=0.3,
        )
        store.add_relation(rel)

        # 置信度阈值 0.5，0.3 的边不通过
        paths = store.find_paths("a", "b", min_confidence=0.5)
        assert len(paths) == 0

        # 降低阈值
        paths = store.find_paths("a", "b", min_confidence=0.2)
        assert len(paths) == 1

    # --- 邻居查询 ---

    def test_get_neighbors_out(self, populated_store):
        neighbors = populated_store.get_neighbors("t1", direction="out")
        assert len(neighbors) == 1
        entity, rel = neighbors[0]
        assert entity.id == "s1"

    def test_get_neighbors_in(self, populated_store):
        neighbors = populated_store.get_neighbors("s1", direction="in")
        assert len(neighbors) == 1
        entity, rel = neighbors[0]
        assert entity.id == "t1"

    def test_get_neighbors_both(self, populated_store):
        neighbors = populated_store.get_neighbors("s1", direction="both")
        assert len(neighbors) == 2  # t1(in) + v1(out)

    def test_get_neighbors_with_type_filter(self, populated_store):
        neighbors = populated_store.get_neighbors(
            "s1", direction="both",
            relation_type=RelationType.HOSTS,
        )
        assert len(neighbors) == 1

    def test_get_neighbors_no_neighbors(self, populated_store):
        neighbors = populated_store.get_neighbors("v1", direction="out")
        assert len(neighbors) == 0

    # --- 统计和清空 ---

    def test_entity_count(self, populated_store):
        assert populated_store.entity_count == 3

    def test_relation_count(self, populated_store):
        assert populated_store.relation_count == 2

    def test_clear(self, populated_store):
        populated_store.clear()
        assert populated_store.entity_count == 0
        assert populated_store.relation_count == 0

    def test_export_to_dict(self, populated_store):
        data = populated_store.export_to_dict()
        assert len(data["entities"]) == 3
        assert len(data["relations"]) == 2


# ==================== KnowledgeManager 测试 ====================


class TestKnowledgeManager:
    """KnowledgeManager 高层接口测试"""

    @pytest.fixture
    def km(self):
        return KnowledgeManager()

    # --- 目标存储 ---

    def test_store_target(self, km):
        tid = km.store_target("192.168.1.1", "ip")
        assert tid.startswith("target_")

        entity = km.get_entity(tid)
        assert entity is not None
        assert entity.type == EntityType.TARGET
        assert entity.properties["target"] == "192.168.1.1"
        assert entity.properties["target_type"] == "ip"

    def test_store_target_with_properties(self, km):
        tid = km.store_target(
            "example.com", "domain",
            properties={"scope": "external"},
        )
        entity = km.get_entity(tid)
        assert entity.properties["scope"] == "external"

    # --- 服务存储 ---

    def test_store_service(self, km):
        tid = km.store_target("192.168.1.1", "ip")
        sid = km.store_service(tid, "http", 80)
        assert sid.startswith("svc_")

        entity = km.get_entity(sid)
        assert entity.type == EntityType.SERVICE
        assert entity.properties["port"] == 80

    def test_store_service_creates_relation(self, km):
        tid = km.store_target("192.168.1.1", "ip")
        sid = km.store_service(tid, "ssh", 22)

        services = km.find_services_for_target(tid)
        assert len(services) == 1
        assert services[0].id == sid

    # --- 漏洞存储 ---

    def test_store_vulnerability(self, km):
        tid = km.store_target("192.168.1.1", "ip")
        sid = km.store_service(tid, "http", 80)
        vid = km.store_vulnerability(sid, "SQL Injection", "critical")
        assert vid.startswith("vuln_")

        entity = km.get_entity(vid)
        assert entity.type == EntityType.VULNERABILITY
        assert entity.properties["severity"] == "critical"

    def test_store_vulnerability_creates_relation(self, km):
        tid = km.store_target("10.0.0.1", "ip")
        sid = km.store_service(tid, "http", 80)
        vid = km.store_vulnerability(sid, "XSS", "high")

        vulns = km.find_vulns_for_service(sid)
        assert len(vulns) == 1
        assert vulns[0].id == vid

    # --- 凭证存储 ---

    def test_store_credential(self, km):
        tid = km.store_target("192.168.1.1", "ip")
        cid = km.store_credential(tid, "password", {"username": "admin"})
        assert cid.startswith("cred_")

        entity = km.get_entity(cid)
        assert entity.type == EntityType.CREDENTIAL
        assert entity.properties["username"] == "admin"

    # --- 通用发现存储 ---

    def test_store_finding_vulnerability(self, km):
        fid = km.store_finding({
            "type": "vulnerability",
            "name": "SSRF",
            "severity": "high",
        })
        entity = km.get_entity(fid)
        assert entity.type == EntityType.VULNERABILITY

    def test_store_finding_open_port(self, km):
        fid = km.store_finding({
            "type": "open_port",
            "port": 443,
            "service": "https",
        })
        entity = km.get_entity(fid)
        assert entity.type == EntityType.SERVICE
        assert entity.properties["port"] == 443

    def test_store_finding_credential(self, km):
        fid = km.store_finding({
            "type": "credential",
            "source": "config_file",
        })
        entity = km.get_entity(fid)
        assert entity.type == EntityType.CREDENTIAL

    def test_store_finding_generic(self, km):
        fid = km.store_finding({
            "type": "information",
            "title": "Server header",
            "value": "Apache/2.4",
        })
        entity = km.get_entity(fid)
        assert entity.type == EntityType.FINDING

    def test_store_finding_unknown_type(self, km):
        fid = km.store_finding({"title": "Something"})
        entity = km.get_entity(fid)
        assert entity.type == EntityType.FINDING

    # --- 查询操作 ---

    def test_find_targets(self, km):
        km.store_target("192.168.1.1", "ip")
        km.store_target("10.0.0.1", "ip")
        km.store_target("example.com", "domain")

        targets = km.find_targets()
        assert len(targets) == 3

    def test_find_targets_with_filter(self, km):
        km.store_target("192.168.1.1", "ip")
        km.store_target("example.com", "domain")

        targets = km.find_targets(target_type="ip")
        assert len(targets) == 1
        assert targets[0].properties["target"] == "192.168.1.1"

    def test_find_vulnerabilities(self, km):
        tid = km.store_target("10.0.0.1", "ip")
        sid = km.store_service(tid, "http", 80)
        km.store_vulnerability(sid, "SQLi", "critical")
        km.store_vulnerability(sid, "XSS", "high")
        km.store_vulnerability(sid, "Info Disclosure", "low")

        all_vulns = km.find_vulnerabilities()
        assert len(all_vulns) == 3

    def test_find_vulnerabilities_by_severity(self, km):
        tid = km.store_target("10.0.0.1", "ip")
        sid = km.store_service(tid, "http", 80)
        km.store_vulnerability(sid, "SQLi", "critical")
        km.store_vulnerability(sid, "XSS", "high")

        critical = km.find_vulnerabilities(severity="critical")
        assert len(critical) == 1
        assert critical[0].name == "SQLi"

    def test_find_services_for_target(self, km):
        tid = km.store_target("10.0.0.1", "ip")
        km.store_service(tid, "http", 80)
        km.store_service(tid, "ssh", 22)
        km.store_service(tid, "mysql", 3306)

        services = km.find_services_for_target(tid)
        assert len(services) == 3

    def test_find_vulns_for_service(self, km):
        tid = km.store_target("10.0.0.1", "ip")
        sid = km.store_service(tid, "http", 80)
        km.store_vulnerability(sid, "SQLi", "critical")
        km.store_vulnerability(sid, "XSS", "medium")

        vulns = km.find_vulns_for_service(sid)
        assert len(vulns) == 2

    # --- 攻击路径 ---

    def test_get_attack_paths(self, km):
        tid = km.store_target("10.0.0.1", "ip")
        sid = km.store_service(tid, "http", 80)
        vid = km.store_vulnerability(sid, "RCE", "critical")

        paths = km.get_attack_paths(tid, vid)
        assert len(paths) == 1
        assert paths[0].length == 3  # target -> service -> vuln

    def test_get_attack_paths_no_path(self, km):
        tid1 = km.store_target("10.0.0.1", "ip")
        tid2 = km.store_target("10.0.0.2", "ip")

        paths = km.get_attack_paths(tid1, tid2)
        assert len(paths) == 0

    def test_attack_path_success_rate(self, km):
        """攻击路径的成功率基于边的置信度"""
        tid = km.store_target("10.0.0.1", "ip")
        sid = km.store_service(tid, "http", 80)
        vid = km.store_vulnerability(sid, "RCE", "critical")

        paths = km.get_attack_paths(tid, vid)
        assert len(paths) == 1
        # 默认置信度 1.0，所以 success_rate = 1.0 * 1.0 = 1.0
        assert paths[0].success_rate == 1.0

    # --- 相似度查询 ---

    def test_find_similar_targets_same_subnet(self, km):
        km.store_target("192.168.1.1", "ip")
        km.store_target("192.168.1.2", "ip")
        km.store_target("10.0.0.1", "ip")

        matches = km.find_similar_targets("192.168.1.100")
        # 192.168.1.1 和 192.168.1.2 应匹配
        subnet_matches = [m for m in matches if "subnet" in m.matched_properties]
        assert len(subnet_matches) == 2

    def test_find_similar_targets_same_domain(self, km):
        km.store_target("sub1.example.com", "domain")
        km.store_target("sub2.example.com", "domain")
        km.store_target("other.test.org", "domain")

        matches = km.find_similar_targets("api.example.com")
        domain_matches = [m for m in matches if "domain" in m.matched_properties]
        assert len(domain_matches) == 2

    def test_find_similar_targets_exact_match(self, km):
        km.store_target("192.168.1.1", "ip")
        matches = km.find_similar_targets("192.168.1.1")
        assert len(matches) == 1
        assert matches[0].score == 1.0

    def test_find_similar_targets_no_match(self, km):
        km.store_target("192.168.1.1", "ip")
        matches = km.find_similar_targets("completely-different")
        assert len(matches) == 0

    def test_find_similar_targets_top_k(self, km):
        for i in range(10):
            km.store_target(f"192.168.1.{i}", "ip")

        matches = km.find_similar_targets("192.168.1.100", top_k=3)
        assert len(matches) <= 3

    # --- 动作记录 ---

    def test_record_action(self, km):
        km.record_action("nmap_scan", "state_abc", True, {"ports": [80]})
        km.record_action("nmap_scan", "state_abc", False, None)

        stats = km.get_stats()
        assert stats["action_history_size"] == 2

    def test_query_action_success_rate(self, km):
        km.record_action("scan", "s1", True)
        km.record_action("scan", "s1", True)
        km.record_action("scan", "s1", False)
        km.record_action("exploit", "s1", False)

        rates = km.query_action_success_rate("s1", ["scan", "exploit"])
        assert abs(rates["scan"] - 2 / 3) < 0.01
        assert rates["exploit"] == 0.0

    def test_query_action_success_rate_no_history(self, km):
        rates = km.query_action_success_rate("unknown", ["scan"])
        assert rates["scan"] == 0.5  # 默认 50%

    # --- 统计和导出 ---

    def test_get_stats(self, km):
        km.store_target("10.0.0.1", "ip")
        tid = km.store_target("10.0.0.2", "ip")
        km.store_service(tid, "http", 80)

        stats = km.get_stats()
        assert stats["total_entities"] == 3
        assert stats["total_relations"] == 1
        assert stats["entities_by_type"]["target"] == 2
        assert stats["entities_by_type"]["service"] == 1

    def test_get_stats_empty(self, km):
        stats = km.get_stats()
        assert stats["total_entities"] == 0
        assert stats["total_relations"] == 0

    def test_export_graph(self, km):
        km.store_target("10.0.0.1", "ip")
        data = km.export_graph()
        assert "entities" in data
        assert "relations" in data
        assert len(data["entities"]) == 1

    def test_clear(self, km):
        km.store_target("10.0.0.1", "ip")
        km.record_action("test", "s1", True)

        km.clear()

        stats = km.get_stats()
        assert stats["total_entities"] == 0
        assert stats["action_history_size"] == 0

    # --- ID 生成 ---

    def test_generate_unique_ids(self, km):
        ids = set()
        for _ in range(100):
            tid = km.store_target("test", "ip")
            ids.add(tid)
        assert len(ids) == 100  # 全部唯一

    # --- 完整流程测试 ---

    def test_full_pentest_workflow(self, km):
        """模拟完整渗透测试流程的知识图谱使用"""
        # 1. 存储目标
        tid = km.store_target("192.168.1.100", "ip")

        # 2. 发现服务
        sid_http = km.store_service(tid, "http", 80)
        sid_ssh = km.store_service(tid, "ssh", 22)
        sid_mysql = km.store_service(tid, "mysql", 3306)

        # 3. 发现漏洞
        vid_sqli = km.store_vulnerability(sid_http, "SQL Injection", "critical")
        vid_xss = km.store_vulnerability(sid_http, "XSS", "medium")

        # 4. 获取凭证
        cid = km.store_credential(
            tid, "password",
            properties={"username": "root", "hash": "abc123"},
        )

        # 5. 验证统计
        stats = km.get_stats()
        assert stats["total_entities"] == 7  # 1 target + 3 services + 2 vulns + 1 cred
        # target->http, target->ssh, target->mysql = 3 HOSTS
        # http->sqli, http->xss = 2 HAS_VULNERABILITY
        # cred->target = 1 OBTAINED_FROM
        assert stats["total_relations"] == 6

        # 6. 查询攻击路径
        paths = km.get_attack_paths(tid, vid_sqli)
        assert len(paths) == 1
        assert paths[0].length == 3

        # 7. 查找所有服务
        services = km.find_services_for_target(tid)
        assert len(services) == 3

        # 8. 查找所有漏洞
        vulns = km.find_vulns_for_service(sid_http)
        assert len(vulns) == 2

        # 9. 相似目标查找
        km.store_target("192.168.1.101", "ip")
        similar = km.find_similar_targets("192.168.1.200")
        assert len(similar) >= 2

    def test_multiple_targets_workflow(self, km):
        """多目标工作流测试"""
        targets = []
        for i in range(5):
            tid = km.store_target(f"10.0.0.{i + 1}", "ip")
            targets.append(tid)
            sid = km.store_service(tid, "http", 80)
            if i % 2 == 0:
                km.store_vulnerability(sid, f"Vuln-{i}", "high")

        stats = km.get_stats()
        assert stats["total_entities"] == 5 + 5 + 3  # 5 targets + 5 services + 3 vulns
        assert stats["entities_by_type"]["target"] == 5
        assert stats["entities_by_type"]["vulnerability"] == 3
