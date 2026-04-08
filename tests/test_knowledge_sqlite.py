#!/usr/bin/env python3
"""
SQLite 知识图谱后端测试

测试 core/knowledge/storage.py 的 CRUD、路径发现、导出功能
"""

import json

import pytest

from core.knowledge.storage import SQLiteKnowledgeStore


@pytest.fixture
def store(tmp_path):
    """创建临时 SQLite 知识图谱"""
    db_path = tmp_path / "test_knowledge.db"
    s = SQLiteKnowledgeStore(db_path)
    yield s
    s.close()


@pytest.fixture
def populated_store(store):
    """预填充数据的图谱: target -> service -> vuln, target -> port"""
    t_id = store.add_entity("target", "192.168.1.1", {"ip": "192.168.1.1"})
    svc_id = store.add_entity("service", "http:80", {"port": 80})
    vuln_id = store.add_entity("vulnerability", "SQLi", {"severity": "critical"})
    port_id = store.add_entity("port", "443", {"protocol": "tcp"})

    store.add_relationship(t_id, svc_id, "hosts")
    store.add_relationship(svc_id, vuln_id, "has_vulnerability")
    store.add_relationship(t_id, port_id, "has_port")

    return {
        "store": store,
        "target_id": t_id,
        "service_id": svc_id,
        "vuln_id": vuln_id,
        "port_id": port_id,
    }


# ==================== Entity CRUD ====================


class TestEntityCRUD:
    """实体增删改查"""

    def test_add_and_get(self, store):
        eid = store.add_entity("target", "10.0.0.1", {"os": "linux"})
        entity = store.get_entity(eid)

        assert entity is not None
        assert entity["type"] == "target"
        assert entity["name"] == "10.0.0.1"
        assert entity["properties"]["os"] == "linux"

    def test_get_nonexistent(self, store):
        assert store.get_entity("does_not_exist") is None

    def test_update_entity(self, store):
        eid = store.add_entity("service", "ssh:22")
        ok = store.update_entity(eid, {"version": "OpenSSH 8.9"})
        assert ok is True

        entity = store.get_entity(eid)
        assert entity["properties"]["version"] == "OpenSSH 8.9"

    def test_update_nonexistent(self, store):
        assert store.update_entity("nope", {"x": 1}) is False

    def test_delete_entity(self, store):
        eid = store.add_entity("target", "deleteme")
        assert store.delete_entity(eid) is True
        assert store.get_entity(eid) is None

    def test_delete_cascades_relationships(self, store):
        a = store.add_entity("target", "a")
        b = store.add_entity("service", "b")
        store.add_relationship(a, b, "hosts")

        store.delete_entity(a)
        rels = store.find_relationships(source_id=a)
        assert len(rels) == 0

    def test_find_entities_by_type(self, store):
        store.add_entity("target", "t1")
        store.add_entity("target", "t2")
        store.add_entity("service", "s1")

        targets = store.find_entities(entity_type="target")
        assert len(targets) == 2

    def test_find_entities_by_property(self, store):
        store.add_entity("vulnerability", "xss", {"severity": "high"})
        store.add_entity("vulnerability", "sqli", {"severity": "critical"})

        results = store.find_entities(entity_type="vulnerability", severity="critical")
        assert len(results) == 1
        assert results[0]["name"] == "sqli"

    def test_entity_count(self, store):
        assert store.entity_count == 0
        store.add_entity("target", "x")
        assert store.entity_count == 1


# ==================== Relationship ====================


class TestRelationships:
    """关系操作"""

    def test_add_and_find(self, store):
        a = store.add_entity("target", "a")
        b = store.add_entity("service", "b")
        rid = store.add_relationship(a, b, "hosts", confidence=0.9)

        rels = store.find_relationships(source_id=a)
        assert len(rels) == 1
        assert rels[0]["id"] == rid
        assert rels[0]["confidence"] == 0.9

    def test_find_by_type(self, store):
        a = store.add_entity("target", "a")
        b = store.add_entity("service", "b")
        c = store.add_entity("port", "c")
        store.add_relationship(a, b, "hosts")
        store.add_relationship(a, c, "has_port")

        rels = store.find_relationships(rel_type="hosts")
        assert len(rels) == 1

    def test_relation_count(self, populated_store):
        assert populated_store["store"].relation_count == 3


# ==================== Path Discovery ====================


class TestPathDiscovery:
    """BFS 路径发现"""

    def test_direct_path(self, populated_store):
        s = populated_store["store"]
        paths = s.find_paths(
            populated_store["target_id"],
            populated_store["service_id"],
        )
        assert len(paths) >= 1
        assert paths[0][0]["id"] == populated_store["target_id"]

    def test_two_hop_path(self, populated_store):
        s = populated_store["store"]
        paths = s.find_paths(
            populated_store["target_id"],
            populated_store["vuln_id"],
            max_depth=3,
        )
        assert len(paths) >= 1
        # target -> service -> vuln = 3 nodes
        assert len(paths[0]) == 3

    def test_no_path(self, populated_store):
        s = populated_store["store"]
        # vuln -> target 无正向路径
        paths = s.find_paths(
            populated_store["vuln_id"],
            populated_store["target_id"],
        )
        assert len(paths) == 0

    def test_max_depth_respected(self, populated_store):
        s = populated_store["store"]
        paths = s.find_paths(
            populated_store["target_id"],
            populated_store["vuln_id"],
            max_depth=1,
        )
        # target -> vuln 需要 2 跳，max_depth=1 找不到
        assert len(paths) == 0


# ==================== Export ====================


class TestExport:
    """导出功能"""

    def test_export_json(self, populated_store):
        s = populated_store["store"]
        result = s.export_graph("json")
        data = json.loads(result)

        assert "entities" in data
        assert "relationships" in data
        assert len(data["entities"]) == 4
        assert len(data["relationships"]) == 3

    def test_export_dot(self, populated_store):
        s = populated_store["store"]
        result = s.export_graph("dot")

        assert result.startswith("digraph KnowledgeGraph {")
        assert "rankdir=LR" in result
        assert "->" in result
        assert result.strip().endswith("}")


# ==================== Session ====================


class TestSession:
    """会话管理"""

    def test_create_and_get(self, store):
        sid = store.create_session("192.168.1.0/24")
        session = store.get_session(sid)
        assert session is not None
        assert session["target"] == "192.168.1.0/24"
        assert session["status"] == "active"


# ==================== Clear & Context Manager ====================


class TestLifecycle:
    """生命周期"""

    def test_clear(self, populated_store):
        s = populated_store["store"]
        assert s.entity_count > 0
        s.clear()
        assert s.entity_count == 0
        assert s.relation_count == 0

    def test_context_manager(self, tmp_path):
        db_path = tmp_path / "ctx.db"
        with SQLiteKnowledgeStore(db_path) as s:
            s.add_entity("target", "ctx_test")
            assert s.entity_count == 1
        # 连接已关闭，不应再操作


# ==================== KnowledgeManager + SQLite 集成 ====================


class TestKnowledgeManagerSQLite:
    """KnowledgeManager 使用 SQLite 后端"""

    def test_init_sqlite_backend(self, tmp_path):
        from core.knowledge import KnowledgeManager

        db_path = tmp_path / "km.db"
        km = KnowledgeManager(backend="sqlite", db_path=str(db_path))

        assert km.sqlite_store is not None
        assert db_path.exists()
        km.close()

    def test_store_target_persists(self, tmp_path):
        from core.knowledge import KnowledgeManager

        db_path = tmp_path / "persist.db"
        km = KnowledgeManager(backend="sqlite", db_path=str(db_path))
        km.store_target("10.0.0.1", "ip")
        km.close()

        # 重新打开，数据仍在
        store = SQLiteKnowledgeStore(db_path)
        entities = store.find_entities(entity_type="target")
        assert len(entities) >= 1
        assert entities[0]["name"] == "10.0.0.1"
        store.close()

    def test_export_json_format(self, tmp_path):
        from core.knowledge import KnowledgeManager

        db_path = tmp_path / "export.db"
        km = KnowledgeManager(backend="sqlite", db_path=str(db_path))
        km.store_target("example.com", "domain")

        result = km.export_graph(fmt="json")
        assert isinstance(result, str)
        data = json.loads(result)
        assert len(data["entities"]) >= 1
        km.close()

    def test_default_backend_unchanged(self):
        from core.knowledge import KnowledgeManager

        km = KnowledgeManager()
        assert km.sqlite_store is None
