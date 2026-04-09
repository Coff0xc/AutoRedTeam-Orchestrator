#!/usr/bin/env python3
"""
SQLite 持久化后端 — 零依赖攻击面图谱存储

提供与 InMemoryGraphStore 兼容的接口，数据持久化到 SQLite。
"""

import json
import logging
import sqlite3
import uuid
from collections import deque
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SQLiteKnowledgeStore:
    """SQLite 后端的知识图谱存储

    与 InMemoryGraphStore 提供相同的高层接口，但数据落盘到 SQLite。

    Usage:
        store = SQLiteKnowledgeStore("data/knowledge.db")
        eid = store.add_entity("target", "192.168.1.1", {"ip": "192.168.1.1"})
        store.add_relationship(eid, other_id, "hosts")
        paths = store.find_paths(eid, other_id)
        store.close()
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str | Path = "data/knowledge.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()
        logger.info("SQLite 知识图谱初始化: %s", self.db_path)

    # ==================== Schema ====================

    def _init_schema(self):
        """创建表结构"""
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS entities (
                id          TEXT PRIMARY KEY,
                type        TEXT NOT NULL,
                name        TEXT NOT NULL,
                properties  TEXT NOT NULL DEFAULT '{}',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
            CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);

            CREATE TABLE IF NOT EXISTS relationships (
                id          TEXT PRIMARY KEY,
                source_id   TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
                target_id   TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
                rel_type    TEXT NOT NULL,
                properties  TEXT NOT NULL DEFAULT '{}',
                confidence  REAL NOT NULL DEFAULT 1.0,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_id);
            CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_id);
            CREATE INDEX IF NOT EXISTS idx_rel_type   ON relationships(rel_type);

            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,
                target      TEXT,
                started_at  TEXT NOT NULL DEFAULT (datetime('now')),
                status      TEXT NOT NULL DEFAULT 'active'
            );

            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            """
        )
        # 版本标记
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
            ("schema_version", str(self.SCHEMA_VERSION)),
        )
        self._conn.commit()

    # ==================== Entity CRUD ====================

    def add_entity(
        self,
        entity_type: str,
        name: str,
        properties: dict | None = None,
    ) -> str:
        """添加实体，返回 entity_id"""
        entity_id = f"e_{uuid.uuid4().hex[:12]}"
        props_json = json.dumps(properties or {}, ensure_ascii=False)
        self._conn.execute(
            "INSERT INTO entities(id, type, name, properties) VALUES (?, ?, ?, ?)",
            (entity_id, entity_type, name, props_json),
        )
        self._conn.commit()
        logger.debug("SQLite 添加实体: %s (%s)", name, entity_id)
        return entity_id

    def get_entity(self, entity_id: str) -> dict | None:
        """获取实体"""
        row = self._conn.execute(
            "SELECT * FROM entities WHERE id = ?", (entity_id,)
        ).fetchone()
        return self._row_to_entity(row) if row else None

    def update_entity(self, entity_id: str, properties: dict) -> bool:
        """合并更新实体属性"""
        existing = self.get_entity(entity_id)
        if not existing:
            return False
        merged = {**existing["properties"], **properties}
        props_json = json.dumps(merged, ensure_ascii=False)
        self._conn.execute(
            "UPDATE entities SET properties = ?, updated_at = datetime('now') WHERE id = ?",
            (props_json, entity_id),
        )
        self._conn.commit()
        return True

    def delete_entity(self, entity_id: str) -> bool:
        """删除实体（级联删除关联关系）"""
        cur = self._conn.execute("DELETE FROM entities WHERE id = ?", (entity_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def find_entities(
        self,
        entity_type: str | None = None,
        limit: int = 100,
        **filters,
    ) -> list[dict]:
        """查找实体，支持按类型和属性 JSON 过滤"""
        clauses: list[str] = []
        params: list[Any] = []

        if entity_type:
            clauses.append("type = ?")
            params.append(entity_type)

        # 属性过滤: json_extract
        for key, value in filters.items():
            clauses.append("json_extract(properties, ?) = ?")
            params.append(f"$.{key}")
            params.append(value)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM entities {where} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_entity(r) for r in rows]

    # ==================== Relationship CRUD ====================

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        properties: dict | None = None,
        confidence: float = 1.0,
    ) -> str:
        """添加关系，返回 relationship_id"""
        rel_id = f"r_{uuid.uuid4().hex[:12]}"
        props_json = json.dumps(properties or {}, ensure_ascii=False)
        self._conn.execute(
            "INSERT INTO relationships(id, source_id, target_id, rel_type, properties, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rel_id, source_id, target_id, rel_type, props_json, confidence),
        )
        self._conn.commit()
        return rel_id

    def find_relationships(
        self,
        source_id: str | None = None,
        target_id: str | None = None,
        rel_type: str | None = None,
    ) -> list[dict]:
        """查找关系"""
        clauses: list[str] = []
        params: list[Any] = []
        if source_id:
            clauses.append("source_id = ?")
            params.append(source_id)
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        if rel_type:
            clauses.append("rel_type = ?")
            params.append(rel_type)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._conn.execute(
            f"SELECT * FROM relationships {where}", params
        ).fetchall()
        return [self._row_to_rel(r) for r in rows]

    # ==================== Path Discovery (BFS) ====================

    def find_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 5,
    ) -> list[list[dict]]:
        """BFS 查找 source → target 所有路径

        Returns:
            路径列表，每条路径是 [node_dict, ...] 序列
        """
        if not self.get_entity(source_id) or not self.get_entity(target_id):
            return []

        # BFS: queue 元素 = [(entity_id, rel_dict|None), ...]
        queue: deque[list[tuple[str, dict | None]]] = deque([[(source_id, None)]])
        found: list[list[dict]] = []

        while queue:
            path = queue.popleft()
            current_id = path[-1][0]

            if len(path) > max_depth + 1:
                continue

            if current_id == target_id and len(path) > 1:
                # 把 id 序列展开为完整 dict
                result_path: list[dict] = []
                for eid, rel in path:
                    entity = self.get_entity(eid)
                    if entity:
                        node = {**entity}
                        if rel:
                            node["_via_rel"] = rel
                        result_path.append(node)
                found.append(result_path)
                continue

            visited = {eid for eid, _ in path}
            rels = self.find_relationships(source_id=current_id)
            for rel in rels:
                next_id = rel["target_id"]
                if next_id not in visited or next_id == target_id:
                    queue.append(path + [(next_id, rel)])

        return found

    # ==================== Export ====================

    def export_graph(self, fmt: str = "json") -> str:
        """导出完整图

        Args:
            fmt: "json" | "dot"

        Returns:
            序列化字符串
        """
        entities = self.find_entities(limit=100000)
        rels = self.find_relationships()

        if fmt == "dot":
            return self._to_dot(entities, rels)
        return self._to_json(entities, rels)

    def _to_json(self, entities: list[dict], rels: list[dict]) -> str:
        """导出 JSON 格式"""
        return json.dumps(
            {"entities": entities, "relationships": rels},
            ensure_ascii=False,
            indent=2,
            default=str,
        )

    def _to_dot(self, entities: list[dict], rels: list[dict]) -> str:
        """导出 Graphviz DOT 格式"""
        lines = ["digraph KnowledgeGraph {", "  rankdir=LR;", "  node [shape=box];"]

        for e in entities:
            label = f'{e["type"]}\\n{e["name"]}'
            lines.append(f'  "{e["id"]}" [label="{label}"];')

        for r in rels:
            lines.append(
                f'  "{r["source_id"]}" -> "{r["target_id"]}" '
                f'[label="{r["rel_type"]}"];'
            )

        lines.append("}")
        return "\n".join(lines)

    # ==================== Session ====================

    def create_session(self, target: str) -> str:
        """创建扫描会话"""
        session_id = f"s_{uuid.uuid4().hex[:12]}"
        self._conn.execute(
            "INSERT INTO sessions(id, target) VALUES (?, ?)",
            (session_id, target),
        )
        self._conn.commit()
        return session_id

    def get_session(self, session_id: str) -> dict | None:
        """获取会话"""
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    # ==================== Stats & Lifecycle ====================

    @property
    def entity_count(self) -> int:
        """实体总数"""
        row = self._conn.execute("SELECT COUNT(*) FROM entities").fetchone()
        return row[0]

    @property
    def relation_count(self) -> int:
        """关系总数"""
        row = self._conn.execute("SELECT COUNT(*) FROM relationships").fetchone()
        return row[0]

    def clear(self):
        """清空所有数据"""
        self._conn.executescript(
            "DELETE FROM relationships; DELETE FROM entities; DELETE FROM sessions;"
        )
        self._conn.commit()
        logger.info("SQLite 知识图谱已清空")

    def close(self):
        """关闭连接"""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.debug("SQLite 连接已关闭")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ==================== Internal helpers ====================

    @staticmethod
    def _row_to_entity(row: sqlite3.Row) -> dict:
        """sqlite3.Row → dict"""
        return {
            "id": row["id"],
            "type": row["type"],
            "name": row["name"],
            "properties": json.loads(row["properties"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _row_to_rel(row: sqlite3.Row) -> dict:
        """sqlite3.Row → dict"""
        return {
            "id": row["id"],
            "source_id": row["source_id"],
            "target_id": row["target_id"],
            "rel_type": row["rel_type"],
            "properties": json.loads(row["properties"]),
            "confidence": row["confidence"],
            "created_at": row["created_at"],
        }
