"""
知识图谱处理器
提供: kg_store (存储实体), kg_query (查询实体), kg_attack_paths (攻击路径)

授权级别:
- MODERATE: kg_store (写入操作)
- 无: kg_query (只读查询)
- DANGEROUS: kg_attack_paths (攻击路径分析)
"""

from typing import Any, Dict, Optional

# 授权中间件
from core.security import require_dangerous_auth, require_moderate_auth

from .error_handling import ErrorCategory, extract_target, handle_errors
from .tooling import tool

# 模块级单例
_km = None


def _get_km():
    """获取 KnowledgeManager 单例"""
    global _km
    if _km is None:
        from core.knowledge import KnowledgeManager

        _km = KnowledgeManager()
    return _km


def register_knowledge_tools(mcp, counter, logger):
    """注册知识图谱工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @require_moderate_auth
    @handle_errors(logger, ErrorCategory.MISC, extract_target)
    async def kg_store(
        entity_type: str,
        name: str,
        properties: Optional[Dict[str, Any]] = None,
        parent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """向知识图谱存储实体

        根据 entity_type 自动选择存储方式，并可选地关联父实体。

        Args:
            entity_type: 实体类型 ("target", "service", "vulnerability", "credential")
            name: 实体名称
            properties: 附加属性
            parent_id: 关联的父实体ID (service需要target_id, vulnerability需要service_id等)
        """
        km = _get_km()
        props = properties or {}

        if entity_type == "target":
            # store_target(target, target_type, properties)
            target_type = props.pop("target_type", "ip")
            entity_id = km.store_target(name, target_type, props)
        elif entity_type == "service":
            if not parent_id:
                return {
                    "success": False,
                    "error": "service 类型需要 parent_id (target_id)",
                }
            port = props.pop("port", 0)
            entity_id = km.store_service(parent_id, name, int(port), props)
        elif entity_type == "vulnerability":
            if not parent_id:
                return {
                    "success": False,
                    "error": "vulnerability 类型需要 parent_id (service_id)",
                }
            severity = props.pop("severity", "medium")
            entity_id = km.store_vulnerability(parent_id, name, severity, props)
        elif entity_type == "credential":
            if not parent_id:
                return {
                    "success": False,
                    "error": "credential 类型需要 parent_id (source_id)",
                }
            cred_type = props.pop("credential_type", "password")
            entity_id = km.store_credential(parent_id, cred_type, props)
        else:
            # 通用发现存储
            finding = {"type": entity_type, "name": name, **props}
            entity_id = km.store_finding(finding)

        logger.info("知识图谱存储实体: type=%s, name=%s, id=%s", entity_type, name, entity_id)
        return {
            "success": True,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "name": name,
        }

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.MISC, extract_target)
    async def kg_query(
        entity_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """查询知识图谱中的实体

        支持按类型和严重程度过滤，返回匹配的实体列表。

        Args:
            entity_type: 过滤实体类型 ("target", "vulnerability", "service", "credential" 等)
            severity: 漏洞严重程度过滤 (仅对 vulnerability 有效)
            limit: 返回数量上限 (默认50)
        """
        km = _get_km()
        entities = []

        if entity_type == "target":
            entities = km.find_targets()
        elif entity_type == "vulnerability":
            entities = km.find_vulnerabilities(severity=severity, limit=limit)
        elif entity_type is not None:
            # 其他类型通过底层 store 查询
            from core.knowledge import EntityType

            type_map = {
                "service": EntityType.SERVICE,
                "credential": EntityType.CREDENTIAL,
                "technique": EntityType.TECHNIQUE,
                "tool": EntityType.TOOL,
                "finding": EntityType.FINDING,
                "session": EntityType.SESSION,
            }
            et = type_map.get(entity_type)
            if et is None:
                return {
                    "success": False,
                    "error": "未知实体类型: %s" % entity_type,
                }
            entities = km._store.find_entities(entity_type=et, limit=limit)
        else:
            # 未指定类型，返回统计信息 + 所有实体
            stats = km.get_stats()
            all_entities = km._store.find_entities(limit=limit)
            return {
                "success": True,
                "stats": stats,
                "entities": [e.to_dict() for e in all_entities],
                "count": len(all_entities),
            }

        result_list = [e.to_dict() for e in entities[:limit]]
        logger.info("知识图谱查询: type=%s, 返回 %d 条", entity_type, len(result_list))
        return {
            "success": True,
            "entities": result_list,
            "count": len(result_list),
            "entity_type": entity_type,
        }

    @tool(mcp)
    @require_dangerous_auth
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def kg_attack_paths(
        source_id: str,
        target_id: str,
        max_depth: int = 5,
    ) -> Dict[str, Any]:
        """查询两个实体间的攻击路径

        基于知识图谱中的实体关系，使用 BFS 搜索从源实体到目标实体的所有可能攻击路径，
        按成功率降序排列返回。

        Args:
            source_id: 起始实体ID
            target_id: 目标实体ID
            max_depth: 最大路径深度 (默认5)
        """
        km = _get_km()

        # 验证实体存在
        source = km.get_entity(source_id)
        if not source:
            return {"success": False, "error": "源实体不存在: %s" % source_id}

        target = km.get_entity(target_id)
        if not target:
            return {"success": False, "error": "目标实体不存在: %s" % target_id}

        paths = km.get_attack_paths(source_id, target_id, max_depth)

        logger.info(
            "攻击路径查询: %s -> %s, 找到 %d 条路径",
            source_id,
            target_id,
            len(paths),
        )
        return {
            "success": True,
            "source": source.to_dict(),
            "target": target.to_dict(),
            "paths": [p.to_dict() for p in paths],
            "path_count": len(paths),
        }

    counter.add("knowledge", 3)
    logger.info("知识图谱工具注册完成 (3个工具)")
