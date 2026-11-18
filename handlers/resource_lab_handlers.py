"""Active-lab resource surfaces. Imported only when the profile allows them."""

from .resource_handlers import _complete_resource_runtime, _gate_resource_runtime


def register_payload_library(mcp, logger) -> int:
    @mcp.resource(
        uri="redteam://payloads/{category}",
        name="payload_library",
        title="Payload 库",
        description="按分类获取 payload 列表 (sqli, xss, ssti, cmd_injection, path_traversal)",
        mime_type="application/json",
    )
    def get_payloads(category: str) -> dict:
        """按分类获取 payload 列表"""
        runtime_gate = _gate_resource_runtime(
            "resource.get_payloads",
            {"category": category},
        )
        try:
            from core.detectors.payloads import PayloadManager

            manager = PayloadManager()
            payloads = manager.get_payloads(category) if hasattr(manager, "get_payloads") else []
            payload = {
                "category": category,
                "payloads": payloads[:50],  # 限制返回数量
                "count": len(payloads),
            }
            return _complete_resource_runtime(
                runtime_gate,
                payload,
                summary_keys=["category", "count"],
            )
        except Exception as e:
            logger.debug("获取 payload 列表失败: %s", e)
            categories = {
                "sqli": "SQL Injection payloads",
                "xss": "Cross-Site Scripting payloads",
                "ssti": "Server-Side Template Injection payloads",
                "cmd_injection": "Command Injection payloads",
                "path_traversal": "Path Traversal payloads",
            }
            return _complete_resource_runtime(
                runtime_gate,
                {
                    "category": category,
                    "description": categories.get(category, f"Unknown category: {category}"),
                    "payloads": [],
                    "count": 0,
                },
                success=False,
                error=str(e),
                summary_keys=["category", "count"],
            )

    return 1
