"""Scan-profile resource surfaces. Imported only when the profile allows them."""

from .resource_handlers import _complete_resource_runtime, _gate_resource_runtime


def register_active_sessions(mcp, logger) -> int:
    @mcp.resource(
        uri="redteam://sessions",
        name="active_sessions",
        title="活跃渗透测试会话",
        description="列出所有活跃的渗透测试会话及其状态",
        mime_type="application/json",
    )
    def list_sessions() -> dict:
        """获取活跃会话列表"""
        runtime_gate = _gate_resource_runtime("resource.list_sessions")
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            sessions = manager.list_sessions() if hasattr(manager, "list_sessions") else []
            payload = {
                "sessions": [
                    {
                        "session_id": s.session_id if hasattr(s, "session_id") else str(s),
                        "target": s.target if hasattr(s, "target") else "unknown",
                        "status": s.status if hasattr(s, "status") else "unknown",
                    }
                    for s in sessions
                ],
                "count": len(sessions),
            }
            return _complete_resource_runtime(
                runtime_gate,
                payload,
                summary_keys=["count"],
            )
        except Exception as e:
            logger.debug("获取会话列表失败: %s", e)
            return _complete_resource_runtime(
                runtime_gate,
                {"sessions": [], "count": 0, "note": "会话管理器未初始化"},
                success=False,
                error=str(e),
            )

    return 1
