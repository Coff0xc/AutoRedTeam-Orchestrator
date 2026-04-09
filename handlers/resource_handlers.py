"""
MCP Resource 处理器

暴露渗透测试状态数据为 MCP Resources，让 AI 编辑器可以查询上下文。

Resources (4个):
- redteam://sessions: 活跃会话列表
- redteam://session/{session_id}: 会话详情
- redteam://tools: 已注册工具列表
- redteam://config: 当前安全配置
"""

from __future__ import annotations


def register_resource_handlers(mcp, counter, logger):
    """注册 MCP Resource 处理器

    Args:
        mcp: FastMCP 实例
        counter: ToolCounter 实例
        logger: Logger 实例
    """

    @mcp.resource(
        uri="redteam://sessions",
        name="active_sessions",
        title="活跃渗透测试会话",
        description="列出所有活跃的渗透测试会话及其状态",
        mime_type="application/json",
    )
    def list_sessions() -> dict:
        """获取活跃会话列表"""
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            sessions = manager.list_sessions() if hasattr(manager, "list_sessions") else []
            return {
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
        except Exception as e:
            logger.debug("获取会话列表失败: %s", e)
            return {"sessions": [], "count": 0, "note": "会话管理器未初始化"}

    counter.add("misc", 1)

    @mcp.resource(
        uri="redteam://tools",
        name="registered_tools",
        title="已注册 MCP 工具",
        description="列出所有已注册的 AutoRedTeam MCP 工具及其分类",
        mime_type="application/json",
    )
    def list_registered_tools() -> dict:
        """获取已注册工具列表"""
        try:
            # list_tools 可能返回 awaitable，如果是同步调用则直接用计数
            if hasattr(counter, "counts"):
                return {
                    "categories": {k: v for k, v in counter.counts.items() if v > 0},
                    "total": counter.total,
                }
            return {"total": "unknown"}
        except Exception as e:
            logger.debug("获取工具列表失败: %s", e)
            return {"total": "unknown", "error": str(e)}

    counter.add("misc", 1)

    @mcp.resource(
        uri="redteam://config",
        name="security_config",
        title="安全配置",
        description="当前 AutoRedTeam 安全配置（授权模式、速率限制等）",
        mime_type="application/json",
    )
    def get_security_config() -> dict:
        """获取当前安全配置"""
        config = {
            "version": "3.0.2",
            "auth_mode": "unknown",
            "tools_registered": counter.total,
        }

        try:
            from core.security.mcp_auth_middleware import _auth_config

            config["auth_mode"] = _auth_config["mode"].value
        except Exception:
            pass

        try:
            from core.security.mcp_security import RateLimitConfig

            rl = RateLimitConfig()
            config["rate_limit"] = {
                "requests_per_minute": rl.requests_per_minute,
                "requests_per_hour": rl.requests_per_hour,
                "burst_limit": rl.burst_limit,
            }
        except Exception:
            pass

        return config

    counter.add("misc", 1)

    @mcp.resource(
        uri="redteam://payloads/{category}",
        name="payload_library",
        title="Payload 库",
        description="按分类获取 payload 列表 (sqli, xss, ssti, cmd_injection, path_traversal)",
        mime_type="application/json",
    )
    def get_payloads(category: str) -> dict:
        """按分类获取 payload 列表"""
        try:
            from core.detectors.payloads import PayloadManager

            manager = PayloadManager()
            payloads = manager.get_payloads(category) if hasattr(manager, "get_payloads") else []
            return {
                "category": category,
                "payloads": payloads[:50],  # 限制返回数量
                "count": len(payloads),
            }
        except Exception as e:
            logger.debug("获取 payload 列表失败: %s", e)
            # 回退: 返回分类描述
            categories = {
                "sqli": "SQL Injection payloads",
                "xss": "Cross-Site Scripting payloads",
                "ssti": "Server-Side Template Injection payloads",
                "cmd_injection": "Command Injection payloads",
                "path_traversal": "Path Traversal payloads",
            }
            return {
                "category": category,
                "description": categories.get(category, f"Unknown category: {category}"),
                "payloads": [],
                "count": 0,
            }

    counter.add("misc", 1)

    logger.info("MCP Resources 注册完成: 4 个资源端点")
