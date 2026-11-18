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

from typing import Any, Dict

from _version import __version__
from core.capability_manifest import surface_enabled_for_mcp

from .runtime_helpers import (
    complete_handler_runtime_action,
    complete_handler_runtime_payload,
    gate_handler_runtime_action,
)


def _gate_resource_runtime(name: str, inputs: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return gate_handler_runtime_action(
        name,
        inputs=inputs or {},
        risk_level="low",
        source="resource_handler",
        network_policy="deny",
    )


def _complete_resource_runtime(
    gate: Dict[str, Any],
    payload: Dict[str, Any],
    *,
    success: bool = True,
    error: str | None = None,
    summary_keys=(),
) -> Dict[str, Any]:
    if success:
        return complete_handler_runtime_payload(gate, payload, summary_keys=summary_keys)
    payload["runtime"] = complete_handler_runtime_action(
        gate,
        False,
        output={"success": False},
        error=error,
    )
    return payload


def register_resource_handlers(mcp, counter, logger):
    """注册 MCP Resource 处理器

    Args:
        mcp: FastMCP 实例
        counter: ToolCounter 实例
        logger: Logger 实例
    """

    registered = 0
    if surface_enabled_for_mcp(mcp, "resource", "active_sessions"):
        from .resource_scan_handlers import register_active_sessions

        registered += register_active_sessions(mcp, logger)
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
        runtime_gate = _gate_resource_runtime("resource.list_registered_tools")
        try:
            # list_tools 可能返回 awaitable，如果是同步调用则直接用计数
            if hasattr(counter, "counts"):
                payload = {
                    "categories": {k: v for k, v in counter.counts.items() if v > 0},
                    "total": counter.total,
                }
                return _complete_resource_runtime(
                    runtime_gate,
                    payload,
                    summary_keys=["total"],
                )
            return _complete_resource_runtime(
                runtime_gate,
                {"total": "unknown"},
                summary_keys=["total"],
            )
        except Exception as e:
            logger.debug("获取工具列表失败: %s", e)
            return _complete_resource_runtime(
                runtime_gate,
                {"total": "unknown", "error": str(e)},
                success=False,
                error=str(e),
            )

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
        runtime_gate = _gate_resource_runtime("resource.get_security_config")
        config = {
            "version": __version__,
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

        return _complete_resource_runtime(
            runtime_gate,
            config,
            summary_keys=["auth_mode", "tools_registered"],
        )

    counter.add("misc", 1)

    if surface_enabled_for_mcp(mcp, "resource", "payload_library"):
        from .resource_lab_handlers import register_payload_library

        registered += register_payload_library(mcp, logger)
        counter.add("misc", 1)

    logger.info("MCP Resources 注册完成: %s 个资源端点", registered + 2)
