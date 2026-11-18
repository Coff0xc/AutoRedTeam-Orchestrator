"""Active-lab AI surfaces. Imported only when the profile allows them."""

from typing import Any, Dict, Optional

from core.security import require_dangerous_auth

from .error_handling import ErrorCategory, extract_target, handle_errors, validate_inputs
from .tooling import no_target_contact, tool


def register_ai_attack_tools(mcp, logger) -> int:
    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_errors(logger, category=ErrorCategory.AI, context_extractor=extract_target)
    @no_target_contact("根据传入的侦察数据规划攻击链，不接触目标")
    async def attack_chain_plan(
        target: str, reconnaissance_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """攻击链规划 - 基于侦察数据规划攻击链

        Args:
            target: 目标URL
            reconnaissance_data: 侦察数据 (可选)

        Returns:
            推荐的攻击链
        """
        from urllib.parse import urlparse

        from core.attack_chain import AttackChainEngine

        if target.startswith(("http://", "https://")):
            urlparse(target)
            target_type = "url"
        elif "." in target and not target.replace(".", "").isdigit():
            target_type = "domain"
        else:
            target_type = "ip"

        engine = AttackChainEngine(tool_registry=None)
        chain = engine.create_chain(target, target_type)

        return {
            "success": True,
            "target": target,
            "target_type": target_type,
            "attack_chain": {
                "id": chain.id,
                "name": chain.name,
                "nodes": [
                    {
                        "id": node.id,
                        "phase": node.phase.value,
                        "technique": node.technique,
                        "tool": node.tool,
                        "params": node.params,
                        "dependencies": node.dependencies,
                    }
                    for node in chain.nodes
                ],
                "total_nodes": len(chain.nodes),
            },
        }

    @tool(mcp)
    @require_dangerous_auth
    @handle_errors(logger, category=ErrorCategory.AI)
    @no_target_contact("从本地 payload 库挑选，不接触目标")
    async def smart_payload(
        vuln_type: str, context: Optional[Dict[str, Any]] = None, waf_detected: bool = False
    ) -> Dict[str, Any]:
        """智能Payload生成 - 根据上下文生成优化的payload

        Args:
            vuln_type: 漏洞类型 (sqli, xss, rce, ssrf, etc.)
            context: 上下文信息 (WAF类型、过滤规则等)
            waf_detected: 是否检测到WAF

        Returns:
            推荐的payloads
        """
        from core.payload import smart_select_payloads

        waf = context.get("waf") if context else None
        payloads = smart_select_payloads(
            vuln_type=vuln_type, waf=waf if waf_detected else None, top_n=20
        )

        return {
            "success": True,
            "vuln_type": vuln_type,
            "payloads": payloads,
            "count": len(payloads),
        }

    return 2
