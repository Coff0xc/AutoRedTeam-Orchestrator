"""
AI辅助工具处理器
包含: smart_analyze, attack_chain_plan, smart_payload, ai_redteam_run_scenario,
     ai_surface_scan_handlers, code_agent_expand_context, ai_redteam_eval_run_state,
     ai_prompt_convert, ai_capability_matrix
"""

from typing import Any, Dict, Optional

from core.security import require_dangerous_auth

from .error_handling import ErrorCategory, extract_target, handle_errors, validate_inputs
from .tooling import tool


def register_ai_tools(mcp, counter, logger):
    """注册AI辅助工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @validate_inputs(target="target")
    @handle_errors(logger, category=ErrorCategory.AI, context_extractor=extract_target)
    async def smart_analyze(target: str, context: Optional[str] = None) -> Dict[str, Any]:
        """智能分析 - AI辅助分析目标并推荐测试策略

        Args:
            target: 目标URL
            context: 额外上下文信息

        Returns:
            分析结果和建议
        """
        from core.ai_engine import AIAnalyzer

        analyzer = AIAnalyzer()
        result = analyzer.analyze(target, context)

        return {"success": True, "target": target, "analysis": result}

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_errors(logger, category=ErrorCategory.AI, context_extractor=extract_target)
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

        # 判断目标类型
        if target.startswith(("http://", "https://")):
            urlparse(target)
            target_type = "url"
        elif "." in target and not target.replace(".", "").isdigit():
            target_type = "domain"
        else:
            target_type = "ip"

        # 创建攻击链引擎 (tool_registry 可为 None，引擎会使用内置工具映射)
        engine = AttackChainEngine(tool_registry=None)
        chain = engine.create_chain(target, target_type)

        # 返回攻击链信息
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

        # 使用统一的 Payload 引擎
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

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_redteam_run_scenario(
        scenario: Optional[Dict[str, Any]] = None, scenario_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """AI红队场景 dry-run - 规划 Target/Probe/Strategy/Scorer 组合

        Args:
            scenario: 声明式 AI 红队场景字典
            scenario_path: 本地 YAML/JSON 场景文件路径

        Returns:
            dry-run 计划结果；不会请求目标、调用模型、执行 shell 或扫描器
        """
        from core.ai_redteam import AIRedTeamRunner, Scenario, load_scenario

        if scenario_path:
            scenario_model = load_scenario(scenario_path)
        elif scenario:
            scenario_model = Scenario.from_dict(scenario)
        else:
            raise ValueError("Provide either scenario or scenario_path")

        result = AIRedTeamRunner(scenario_model).run()
        return result.to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_surface_scan_handlers(path: str = "handlers") -> Dict[str, Any]:
        """AI/MCP 工具攻击面静态盘点 - 解析 handler 源码并输出风险边界

        Args:
            path: handler 文件或目录，默认扫描本仓库 handlers/

        Returns:
            静态风险盘点结果；不会导入 handler、注册工具、请求目标或执行 payload
        """
        from core.ai_surface import scan_handler_surface

        return scan_handler_surface(path).to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_surface_scan_skills(path: str) -> Dict[str, Any]:
        """Agent Skill/插件提示静态盘点 - 发现危险指令和敏感能力边界"""
        from core.ai_surface import scan_skill_surface

        return scan_skill_surface(path).to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_surface_scan_mcp_config(path: str) -> Dict[str, Any]:
        """MCP 配置静态盘点 - 发现泛化命令运行时和敏感 env key"""
        from core.ai_surface import scan_mcp_config

        return scan_mcp_config(path).to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def code_agent_expand_context(
        path: str = "core",
        seed: Optional[str] = None,
        file_path: Optional[str] = None,
        line: Optional[int] = None,
        max_depth: int = 2,
    ) -> Dict[str, Any]:
        """代码 Agent 调用链上下文扩展 - 静态 AST 分析和 confidence score

        Args:
            path: Python 文件或目录
            seed: 函数名、qualified name 或 function_id
            file_path: 可选 seed 文件
            line: 可选 seed 行号
            max_depth: caller/callee 扩展深度

        Returns:
            静态调用链上下文、风险证据和 confidence score；不会导入或执行代码
        """
        from core.code_agent import expand_code_context

        return expand_code_context(
            path=path,
            seed=seed,
            file_path=file_path,
            line=line,
            max_depth=max_depth,
        ).to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_redteam_eval_run_state(run_state: Dict[str, Any]) -> Dict[str, Any]:
        """AgentRunState 本地评测 - deterministic agent/tool eval cases"""
        from core.agent_runtime import agent_run_state_from_dict
        from core.ai_redteam import evaluate_run_cases

        return evaluate_run_cases(agent_run_state_from_dict(run_state))

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_prompt_convert(prompt: str, converter: str = "identity") -> Dict[str, Any]:
        """本地 Prompt converter - PyRIT 风格 converter 抽象，不调用模型或目标"""
        from core.ai_redteam import convert_prompt

        return convert_prompt(prompt, converter).to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_capability_matrix() -> Dict[str, Any]:
        """AI red-team 目标能力覆盖矩阵 - 本地只读 capability registry"""
        from core.ai_capabilities import capability_matrix

        return capability_matrix()

    counter.add("ai", 11)
    logger.info("[AI] 已注册 11 个AI辅助工具")
