"""
AI辅助工具处理器
包含: smart_analyze, attack_chain_plan, smart_payload, ai_redteam_run_scenario,
     ai_surface_scan_handlers, code_agent_expand_context, ai_redteam_eval_run_state,
     ai_prompt_convert, ai_capability_matrix, skill_catalog, skill_read,
     engage_init, engage_status, engage_next, engage_run
"""

from typing import Any, Dict, Optional

from core.capability_manifest import surface_enabled_for_mcp

from .error_handling import ErrorCategory, extract_target, handle_errors, validate_inputs
from .tooling import no_target_contact, tool


def register_ai_tools(mcp, counter, logger):
    """注册AI辅助工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    registered = 13
    if surface_enabled_for_mcp(mcp, "tool", "smart_analyze"):
        from .ai_scan_handlers import register_ai_scan_tools

        registered += register_ai_scan_tools(mcp, logger)
    if surface_enabled_for_mcp(mcp, "tool", "attack_chain_plan"):
        from .ai_attack_handlers import register_ai_attack_tools

        registered += register_ai_attack_tools(mcp, logger)
    if surface_enabled_for_mcp(mcp, "tool", "engage_run"):
        from .ai_scan_handlers import register_engage_run

        registered += register_engage_run(mcp, logger)

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
        """Agent Skill/插件提示静态盘点 - 发现危险指令和敏感能力边界

        Args:
            path: Skill/插件所在路径 (文件或目录)
        """
        from core.ai_surface import scan_skill_surface

        return scan_skill_surface(path).to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_surface_scan_mcp_config(
        path: str,
        discover: bool = False,
        home: Optional[str] = None,
    ) -> Dict[str, Any]:
        """MCP 配置静态盘点 - 发现泛化命令运行时和敏感 env key

        Args:
            path: MCP 配置文件或所在目录。discover 时作为项目根
            discover: True 时枚举本机客户端配置和 skill 根，不启动 server
            home: 可选库存主目录；默认 AUTORT_INVENTORY_HOME 或用户主目录
        """
        from core.ai_surface import discover_agent_stack, scan_mcp_config

        if discover:
            return discover_agent_stack(home=home, project=path).to_dict()
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
        """本地评测 AgentRunState 或 autort.eval/v1 suite — 不调用模型或目标

        Args:
            run_state: AgentRunState dict，或 schema=autort.eval/v1 的 suite
        """
        from core.ai_redteam import evaluate_eval_document

        return evaluate_eval_document(run_state)

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_prompt_convert(prompt: str, converter: str = "identity") -> Dict[str, Any]:
        """本地 Prompt converter - PyRIT 风格 converter 抽象，不调用模型或目标

        Args:
            prompt: 待转换的 prompt
            converter: converter 名称 (默认 identity，原样返回)
        """
        from core.ai_redteam import convert_prompt

        return convert_prompt(prompt, converter).to_dict()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def ai_capability_matrix() -> Dict[str, Any]:
        """AI red-team 目标能力覆盖矩阵 - 本地只读 capability registry"""
        from core.ai_capabilities import capability_matrix

        return capability_matrix()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def skill_catalog() -> Dict[str, Any]:
        """List pinned SKILL.md packs. Metadata only; no clone, no script execution.

        Returns:
            Pin table: git URL, full sha, license, and Autort tool binds
        """
        from core.skills import list_skill_packs

        return list_skill_packs()

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    async def skill_read(
        path: str,
        pin_id: Optional[str] = None,
        reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Scan a local SKILL.md checkout, then return the body if it is not critical.

        Args:
            path: Local skill module, pack root, SKILL.md, or references/*.md
            pin_id: Optional pin id from skill_catalog
            reference: Optional references/*.md filename inside the module
        """
        from core.skills import read_skill

        return read_skill(path, pin_id=pin_id, reference=reference)

    @tool(mcp)
    @validate_inputs(target="target")
    @handle_errors(logger, category=ErrorCategory.AI, context_extractor=extract_target)
    @no_target_contact("Writes a local engagement file; does not contact the target")
    async def engage_init(
        target: str,
        profile: str = "scan",
        path: str = ".autort/engage.yaml",
        phases: Optional[str] = None,
        hitl: str = "off",
        quick_mode: bool = True,
    ) -> Dict[str, Any]:
        """Create a local authorized engagement. Next step is engage_run or engage_next.

        Args:
            target: Authorized URL or host stored in the engagement file
            profile: scan, active-lab, or full
            path: Engagement YAML path
            phases: Comma-separated recon,detect,verify,export
            hitl: off, approval, or review_edit
            quick_mode: Skip slow recon phases
        """
        from core.engage import init_engagement

        kwargs: Dict[str, Any] = {
            "profile": profile,
            "path": path,
            "hitl": hitl,
            "quick_mode": quick_mode,
        }
        if phases:
            kwargs["phases"] = phases
        return init_engagement(target, **kwargs)

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    @no_target_contact("Reads local engagement state; does not contact the target")
    async def engage_status(path: str = ".autort/engage.yaml") -> Dict[str, Any]:
        """Show engagement config, finding counts, and the next step."""
        from core.engage import engagement_status

        return engagement_status(path)

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.AI)
    @no_target_contact("Plans the next engagement step; does not contact the target")
    async def engage_next(path: str = ".autort/engage.yaml") -> Dict[str, Any]:
        """Return the next gap-filling aggregator step for this engagement."""
        from core.engage import engagement_next

        return engagement_next(path)

    counter.add("ai", registered)
    logger.info("[AI] 已注册 %s 个AI辅助工具", registered)
