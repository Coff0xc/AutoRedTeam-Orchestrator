"""
AutoRedTeam MCP Handlers
模块化的MCP工具处理器

此模块将原 mcp_stdio_server.py 中的工具按功能拆分为独立模块:
- recon_handlers: 侦察工具 (10个)
- detector_factory: 漏洞检测工具 (29个, 工厂模式生成)
- evidence_handlers: 证据验证工具 (1个)
- cve_handlers: CVE相关工具 (8个)
- api_security_handlers: API安全工具 (7个)
- cloud_security_handlers: 云安全工具 (3个)
- supply_chain_handlers: 供应链安全工具 (3个)
- redteam_handlers: 红队工具 (14个)
- orchestration_handlers: 自动化渗透编排工具 (12个)
- lateral_handlers: 横向移动工具 (9个)
- persistence_handlers: 持久化工具 (3个)
- ad_handlers: AD攻击工具 (3个)
- session_handlers: 会话管理工具 (4个)
- report_handlers: 报告工具 (2个)
- ai_handlers: AI辅助工具 (11个)
- misc_handlers: 杂项工具 (5个)
- external_tools_handlers: 外部工具集成 (8个)
- parallel_handlers: 并发扫描工具 (1个)
- knowledge_handlers: 知识图谱工具 (3个)
- mcts_handlers: MCTS攻击规划工具 (1个)
- prompt_handlers: MCP提示模板 (6个)
- resource_handlers: MCP资源端点 (4个)
"""

from __future__ import annotations

import importlib
import sys
from typing import Any, Callable, cast

from core.capability_manifest import (
    CapabilityManifestError,
    get_capability,
    handler_enabled,
    normalize_profile,
)

# 注册函数按名懒加载。safe 档案不会导入只含更高档案 surface 的模块。
_REGISTER_LOADERS = {
    "register_recon_tools": "recon_handlers",
    "register_detector_tools": "detector_factory",
    "register_evidence_tools": "evidence_handlers",
    "register_cve_tools": "cve_handlers",
    "register_api_security_tools": "api_security_handlers",
    "register_cloud_security_tools": "cloud_security_handlers",
    "register_supply_chain_tools": "supply_chain_handlers",
    "register_redteam_tools": "redteam_handlers",
    "register_orchestration_tools": "orchestration_handlers",
    "register_lateral_tools": "lateral_handlers",
    "register_persistence_tools": "persistence_handlers",
    "register_ad_tools": "ad_handlers",
    "register_session_tools": "session_handlers",
    "register_report_tools": "report_handlers",
    "register_ai_tools": "ai_handlers",
    "register_misc_tools": "misc_handlers",
    "register_external_tools": "external_tools_handlers",
    "register_parallel_tools": "parallel_handlers",
    "register_knowledge_tools": "knowledge_handlers",
    "register_mcts_tools": "mcts_handlers",
    "register_prompt_handlers": "prompt_handlers",
    "register_resource_handlers": "resource_handlers",
}

__all__ = [
    "register_recon_tools",
    "register_detector_tools",
    "register_evidence_tools",
    "register_cve_tools",
    "register_api_security_tools",
    "register_cloud_security_tools",
    "register_supply_chain_tools",
    "register_redteam_tools",
    "register_orchestration_tools",
    "register_lateral_tools",
    "register_persistence_tools",
    "register_ad_tools",
    "register_session_tools",
    "register_report_tools",
    "register_ai_tools",
    "register_misc_tools",
    "register_external_tools",
    "register_parallel_tools",
    "register_knowledge_tools",
    "register_mcts_tools",
    "register_prompt_handlers",
    "register_resource_handlers",
]


class _CounterView:
    """Expose live totals while ignoring legacy batch increments."""

    def __init__(self, counter):
        self._counter = counter

    @property
    def counts(self):
        return self._counter.counts

    @property
    def total(self):
        return self._counter.total

    def add(self, category: str, count: int = 1):
        return None

    def summary(self):
        return self._counter.summary()

    def __getattr__(self, name: str):
        return getattr(self._counter, name)


class _ProfileLoggerView:
    """Suppress legacy full-count registration messages for filtered profiles."""

    def __init__(self, logger):
        self._logger = logger

    def info(self, message, *args, **kwargs):
        text = str(message)
        if "已注册" in text or "注册完成" in text:
            return None
        return self._logger.info(message, *args, **kwargs)

    def __getattr__(self, name: str):
        return getattr(self._logger, name)


class _ProfiledMCP:
    """Filter MCP decorators through the capability manifest."""

    def __init__(self, mcp, counter, profile: str, handler: str):
        self._mcp = mcp
        self._counter = counter
        self._profile = profile
        self._handler = handler

    @property
    def capability_profile(self) -> str:
        return self._profile

    def _decorator(
        self,
        kind: str,
        factory: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def apply(func: Callable[..., Any]) -> Callable[..., Any]:
            public_name = kwargs.get("name") or func.__name__
            capability = get_capability(kind, public_name)
            if capability.handler != self._handler:
                raise CapabilityManifestError(
                    f"MCP surface {kind}:{public_name} is assigned to handler "
                    f"{capability.handler!r}, not {self._handler!r}"
                )
            if not capability.allowed_in(self._profile):
                return func

            description = capability.public_description()
            func.__doc__ = description
            if not capability.resident:
                catalog = getattr(self._mcp, "_autort_catalog", None)
                if catalog is None:
                    catalog = {}
                    setattr(self._mcp, "_autort_catalog", catalog)
                catalog[(kind, public_name)] = func
                return func

            call_kwargs = dict(kwargs)
            call_kwargs["description"] = description
            registered = factory(*args, **call_kwargs)(func)
            self._counter.add(capability.category, 1)
            return cast(Callable[..., Any], registered)

        return apply

    def tool(self, *args: Any, **kwargs: Any):
        return self._decorator("tool", self._mcp.tool, *args, **kwargs)

    def prompt(self, *args: Any, **kwargs: Any):
        return self._decorator("prompt", self._mcp.prompt, *args, **kwargs)

    def resource(self, *args: Any, **kwargs: Any):
        return self._decorator("resource", self._mcp.resource, *args, **kwargs)


def __getattr__(name: str) -> Any:
    """按需加载注册函数，避免 import handlers 时拉起全部能力模块。"""
    module_name = _REGISTER_LOADERS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value


def _handler_specs():
    return [
        ("侦察工具", "recon", "register_recon_tools"),
        ("漏洞检测工具", "detector", "register_detector_tools"),
        ("证据验证工具", "evidence", "register_evidence_tools"),
        ("CVE工具", "cve", "register_cve_tools"),
        ("API安全工具", "api_security", "register_api_security_tools"),
        ("云安全工具", "cloud_security", "register_cloud_security_tools"),
        ("供应链安全工具", "supply_chain", "register_supply_chain_tools"),
        ("红队工具", "redteam", "register_redteam_tools"),
        ("自动化渗透编排工具", "orchestration", "register_orchestration_tools"),
        ("横向移动工具", "lateral", "register_lateral_tools"),
        ("持久化工具", "persistence", "register_persistence_tools"),
        ("AD攻击工具", "ad", "register_ad_tools"),
        ("会话管理工具", "session", "register_session_tools"),
        ("报告工具", "report", "register_report_tools"),
        ("AI辅助工具", "ai", "register_ai_tools"),
        ("杂项工具", "misc", "register_misc_tools"),
        ("外部工具集成", "external_tools", "register_external_tools"),
        ("并发扫描", "parallel", "register_parallel_tools"),
        ("知识图谱", "knowledge", "register_knowledge_tools"),
        ("MCTS攻击规划", "mcts", "register_mcts_tools"),
        ("MCP提示模板", "prompts", "register_prompt_handlers"),
        ("MCP资源端点", "resources", "register_resource_handlers"),
    ]


def register_all_handlers(mcp, counter, logger, *, profile: str = "full"):
    """注册所有处理器到MCP服务器

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
        profile: capability profile；省略时保持旧版 full 注册行为
    """
    selected_profile = normalize_profile(profile)
    registration_attr = "_autort_capability_profile"
    registered_profile = vars(mcp).get(registration_attr)
    if registered_profile is not None:
        raise CapabilityManifestError(
            f"MCP instance already registered with profile {registered_profile!r}; "
            "create a new instance to change or repeat registration"
        )
    setattr(mcp, registration_attr, selected_profile)

    counter_view = _CounterView(counter)
    handler_logger = logger if selected_profile == "full" else _ProfileLoggerView(logger)

    for name, handler, register_name in _handler_specs():
        if not handler_enabled(selected_profile, handler):
            continue
        profiled_mcp = _ProfiledMCP(mcp, counter, selected_profile, handler)
        try:
            register_func = getattr(sys.modules[__name__], register_name)
            register_func(profiled_mcp, counter_view, handler_logger)
        except CapabilityManifestError:
            raise
        except ImportError as e:
            # 模块依赖缺失，某些功能可能不可用
            logger.warning("%s注册失败 - 模块导入错误: %s", name, e)
        except AttributeError as e:
            # 注册函数不存在或签名不匹配
            logger.warning("%s注册失败 - 属性错误: %s", name, e)
        except TypeError as e:
            # 参数类型不匹配
            logger.warning("%s注册失败 - 类型错误: %s", name, e)
        except Exception as e:
            # 兜底: 注册过程可能涉及第三方库的各种异常，
            # 为保证其他模块正常注册，此处捕获所有异常
            logger.warning("%s注册失败 - 未预期错误: %s: %s", name, type(e).__name__, e)
