#!/usr/bin/env python3
"""
工具注册表 - 管理所有红队工具
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """工具类别"""
    # 信息收集
    RECON = "recon"                    # 信息收集
    # 漏洞相关
    VULN_SCAN = "vuln_scan"            # 漏洞扫描
    WEB_ATTACK = "web_attack"          # Web攻击
    NETWORK = "network"                # 网络攻击
    EXPLOIT = "exploit"                # 漏洞利用
    # 后渗透
    POST_EXPLOIT = "post_exploit"      # 后渗透
    CREDENTIAL_ACCESS = "credential_access"  # 凭证访问
    LATERAL_MOVEMENT = "lateral_movement"    # 横向移动
    PERSISTENCE = "persistence"              # 持久化
    # 其他攻击
    SOCIAL = "social"                  # 社会工程
    WIRELESS = "wireless"              # 无线攻击
    CRYPTO = "crypto"                  # 密码攻击
    # 新增类别 (v2.6+)
    CONFIG = "config"                  # 配置管理
    SESSION = "session"                # 会话管理
    TASK = "task"                      # 任务队列
    CVE = "cve"                        # CVE情报
    AI = "ai"                          # AI决策
    PAYLOAD = "payload"                # Payload生成
    PENTEST = "pentest"                # 渗透测试
    API_SECURITY = "api_security"      # API安全 (JWT/CORS/GraphQL/WebSocket)
    SUPPLY_CHAIN = "supply_chain"      # 供应链安全 (SBOM/依赖扫描)
    CLOUD_NATIVE = "cloud_native"      # 云原生安全 (K8s/gRPC)
    EXTERNAL = "external"              # 外部工具集成
    REPORT = "report"                  # 报告生成


@dataclass
class ToolParameter:
    """工具参数定义"""
    name: str
    type: str
    description: str
    required: bool = True
    default: Any = None
    choices: List[Any] = None


@dataclass
class BaseTool(ABC):
    """工具基类"""
    name: str
    description: str
    category: ToolCategory
    parameters: List[ToolParameter] = field(default_factory=list)
    requires_root: bool = False
    timeout: int = 300  # 默认超时5分钟
    
    @abstractmethod
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        """执行工具"""
        pass
    
    def validate_params(self, params: Dict[str, Any]) -> bool:
        """验证参数"""
        for param in self.parameters:
            if param.required and param.name not in params:
                if param.default is None:
                    raise ValueError(f"缺少必需参数: {param.name}")
                params[param.name] = param.default
            
            if param.choices and params.get(param.name) not in param.choices:
                raise ValueError(
                    f"参数 {param.name} 值无效, 可选值: {param.choices}"
                )
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.description,
                    "required": p.required,
                    "default": p.default,
                    "choices": p.choices
                }
                for p in self.parameters
            ],
            "requires_root": self.requires_root,
            "timeout": self.timeout
        }


class ToolRegistry:
    """工具注册表"""
    
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._categories: Dict[ToolCategory, List[str]] = {
            cat: [] for cat in ToolCategory
        }
        logger.info("工具注册表初始化完成")
    
    def register(self, tool: BaseTool):
        """注册工具"""
        if tool.name in self._tools:
            logger.warning(f"工具 {tool.name} 已存在，将被覆盖")
        
        self._tools[tool.name] = tool
        if tool.name not in self._categories[tool.category]:
            self._categories[tool.category].append(tool.name)
        
        logger.info(f"工具已注册: {tool.name} [{tool.category.value}]")
    
    def unregister(self, tool_name: str):
        """注销工具"""
        if tool_name in self._tools:
            tool = self._tools.pop(tool_name)
            self._categories[tool.category].remove(tool_name)
            logger.info(f"工具已注销: {tool_name}")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """获取工具"""
        return self._tools.get(tool_name)
    
    def list_tools(self, category: ToolCategory = None) -> List[Dict[str, Any]]:
        """列出工具"""
        if category:
            tool_names = self._categories.get(category, [])
            return [self._tools[name].to_dict() for name in tool_names]
        return [tool.to_dict() for tool in self._tools.values()]
    
    def get_tools_by_category(self, category: ToolCategory) -> List[BaseTool]:
        """按类别获取工具"""
        tool_names = self._categories.get(category, [])
        return [self._tools[name] for name in tool_names]
    
    def execute(self, tool_name: str, params: Dict[str, Any], 
                session_id: str = None) -> Dict[str, Any]:
        """执行工具"""
        tool = self.get_tool(tool_name)
        if not tool:
            raise ValueError(f"工具不存在: {tool_name}")
        
        # 验证参数
        tool.validate_params(params)
        
        logger.info(f"执行工具: {tool_name}, 参数: {params}")
        
        try:
            result = tool.execute(params, session_id)
            logger.info(f"工具执行成功: {tool_name}")
            return result
        except Exception as e:
            logger.error(f"工具执行失败: {tool_name}, 错误: {str(e)}")
            raise
    
    def search_tools(self, keyword: str) -> List[Dict[str, Any]]:
        """搜索工具"""
        keyword = keyword.lower()
        results = []
        for tool in self._tools.values():
            if (keyword in tool.name.lower() or 
                keyword in tool.description.lower()):
                results.append(tool.to_dict())
        return results
    
    @property
    def tool_count(self) -> int:
        """工具数量"""
        return len(self._tools)
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_tools": self.tool_count,
            "by_category": {
                cat.value: len(tools)
                for cat, tools in self._categories.items()
            }
        }


# ========== FunctionTool: 函数包装器 ==========

class FunctionTool(BaseTool):
    """将普通函数包装为 BaseTool 的适配器

    允许将现有的 @mcp.tool() 函数无缝转换为 BaseTool 子类，
    无需重写整个函数。

    Usage:
        def my_scanner(target: str, ports: str = "1-1000") -> dict:
            ...

        tool = FunctionTool.from_function(
            my_scanner,
            category=ToolCategory.RECON,
            description="端口扫描工具"
        )
        registry.register(tool)
    """

    def __init__(self, name: str, description: str, category: ToolCategory,
                 func: callable, parameters: List[ToolParameter] = None,
                 requires_root: bool = False, timeout: int = 300):
        # 使用 object.__setattr__ 因为 dataclass 可能 frozen
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'description', description)
        object.__setattr__(self, 'category', category)
        object.__setattr__(self, 'parameters', parameters or [])
        object.__setattr__(self, 'requires_root', requires_root)
        object.__setattr__(self, 'timeout', timeout)
        object.__setattr__(self, '_func', func)

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        """执行包装的函数"""
        try:
            # 调用原始函数
            result = self._func(**params)
            return result if isinstance(result, dict) else {"result": result}
        except TypeError as e:
            # 参数不匹配
            return {"success": False, "error": f"参数错误: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    def from_function(cls, func: callable, category: ToolCategory,
                      description: str = None, name: str = None,
                      requires_root: bool = False, timeout: int = 300) -> 'FunctionTool':
        """从函数创建 FunctionTool

        自动从函数签名提取参数信息。

        Args:
            func: 要包装的函数
            category: 工具类别
            description: 工具描述 (默认使用函数 docstring)
            name: 工具名称 (默认使用函数名)
            requires_root: 是否需要 root 权限
            timeout: 超时时间

        Returns:
            FunctionTool 实例
        """
        import inspect

        # 提取函数信息
        tool_name = name or func.__name__
        tool_desc = description or (func.__doc__ or f"{tool_name} 工具").split('\n')[0].strip()

        # 从函数签名提取参数
        sig = inspect.signature(func)
        parameters = []

        for param_name, param in sig.parameters.items():
            if param_name in ('session_id', 'self', 'cls'):
                continue

            # 推断参数类型
            param_type = "str"
            if param.annotation != inspect.Parameter.empty:
                type_map = {
                    str: "str", int: "int", float: "float",
                    bool: "bool", list: "list", dict: "dict"
                }
                param_type = type_map.get(param.annotation, "str")

            # 判断是否必需
            has_default = param.default != inspect.Parameter.empty
            default_value = param.default if has_default else None

            parameters.append(ToolParameter(
                name=param_name,
                type=param_type,
                description=f"参数 {param_name}",
                required=not has_default,
                default=default_value
            ))

        return cls(
            name=tool_name,
            description=tool_desc,
            category=category,
            func=func,
            parameters=parameters,
            requires_root=requires_root,
            timeout=timeout
        )


# ========== MCPBridge: MCP 桥接器 ==========

class MCPBridge:
    """ToolRegistry 与 FastMCP 的桥接器

    支持双向桥接:
    1. Registry → MCP: 将 Registry 中的工具自动注册到 MCP
    2. MCP → Registry: 将 @mcp.tool() 函数转换为 BaseTool 并注册

    Usage:
        from mcp.server.fastmcp import FastMCP
        from core.tool_registry import ToolRegistry, MCPBridge

        mcp = FastMCP("AutoRedTeam")
        registry = ToolRegistry()

        # 将现有 MCP 工具导入 Registry
        bridge = MCPBridge(registry, mcp)

        # 注册新工具到 Registry，同时自动注册到 MCP
        tool = FunctionTool.from_function(my_scanner, ToolCategory.RECON)
        bridge.register_tool(tool)

        # 或批量从函数列表注册
        bridge.register_functions([
            (scanner_func, ToolCategory.RECON),
            (vuln_check, ToolCategory.VULN_SCAN),
        ])
    """

    def __init__(self, registry: ToolRegistry = None, mcp=None):
        """初始化桥接器

        Args:
            registry: ToolRegistry 实例 (如为 None 则创建新实例)
            mcp: FastMCP 实例 (可选，稍后通过 bind_mcp 设置)
        """
        self._registry = registry or ToolRegistry()
        self._mcp = mcp
        self._registered_to_mcp: set = set()  # 已注册到 MCP 的工具名

    @property
    def registry(self) -> ToolRegistry:
        """获取 ToolRegistry 实例"""
        return self._registry

    def bind_mcp(self, mcp):
        """绑定 FastMCP 实例

        Args:
            mcp: FastMCP 实例
        """
        self._mcp = mcp
        logger.info("MCPBridge 已绑定 FastMCP 实例")

    def register_tool(self, tool: BaseTool, register_to_mcp: bool = True):
        """注册工具到 Registry，可选同时注册到 MCP

        Args:
            tool: BaseTool 实例
            register_to_mcp: 是否同时注册到 MCP
        """
        # 注册到 Registry
        self._registry.register(tool)

        # 注册到 MCP
        if register_to_mcp and self._mcp and tool.name not in self._registered_to_mcp:
            self._register_to_mcp(tool)

    def _register_to_mcp(self, tool: BaseTool):
        """将单个工具注册到 MCP"""
        if not self._mcp:
            logger.warning("MCP 未绑定，跳过 MCP 注册")
            return

        # 创建包装函数
        def wrapper(**kwargs):
            return tool.execute(kwargs)

        # 设置函数元数据
        wrapper.__name__ = tool.name
        wrapper.__doc__ = tool.description

        # 使用 MCP 装饰器注册
        try:
            self._mcp.tool()(wrapper)
            self._registered_to_mcp.add(tool.name)
            logger.info(f"工具已注册到 MCP: {tool.name}")
        except Exception as e:
            logger.error(f"MCP 注册失败: {tool.name}, 错误: {e}")

    def register_function(self, func: callable, category: ToolCategory,
                          description: str = None, name: str = None,
                          register_to_mcp: bool = True):
        """将函数注册为工具

        Args:
            func: 要注册的函数
            category: 工具类别
            description: 工具描述
            name: 工具名称
            register_to_mcp: 是否同时注册到 MCP
        """
        tool = FunctionTool.from_function(func, category, description, name)
        self.register_tool(tool, register_to_mcp)

    def register_functions(self, functions: List[tuple], register_to_mcp: bool = True):
        """批量注册函数

        Args:
            functions: [(func, category, description?), ...] 列表
            register_to_mcp: 是否同时注册到 MCP
        """
        for item in functions:
            if len(item) == 2:
                func, category = item
                description = None
            else:
                func, category, description = item[:3]

            self.register_function(func, category, description,
                                   register_to_mcp=register_to_mcp)

    def sync_from_mcp_tools(self, tools_module, category_mapping: Dict[str, ToolCategory] = None):
        """从现有 tools/ 模块同步工具到 Registry

        这个方法允许将现有的 @mcp.tool() 装饰的函数导入到 Registry，
        实现渐进式迁移。

        Args:
            tools_module: tools 模块 (如 from tools import recon_tools)
            category_mapping: {tool_name: ToolCategory} 映射
        """
        import inspect

        category_mapping = category_mapping or {}

        # 遍历模块中的函数
        for name, obj in inspect.getmembers(tools_module):
            if not callable(obj) or name.startswith('_'):
                continue

            # 跳过类和已注册的
            if inspect.isclass(obj) or name in self._registry._tools:
                continue

            # 确定类别
            category = category_mapping.get(name, ToolCategory.RECON)

            try:
                tool = FunctionTool.from_function(obj, category)
                self._registry.register(tool)
                logger.debug(f"从模块同步工具: {name}")
            except Exception as e:
                logger.debug(f"跳过 {name}: {e}")

    def export_stats(self) -> Dict[str, Any]:
        """导出统计信息"""
        registry_stats = self._registry.get_stats()
        return {
            **registry_stats,
            "mcp_registered": len(self._registered_to_mcp),
            "mcp_tools": list(self._registered_to_mcp)
        }


# ========== 全局单例 ==========

_global_registry: Optional[ToolRegistry] = None
_global_bridge: Optional[MCPBridge] = None


def get_registry() -> ToolRegistry:
    """获取全局 ToolRegistry 单例"""
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry


def get_bridge(mcp=None) -> MCPBridge:
    """获取全局 MCPBridge 单例

    Args:
        mcp: FastMCP 实例 (首次调用时设置)
    """
    global _global_bridge
    if _global_bridge is None:
        _global_bridge = MCPBridge(get_registry(), mcp)
    elif mcp and _global_bridge._mcp is None:
        _global_bridge.bind_mcp(mcp)
    return _global_bridge
