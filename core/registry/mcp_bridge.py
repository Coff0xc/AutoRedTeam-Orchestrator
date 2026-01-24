#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MCP协议桥接模块

提供ToolRegistry与FastMCP的双向桥接，支持批量注册和工具同步。
"""

from __future__ import annotations

import logging
import asyncio
import functools
from typing import (
    Any, Callable, Dict, List, Optional, Set, Type, TYPE_CHECKING
)
from dataclasses import dataclass, field

from .categories import ToolCategory
from .base import BaseTool, FunctionTool, ToolMetadata, ToolParameter, ToolResult

if TYPE_CHECKING:
    from .registry import ToolRegistry


logger = logging.getLogger(__name__)


@dataclass
class MCPToolSchema:
    """MCP工具Schema

    描述MCP协议所需的工具Schema格式。

    Attributes:
        name: 工具名称
        description: 工具描述
        inputSchema: 输入参数的JSON Schema
    """
    name: str
    description: str
    inputSchema: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            Schema字典
        """
        return {
            'name': self.name,
            'description': self.description,
            'inputSchema': self.inputSchema,
        }


class MCPBridge:
    """MCP协议桥接器

    实现ToolRegistry与FastMCP之间的双向桥接：
    1. Registry → MCP: 将Registry中的工具自动注册到MCP
    2. MCP → Registry: 将@mcp.tool()函数转换为BaseTool并注册

    Usage:
        from mcp.server.fastmcp import FastMCP
        from core.registry import ToolRegistry, MCPBridge

        mcp = FastMCP("AutoRedTeam")
        registry = ToolRegistry()

        # 创建桥接器
        bridge = MCPBridge(mcp, registry)

        # 从注册表批量注册到MCP
        count = bridge.register_from_registry()

        # 或者同时注册到两边
        bridge.register_function(my_scanner, ToolCategory.RECON)
    """

    def __init__(
        self,
        mcp_server: Any = None,
        registry: Optional['ToolRegistry'] = None
    ):
        """初始化桥接器

        Args:
            mcp_server: FastMCP服务器实例
            registry: ToolRegistry实例 (如为None则使用全局单例)
        """
        self._mcp = mcp_server
        self._registry = registry
        self._registered_tools: Set[str] = set()
        self._pending_tools: List[BaseTool] = []

    @property
    def mcp(self) -> Any:
        """获取MCP服务器实例"""
        return self._mcp

    @property
    def registry(self) -> 'ToolRegistry':
        """获取注册表实例"""
        if self._registry is None:
            from .registry import get_registry
            self._registry = get_registry()
        return self._registry

    def bind_mcp(self, mcp_server: Any) -> None:
        """绑定MCP服务器

        Args:
            mcp_server: FastMCP服务器实例
        """
        self._mcp = mcp_server
        logger.info("MCPBridge已绑定MCP服务器")

        # 注册之前挂起的工具
        if self._pending_tools:
            for tool in self._pending_tools:
                self._register_to_mcp(tool)
            self._pending_tools.clear()

    def register_from_registry(
        self,
        categories: Optional[List[ToolCategory]] = None,
        exclude: Optional[List[str]] = None
    ) -> int:
        """从注册表批量注册工具到MCP

        Args:
            categories: 只注册指定分类的工具
            exclude: 排除的工具名列表

        Returns:
            成功注册的工具数量
        """
        if not self._mcp:
            logger.warning("MCP服务器未绑定，跳过注册")
            return 0

        exclude = set(exclude or [])
        count = 0

        for name in self.registry.list_tools():
            if name in exclude:
                continue

            if name in self._registered_tools:
                continue

            tool = self.registry.get(name)
            if not tool:
                continue

            # 分类过滤
            if categories and tool.metadata.category not in categories:
                continue

            try:
                self._register_to_mcp(tool)
                count += 1
            except Exception as e:
                logger.error(f"注册工具到MCP失败: {name}, 错误: {e}")

        logger.info(f"从注册表同步 {count} 个工具到MCP")
        return count

    def register_tool(
        self,
        tool: BaseTool,
        to_registry: bool = True,
        to_mcp: bool = True
    ) -> None:
        """注册工具

        Args:
            tool: 工具实例
            to_registry: 是否注册到Registry
            to_mcp: 是否注册到MCP
        """
        name = tool.metadata.name

        # 注册到Registry
        if to_registry:
            self.registry.register(tool)

        # 注册到MCP
        if to_mcp:
            if self._mcp:
                self._register_to_mcp(tool)
            else:
                # MCP未绑定，加入挂起列表
                self._pending_tools.append(tool)
                logger.debug(f"工具 {name} 加入挂起队列，等待MCP绑定")

    def register_function(
        self,
        fn: Callable,
        category: ToolCategory,
        name: Optional[str] = None,
        description: Optional[str] = None,
        to_registry: bool = True,
        to_mcp: bool = True,
        **kwargs
    ) -> BaseTool:
        """注册函数为工具

        Args:
            fn: 要注册的函数
            category: 工具分类
            name: 工具名称
            description: 工具描述
            to_registry: 是否注册到Registry
            to_mcp: 是否注册到MCP
            **kwargs: 额外的元数据属性

        Returns:
            创建的工具实例
        """
        tool = FunctionTool.from_function(
            fn,
            category=category,
            name=name,
            description=description,
            **kwargs
        )
        self.register_tool(tool, to_registry=to_registry, to_mcp=to_mcp)
        return tool

    def _register_to_mcp(self, tool: BaseTool) -> None:
        """将工具注册到MCP

        Args:
            tool: 工具实例
        """
        if not self._mcp:
            raise RuntimeError("MCP服务器未绑定")

        name = tool.metadata.name
        if name in self._registered_tools:
            logger.debug(f"工具 {name} 已注册到MCP，跳过")
            return

        # 创建MCP包装函数
        wrapper = self._create_mcp_wrapper(tool)

        # 设置函数元数据
        wrapper.__name__ = name
        wrapper.__doc__ = tool.metadata.description

        # 使用MCP装饰器注册
        try:
            self._mcp.tool(name=name, description=tool.metadata.description)(wrapper)
            self._registered_tools.add(name)
            logger.debug(f"工具已注册到MCP: {name}")
        except Exception as e:
            logger.error(f"MCP注册失败: {name}, 错误: {e}")
            raise

    def _create_mcp_wrapper(self, tool: BaseTool) -> Callable:
        """创建MCP包装函数

        Args:
            tool: 工具实例

        Returns:
            包装函数
        """
        # 判断工具是否支持异步
        if tool.metadata.async_support:
            @functools.wraps(tool.execute)
            async def async_wrapper(**kwargs) -> Any:
                result = await tool.async_execute(**kwargs)
                return self._format_mcp_result(result)
            return async_wrapper
        else:
            @functools.wraps(tool.execute)
            def sync_wrapper(**kwargs) -> Any:
                result = tool.execute(**kwargs)
                return self._format_mcp_result(result)
            return sync_wrapper

    def _format_mcp_result(self, result: ToolResult) -> Any:
        """格式化MCP返回结果

        Args:
            result: 工具执行结果

        Returns:
            格式化后的结果
        """
        if result.success:
            return result.data
        else:
            # 对于错误，返回包含错误信息的字典
            return {
                'success': False,
                'error': result.error,
                'data': result.data,
            }

    def get_mcp_schema(self, tool: BaseTool) -> MCPToolSchema:
        """获取工具的MCP Schema

        Args:
            tool: 工具实例

        Returns:
            MCP Schema对象
        """
        return MCPToolSchema(
            name=tool.metadata.name,
            description=tool.metadata.description,
            inputSchema=tool.get_schema(),
        )

    def get_all_schemas(self) -> List[MCPToolSchema]:
        """获取所有已注册工具的MCP Schema

        Returns:
            MCP Schema列表
        """
        schemas = []
        for name in self._registered_tools:
            tool = self.registry.get(name)
            if tool:
                schemas.append(self.get_mcp_schema(tool))
        return schemas

    @property
    def registered_count(self) -> int:
        """已注册到MCP的工具数量"""
        return len(self._registered_tools)

    @property
    def registered_tools(self) -> List[str]:
        """已注册到MCP的工具名列表"""
        return list(self._registered_tools)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息字典
        """
        return {
            'registry_count': len(self.registry),
            'mcp_registered': self.registered_count,
            'pending_count': len(self._pending_tools),
            'mcp_bound': self._mcp is not None,
        }


# ============ 便捷函数 ============

def create_mcp_tool(
    mcp_server: Any,
    name: str,
    description: str,
    category: ToolCategory,
    parameters: Optional[List[ToolParameter]] = None,
    **kwargs
) -> Callable:
    """创建MCP工具装饰器

    同时注册到全局Registry和MCP。

    Usage:
        @create_mcp_tool(mcp, 'port_scan', '端口扫描', ToolCategory.PORT_SCAN)
        def port_scan(target: str, ports: str = "1-1000") -> dict:
            ...

    Args:
        mcp_server: FastMCP服务器实例
        name: 工具名称
        description: 工具描述
        category: 工具分类
        parameters: 参数列表
        **kwargs: 额外的元数据属性

    Returns:
        装饰器函数
    """
    def decorator(fn: Callable) -> Callable:
        from .registry import get_registry

        # 创建元数据
        params = parameters
        if params is None:
            params = FunctionTool._infer_parameters(fn)

        metadata = ToolMetadata(
            name=name,
            description=description,
            category=category,
            parameters=params,
            **kwargs
        )

        # 创建工具并注册
        tool = FunctionTool(fn, metadata)
        get_registry().register(tool)

        # 注册到MCP
        if mcp_server:
            bridge = get_global_bridge()
            if bridge._mcp is None:
                bridge.bind_mcp(mcp_server)
            bridge._register_to_mcp(tool)

        return fn

    return decorator


def mcp_tool(
    category: ToolCategory,
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable:
    """简化的MCP工具装饰器

    仅注册到Registry，延迟注册到MCP（需要后续调用bridge.register_from_registry）。

    Usage:
        @mcp_tool(ToolCategory.RECON)
        def my_scanner(target: str) -> dict:
            '''扫描目标'''
            ...

    Args:
        category: 工具分类
        name: 工具名称 (默认使用函数名)
        description: 工具描述 (默认使用docstring)
        **kwargs: 额外的元数据属性

    Returns:
        装饰器函数
    """
    def decorator(fn: Callable) -> Callable:
        from .registry import get_registry

        tool = FunctionTool.from_function(
            fn,
            category=category,
            name=name,
            description=description,
            **kwargs
        )
        get_registry().register(tool)

        # 保存工具引用
        fn._tool = tool

        return fn

    return decorator


# ============ 全局桥接器 ============

_global_bridge: Optional[MCPBridge] = None


def get_global_bridge(mcp_server: Any = None) -> MCPBridge:
    """获取全局MCPBridge实例

    Args:
        mcp_server: FastMCP服务器实例 (首次调用时设置)

    Returns:
        全局MCPBridge实例
    """
    global _global_bridge
    if _global_bridge is None:
        _global_bridge = MCPBridge(mcp_server)
    elif mcp_server and _global_bridge._mcp is None:
        _global_bridge.bind_mcp(mcp_server)
    return _global_bridge


def reset_global_bridge() -> None:
    """重置全局桥接器

    警告: 仅用于测试！
    """
    global _global_bridge
    _global_bridge = None


class MCPToolBuilder:
    """MCP工具构建器

    提供流式API创建和注册MCP工具。

    Usage:
        tool = (MCPToolBuilder('port_scan')
            .description('端口扫描工具')
            .category(ToolCategory.PORT_SCAN)
            .param('target', ParamType.IP, '目标IP', required=True)
            .param('ports', ParamType.PORT_RANGE, '端口范围', default='1-1000')
            .timeout(120)
            .handler(scan_ports)
            .build())
    """

    def __init__(self, name: str):
        """初始化构建器

        Args:
            name: 工具名称
        """
        self._name = name
        self._description = ''
        self._category = ToolCategory.MISC
        self._parameters: List[ToolParameter] = []
        self._timeout = 60.0
        self._tags: List[str] = []
        self._handler: Optional[Callable] = None
        self._async_support = True
        self._requires_auth = False
        self._examples: List[Dict] = []

    def description(self, desc: str) -> 'MCPToolBuilder':
        """设置描述"""
        self._description = desc
        return self

    def category(self, cat: ToolCategory) -> 'MCPToolBuilder':
        """设置分类"""
        self._category = cat
        return self

    def param(
        self,
        name: str,
        param_type: 'ParamType',
        description: str,
        required: bool = True,
        default: Any = None,
        **kwargs
    ) -> 'MCPToolBuilder':
        """添加参数"""
        from .base import ParamType as PT

        self._parameters.append(ToolParameter(
            name=name,
            type=param_type,
            description=description,
            required=required,
            default=default,
            **kwargs
        ))
        return self

    def timeout(self, seconds: float) -> 'MCPToolBuilder':
        """设置超时"""
        self._timeout = seconds
        return self

    def tags(self, *tags: str) -> 'MCPToolBuilder':
        """添加标签"""
        self._tags.extend(tags)
        return self

    def async_support(self, enabled: bool = True) -> 'MCPToolBuilder':
        """设置异步支持"""
        self._async_support = enabled
        return self

    def requires_auth(self, required: bool = True) -> 'MCPToolBuilder':
        """设置认证要求"""
        self._requires_auth = required
        return self

    def example(self, **kwargs) -> 'MCPToolBuilder':
        """添加使用示例"""
        self._examples.append(kwargs)
        return self

    def handler(self, fn: Callable) -> 'MCPToolBuilder':
        """设置处理函数"""
        self._handler = fn
        return self

    def build(self, register: bool = True) -> BaseTool:
        """构建工具

        Args:
            register: 是否自动注册到全局Registry

        Returns:
            构建的工具实例

        Raises:
            ValueError: 缺少必要配置
        """
        if not self._handler:
            raise ValueError("必须设置handler函数")

        metadata = ToolMetadata(
            name=self._name,
            description=self._description,
            category=self._category,
            parameters=self._parameters,
            timeout=self._timeout,
            tags=self._tags,
            async_support=self._async_support,
            requires_auth=self._requires_auth,
            examples=self._examples,
        )

        tool = FunctionTool(self._handler, metadata)

        if register:
            from .registry import get_registry
            get_registry().register(tool)

        return tool

    def build_and_register_mcp(self, mcp_server: Any) -> BaseTool:
        """构建并注册到MCP

        Args:
            mcp_server: FastMCP服务器实例

        Returns:
            构建的工具实例
        """
        tool = self.build(register=True)

        bridge = get_global_bridge()
        if bridge._mcp is None:
            bridge.bind_mcp(mcp_server)
        bridge._register_to_mcp(tool)

        return tool
