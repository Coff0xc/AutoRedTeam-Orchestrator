#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具注册表模块

提供线程安全的单例工具注册表，支持工具注册、查询、执行和管理。
"""

from __future__ import annotations

import logging
import threading
import asyncio
from typing import (
    Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, Type, Union
)
from collections import defaultdict

from .categories import (
    ToolCategory, CATEGORY_DESCRIPTIONS, CATEGORY_HIERARCHY,
    get_category_description, get_phase_for_category
)
from .base import (
    BaseTool, FunctionTool, ToolMetadata, ToolParameter, ToolResult, ParamType
)


logger = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    """工具不存在异常"""
    pass


class ToolAlreadyExistsError(Exception):
    """工具已存在异常"""
    pass


class ToolValidationError(Exception):
    """参数验证异常"""
    pass


class ToolRegistry:
    """工具注册表

    线程安全的单例模式，管理所有注册的工具。
    支持按分类索引、标签检索、模糊搜索等功能。

    Usage:
        # 获取全局注册表
        registry = ToolRegistry()

        # 注册工具
        registry.register(my_tool)

        # 执行工具
        result = registry.execute('port_scan', target='192.168.1.1')

        # 按分类列出
        tools = registry.list_by_category(ToolCategory.RECON)
    """

    _instance: Optional['ToolRegistry'] = None
    _lock = threading.Lock()
    _initialized: bool = False

    def __new__(cls) -> 'ToolRegistry':
        """单例模式实现"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
            return cls._instance

    def __init__(self):
        """初始化注册表"""
        # 防止重复初始化
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            # 工具存储
            self._tools: Dict[str, BaseTool] = {}

            # 按分类索引
            self._by_category: Dict[ToolCategory, Set[str]] = defaultdict(set)

            # 按标签索引
            self._by_tag: Dict[str, Set[str]] = defaultdict(set)

            # 按阶段索引
            self._by_phase: Dict[str, Set[str]] = defaultdict(set)

            # 别名映射
            self._aliases: Dict[str, str] = {}

            # 读写锁
            self._rw_lock = threading.RLock()

            self._initialized = True
            logger.info("工具注册表初始化完成")

    def register(
        self,
        tool: BaseTool,
        aliases: Optional[List[str]] = None,
        override: bool = False
    ) -> None:
        """注册工具

        Args:
            tool: 工具实例
            aliases: 工具别名列表
            override: 是否覆盖已存在的工具

        Raises:
            ToolAlreadyExistsError: 工具已存在且不允许覆盖
        """
        name = tool.metadata.name

        with self._rw_lock:
            # 检查是否存在
            if name in self._tools and not override:
                raise ToolAlreadyExistsError(f"工具 '{name}' 已存在")

            # 如果是覆盖，先清理旧索引
            if name in self._tools:
                self._remove_indexes(name)

            # 存储工具
            self._tools[name] = tool

            # 建立分类索引
            category = tool.metadata.category
            self._by_category[category].add(name)

            # 建立阶段索引
            phase = get_phase_for_category(category)
            self._by_phase[phase].add(name)

            # 建立标签索引
            for tag in tool.metadata.tags:
                self._by_tag[tag].add(name)

            # 注册别名
            if aliases:
                for alias in aliases:
                    self._aliases[alias] = name

            logger.debug(f"工具已注册: {name} [{category.value}]")

    def register_function(
        self,
        fn: Callable,
        category: ToolCategory,
        name: Optional[str] = None,
        description: Optional[str] = None,
        parameters: Optional[List[ToolParameter]] = None,
        **kwargs
    ) -> BaseTool:
        """将函数注册为工具

        Args:
            fn: 要注册的函数
            category: 工具分类
            name: 工具名称
            description: 工具描述
            parameters: 参数列表
            **kwargs: 额外的元数据属性

        Returns:
            创建的工具实例
        """
        tool = FunctionTool.from_function(
            fn,
            category=category,
            name=name,
            description=description,
            parameters=parameters,
            **kwargs
        )
        self.register(tool)
        return tool

    def unregister(self, name: str) -> Optional[BaseTool]:
        """注销工具

        Args:
            name: 工具名称

        Returns:
            被注销的工具实例，不存在则返回None
        """
        with self._rw_lock:
            if name not in self._tools:
                return None

            tool = self._tools.pop(name)
            self._remove_indexes(name)

            # 移除别名
            aliases_to_remove = [
                alias for alias, target in self._aliases.items()
                if target == name
            ]
            for alias in aliases_to_remove:
                del self._aliases[alias]

            logger.debug(f"工具已注销: {name}")
            return tool

    def _remove_indexes(self, name: str) -> None:
        """移除工具的索引

        Args:
            name: 工具名称
        """
        # 从分类索引移除
        for category_tools in self._by_category.values():
            category_tools.discard(name)

        # 从阶段索引移除
        for phase_tools in self._by_phase.values():
            phase_tools.discard(name)

        # 从标签索引移除
        for tag_tools in self._by_tag.values():
            tag_tools.discard(name)

    def get(self, name: str) -> Optional[BaseTool]:
        """获取工具

        Args:
            name: 工具名称或别名

        Returns:
            工具实例，不存在则返回None
        """
        with self._rw_lock:
            # 直接查找
            if name in self._tools:
                return self._tools[name]

            # 通过别名查找
            if name in self._aliases:
                return self._tools.get(self._aliases[name])

            return None

    def get_or_raise(self, name: str) -> BaseTool:
        """获取工具，不存在则抛出异常

        Args:
            name: 工具名称

        Returns:
            工具实例

        Raises:
            ToolNotFoundError: 工具不存在
        """
        tool = self.get(name)
        if tool is None:
            raise ToolNotFoundError(f"工具 '{name}' 不存在")
        return tool

    def exists(self, name: str) -> bool:
        """检查工具是否存在

        Args:
            name: 工具名称

        Returns:
            是否存在
        """
        return self.get(name) is not None

    def list_tools(
        self,
        category: Optional[ToolCategory] = None,
        phase: Optional[str] = None,
        tag: Optional[str] = None
    ) -> List[str]:
        """列出工具名称

        Args:
            category: 按分类过滤
            phase: 按阶段过滤
            tag: 按标签过滤

        Returns:
            工具名称列表
        """
        with self._rw_lock:
            if category:
                return list(self._by_category.get(category, set()))
            if phase:
                return list(self._by_phase.get(phase, set()))
            if tag:
                return list(self._by_tag.get(tag, set()))
            return list(self._tools.keys())

    def list_by_category(self, category: ToolCategory) -> List[BaseTool]:
        """按分类列出工具

        Args:
            category: 工具分类

        Returns:
            工具实例列表
        """
        with self._rw_lock:
            names = self._by_category.get(category, set())
            return [self._tools[name] for name in names if name in self._tools]

    def list_by_phase(self, phase: str) -> List[BaseTool]:
        """按阶段列出工具

        Args:
            phase: 阶段名称

        Returns:
            工具实例列表
        """
        with self._rw_lock:
            names = self._by_phase.get(phase, set())
            return [self._tools[name] for name in names if name in self._tools]

    def list_by_tag(self, tag: str) -> List[BaseTool]:
        """按标签列出工具

        Args:
            tag: 标签

        Returns:
            工具实例列表
        """
        with self._rw_lock:
            names = self._by_tag.get(tag, set())
            return [self._tools[name] for name in names if name in self._tools]

    def search(
        self,
        keyword: str,
        include_description: bool = True,
        include_tags: bool = True
    ) -> List[BaseTool]:
        """搜索工具

        Args:
            keyword: 关键词
            include_description: 是否搜索描述
            include_tags: 是否搜索标签

        Returns:
            匹配的工具列表
        """
        keyword = keyword.lower()
        results: List[BaseTool] = []

        with self._rw_lock:
            for tool in self._tools.values():
                # 搜索名称
                if keyword in tool.metadata.name.lower():
                    results.append(tool)
                    continue

                # 搜索描述
                if include_description:
                    if keyword in tool.metadata.description.lower():
                        results.append(tool)
                        continue

                # 搜索标签
                if include_tags:
                    for tag in tool.metadata.tags:
                        if keyword in tag.lower():
                            results.append(tool)
                            break

        return results

    def execute(
        self,
        name: str,
        validate: bool = True,
        **kwargs
    ) -> ToolResult:
        """同步执行工具

        Args:
            name: 工具名称
            validate: 是否验证参数
            **kwargs: 工具参数

        Returns:
            执行结果
        """
        try:
            tool = self.get_or_raise(name)

            # 参数验证
            if validate:
                valid, errors = tool.validate_params(**kwargs)
                if not valid:
                    return ToolResult.fail(
                        error="参数验证失败: " + "; ".join(errors)
                    )

            # 执行
            return tool.execute(**kwargs)

        except ToolNotFoundError as e:
            return ToolResult.fail(error=str(e))
        except Exception as e:
            logger.exception(f"工具执行异常: {name}")
            return ToolResult.fail(error=f"执行异常: {e}")

    async def async_execute(
        self,
        name: str,
        validate: bool = True,
        **kwargs
    ) -> ToolResult:
        """异步执行工具

        Args:
            name: 工具名称
            validate: 是否验证参数
            **kwargs: 工具参数

        Returns:
            执行结果
        """
        try:
            tool = self.get_or_raise(name)

            # 参数验证
            if validate:
                valid, errors = tool.validate_params(**kwargs)
                if not valid:
                    return ToolResult.fail(
                        error="参数验证失败: " + "; ".join(errors)
                    )

            # 异步执行
            return await tool.async_execute(**kwargs)

        except ToolNotFoundError as e:
            return ToolResult.fail(error=str(e))
        except Exception as e:
            logger.exception(f"工具异步执行异常: {name}")
            return ToolResult.fail(error=f"执行异常: {e}")

    def get_schemas(self) -> Dict[str, Dict[str, Any]]:
        """获取所有工具的JSON Schema

        Returns:
            {tool_name: schema} 字典
        """
        with self._rw_lock:
            return {
                name: tool.get_schema()
                for name, tool in self._tools.items()
            }

    def get_schema(self, name: str) -> Optional[Dict[str, Any]]:
        """获取单个工具的JSON Schema

        Args:
            name: 工具名称

        Returns:
            JSON Schema或None
        """
        tool = self.get(name)
        if tool:
            return tool.get_schema()
        return None

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息

        Returns:
            统计信息字典
        """
        with self._rw_lock:
            by_category = {
                cat.value: len(names)
                for cat, names in self._by_category.items()
                if names
            }

            by_phase = {
                phase: len(names)
                for phase, names in self._by_phase.items()
                if names
            }

            return {
                'total_tools': len(self._tools),
                'by_category': by_category,
                'by_phase': by_phase,
                'total_aliases': len(self._aliases),
                'total_tags': len(self._by_tag),
            }

    def get_categories(self) -> List[Dict[str, Any]]:
        """获取分类信息列表

        Returns:
            分类信息列表
        """
        with self._rw_lock:
            result = []
            for category in ToolCategory:
                count = len(self._by_category.get(category, set()))
                if count > 0:
                    result.append({
                        'category': category.value,
                        'description': get_category_description(category),
                        'count': count,
                        'phase': get_phase_for_category(category),
                    })
            return result

    def export_all(self) -> Dict[str, Any]:
        """导出所有工具信息

        Returns:
            完整的工具信息字典
        """
        with self._rw_lock:
            tools = {
                name: tool.get_info()
                for name, tool in self._tools.items()
            }

            return {
                'tools': tools,
                'stats': self.get_stats(),
                'categories': self.get_categories(),
            }

    def clear(self) -> None:
        """清空注册表

        警告: 仅用于测试！
        """
        with self._rw_lock:
            self._tools.clear()
            self._by_category.clear()
            self._by_tag.clear()
            self._by_phase.clear()
            self._aliases.clear()
            logger.warning("工具注册表已清空")

    def __len__(self) -> int:
        """返回工具数量"""
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        """检查工具是否存在"""
        return self.exists(name)

    def __iter__(self) -> Iterator[str]:
        """迭代工具名称"""
        return iter(self._tools.keys())

    def __getitem__(self, name: str) -> BaseTool:
        """通过索引获取工具"""
        return self.get_or_raise(name)


# ============ 全局单例访问 ============

_global_registry: Optional[ToolRegistry] = None
_registry_lock = threading.Lock()


def get_registry() -> ToolRegistry:
    """获取全局工具注册表

    Returns:
        全局ToolRegistry单例
    """
    global _global_registry
    if _global_registry is None:
        with _registry_lock:
            if _global_registry is None:
                _global_registry = ToolRegistry()
    return _global_registry


def reset_registry() -> None:
    """重置全局注册表

    警告: 仅用于测试！
    """
    global _global_registry
    with _registry_lock:
        if _global_registry is not None:
            _global_registry.clear()
        _global_registry = None
        # 重置单例
        ToolRegistry._instance = None
        ToolRegistry._initialized = False
    logger.warning("全局注册表已重置")


# ============ 快捷函数 ============

def register_tool(
    tool: BaseTool,
    aliases: Optional[List[str]] = None
) -> None:
    """注册工具到全局注册表

    Args:
        tool: 工具实例
        aliases: 别名列表
    """
    get_registry().register(tool, aliases=aliases)


def register_function(
    fn: Callable,
    category: ToolCategory,
    **kwargs
) -> BaseTool:
    """将函数注册到全局注册表

    Args:
        fn: 函数
        category: 分类
        **kwargs: 额外参数

    Returns:
        创建的工具
    """
    return get_registry().register_function(fn, category, **kwargs)


def get_tool(name: str) -> Optional[BaseTool]:
    """从全局注册表获取工具

    Args:
        name: 工具名称

    Returns:
        工具实例
    """
    return get_registry().get(name)


def execute_tool(name: str, **kwargs) -> ToolResult:
    """执行全局注册表中的工具

    Args:
        name: 工具名称
        **kwargs: 工具参数

    Returns:
        执行结果
    """
    return get_registry().execute(name, **kwargs)


async def async_execute_tool(name: str, **kwargs) -> ToolResult:
    """异步执行全局注册表中的工具

    Args:
        name: 工具名称
        **kwargs: 工具参数

    Returns:
        执行结果
    """
    return await get_registry().async_execute(name, **kwargs)


def list_all_tools() -> List[str]:
    """列出所有工具名称

    Returns:
        工具名称列表
    """
    return get_registry().list_tools()


def search_tools(keyword: str) -> List[BaseTool]:
    """搜索工具

    Args:
        keyword: 关键词

    Returns:
        匹配的工具列表
    """
    return get_registry().search(keyword)
