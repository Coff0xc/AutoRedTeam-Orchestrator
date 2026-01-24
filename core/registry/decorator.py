#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
注册装饰器模块

提供便捷的装饰器，用于将函数注册为工具。
支持同步和异步函数、参数验证、自动Schema生成。
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import (
    Any, Callable, Dict, List, Optional, TypeVar, Union, overload
)

from .categories import ToolCategory
from .base import (
    BaseTool, FunctionTool, AsyncTool, ToolMetadata, ToolParameter, ToolResult, ParamType
)
from .registry import get_registry


# 类型变量
F = TypeVar('F', bound=Callable[..., Any])


def tool(
    name: Optional[str] = None,
    category: Optional[ToolCategory] = None,
    description: Optional[str] = None,
    parameters: Optional[List[ToolParameter]] = None,
    tags: Optional[List[str]] = None,
    timeout: float = 60.0,
    version: str = '1.0.0',
    author: str = '',
    requires_auth: bool = False,
    requires_root: bool = False,
    deprecated: bool = False,
    deprecated_reason: Optional[str] = None,
    replacement: Optional[str] = None,
    register: bool = True
) -> Callable[[F], F]:
    """工具注册装饰器

    将函数注册为工具到全局Registry。

    Usage:
        @tool(name='port_scan', category=ToolCategory.PORT_SCAN)
        def scan_ports(target: str, ports: str = '1-1000') -> dict:
            '''端口扫描工具'''
            ...

        @tool(category=ToolCategory.RECON, tags=['network', 'discovery'])
        async def async_scanner(target: str) -> dict:
            '''异步扫描器'''
            ...

    Args:
        name: 工具名称 (默认使用函数名)
        category: 工具分类 (默认为MISC)
        description: 工具描述 (默认使用docstring)
        parameters: 参数列表 (默认从签名推断)
        tags: 标签列表
        timeout: 执行超时秒数
        version: 版本号
        author: 作者
        requires_auth: 是否需要认证
        requires_root: 是否需要root权限
        deprecated: 是否已废弃
        deprecated_reason: 废弃原因
        replacement: 替代工具名称
        register: 是否自动注册到Registry

    Returns:
        装饰后的函数
    """
    def decorator(fn: F) -> F:
        # 提取函数信息
        tool_name = name or fn.__name__
        tool_desc = description
        if tool_desc is None:
            doc = fn.__doc__ or ''
            tool_desc = doc.split('\n')[0].strip() or f"{tool_name} 工具"

        # 推断参数
        tool_params = parameters
        if tool_params is None:
            tool_params = FunctionTool._infer_parameters(fn)

        # 检测异步
        is_async = asyncio.iscoroutinefunction(fn)

        # 创建元数据
        metadata = ToolMetadata(
            name=tool_name,
            description=tool_desc,
            category=category or ToolCategory.MISC,
            parameters=tool_params,
            version=version,
            author=author,
            tags=tags or [],
            timeout=timeout,
            async_support=is_async,
            requires_auth=requires_auth,
            requires_root=requires_root,
            deprecated=deprecated,
            deprecated_reason=deprecated_reason,
            replacement=replacement,
        )

        # 创建工具
        function_tool = FunctionTool(fn, metadata)

        # 注册到Registry
        if register:
            get_registry().register(function_tool)

        # 包装函数，保留原始行为
        if is_async:
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                return await fn(*args, **kwargs)
            async_wrapper._tool = function_tool
            return async_wrapper  # type: ignore
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                return fn(*args, **kwargs)
            sync_wrapper._tool = function_tool
            return sync_wrapper  # type: ignore

    return decorator


def async_tool(
    name: Optional[str] = None,
    category: Optional[ToolCategory] = None,
    description: Optional[str] = None,
    parameters: Optional[List[ToolParameter]] = None,
    **kwargs
) -> Callable[[F], F]:
    """异步工具注册装饰器

    专门用于异步函数的注册装饰器。
    等同于 @tool(...) 但明确标记为异步。

    Usage:
        @async_tool(category=ToolCategory.RECON)
        async def async_scanner(target: str) -> dict:
            async with aiohttp.ClientSession() as session:
                ...

    Args:
        name: 工具名称
        category: 工具分类
        description: 工具描述
        parameters: 参数列表
        **kwargs: 额外的元数据属性

    Returns:
        装饰后的函数
    """
    return tool(
        name=name,
        category=category,
        description=description,
        parameters=parameters,
        **kwargs
    )


def recon_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """信息收集工具装饰器

    Usage:
        @recon_tool()
        def subdomain_enum(domain: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.RECON,
        description=description,
        **kwargs
    )


def vuln_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """漏洞检测工具装饰器

    Usage:
        @vuln_tool()
        def sqli_detect(url: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.VULN_SCAN,
        description=description,
        **kwargs
    )


def api_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """API安全工具装饰器

    Usage:
        @api_tool()
        def jwt_test(token: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.API_SECURITY,
        description=description,
        **kwargs
    )


def exploit_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """漏洞利用工具装饰器

    Usage:
        @exploit_tool()
        def rce_exploit(target: str, payload: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.EXPLOIT,
        description=description,
        **kwargs
    )


def c2_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """C2工具装饰器

    Usage:
        @c2_tool()
        def beacon_start(target: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.C2,
        description=description,
        **kwargs
    )


def lateral_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """横向移动工具装饰器

    Usage:
        @lateral_tool()
        def smb_exec(target: str, command: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.LATERAL,
        description=description,
        **kwargs
    )


def cve_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """CVE工具装饰器

    Usage:
        @cve_tool()
        def cve_search(keyword: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.CVE,
        description=description,
        **kwargs
    )


def report_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """报告工具装饰器

    Usage:
        @report_tool()
        def generate_report(session_id: str) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.REPORT,
        description=description,
        **kwargs
    )


def ai_tool(
    name: Optional[str] = None,
    description: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """AI工具装饰器

    Usage:
        @ai_tool()
        def smart_analyze(data: dict) -> dict:
            ...
    """
    return tool(
        name=name,
        category=ToolCategory.AI,
        description=description,
        **kwargs
    )


# ============ 参数装饰器 ============

def param(
    name: str,
    param_type: ParamType = ParamType.STRING,
    description: str = '',
    required: bool = True,
    default: Any = None,
    choices: Optional[List[Any]] = None,
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
    pattern: Optional[str] = None,
    **kwargs
) -> Callable[[F], F]:
    """参数定义装饰器

    为函数添加参数定义，可与@tool链式使用。

    Usage:
        @tool(category=ToolCategory.PORT_SCAN)
        @param('target', ParamType.IP, '目标IP地址', required=True)
        @param('ports', ParamType.PORT_RANGE, '端口范围', default='1-1000')
        def port_scan(target: str, ports: str = '1-1000') -> dict:
            ...

    Args:
        name: 参数名称
        param_type: 参数类型
        description: 参数描述
        required: 是否必需
        default: 默认值
        choices: 可选值列表
        min_value: 最小值
        max_value: 最大值
        pattern: 正则验证模式
        **kwargs: 额外属性

    Returns:
        装饰后的函数
    """
    def decorator(fn: F) -> F:
        # 获取或创建参数列表
        if not hasattr(fn, '_tool_params'):
            fn._tool_params = []  # type: ignore

        # 创建参数定义
        tool_param = ToolParameter(
            name=name,
            type=param_type,
            description=description,
            required=required,
            default=default,
            choices=choices,
            min_value=min_value,
            max_value=max_value,
            pattern=pattern,
            **kwargs
        )

        # 添加到列表（注意：装饰器从下往上执行，所以插入到开头）
        fn._tool_params.insert(0, tool_param)  # type: ignore

        return fn

    return decorator


def validate_params(fn: F) -> F:
    """参数验证装饰器

    在函数执行前自动验证参数。

    Usage:
        @tool(category=ToolCategory.RECON)
        @validate_params
        def scanner(target: str) -> dict:
            # target已经过验证
            ...
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # 获取工具定义
        tool = getattr(fn, '_tool', None)
        if tool:
            valid, errors = tool.validate_params(**kwargs)
            if not valid:
                raise ValueError("; ".join(errors))
        return fn(*args, **kwargs)

    @functools.wraps(fn)
    async def async_wrapper(*args, **kwargs):
        tool = getattr(fn, '_tool', None)
        if tool:
            valid, errors = tool.validate_params(**kwargs)
            if not valid:
                raise ValueError("; ".join(errors))
        return await fn(*args, **kwargs)

    if asyncio.iscoroutinefunction(fn):
        return async_wrapper  # type: ignore
    return wrapper  # type: ignore


def deprecated(
    reason: str = '',
    replacement: Optional[str] = None,
    remove_in: Optional[str] = None
) -> Callable[[F], F]:
    """废弃标记装饰器

    标记工具为已废弃，执行时输出警告。

    Usage:
        @deprecated(reason='使用新的scan_v2', replacement='scan_v2')
        @tool(category=ToolCategory.RECON)
        def old_scan(target: str) -> dict:
            ...
    """
    import warnings

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            msg = f"工具 {fn.__name__} 已废弃"
            if reason:
                msg += f": {reason}"
            if replacement:
                msg += f", 请使用 {replacement}"
            if remove_in:
                msg += f", 将在 {remove_in} 移除"
            warnings.warn(msg, DeprecationWarning, stacklevel=2)
            return fn(*args, **kwargs)

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            msg = f"工具 {fn.__name__} 已废弃"
            if reason:
                msg += f": {reason}"
            if replacement:
                msg += f", 请使用 {replacement}"
            if remove_in:
                msg += f", 将在 {remove_in} 移除"
            warnings.warn(msg, DeprecationWarning, stacklevel=2)
            return await fn(*args, **kwargs)

        # 标记废弃信息
        wrapper._deprecated = True  # type: ignore
        wrapper._deprecated_reason = reason  # type: ignore
        wrapper._replacement = replacement  # type: ignore

        if asyncio.iscoroutinefunction(fn):
            async_wrapper._deprecated = True  # type: ignore
            async_wrapper._deprecated_reason = reason  # type: ignore
            async_wrapper._replacement = replacement  # type: ignore
            return async_wrapper  # type: ignore

        return wrapper  # type: ignore

    return decorator


def require_auth(fn: F) -> F:
    """认证要求装饰器

    标记工具需要认证后才能执行。

    Usage:
        @require_auth
        @tool(category=ToolCategory.CREDENTIAL)
        def dump_creds(target: str) -> dict:
            ...
    """
    fn._requires_auth = True  # type: ignore
    return fn


def require_root(fn: F) -> F:
    """Root权限要求装饰器

    标记工具需要root/管理员权限。

    Usage:
        @require_root
        @tool(category=ToolCategory.PERSISTENCE)
        def install_backdoor(target: str) -> dict:
            ...
    """
    fn._requires_root = True  # type: ignore
    return fn


def tags(*tag_list: str) -> Callable[[F], F]:
    """标签装饰器

    为工具添加标签。

    Usage:
        @tags('network', 'discovery', 'fast')
        @tool(category=ToolCategory.RECON)
        def quick_scan(target: str) -> dict:
            ...
    """
    def decorator(fn: F) -> F:
        if not hasattr(fn, '_tags'):
            fn._tags = []  # type: ignore
        fn._tags.extend(tag_list)  # type: ignore
        return fn
    return decorator


def timeout(seconds: float) -> Callable[[F], F]:
    """超时装饰器

    设置工具的执行超时。

    Usage:
        @timeout(120.0)
        @tool(category=ToolCategory.RECON)
        def slow_scan(target: str) -> dict:
            ...
    """
    def decorator(fn: F) -> F:
        fn._timeout = seconds  # type: ignore
        return fn
    return decorator


def example(**kwargs) -> Callable[[F], F]:
    """示例装饰器

    为工具添加使用示例。

    Usage:
        @example(target='192.168.1.1', ports='1-1000')
        @example(target='10.0.0.1', ports='80,443,8080')
        @tool(category=ToolCategory.PORT_SCAN)
        def port_scan(target: str, ports: str) -> dict:
            ...
    """
    def decorator(fn: F) -> F:
        if not hasattr(fn, '_examples'):
            fn._examples = []  # type: ignore
        fn._examples.append(kwargs)  # type: ignore
        return fn
    return decorator


# ============ 组合装饰器 ============

def register_tools(*functions: Callable, category: ToolCategory) -> List[BaseTool]:
    """批量注册函数为工具

    Usage:
        tools = register_tools(
            scan_ports,
            scan_subdomain,
            scan_dns,
            category=ToolCategory.RECON
        )

    Args:
        *functions: 要注册的函数
        category: 工具分类

    Returns:
        创建的工具列表
    """
    tools = []
    registry = get_registry()

    for fn in functions:
        func_tool = FunctionTool.from_function(fn, category=category)
        registry.register(func_tool)
        tools.append(func_tool)

    return tools


def unregister_tool(name: str) -> bool:
    """注销工具

    Args:
        name: 工具名称

    Returns:
        是否成功注销
    """
    tool = get_registry().unregister(name)
    return tool is not None
