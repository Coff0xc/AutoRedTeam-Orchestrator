#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具基类定义模块

提供工具基类、参数类型、工具元数据和执行结果的定义。
支持同步和异步执行、参数验证、JSON Schema生成。
"""

from __future__ import annotations

import re
import inspect
import asyncio
import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any, Callable, Dict, List, Optional, Tuple, Type, Union,
    TypeVar, Generic, get_type_hints, get_origin, get_args
)
from urllib.parse import urlparse

from core.result import ToolResult
from .categories import ToolCategory


class ParamType(Enum):
    """参数类型枚举

    定义工具参数的数据类型，用于验证和Schema生成。
    """
    STRING = 'string'          # 字符串
    INTEGER = 'integer'        # 整数
    FLOAT = 'float'            # 浮点数
    NUMBER = 'number'          # 数值 (整数或浮点)
    BOOLEAN = 'boolean'        # 布尔值
    ARRAY = 'array'            # 数组
    OBJECT = 'object'          # 对象/字典
    URL = 'url'                # URL地址
    IP = 'ip'                  # IP地址
    IPV4 = 'ipv4'              # IPv4地址
    IPV6 = 'ipv6'              # IPv6地址
    CIDR = 'cidr'              # CIDR网段
    PORT = 'port'              # 端口号 (1-65535)
    PORT_RANGE = 'port_range'  # 端口范围 (如 "1-1000")
    FILE = 'file'              # 文件路径
    DIRECTORY = 'directory'    # 目录路径
    EMAIL = 'email'            # 电子邮件
    DOMAIN = 'domain'          # 域名
    REGEX = 'regex'            # 正则表达式
    JSON = 'json'              # JSON字符串
    BASE64 = 'base64'          # Base64编码
    HEX = 'hex'                # 十六进制
    UUID = 'uuid'              # UUID
    DATETIME = 'datetime'      # 日期时间
    ENUM = 'enum'              # 枚举值


# Python类型到ParamType的映射
PYTHON_TYPE_MAPPING: Dict[Type, ParamType] = {
    str: ParamType.STRING,
    int: ParamType.INTEGER,
    float: ParamType.FLOAT,
    bool: ParamType.BOOLEAN,
    list: ParamType.ARRAY,
    dict: ParamType.OBJECT,
    bytes: ParamType.STRING,
}


@dataclass
class ToolParameter:
    """工具参数定义

    描述工具的输入参数，包括类型、验证规则和元数据。

    Attributes:
        name: 参数名称
        type: 参数类型
        description: 参数描述
        required: 是否必需
        default: 默认值
        choices: 可选值列表
        min_value: 最小值 (数值类型)
        max_value: 最大值 (数值类型)
        min_length: 最小长度 (字符串/数组)
        max_length: 最大长度 (字符串/数组)
        pattern: 正则表达式验证模式
        examples: 示例值列表
        sensitive: 是否为敏感参数 (如密码)
        deprecated: 是否已废弃
        alias: 参数别名
    """
    name: str
    type: ParamType
    description: str
    required: bool = True
    default: Any = None
    choices: Optional[List[Any]] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    examples: List[Any] = field(default_factory=list)
    sensitive: bool = False
    deprecated: bool = False
    alias: Optional[str] = None

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """验证参数值

        Args:
            value: 要验证的值

        Returns:
            (是否有效, 错误信息)
        """
        # 空值检查
        if value is None:
            if self.required and self.default is None:
                return False, f"参数 '{self.name}' 是必需的"
            return True, None

        # 类型验证
        type_valid, type_error = self._validate_type(value)
        if not type_valid:
            return False, type_error

        # 选项验证
        if self.choices and value not in self.choices:
            return False, f"参数 '{self.name}' 值必须是: {self.choices}"

        # 数值范围验证
        if self.type in (ParamType.INTEGER, ParamType.FLOAT, ParamType.NUMBER, ParamType.PORT):
            if self.min_value is not None and value < self.min_value:
                return False, f"参数 '{self.name}' 最小值为 {self.min_value}"
            if self.max_value is not None and value > self.max_value:
                return False, f"参数 '{self.name}' 最大值为 {self.max_value}"

        # 长度验证
        if self.type in (ParamType.STRING, ParamType.ARRAY):
            length = len(value) if value else 0
            if self.min_length is not None and length < self.min_length:
                return False, f"参数 '{self.name}' 最小长度为 {self.min_length}"
            if self.max_length is not None and length > self.max_length:
                return False, f"参数 '{self.name}' 最大长度为 {self.max_length}"

        # 正则验证
        if self.pattern and self.type == ParamType.STRING:
            if not re.match(self.pattern, str(value)):
                return False, f"参数 '{self.name}' 格式不匹配: {self.pattern}"

        return True, None

    def _validate_type(self, value: Any) -> Tuple[bool, Optional[str]]:
        """类型验证

        Args:
            value: 要验证的值

        Returns:
            (是否有效, 错误信息)
        """
        type_checks = {
            ParamType.STRING: lambda v: isinstance(v, str),
            ParamType.INTEGER: lambda v: isinstance(v, int) and not isinstance(v, bool),
            ParamType.FLOAT: lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            ParamType.NUMBER: lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            ParamType.BOOLEAN: lambda v: isinstance(v, bool),
            ParamType.ARRAY: lambda v: isinstance(v, (list, tuple)),
            ParamType.OBJECT: lambda v: isinstance(v, dict),
            ParamType.URL: self._validate_url,
            ParamType.IP: self._validate_ip,
            ParamType.IPV4: self._validate_ipv4,
            ParamType.IPV6: self._validate_ipv6,
            ParamType.CIDR: self._validate_cidr,
            ParamType.PORT: self._validate_port,
            ParamType.PORT_RANGE: self._validate_port_range,
            ParamType.EMAIL: self._validate_email,
            ParamType.DOMAIN: self._validate_domain,
            ParamType.UUID: self._validate_uuid,
        }

        check_func = type_checks.get(self.type)
        if check_func:
            try:
                if not check_func(value):
                    return False, f"参数 '{self.name}' 类型必须是 {self.type.value}"
            except Exception:
                return False, f"参数 '{self.name}' 类型验证失败"

        return True, None

    @staticmethod
    def _validate_url(value: str) -> bool:
        """验证URL"""
        try:
            result = urlparse(value)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def _validate_ip(value: str) -> bool:
        """验证IP地址"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _validate_ipv4(value: str) -> bool:
        """验证IPv4地址"""
        try:
            ip = ipaddress.ip_address(value)
            return isinstance(ip, ipaddress.IPv4Address)
        except ValueError:
            return False

    @staticmethod
    def _validate_ipv6(value: str) -> bool:
        """验证IPv6地址"""
        try:
            ip = ipaddress.ip_address(value)
            return isinstance(ip, ipaddress.IPv6Address)
        except ValueError:
            return False

    @staticmethod
    def _validate_cidr(value: str) -> bool:
        """验证CIDR网段"""
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def _validate_port(value: Any) -> bool:
        """验证端口号"""
        try:
            port = int(value)
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _validate_port_range(value: str) -> bool:
        """验证端口范围"""
        try:
            if '-' in value:
                start, end = value.split('-', 1)
                return 1 <= int(start) <= int(end) <= 65535
            return ToolParameter._validate_port(value)
        except Exception:
            return False

    @staticmethod
    def _validate_email(value: str) -> bool:
        """验证邮箱地址"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, value))

    @staticmethod
    def _validate_domain(value: str) -> bool:
        """验证域名"""
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, value))

    @staticmethod
    def _validate_uuid(value: str) -> bool:
        """验证UUID"""
        pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        return bool(re.match(pattern, value))

    def to_json_schema(self) -> Dict[str, Any]:
        """转换为JSON Schema

        Returns:
            JSON Schema字典
        """
        schema: Dict[str, Any] = {
            'type': self._type_to_json_type(),
            'description': self.description,
        }

        # 默认值
        if self.default is not None:
            schema['default'] = self.default

        # 枚举值
        if self.choices:
            schema['enum'] = self.choices

        # 数值约束
        if self.min_value is not None:
            schema['minimum'] = self.min_value
        if self.max_value is not None:
            schema['maximum'] = self.max_value

        # 字符串约束
        if self.type == ParamType.STRING:
            if self.min_length is not None:
                schema['minLength'] = self.min_length
            if self.max_length is not None:
                schema['maxLength'] = self.max_length
            if self.pattern:
                schema['pattern'] = self.pattern

        # 数组约束
        if self.type == ParamType.ARRAY:
            if self.min_length is not None:
                schema['minItems'] = self.min_length
            if self.max_length is not None:
                schema['maxItems'] = self.max_length

        # 示例
        if self.examples:
            schema['examples'] = self.examples

        # 格式 (针对特殊类型)
        format_mapping = {
            ParamType.URL: 'uri',
            ParamType.IP: 'ip-address',
            ParamType.IPV4: 'ipv4',
            ParamType.IPV6: 'ipv6',
            ParamType.EMAIL: 'email',
            ParamType.UUID: 'uuid',
            ParamType.DATETIME: 'date-time',
        }
        if self.type in format_mapping:
            schema['format'] = format_mapping[self.type]

        return schema

    def _type_to_json_type(self) -> str:
        """转换为JSON类型

        Returns:
            JSON类型字符串
        """
        mapping = {
            ParamType.STRING: 'string',
            ParamType.INTEGER: 'integer',
            ParamType.FLOAT: 'number',
            ParamType.NUMBER: 'number',
            ParamType.BOOLEAN: 'boolean',
            ParamType.ARRAY: 'array',
            ParamType.OBJECT: 'object',
            ParamType.URL: 'string',
            ParamType.IP: 'string',
            ParamType.IPV4: 'string',
            ParamType.IPV6: 'string',
            ParamType.CIDR: 'string',
            ParamType.PORT: 'integer',
            ParamType.PORT_RANGE: 'string',
            ParamType.FILE: 'string',
            ParamType.DIRECTORY: 'string',
            ParamType.EMAIL: 'string',
            ParamType.DOMAIN: 'string',
            ParamType.REGEX: 'string',
            ParamType.JSON: 'string',
            ParamType.BASE64: 'string',
            ParamType.HEX: 'string',
            ParamType.UUID: 'string',
            ParamType.DATETIME: 'string',
            ParamType.ENUM: 'string',
        }
        return mapping.get(self.type, 'string')


@dataclass
class ToolMetadata:
    """工具元数据

    描述工具的完整信息，包括名称、描述、参数、执行控制等。

    Attributes:
        name: 工具名称 (唯一标识)
        description: 工具描述
        category: 工具分类
        parameters: 参数列表
        version: 版本号
        author: 作者
        tags: 标签列表
        examples: 使用示例
        timeout: 执行超时 (秒)
        async_support: 是否支持异步
        requires_auth: 是否需要认证
        requires_root: 是否需要root权限
        deprecated: 是否已废弃
        deprecated_reason: 废弃原因
        replacement: 替代工具名称
    """
    name: str
    description: str
    category: ToolCategory
    parameters: List[ToolParameter] = field(default_factory=list)

    # 版本信息
    version: str = '1.0.0'
    author: str = ''
    tags: List[str] = field(default_factory=list)

    # 使用示例
    examples: List[Dict[str, Any]] = field(default_factory=list)

    # 执行控制
    timeout: float = 60.0
    async_support: bool = True
    requires_auth: bool = False
    requires_root: bool = False

    # 废弃信息
    deprecated: bool = False
    deprecated_reason: Optional[str] = None
    replacement: Optional[str] = None

    def get_required_params(self) -> List[str]:
        """获取必需参数名列表

        Returns:
            必需参数名列表
        """
        return [p.name for p in self.parameters if p.required]

    def get_optional_params(self) -> List[str]:
        """获取可选参数名列表

        Returns:
            可选参数名列表
        """
        return [p.name for p in self.parameters if not p.required]

    def get_param(self, name: str) -> Optional[ToolParameter]:
        """根据名称获取参数

        Args:
            name: 参数名称

        Returns:
            参数对象或None
        """
        for param in self.parameters:
            if param.name == name or param.alias == name:
                return param
        return None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典

        Returns:
            元数据字典
        """
        return {
            'name': self.name,
            'description': self.description,
            'category': self.category.value,
            'parameters': [
                {
                    'name': p.name,
                    'type': p.type.value,
                    'description': p.description,
                    'required': p.required,
                    'default': p.default,
                    'choices': p.choices,
                }
                for p in self.parameters
            ],
            'version': self.version,
            'author': self.author,
            'tags': self.tags,
            'timeout': self.timeout,
            'async_support': self.async_support,
            'requires_auth': self.requires_auth,
            'requires_root': self.requires_root,
            'deprecated': self.deprecated,
        }


class BaseTool(ABC):
    """工具基类

    所有工具必须继承此类并实现execute方法。
    支持同步和异步执行、参数验证、Schema生成。

    Usage:
        class PortScanner(BaseTool):
            metadata = ToolMetadata(
                name='port_scan',
                description='端口扫描工具',
                category=ToolCategory.PORT_SCAN,
                parameters=[
                    ToolParameter(name='target', type=ParamType.IP, description='目标IP'),
                    ToolParameter(name='ports', type=ParamType.PORT_RANGE, description='端口范围'),
                ]
            )

            def execute(self, **kwargs) -> ToolResult:
                target = kwargs['target']
                ports = kwargs.get('ports', '1-1000')
                # ... 扫描逻辑
                return ToolResult.ok(data={'open_ports': [80, 443]})
    """

    metadata: ToolMetadata

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化工具

        Args:
            config: 配置字典
        """
        self.config = config or {}
        self._validate_metadata()

    def _validate_metadata(self) -> None:
        """验证元数据完整性"""
        if not hasattr(self, 'metadata') or self.metadata is None:
            raise ValueError(f"工具 {self.__class__.__name__} 缺少metadata定义")

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        """同步执行工具

        Args:
            **kwargs: 工具参数

        Returns:
            执行结果
        """
        ...

    async def async_execute(self, **kwargs) -> ToolResult:
        """异步执行工具

        默认实现：在线程池中运行同步方法。
        子类可重写以实现真正的异步执行。

        Args:
            **kwargs: 工具参数

        Returns:
            执行结果
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.execute(**kwargs))

    def validate_params(self, **kwargs) -> Tuple[bool, List[str]]:
        """验证所有参数

        Args:
            **kwargs: 要验证的参数

        Returns:
            (是否全部有效, 错误信息列表)
        """
        errors: List[str] = []

        for param in self.metadata.parameters:
            value = kwargs.get(param.name)

            # 处理别名
            if value is None and param.alias:
                value = kwargs.get(param.alias)

            # 使用默认值
            if value is None and param.default is not None:
                continue

            valid, error = param.validate(value)
            if not valid and error:
                errors.append(error)

        return len(errors) == 0, errors

    def get_schema(self) -> Dict[str, Any]:
        """获取JSON Schema

        Returns:
            JSON Schema字典
        """
        properties: Dict[str, Any] = {}
        required: List[str] = []

        for param in self.metadata.parameters:
            properties[param.name] = param.to_json_schema()
            if param.required:
                required.append(param.name)

        return {
            'type': 'object',
            'properties': properties,
            'required': required,
            'additionalProperties': False,
        }

    def get_info(self) -> Dict[str, Any]:
        """获取工具信息

        Returns:
            工具信息字典
        """
        return {
            **self.metadata.to_dict(),
            'schema': self.get_schema(),
        }

    def __str__(self) -> str:
        return f"<{self.__class__.__name__}: {self.metadata.name}>"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.metadata.name!r})"


class FunctionTool(BaseTool):
    """函数包装工具

    将普通函数包装为BaseTool，支持自动参数推断。

    Usage:
        def scan_ports(target: str, ports: str = "1-1000") -> dict:
            '''端口扫描'''
            ...

        tool = FunctionTool.from_function(
            scan_ports,
            category=ToolCategory.PORT_SCAN
        )
    """

    def __init__(
        self,
        fn: Callable,
        metadata: ToolMetadata,
        config: Optional[Dict[str, Any]] = None
    ):
        """初始化函数工具

        Args:
            fn: 要包装的函数
            metadata: 工具元数据
            config: 配置字典
        """
        self._fn = fn
        self.metadata = metadata
        super().__init__(config)

    def execute(self, **kwargs) -> ToolResult:
        """执行函数

        Args:
            **kwargs: 函数参数

        Returns:
            执行结果
        """
        try:
            # 填充默认值
            filled_kwargs = self._fill_defaults(kwargs)

            # 调用函数
            result = self._fn(**filled_kwargs)

            # 包装结果
            if isinstance(result, ToolResult):
                return result
            elif isinstance(result, dict):
                # 检查是否已是结果格式
                if 'success' in result:
                    success = result.get('success', True)
                    data = result.get('data', result)
                    error = result.get('error')
                    error_type = result.get('error_type')
                    metadata = result.get('metadata')
                    if not isinstance(metadata, dict):
                        metadata = {}
                    if success:
                        return ToolResult.ok(data=data, **metadata)
                    return ToolResult.fail(
                        error=error or "执行失败",
                        error_type=error_type,
                        data=data,
                        **metadata
                    )
                return ToolResult.ok(data=result)
            else:
                return ToolResult.ok(data=result)

        except TypeError as e:
            return ToolResult.fail(error=f"参数错误: {e}")
        except Exception as e:
            return ToolResult.fail(error=str(e))

    async def async_execute(self, **kwargs) -> ToolResult:
        """异步执行函数

        Args:
            **kwargs: 函数参数

        Returns:
            执行结果
        """
        try:
            filled_kwargs = self._fill_defaults(kwargs)

            # 检查是否为协程函数
            if asyncio.iscoroutinefunction(self._fn):
                result = await self._fn(**filled_kwargs)
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, lambda: self._fn(**filled_kwargs)
                )

            # 包装结果
            if isinstance(result, ToolResult):
                return result
            elif isinstance(result, dict):
                if 'success' in result:
                    success = result.get('success', True)
                    data = result.get('data', result)
                    error = result.get('error')
                    error_type = result.get('error_type')
                    metadata = result.get('metadata')
                    if not isinstance(metadata, dict):
                        metadata = {}
                    if success:
                        return ToolResult.ok(data=data, **metadata)
                    return ToolResult.fail(
                        error=error or "执行失败",
                        error_type=error_type,
                        data=data,
                        **metadata
                    )
                return ToolResult.ok(data=result)
            else:
                return ToolResult.ok(data=result)

        except Exception as e:
            return ToolResult.fail(error=str(e))

    def _fill_defaults(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """填充默认值

        Args:
            kwargs: 原始参数

        Returns:
            填充后的参数
        """
        filled = dict(kwargs)
        for param in self.metadata.parameters:
            if param.name not in filled:
                if param.alias and param.alias in filled:
                    filled[param.name] = filled.pop(param.alias)
                elif param.default is not None:
                    filled[param.name] = param.default
        return filled

    @classmethod
    def from_function(
        cls,
        fn: Callable,
        category: ToolCategory,
        name: Optional[str] = None,
        description: Optional[str] = None,
        parameters: Optional[List[ToolParameter]] = None,
        **kwargs
    ) -> 'FunctionTool':
        """从函数创建工具

        自动从函数签名推断参数信息。

        Args:
            fn: 要包装的函数
            category: 工具分类
            name: 工具名称 (默认使用函数名)
            description: 工具描述 (默认使用docstring)
            parameters: 参数列表 (默认从签名推断)
            **kwargs: 额外的元数据属性

        Returns:
            FunctionTool实例
        """
        # 提取函数信息
        tool_name = name or fn.__name__
        tool_desc = description
        if tool_desc is None:
            doc = fn.__doc__ or ''
            tool_desc = doc.split('\n')[0].strip() or f"{tool_name} 工具"

        # 推断参数
        if parameters is None:
            parameters = cls._infer_parameters(fn)

        # 检测是否支持异步
        async_support = asyncio.iscoroutinefunction(fn)

        # 创建元数据
        metadata = ToolMetadata(
            name=tool_name,
            description=tool_desc,
            category=category,
            parameters=parameters,
            async_support=async_support,
            **{k: v for k, v in kwargs.items() if hasattr(ToolMetadata, k)}
        )

        return cls(fn, metadata)

    @classmethod
    def _infer_parameters(cls, fn: Callable) -> List[ToolParameter]:
        """从函数签名推断参数

        Args:
            fn: 函数

        Returns:
            参数列表
        """
        sig = inspect.signature(fn)
        parameters: List[ToolParameter] = []

        # 尝试获取类型注解
        try:
            hints = get_type_hints(fn)
        except Exception:
            hints = {}

        for param_name, param in sig.parameters.items():
            # 跳过特殊参数
            if param_name in ('self', 'cls', 'session_id', 'context'):
                continue

            # 推断类型
            param_type = ParamType.STRING
            annotation = hints.get(param_name, param.annotation)

            if annotation != inspect.Parameter.empty:
                param_type = cls._annotation_to_param_type(annotation)

            # 判断是否必需
            has_default = param.default != inspect.Parameter.empty
            default_value = param.default if has_default else None

            # 提取描述 (从docstring)
            param_desc = f"参数 {param_name}"

            parameters.append(ToolParameter(
                name=param_name,
                type=param_type,
                description=param_desc,
                required=not has_default,
                default=default_value,
            ))

        return parameters

    @classmethod
    def _annotation_to_param_type(cls, annotation: Any) -> ParamType:
        """将类型注解转换为ParamType

        Args:
            annotation: 类型注解

        Returns:
            参数类型
        """
        # 处理Optional类型
        origin = get_origin(annotation)
        if origin is Union:
            args = get_args(annotation)
            # Optional[X] = Union[X, None]
            non_none_args = [a for a in args if a is not type(None)]
            if len(non_none_args) == 1:
                annotation = non_none_args[0]

        # 直接映射
        if annotation in PYTHON_TYPE_MAPPING:
            return PYTHON_TYPE_MAPPING[annotation]

        # 处理泛型类型
        origin = get_origin(annotation)
        if origin is list:
            return ParamType.ARRAY
        elif origin is dict:
            return ParamType.OBJECT

        return ParamType.STRING


class AsyncTool(BaseTool):
    """异步工具基类

    用于需要原生异步支持的工具。

    Usage:
        class AsyncScanner(AsyncTool):
            metadata = ToolMetadata(...)

            async def async_execute(self, **kwargs) -> ToolResult:
                async with aiohttp.ClientSession() as session:
                    ...
    """

    def execute(self, **kwargs) -> ToolResult:
        """同步执行 (运行异步方法)

        Args:
            **kwargs: 工具参数

        Returns:
            执行结果
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 如果事件循环正在运行，创建新任务
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(
                        asyncio.run, self.async_execute(**kwargs)
                    )
                    return future.result(timeout=self.metadata.timeout)
            else:
                return loop.run_until_complete(self.async_execute(**kwargs))
        except Exception as e:
            return ToolResult.fail(error=str(e))

    @abstractmethod
    async def async_execute(self, **kwargs) -> ToolResult:
        """异步执行工具

        Args:
            **kwargs: 工具参数

        Returns:
            执行结果
        """
        ...
