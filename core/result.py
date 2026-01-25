"""
统一的工具返回值 Schema

提供标准化的工具执行结果格式，确保所有 MCP 工具返回一致的数据结构。

使用示例:
    # 成功返回
    return ToolResult.ok(data={'target': url, 'vulns': findings})

    # 失败返回
    return ToolResult.fail("Connection timeout", error_type="TimeoutError")

    # 部分成功
    return ToolResult.partial(
        data={'completed': results},
        error="Some targets unreachable"
    )

    # 转换为字典（用于 MCP 响应）
    result = ToolResult.ok(data={'status': 'done'})
    return result.to_dict()
"""

from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any, List, Union
from enum import Enum
from datetime import datetime


class ResultStatus(Enum):
    """工具执行状态枚举"""
    SUCCESS = "success"      # 完全成功
    FAILED = "failed"        # 执行失败
    PARTIAL = "partial"      # 部分成功（部分目标失败等）
    TIMEOUT = "timeout"      # 执行超时
    ERROR = "error"          # 内部错误
    SKIPPED = "skipped"      # 跳过执行（条件不满足等）
    PENDING = "pending"      # 待执行（异步任务）


@dataclass
class ToolResult:
    """
    统一的工具返回结果数据类

    所有 MCP 工具应使用此类返回结果，确保 AI 能够一致地解析响应。

    Attributes:
        success: 执行是否成功（布尔值，必需）
        status: 详细状态枚举（默认 SUCCESS）
        data: 返回的数据内容（字典格式）
        error: 错误信息（失败时填写）
        error_type: 错误类型/异常类名
        metadata: 额外元数据（执行时间、版本等）

    Example:
        >>> result = ToolResult.ok(data={'port': 80, 'open': True})
        >>> result.to_dict()
        {'success': True, 'status': 'success', 'data': {'port': 80, 'open': True}, ...}
    """
    success: bool
    status: ResultStatus = ResultStatus.SUCCESS
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理：自动添加时间戳"""
        if 'timestamp' not in self.metadata:
            self.metadata['timestamp'] = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式，适用于 JSON 序列化

        Returns:
            包含所有字段的字典，status 转换为字符串值
        """
        # 手动构建字典，避免 asdict 与类方法名冲突
        result = {
            'success': self.success,
            'status': self.status.value,
            'data': self.data,
            'error': self.error,
            'error_type': self.error_type,
            'metadata': self.metadata,
        }
        # 移除空值字段以减少响应大小
        return {k: v for k, v in result.items() if v is not None}

    def to_json_safe(self) -> Dict[str, Any]:
        """
        转换为 JSON 安全的字典格式

        处理可能无法序列化的对象（如 datetime）

        Returns:
            JSON 可序列化的字典
        """
        result = self.to_dict()
        # 确保 metadata 中的值都可序列化
        if 'metadata' in result:
            for key, value in result['metadata'].items():
                if isinstance(value, datetime):
                    result['metadata'][key] = value.isoformat()
        return result

    @classmethod
    def ok(cls, data: Optional[Dict[str, Any]] = None, **metadata) -> 'ToolResult':
        """
        创建成功结果

        Args:
            data: 返回的数据
            **metadata: 额外的元数据键值对

        Returns:
            成功状态的 ToolResult 实例

        Example:
            >>> ToolResult.ok(data={'found': 5, 'items': [...]})
        """
        return cls(
            success=True,
            status=ResultStatus.SUCCESS,
            data=data,
            metadata=metadata
        )

    @classmethod
    def fail(
        cls,
        error: str,
        error_type: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        **metadata
    ) -> 'ToolResult':
        """
        创建失败结果

        Args:
            error: 错误信息
            error_type: 错误类型（如异常类名）
            data: 可选的部分数据
            **metadata: 额外的元数据键值对

        Returns:
            失败状态的 ToolResult 实例

        Example:
            >>> ToolResult.fail("Connection refused", error_type="ConnectionError")
        """
        return cls(
            success=False,
            status=ResultStatus.FAILED,
            data=data,
            error=error,
            error_type=error_type,
            metadata=metadata
        )

    @classmethod
    def partial(
        cls,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        **metadata
    ) -> 'ToolResult':
        """
        创建部分成功结果

        用于批量操作中部分目标成功、部分失败的情况。

        Args:
            data: 已完成的数据
            error: 失败部分的说明
            **metadata: 额外的元数据键值对

        Returns:
            部分成功状态的 ToolResult 实例

        Example:
            >>> ToolResult.partial(
            ...     data={'completed': 8, 'failed': 2},
            ...     error="2 targets unreachable"
            ... )
        """
        return cls(
            success=True,  # 部分成功仍视为成功
            status=ResultStatus.PARTIAL,
            data=data,
            error=error,
            metadata=metadata
        )

    @classmethod
    def timeout(
        cls,
        error: str = "Operation timed out",
        data: Optional[Dict[str, Any]] = None,
        **metadata
    ) -> 'ToolResult':
        """
        创建超时结果

        Args:
            error: 超时描述
            data: 超时前已获取的数据
            **metadata: 额外的元数据键值对

        Returns:
            超时状态的 ToolResult 实例
        """
        return cls(
            success=False,
            status=ResultStatus.TIMEOUT,
            data=data,
            error=error,
            error_type="TimeoutError",
            metadata=metadata
        )

    @classmethod
    def internal_error(
        cls,
        error: str,
        error_type: Optional[str] = None,
        **metadata
    ) -> 'ToolResult':
        """
        创建内部错误结果

        用于非预期的内部错误（区别于业务层面的失败）。

        Args:
            error: 错误信息
            error_type: 错误类型
            **metadata: 额外的元数据键值对

        Returns:
            错误状态的 ToolResult 实例
        """
        return cls(
            success=False,
            status=ResultStatus.ERROR,
            error=error,
            error_type=error_type,
            metadata=metadata
        )

    @classmethod
    def skipped(
        cls,
        reason: str,
        **metadata
    ) -> 'ToolResult':
        """
        创建跳过执行结果

        用于条件不满足而跳过执行的情况。

        Args:
            reason: 跳过原因
            **metadata: 额外的元数据键值对

        Returns:
            跳过状态的 ToolResult 实例
        """
        return cls(
            success=True,  # 跳过不视为失败
            status=ResultStatus.SKIPPED,
            error=reason,
            metadata=metadata
        )

    @classmethod
    def pending(
        cls,
        task_id: str,
        **metadata
    ) -> 'ToolResult':
        """
        创建待执行结果

        用于异步任务提交后返回任务 ID。

        Args:
            task_id: 异步任务 ID
            **metadata: 额外的元数据键值对

        Returns:
            待执行状态的 ToolResult 实例
        """
        return cls(
            success=True,
            status=ResultStatus.PENDING,
            data={'task_id': task_id},
            metadata=metadata
        )

    @classmethod
    def from_exception(cls, exc: Exception, **metadata) -> 'ToolResult':
        """
        从异常创建失败结果

        自动提取异常类型和消息。

        Args:
            exc: 捕获的异常
            **metadata: 额外的元数据键值对

        Returns:
            错误状态的 ToolResult 实例

        Example:
            >>> try:
            ...     risky_operation()
            ... except Exception as e:
            ...     return ToolResult.from_exception(e)
        """
        return cls(
            success=False,
            status=ResultStatus.ERROR,
            error=str(exc),
            error_type=type(exc).__name__,
            metadata=metadata
        )

    def with_metadata(self, **kwargs) -> 'ToolResult':
        """
        添加额外元数据（返回新实例）

        Args:
            **kwargs: 要添加的元数据键值对

        Returns:
            包含新元数据的 ToolResult 实例
        """
        new_metadata = {**self.metadata, **kwargs}
        return ToolResult(
            success=self.success,
            status=self.status,
            data=self.data,
            error=self.error,
            error_type=self.error_type,
            metadata=new_metadata
        )

    def __bool__(self) -> bool:
        """支持布尔判断：if result: ..."""
        return self.success


# 类型别名，方便类型注解
ToolResultType = Union[ToolResult, Dict[str, Any]]


def ensure_tool_result(result: ToolResultType) -> ToolResult:
    """
    确保返回值是 ToolResult 类型

    用于兼容旧代码，将字典转换为 ToolResult。

    Args:
        result: ToolResult 实例或字典

    Returns:
        ToolResult 实例
    """
    if isinstance(result, ToolResult):
        return result

    if isinstance(result, dict):
        success = result.get('success', True)
        status_raw = result.get('status')
        status_str = status_raw if status_raw is not None else ('success' if success else 'failed')
        try:
            status = ResultStatus(status_str)
            keep_status = False
        except ValueError:
            status = ResultStatus.SUCCESS if success else ResultStatus.FAILED
            keep_status = status_raw is not None
        metadata = result.get('metadata')
        if not isinstance(metadata, dict):
            metadata = {}

        exclude_keys = {'success', 'error', 'error_type', 'metadata', 'data'}
        if not keep_status:
            exclude_keys.add('status')
        extras = {
            key: value
            for key, value in result.items()
            if key not in exclude_keys
        }
        data = result.get('data')
        if data is None and 'data' not in result:
            data = extras or None
        elif extras:
            if isinstance(data, dict):
                data = {**extras, **data}
            else:
                data = {'value': data, **extras}

        return ToolResult(
            success=success,
            status=status,
            data=data,
            error=result.get('error'),
            error_type=result.get('error_type'),
            metadata=metadata
        )

    # 其他类型包装为 data
    return ToolResult.ok(data={'value': result})
