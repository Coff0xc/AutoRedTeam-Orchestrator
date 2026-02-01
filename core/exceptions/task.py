"""
AutoRedTeam-Orchestrator 任务和报告异常

任务队列、报告生成相关的错误类型定义。
"""

from __future__ import annotations

from typing import Any, Optional

from .base import AutoRedTeamError

# ============================================================================
# 任务错误
# ============================================================================


class TaskError(AutoRedTeamError):
    """
    任务错误基类

    异步任务队列相关的错误。

    属性:
        task_id: 任务ID
    """

    def __init__(self, message: str, task_id: Optional[str] = None, **kwargs: Any):
        """
        初始化任务错误

        参数:
            message: 错误消息
            task_id: 任务标识符
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.task_id = task_id
        if task_id:
            self.details["task_id"] = task_id


class TaskNotFound(TaskError):
    """
    任务未找到

    当查询的任务ID不存在时抛出。

    示例:
        >>> raise TaskNotFound("任务不存在", task_id="task-12345")
    """


class TaskCancelled(TaskError):
    """
    任务已取消

    当尝试操作已取消的任务时抛出。

    示例:
        >>> raise TaskCancelled("任务已被用户取消", task_id="task-12345")
    """


class QueueFull(TaskError):
    """
    队列已满

    当任务队列达到容量上限时抛出。

    属性:
        queue_size: 当前队列大小
        max_size: 最大容量
    """

    def __init__(
        self,
        message: str = "任务队列已满",
        queue_size: Optional[int] = None,
        max_size: Optional[int] = None,
        **kwargs: Any,
    ):
        """
        初始化队列满错误

        参数:
            message: 错误消息
            queue_size: 当前队列中的任务数
            max_size: 队列最大容量
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.queue_size = queue_size
        self.max_size = max_size
        if queue_size is not None:
            self.details["queue_size"] = queue_size
        if max_size is not None:
            self.details["max_size"] = max_size


# ============================================================================
# 报告错误
# ============================================================================


class ReportError(AutoRedTeamError):
    """
    报告错误基类

    报告生成、导出相关的错误。

    属性:
        report_type: 报告类型
    """

    def __init__(self, message: str, report_type: Optional[str] = None, **kwargs: Any):
        """
        初始化报告错误

        参数:
            message: 错误消息
            report_type: 报告类型（HTML, PDF, JSON等）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.report_type = report_type
        if report_type:
            self.details["report_type"] = report_type


class TemplateError(ReportError):
    """
    模板错误

    当报告模板加载失败、渲染失败时抛出。

    示例:
        >>> raise TemplateError("模板文件不存在", details={"template": "report.html"})
        >>> raise TemplateError("模板语法错误", details={"line": 42})
    """


class ExportError(ReportError):
    """
    导出错误

    当报告导出失败时抛出。

    示例:
        >>> raise ExportError("PDF导出失败", report_type="PDF")
        >>> raise ExportError("无法写入文件", details={"path": "/reports/output.html"})
    """


__all__ = [
    # 任务错误
    "TaskError",
    "TaskNotFound",
    "TaskCancelled",
    "QueueFull",
    # 报告错误
    "ReportError",
    "TemplateError",
    "ExportError",
]
