"""
AutoRedTeam-Orchestrator 扫描异常

扫描和检测器相关的错误类型定义。
"""

from __future__ import annotations

from typing import Optional, Any

from .base import AutoRedTeamError


# ============================================================================
# 扫描错误
# ============================================================================

class ScanError(AutoRedTeamError):
    """
    扫描错误基类

    所有扫描相关错误的父类。

    属性:
        target: 扫描目标
    """

    def __init__(
        self,
        message: str,
        target: Optional[str] = None,
        **kwargs: Any
    ):
        """
        初始化扫描错误

        参数:
            message: 错误消息
            target: 扫描目标（URL、IP等）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.target = target
        if target:
            self.details['target'] = target


class TargetUnreachable(ScanError):
    """
    目标不可达

    当扫描目标无法访问时抛出。

    示例:
        >>> raise TargetUnreachable("目标主机离线", target="192.168.1.100")
        >>> raise TargetUnreachable("端口未开放", target="192.168.1.100:8080")
    """
    pass


class ScanTimeout(ScanError):
    """
    扫描超时

    当扫描任务执行时间超过限制时抛出。

    属性:
        elapsed: 已耗时（秒）
        limit: 时间限制（秒）
    """

    def __init__(
        self,
        message: str,
        elapsed: Optional[float] = None,
        limit: Optional[float] = None,
        **kwargs: Any
    ):
        """
        初始化扫描超时错误

        参数:
            message: 错误消息
            elapsed: 实际耗时（秒）
            limit: 超时限制（秒）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.elapsed = elapsed
        self.limit = limit
        if elapsed is not None:
            self.details['elapsed'] = elapsed
        if limit is not None:
            self.details['limit'] = limit


class RateLimited(ScanError):
    """
    被限流

    当目标服务器返回429或检测到限流时抛出。

    属性:
        retry_after: 建议的重试等待时间（秒）
    """

    def __init__(
        self,
        message: str = "请求被限流",
        retry_after: Optional[int] = None,
        **kwargs: Any
    ):
        """
        初始化限流错误

        参数:
            message: 错误消息
            retry_after: 建议的重试等待时间（秒）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.retry_after = retry_after
        if retry_after is not None:
            self.details['retry_after'] = retry_after


# ============================================================================
# 检测器错误
# ============================================================================

class DetectorError(AutoRedTeamError):
    """
    检测器错误基类

    漏洞检测器执行过程中的错误。

    属性:
        detector_name: 检测器名称
    """

    def __init__(
        self,
        message: str,
        detector_name: Optional[str] = None,
        **kwargs: Any
    ):
        """
        初始化检测器错误

        参数:
            message: 错误消息
            detector_name: 检测器名称
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.detector_name = detector_name
        if detector_name:
            self.details['detector'] = detector_name


class PayloadError(DetectorError):
    """
    Payload错误

    当Payload生成失败、格式错误、编码失败时抛出。

    示例:
        >>> raise PayloadError("Payload编码失败", details={"encoding": "base64", "reason": "invalid characters"})
    """
    pass


class ValidationError(DetectorError):
    """
    验证错误

    当输入参数验证失败、响应格式不符合预期时抛出。

    示例:
        >>> raise ValidationError("URL格式无效", details={"url": "not-a-valid-url"})
        >>> raise ValidationError("必填参数缺失", details={"missing": ["target", "port"]})
    """
    pass


class DetectionTimeout(DetectorError):
    """
    检测超时

    当单个漏洞检测执行超时时抛出。

    示例:
        >>> raise DetectionTimeout("SQL注入检测超时", detector_name="sqli_detector")
    """
    pass


__all__ = [
    # 扫描错误
    'ScanError',
    'TargetUnreachable',
    'ScanTimeout',
    'RateLimited',
    # 检测器错误
    'DetectorError',
    'PayloadError',
    'ValidationError',
    'DetectionTimeout',
]