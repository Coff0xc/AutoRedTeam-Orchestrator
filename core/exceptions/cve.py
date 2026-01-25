"""
AutoRedTeam-Orchestrator CVE 异常

CVE 查询、同步、PoC 相关的错误类型定义。
"""

from __future__ import annotations

from typing import Optional, Any

from .base import AutoRedTeamError


class CVEError(AutoRedTeamError):
    """
    CVE相关错误基类

    CVE查询、同步、PoC相关的错误。

    属性:
        cve_id: CVE编号
    """

    def __init__(
        self,
        message: str,
        cve_id: Optional[str] = None,
        **kwargs: Any
    ):
        """
        初始化CVE错误

        参数:
            message: 错误消息
            cve_id: CVE编号（如 CVE-2021-44228）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.cve_id = cve_id
        if cve_id:
            self.details['cve_id'] = cve_id


class CVENotFound(CVEError):
    """
    CVE未找到

    当查询的CVE不存在时抛出。

    示例:
        >>> raise CVENotFound("CVE不存在", cve_id="CVE-9999-99999")
    """
    pass


class PoCError(CVEError):
    """
    PoC错误

    PoC执行失败、生成失败时抛出。

    属性:
        poc_name: PoC名称
    """

    def __init__(
        self,
        message: str,
        poc_name: Optional[str] = None,
        **kwargs: Any
    ):
        """
        初始化PoC错误

        参数:
            message: 错误消息
            poc_name: PoC名称
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.poc_name = poc_name
        if poc_name:
            self.details['poc'] = poc_name


class SyncError(CVEError):
    """
    同步错误

    CVE数据库同步失败时抛出。

    属性:
        source: 同步源（NVD, Nuclei, Exploit-DB等）
    """

    def __init__(
        self,
        message: str,
        source: Optional[str] = None,
        **kwargs: Any
    ):
        """
        初始化同步错误

        参数:
            message: 错误消息
            source: 数据源名称
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.source = source
        if source:
            self.details['source'] = source


__all__ = [
    'CVEError',
    'CVENotFound',
    'PoCError',
    'SyncError',
]