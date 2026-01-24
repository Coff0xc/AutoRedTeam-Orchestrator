"""
AutoRedTeam-Orchestrator 统一异常体系

本模块定义了项目中所有可能的错误场景对应的异常类型，
提供统一的异常处理机制和序列化支持。

异常层次结构:
AutoRedTeamError (基类)
├── ConfigError (配置错误)
├── HTTPError (HTTP错误)
│   ├── ConnectionError
│   ├── TimeoutError
│   ├── SSLError
│   └── ProxyError
├── AuthError (认证错误)
│   ├── InvalidCredentials
│   ├── TokenExpired
│   └── PermissionDenied
├── ScanError (扫描错误)
│   ├── TargetUnreachable
│   ├── ScanTimeout
│   └── RateLimited
├── DetectorError (检测器错误)
│   ├── PayloadError
│   ├── ValidationError
│   └── DetectionTimeout
├── ExploitError (漏洞利用错误)
│   ├── ExploitFailed
│   ├── PayloadDeliveryFailed
│   └── ShellError
├── C2Error (C2通信错误)
│   ├── BeaconError
│   ├── TunnelError
│   └── EncryptionError
├── LateralError (横向移动错误)
│   ├── SMBError
│   ├── SSHError
│   └── WMIError
├── CVEError (CVE相关错误)
│   ├── CVENotFound
│   ├── PoCError
│   └── SyncError
├── TaskError (任务错误)
│   ├── TaskNotFound
│   ├── TaskCancelled
│   └── QueueFull
└── ReportError (报告错误)
    ├── TemplateError
    └── ExportError

使用示例:
    from core.exceptions import (
        AutoRedTeamError, HTTPError, TimeoutError,
        wrap_exception, handle_exceptions
    )

    # 基本使用
    raise TimeoutError("请求超时", url="https://example.com", timeout=30)

    # 异常链
    try:
        response = requests.get(url)
    except requests.Timeout as e:
        raise TimeoutError("连接超时", url=url, cause=e)

    # 使用装饰器
    @handle_exceptions(logger=logger, default_return=None)
    def fetch_data(url):
        ...

    # 序列化
    try:
        ...
    except AutoRedTeamError as e:
        return jsonify(e.to_dict())

作者: AutoRedTeam Team
版本: 2.0.0
"""

from __future__ import annotations

import functools
import logging
import traceback
from typing import Optional, Any, Dict, Callable, TypeVar, Union, Type

T = TypeVar('T')


# ============================================================================
# 基础异常类
# ============================================================================

class AutoRedTeamError(Exception):
    """
    AutoRedTeam 基础异常类

    所有自定义异常的父类，提供统一的异常格式和序列化支持。

    属性:
        message: 错误消息
        code: 错误代码，默认为异常类名
        details: 额外的错误详情字典
        cause: 原始异常（支持异常链）

    示例:
        >>> raise AutoRedTeamError("操作失败", code="OP_FAILED", details={"target": "192.168.1.1"})
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     raise AutoRedTeamError("包装后的异常", cause=e)
    """

    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        """
        初始化异常实例

        参数:
            message: 错误消息描述
            code: 错误代码，用于程序化处理。如果未指定，使用类名
            details: 附加的错误详情，如目标URL、参数等
            cause: 导致此异常的原始异常，用于异常链追踪
        """
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}
        self.cause = cause

        # 如果有原始异常，设置异常链
        if cause is not None:
            self.__cause__ = cause

    def __str__(self) -> str:
        """返回格式化的错误字符串"""
        parts = [f"[{self.code}] {self.message}"]
        if self.details:
            parts.append(f"Details: {self.details}")
        if self.cause:
            parts.append(f"Caused by: {type(self.cause).__name__}: {self.cause}")
        return " | ".join(parts)

    def __repr__(self) -> str:
        """返回可用于调试的表示形式"""
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"code={self.code!r}, "
            f"details={self.details!r})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        将异常转换为字典格式，便于JSON序列化

        返回:
            包含错误信息的字典
        """
        result = {
            'error': self.code,
            'message': self.message,
            'details': self.details,
            'type': self.__class__.__name__,
        }
        if self.cause:
            result['cause'] = {
                'type': type(self.cause).__name__,
                'message': str(self.cause)
            }
        return result

    def get_traceback(self) -> str:
        """获取完整的异常堆栈追踪"""
        return ''.join(traceback.format_exception(type(self), self, self.__traceback__))


# ============================================================================
# 配置错误
# ============================================================================

class ConfigError(AutoRedTeamError):
    """
    配置错误

    当配置文件缺失、格式错误、参数无效时抛出。

    示例:
        >>> raise ConfigError("配置文件不存在", details={"path": "/etc/config.yaml"})
        >>> raise ConfigError("无效的配置项", code="INVALID_CONFIG", details={"key": "timeout", "value": -1})
    """
    pass


# ============================================================================
# HTTP错误
# ============================================================================

class HTTPError(AutoRedTeamError):
    """
    HTTP请求错误基类

    所有HTTP相关错误的父类，提供状态码和URL信息。

    属性:
        status_code: HTTP状态码（可选）
        url: 请求的URL（可选）
        method: HTTP方法（可选）
        response_body: 响应体片段（可选）
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        method: Optional[str] = None,
        response_body: Optional[str] = None,
        **kwargs
    ):
        """
        初始化HTTP错误

        参数:
            message: 错误消息
            status_code: HTTP响应状态码
            url: 请求的目标URL
            method: HTTP请求方法 (GET, POST等)
            response_body: 响应体的前N个字符（用于调试）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.url = url
        self.method = method
        self.response_body = response_body

        # 将HTTP特定信息添加到details
        if status_code is not None:
            self.details['status_code'] = status_code
        if url:
            self.details['url'] = url
        if method:
            self.details['method'] = method

    def to_dict(self) -> Dict[str, Any]:
        """扩展父类方法，添加HTTP特定字段"""
        result = super().to_dict()
        if self.status_code is not None:
            result['status_code'] = self.status_code
        if self.url:
            result['url'] = self.url
        return result


class ConnectionError(HTTPError):
    """
    连接错误

    当无法建立TCP连接、DNS解析失败、网络不可达时抛出。

    示例:
        >>> raise ConnectionError("无法连接到目标服务器", url="https://target.com")
        >>> raise ConnectionError("DNS解析失败", details={"hostname": "unknown.local"})
    """
    pass


class TimeoutError(HTTPError):
    """
    超时错误

    当请求超过预定时间未响应时抛出。

    属性:
        timeout: 超时时间设置（秒）
    """

    def __init__(
        self,
        message: str,
        timeout: Optional[float] = None,
        **kwargs
    ):
        """
        初始化超时错误

        参数:
            message: 错误消息
            timeout: 超时时间设置（秒）
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.timeout = timeout
        if timeout is not None:
            self.details['timeout'] = timeout


class SSLError(HTTPError):
    """
    SSL/TLS错误

    当SSL证书验证失败、TLS握手失败时抛出。

    示例:
        >>> raise SSLError("证书验证失败", url="https://self-signed.example.com")
        >>> raise SSLError("TLS版本不兼容", details={"supported": "TLSv1.2", "required": "TLSv1.3"})
    """
    pass


class ProxyError(HTTPError):
    """
    代理错误

    当代理连接失败、代理认证失败时抛出。

    属性:
        proxy_url: 代理服务器地址
    """

    def __init__(
        self,
        message: str,
        proxy_url: Optional[str] = None,
        **kwargs
    ):
        """
        初始化代理错误

        参数:
            message: 错误消息
            proxy_url: 代理服务器地址
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.proxy_url = proxy_url
        if proxy_url:
            self.details['proxy_url'] = proxy_url


# ============================================================================
# 认证错误
# ============================================================================

class AuthError(AutoRedTeamError):
    """
    认证错误基类

    所有认证相关错误的父类。

    示例:
        >>> raise AuthError("认证失败")
    """
    pass


class InvalidCredentials(AuthError):
    """
    无效凭证

    当用户名密码错误、API密钥无效时抛出。

    示例:
        >>> raise InvalidCredentials("用户名或密码错误")
        >>> raise InvalidCredentials("API密钥无效", details={"key_prefix": "sk-xxx..."})
    """
    pass


class TokenExpired(AuthError):
    """
    Token已过期

    当JWT、Session Token等认证令牌过期时抛出。

    属性:
        expired_at: 过期时间
    """

    def __init__(
        self,
        message: str = "认证令牌已过期",
        expired_at: Optional[str] = None,
        **kwargs
    ):
        """
        初始化Token过期错误

        参数:
            message: 错误消息
            expired_at: Token过期时间
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.expired_at = expired_at
        if expired_at:
            self.details['expired_at'] = expired_at


class PermissionDenied(AuthError):
    """
    权限不足

    当当前用户/角色没有执行操作的权限时抛出。

    示例:
        >>> raise PermissionDenied("需要管理员权限")
        >>> raise PermissionDenied("无权访问该资源", details={"resource": "/admin/users", "required_role": "admin"})
    """
    pass


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
        **kwargs
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
        **kwargs
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
        **kwargs
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
        **kwargs
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


# ============================================================================
# 漏洞利用错误
# ============================================================================

class ExploitError(AutoRedTeamError):
    """
    漏洞利用错误基类

    漏洞利用过程中的错误。

    属性:
        vuln_type: 漏洞类型
        exploit_name: 利用程序名称
    """

    def __init__(
        self,
        message: str,
        vuln_type: Optional[str] = None,
        exploit_name: Optional[str] = None,
        **kwargs
    ):
        """
        初始化漏洞利用错误

        参数:
            message: 错误消息
            vuln_type: 漏洞类型（如 SQLi, RCE）
            exploit_name: 利用程序名称
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.vuln_type = vuln_type
        self.exploit_name = exploit_name
        if vuln_type:
            self.details['vuln_type'] = vuln_type
        if exploit_name:
            self.details['exploit'] = exploit_name


class ExploitFailed(ExploitError):
    """
    利用失败

    当漏洞利用尝试未能成功时抛出。

    示例:
        >>> raise ExploitFailed("利用条件不满足", vuln_type="SQLi", details={"reason": "WAF拦截"})
    """
    pass


class PayloadDeliveryFailed(ExploitError):
    """
    Payload投递失败

    当Payload无法成功发送到目标时抛出。

    示例:
        >>> raise PayloadDeliveryFailed("Payload被过滤", details={"filter": "WAF", "payload_size": 1024})
    """
    pass


class ShellError(ExploitError):
    """
    Shell错误

    当获取/维持Shell连接失败时抛出。

    示例:
        >>> raise ShellError("反向Shell连接失败", details={"lhost": "10.0.0.1", "lport": 4444})
    """
    pass


# ============================================================================
# C2错误
# ============================================================================

class C2Error(AutoRedTeamError):
    """
    C2通信错误基类

    Command & Control 通信过程中的错误。

    属性:
        c2_server: C2服务器地址
        beacon_id: Beacon标识符
    """

    def __init__(
        self,
        message: str,
        c2_server: Optional[str] = None,
        beacon_id: Optional[str] = None,
        **kwargs
    ):
        """
        初始化C2错误

        参数:
            message: 错误消息
            c2_server: C2服务器地址
            beacon_id: Beacon标识符
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.c2_server = c2_server
        self.beacon_id = beacon_id
        if c2_server:
            self.details['c2_server'] = c2_server
        if beacon_id:
            self.details['beacon_id'] = beacon_id


class BeaconError(C2Error):
    """
    Beacon错误

    当Beacon心跳失败、状态异常时抛出。

    示例:
        >>> raise BeaconError("Beacon心跳超时", beacon_id="beacon-001")
        >>> raise BeaconError("Beacon注册失败", details={"reason": "认证失败"})
    """
    pass


class TunnelError(C2Error):
    """
    隧道错误

    当隧道建立失败、隧道断开时抛出。

    属性:
        tunnel_type: 隧道类型（HTTP, DNS, WebSocket等）
    """

    def __init__(
        self,
        message: str,
        tunnel_type: Optional[str] = None,
        **kwargs
    ):
        """
        初始化隧道错误

        参数:
            message: 错误消息
            tunnel_type: 隧道类型
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.tunnel_type = tunnel_type
        if tunnel_type:
            self.details['tunnel_type'] = tunnel_type


class EncryptionError(C2Error):
    """
    加密错误

    当加密/解密失败、密钥交换失败时抛出。

    示例:
        >>> raise EncryptionError("密钥协商失败")
        >>> raise EncryptionError("解密失败", details={"algorithm": "AES-256-GCM"})
    """
    pass


# ============================================================================
# 横向移动错误
# ============================================================================

class LateralError(AutoRedTeamError):
    """
    横向移动错误基类

    横向移动过程中的错误。

    属性:
        source_host: 源主机
        target_host: 目标主机
    """

    def __init__(
        self,
        message: str,
        source_host: Optional[str] = None,
        target_host: Optional[str] = None,
        **kwargs
    ):
        """
        初始化横向移动错误

        参数:
            message: 错误消息
            source_host: 源主机地址
            target_host: 目标主机地址
            **kwargs: 传递给父类的其他参数
        """
        super().__init__(message, **kwargs)
        self.source_host = source_host
        self.target_host = target_host
        if source_host:
            self.details['source'] = source_host
        if target_host:
            self.details['target'] = target_host


class SMBError(LateralError):
    """
    SMB错误

    SMB协议操作失败时抛出。

    示例:
        >>> raise SMBError("SMB认证失败", target_host="192.168.1.10")
        >>> raise SMBError("共享访问被拒绝", details={"share": "C$"})
    """
    pass


class SSHError(LateralError):
    """
    SSH错误

    SSH连接或操作失败时抛出。

    示例:
        >>> raise SSHError("SSH认证失败", target_host="10.0.0.5")
        >>> raise SSHError("密钥认证失败", details={"key_type": "RSA"})
    """
    pass


class WMIError(LateralError):
    """
    WMI错误

    WMI操作失败时抛出。

    示例:
        >>> raise WMIError("WMI连接失败", target_host="192.168.1.20")
        >>> raise WMIError("WMI查询执行失败", details={"query": "SELECT * FROM Win32_Process"})
    """
    pass


# ============================================================================
# CVE错误
# ============================================================================

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
        **kwargs
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
        **kwargs
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
        **kwargs
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

    def __init__(
        self,
        message: str,
        task_id: Optional[str] = None,
        **kwargs
    ):
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
            self.details['task_id'] = task_id


class TaskNotFound(TaskError):
    """
    任务未找到

    当查询的任务ID不存在时抛出。

    示例:
        >>> raise TaskNotFound("任务不存在", task_id="task-12345")
    """
    pass


class TaskCancelled(TaskError):
    """
    任务已取消

    当尝试操作已取消的任务时抛出。

    示例:
        >>> raise TaskCancelled("任务已被用户取消", task_id="task-12345")
    """
    pass


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
        **kwargs
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
            self.details['queue_size'] = queue_size
        if max_size is not None:
            self.details['max_size'] = max_size


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

    def __init__(
        self,
        message: str,
        report_type: Optional[str] = None,
        **kwargs
    ):
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
            self.details['report_type'] = report_type


class TemplateError(ReportError):
    """
    模板错误

    当报告模板加载失败、渲染失败时抛出。

    示例:
        >>> raise TemplateError("模板文件不存在", details={"template": "report.html"})
        >>> raise TemplateError("模板语法错误", details={"line": 42})
    """
    pass


class ExportError(ReportError):
    """
    导出错误

    当报告导出失败时抛出。

    示例:
        >>> raise ExportError("PDF导出失败", report_type="PDF")
        >>> raise ExportError("无法写入文件", details={"path": "/reports/output.html"})
    """
    pass


# ============================================================================
# 辅助函数
# ============================================================================

def wrap_exception(
    exc: Exception,
    wrapper_class: Type[AutoRedTeamError] = AutoRedTeamError,
    message: Optional[str] = None
) -> AutoRedTeamError:
    """
    将标准异常包装为自定义异常

    如果传入的异常已经是 AutoRedTeamError 类型，直接返回。
    否则创建一个新的包装异常。

    参数:
        exc: 原始异常
        wrapper_class: 包装使用的异常类，默认为 AutoRedTeamError
        message: 自定义错误消息，如果为None则使用原始异常的消息

    返回:
        AutoRedTeamError 类型的异常

    示例:
        >>> try:
        ...     risky_operation()
        ... except Exception as e:
        ...     raise wrap_exception(e, HTTPError, "HTTP请求失败")
    """
    if isinstance(exc, AutoRedTeamError):
        return exc

    error_message = message or str(exc)
    return wrapper_class(
        error_message,
        cause=exc,
        details={'original_type': type(exc).__name__}
    )


def handle_exceptions(
    logger: Optional[logging.Logger] = None,
    default_return: Any = None,
    reraise: bool = False,
    error_mapping: Optional[Dict[Type[Exception], Type[AutoRedTeamError]]] = None
) -> Callable:
    """
    统一异常处理装饰器

    自动捕获函数中的异常，根据配置进行日志记录、异常转换或返回默认值。
    支持同步和异步函数。

    参数:
        logger: 日志记录器，用于记录异常信息
        default_return: 异常发生时的默认返回值
        reraise: 是否重新抛出异常（转换后的异常）
        error_mapping: 异常类型映射字典，如 {requests.Timeout: TimeoutError}

    返回:
        装饰器函数

    示例:
        >>> @handle_exceptions(logger=logger, default_return=[])
        ... def scan_ports(target):
        ...     ...

        >>> @handle_exceptions(reraise=True, error_mapping={socket.timeout: TimeoutError})
        ... async def fetch_data(url):
        ...     ...
    """
    import asyncio

    # 延迟导入 requests 以避免在未安装时报错
    try:
        import requests
        default_mapping: Dict[Type[Exception], Type[AutoRedTeamError]] = {
            requests.exceptions.Timeout: TimeoutError,
            requests.exceptions.ConnectionError: ConnectionError,
            requests.exceptions.SSLError: SSLError,
            requests.exceptions.ProxyError: ProxyError,
            requests.exceptions.RequestException: HTTPError,
        }
    except ImportError:
        default_mapping = {}

    # 添加标准库异常映射
    default_mapping.update({
        OSError: ConnectionError,
        ValueError: ValidationError,
        PermissionError: PermissionDenied,
        FileNotFoundError: ConfigError,
    })

    if error_mapping:
        default_mapping.update(error_mapping)

    def decorator(func: Callable[..., T]) -> Callable[..., Union[T, Any]]:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Union[T, Any]:
            try:
                return func(*args, **kwargs)
            except AutoRedTeamError:
                # 自定义异常直接处理
                if reraise:
                    raise
                if logger:
                    logger.exception("捕获到已知异常")
                return default_return
            except Exception as e:
                # 尝试映射到自定义异常
                for exc_type, target_exc in default_mapping.items():
                    if isinstance(e, exc_type):
                        new_exc = wrap_exception(e, target_exc)
                        if logger:
                            logger.warning(f"{target_exc.__name__}: {e}")
                        if reraise:
                            raise new_exc from e
                        return default_return

                # 未映射的异常
                if logger:
                    logger.exception(f"未预期的错误: {e}")
                if reraise:
                    raise wrap_exception(e) from e
                return default_return

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Union[T, Any]:
            try:
                return await func(*args, **kwargs)
            except AutoRedTeamError:
                if reraise:
                    raise
                if logger:
                    logger.exception("捕获到已知异常")
                return default_return
            except Exception as e:
                for exc_type, target_exc in default_mapping.items():
                    if isinstance(e, exc_type):
                        new_exc = wrap_exception(e, target_exc)
                        if logger:
                            logger.warning(f"{target_exc.__name__}: {e}")
                        if reraise:
                            raise new_exc from e
                        return default_return

                if logger:
                    logger.exception(f"未预期的错误: {e}")
                if reraise:
                    raise wrap_exception(e) from e
                return default_return

        # 根据函数类型返回对应的包装器
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# ============================================================================
# 向后兼容的别名
# ============================================================================

# 保持与旧代码的兼容性
NetworkError = HTTPError  # 旧名称映射到新名称
SecurityError = AuthError  # 旧名称映射到新名称
ToolError = AutoRedTeamError  # 通用工具错误


# ============================================================================
# 导出列表
# ============================================================================

__all__ = [
    # 基类
    'AutoRedTeamError',

    # 配置错误
    'ConfigError',

    # HTTP错误
    'HTTPError',
    'ConnectionError',
    'TimeoutError',
    'SSLError',
    'ProxyError',

    # 认证错误
    'AuthError',
    'InvalidCredentials',
    'TokenExpired',
    'PermissionDenied',

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

    # 漏洞利用错误
    'ExploitError',
    'ExploitFailed',
    'PayloadDeliveryFailed',
    'ShellError',

    # C2错误
    'C2Error',
    'BeaconError',
    'TunnelError',
    'EncryptionError',

    # 横向移动错误
    'LateralError',
    'SMBError',
    'SSHError',
    'WMIError',

    # CVE错误
    'CVEError',
    'CVENotFound',
    'PoCError',
    'SyncError',

    # 任务错误
    'TaskError',
    'TaskNotFound',
    'TaskCancelled',
    'QueueFull',

    # 报告错误
    'ReportError',
    'TemplateError',
    'ExportError',

    # 辅助函数
    'wrap_exception',
    'handle_exceptions',

    # 向后兼容别名
    'NetworkError',
    'SecurityError',
    'ToolError',
]
