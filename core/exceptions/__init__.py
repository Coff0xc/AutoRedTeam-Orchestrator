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
├── PrivilegeEscalationError (权限提升错误)
│   ├── EscalationVectorNotFound
│   ├── InsufficientPrivilege
│   ├── UACBypassFailed
│   └── TokenManipulationError
├── ExfiltrationError (数据外泄错误)
│   ├── ChannelBlocked
│   ├── DataTooLarge
│   ├── ChannelConnectionError
│   └── EncryptionRequired
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
版本: 3.0.0
"""

# 基础异常
from .base import AutoRedTeamError, ConfigError

# HTTP 错误
from .http import (
    HTTPError,
    ConnectionError,
    TimeoutError,
    SSLError,
    ProxyError,
    NetworkError,  # 向后兼容别名
)

# 认证错误
from .auth import (
    AuthError,
    InvalidCredentials,
    TokenExpired,
    PermissionDenied,
    SecurityError,  # 向后兼容别名
)

# 扫描和检测器错误
from .scan import (
    ScanError,
    TargetUnreachable,
    ScanTimeout,
    RateLimited,
    DetectorError,
    PayloadError,
    ValidationError,
    DetectionTimeout,
)

# 漏洞利用、C2、横向移动错误
from .exploit import (
    ExploitError,
    ExploitFailed,
    PayloadDeliveryFailed,
    ShellError,
    C2Error,
    BeaconError,
    TunnelError,
    EncryptionError,
    LateralError,
    SMBError,
    SSHError,
    WMIError,
)

# 权限提升和数据外泄错误
from .privilege import (
    PrivilegeEscalationError,
    EscalationVectorNotFound,
    InsufficientPrivilege,
    UACBypassFailed,
    TokenManipulationError,
    ExfiltrationError,
    ChannelBlocked,
    DataTooLarge,
    ChannelConnectionError,
    EncryptionRequired,
)

# CVE 错误
from .cve import (
    CVEError,
    CVENotFound,
    PoCError,
    SyncError,
)

# 任务和报告错误
from .task import (
    TaskError,
    TaskNotFound,
    TaskCancelled,
    QueueFull,
    ReportError,
    TemplateError,
    ExportError,
)

# 辅助函数
from .utils import (
    wrap_exception,
    handle_exceptions,
)

# 向后兼容别名
ToolError = AutoRedTeamError

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

    # 权限提升错误
    'PrivilegeEscalationError',
    'EscalationVectorNotFound',
    'InsufficientPrivilege',
    'UACBypassFailed',
    'TokenManipulationError',

    # 数据外泄错误
    'ExfiltrationError',
    'ChannelBlocked',
    'DataTooLarge',
    'ChannelConnectionError',
    'EncryptionRequired',

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