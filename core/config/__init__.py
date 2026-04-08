"""
core.config — 统一 Pydantic 配置系统

使用示例:
    from core.config import get_config, AutoRTConfig

    cfg = get_config()
    cfg.scan.timeout        # 30.0
    cfg.http.user_agent     # "Mozilla/5.0 ..."
    cfg.detector.timeout    # 30.0
"""

from .loader import get_config, reload_config, reset_config
from .models import (
    AIConfig,
    AuthConfig,
    AutoRTConfig,
    C2Config,
    CacheConfig,
    CredentialConfig,
    CVEConfig,
    DetectorConfig,
    DNSConfig,
    GitConfig,
    HTTPConfig,
    LateralConfig,
    LoggingConfig,
    PerformanceConfig,
    ReportingConfig,
    ScanConfig,
    ScanningConfig,
    SecurityConfig,
    ServerConfig,
    ToolManagerConfig,
    ToolsConfig,
    WordlistsConfig,
)
from core.sandbox.config import SandboxConfig

__all__ = [
    # 加载器
    "get_config",
    "reload_config",
    "reset_config",
    # 根模型
    "AutoRTConfig",
    # 子模型
    "ScanConfig",
    "HTTPConfig",
    "C2Config",
    "LateralConfig",
    "DetectorConfig",
    "CVEConfig",
    "CredentialConfig",
    "DNSConfig",
    "PerformanceConfig",
    "AIConfig",
    "ToolManagerConfig",
    "GitConfig",
    "AuthConfig",
    "ServerConfig",
    "LoggingConfig",
    "CacheConfig",
    "SecurityConfig",
    "WordlistsConfig",
    "ReportingConfig",
    "ToolsConfig",
    "ScanningConfig",
    "SandboxConfig",
]
