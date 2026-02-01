#!/usr/bin/env python3
"""
项目默认值和常量配置

统一管理项目中的各种默认参数、超时值、限制等。
修改此文件可以全局调整默认行为。

环境变量覆盖:
    部分值支持通过环境变量覆盖，格式为 AUTORT_{CATEGORY}_{NAME}
    例如: AUTORT_SCAN_TIMEOUT=60 覆盖扫描超时

使用示例:
    from core.defaults import ScanDefaults, C2Defaults, LateralDefaults

    timeout = ScanDefaults.TIMEOUT
    max_workers = LateralDefaults.MAX_WORKERS
"""

import os


def _env_int(key: str, default: int) -> int:
    """从环境变量获取整数，不存在则返回默认值"""
    value = os.environ.get(f"AUTORT_{key}")
    if value is not None:
        try:
            return int(value)
        except ValueError:
            pass
    return default


def _env_float(key: str, default: float) -> float:
    """从环境变量获取浮点数"""
    value = os.environ.get(f"AUTORT_{key}")
    if value is not None:
        try:
            return float(value)
        except ValueError:
            pass
    return default


class ScanDefaults:
    """扫描相关默认值（命名空间，不可实例化）"""

    TIMEOUT: float = _env_float("SCAN_TIMEOUT", 30.0)
    PORT_TIMEOUT: float = _env_float("SCAN_PORT_TIMEOUT", 3.0)
    MAX_WORKERS: int = _env_int("SCAN_MAX_WORKERS", 20)
    MAX_PAYLOADS: int = _env_int("SCAN_MAX_PAYLOADS", 50)
    MAX_RETRIES: int = _env_int("SCAN_MAX_RETRIES", 3)
    VERIFY_SSL: bool = False
    FOLLOW_REDIRECTS: bool = True
    MAX_REDIRECTS: int = 5


class HTTPDefaults:
    """HTTP 客户端默认值"""

    TIMEOUT: float = _env_float("HTTP_TIMEOUT", 30.0)
    CONNECT_TIMEOUT: float = _env_float("HTTP_CONNECT_TIMEOUT", 10.0)
    READ_TIMEOUT: float = _env_float("HTTP_READ_TIMEOUT", 30.0)
    MAX_CONNECTIONS: int = _env_int("HTTP_MAX_CONNECTIONS", 100)
    MAX_CONNECTIONS_PER_HOST: int = _env_int("HTTP_MAX_CONNECTIONS_PER_HOST", 30)
    VERIFY_SSL: bool = False
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class C2Defaults:
    """C2 通信默认值"""

    SHELL_TIMEOUT: int = _env_int("C2_SHELL_TIMEOUT", 60)
    MAX_OUTPUT_SIZE: int = _env_int("C2_MAX_OUTPUT_SIZE", 10000)
    BEACON_INTERVAL: float = _env_float("C2_BEACON_INTERVAL", 60.0)
    JITTER_PERCENT: float = _env_float("C2_JITTER_PERCENT", 20.0)
    HEARTBEAT_INTERVAL: float = _env_float("C2_HEARTBEAT_INTERVAL", 30.0)


class LateralDefaults:
    """横向移动默认值"""

    MAX_WORKERS: int = _env_int("LATERAL_MAX_WORKERS", 10)
    COMMAND_TIMEOUT: int = _env_int("LATERAL_CMD_TIMEOUT", 30)
    FILE_TRANSFER_CHUNK_SIZE: int = _env_int("LATERAL_CHUNK_SIZE", 65536)
    SSH_PORT: int = 22
    SMB_PORT: int = 445
    WMI_PORT: int = 135
    WINRM_PORT: int = 5985
    WINRM_SSL_PORT: int = 5986


class DetectorDefaults:
    """检测器默认值"""

    TIMEOUT: float = _env_float("DETECTOR_TIMEOUT", 30.0)
    MAX_PAYLOADS: int = _env_int("DETECTOR_MAX_PAYLOADS", 50)
    OOB_WAIT_TIME: float = _env_float("DETECTOR_OOB_WAIT", 3.0)
    MAX_RESPONSE_SIZE: int = _env_int("DETECTOR_MAX_RESPONSE", 1048576)  # 1MB


class CVEDefaults:
    """CVE 操作默认值"""

    SEARCH_LIMIT: int = _env_int("CVE_SEARCH_LIMIT", 20)
    CACHE_DAYS: int = _env_int("CVE_CACHE_DAYS", 7)
    SYNC_BATCH_SIZE: int = _env_int("CVE_SYNC_BATCH", 100)
    SYNC_TIMEOUT: float = _env_float("CVE_SYNC_TIMEOUT", 60.0)


class CredentialDefaults:
    """凭证操作默认值"""

    DUMP_TIMEOUT: int = _env_int("CRED_DUMP_TIMEOUT", 60)
    SEARCH_TIMEOUT: int = _env_int("CRED_SEARCH_TIMEOUT", 30)


class DNSDefaults:
    """DNS 操作默认值"""

    TIMEOUT: float = _env_float("DNS_TIMEOUT", 5.0)
    MAX_RETRIES: int = _env_int("DNS_MAX_RETRIES", 3)


class PerformanceDefaults:
    """性能相关默认值"""

    MAX_THREADS: int = _env_int("PERF_MAX_THREADS", 16)
    MAX_ASYNC_TASKS: int = _env_int("PERF_MAX_ASYNC_TASKS", 100)
    RATE_LIMIT_PER_SECOND: int = _env_int("PERF_RATE_LIMIT", 100)
    MEMORY_LIMIT_MB: int = _env_int("PERF_MEMORY_LIMIT_MB", 512)


class AIDefaults:
    """AI 引擎默认值"""

    REQUEST_TIMEOUT: float = _env_float("AI_REQUEST_TIMEOUT", 30.0)
    MAX_TOKENS: int = _env_int("AI_MAX_TOKENS", 2000)
    MAX_INPUT_LENGTH: int = _env_int("AI_MAX_INPUT_LENGTH", 200)
    MAX_OUTPUT_LENGTH: int = _env_int("AI_MAX_OUTPUT_LENGTH", 2000)
    MAX_CONTEXT_LENGTH: int = _env_int("AI_MAX_CONTEXT_LENGTH", 2000)
    MAX_SANITIZED_LENGTH: int = _env_int("AI_MAX_SANITIZED_LENGTH", 50)
    BASE_ESTIMATE_MINUTES: int = _env_int("AI_BASE_ESTIMATE_MINUTES", 30)


class ToolManagerDefaults:
    """外部工具管理器默认值"""

    SUBPROCESS_TIMEOUT: float = _env_float("TOOL_SUBPROCESS_TIMEOUT", 30.0)
    DEFAULT_CHUNK_SIZE: int = _env_int("TOOL_CHUNK_SIZE", 1024)
    MAX_SCAN_RATE: int = _env_int("TOOL_MAX_SCAN_RATE", 10000)
    MAX_PORT: int = 65535
    MASSCAN_DEFAULT_RATE: int = _env_int("TOOL_MASSCAN_RATE", 1000)


class GitDefaults:
    """Git 操作默认值"""

    MAX_COMMITS: int = _env_int("GIT_MAX_COMMITS", 100)


# 便捷访问的常量别名
SCAN_TIMEOUT = ScanDefaults.TIMEOUT
HTTP_TIMEOUT = HTTPDefaults.TIMEOUT
C2_SHELL_TIMEOUT = C2Defaults.SHELL_TIMEOUT
LATERAL_MAX_WORKERS = LateralDefaults.MAX_WORKERS
DNS_TIMEOUT = DNSDefaults.TIMEOUT
CRED_DUMP_TIMEOUT = CredentialDefaults.DUMP_TIMEOUT
AI_REQUEST_TIMEOUT = AIDefaults.REQUEST_TIMEOUT
AI_MAX_TOKENS = AIDefaults.MAX_TOKENS
SUBPROCESS_TIMEOUT = ToolManagerDefaults.SUBPROCESS_TIMEOUT
