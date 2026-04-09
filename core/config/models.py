"""
统一 Pydantic 配置模型

将 core/defaults.py, utils/config.py, core/http/config.py, config/config.yaml
中的分散配置合并为单一 Pydantic 模型树。

优先级（高 → 低）:
    环境变量 (AUTORT_ 前缀) > config/config.yaml > 代码默认值

使用示例:
    from core.config import get_config

    cfg = get_config()
    print(cfg.scan.timeout)       # 30.0
    print(cfg.http.user_agent)    # "Mozilla/5.0 ..."
"""

from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field

from core.sandbox.config import SandboxConfig  # noqa: E402 — 沙箱配置


# ---------------------------------------------------------------------------
# 子模型
# ---------------------------------------------------------------------------


class ScanConfig(BaseModel):
    """扫描相关配置 (对应 core.defaults.ScanDefaults)"""

    timeout: float = 30.0
    port_timeout: float = 3.0
    max_workers: int = 20
    max_payloads: int = 50
    max_retries: int = 3
    verify_ssl: bool = False
    follow_redirects: bool = True
    max_redirects: int = 5


class HTTPConfig(BaseModel):
    """HTTP 客户端配置 (对应 core.defaults.HTTPDefaults + core.http.config.HTTPConfig)"""

    timeout: float = 30.0
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    write_timeout: float = 30.0
    max_connections: int = 100
    max_connections_per_host: int = 30
    verify_ssl: bool = False
    follow_redirects: bool = True
    max_redirects: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # 重试
    max_retries: int = 3
    retry_delay: float = 1.0
    max_retry_delay: float = 30.0
    backoff_factor: float = 2.0

    # 连接池
    max_keepalive: int = 20
    keepalive_timeout: float = 5.0
    http2: bool = False

    # 调试
    debug: bool = False
    log_requests: bool = False
    log_responses: bool = False


class C2Config(BaseModel):
    """C2 通信配置 (对应 core.defaults.C2Defaults)"""

    shell_timeout: int = 60
    max_output_size: int = 10000
    beacon_interval: float = 60.0
    jitter_percent: float = 20.0
    heartbeat_interval: float = 30.0


class LateralConfig(BaseModel):
    """横向移动配置 (对应 core.defaults.LateralDefaults)"""

    max_workers: int = 10
    command_timeout: int = 30
    file_transfer_chunk_size: int = 65536
    ssh_port: int = 22
    smb_port: int = 445
    wmi_port: int = 135
    winrm_port: int = 5985
    winrm_ssl_port: int = 5986


class DetectorConfig(BaseModel):
    """检测器配置 (对应 core.defaults.DetectorDefaults)"""

    timeout: float = 30.0
    max_payloads: int = 50
    oob_wait_time: float = 3.0
    max_response_size: int = 1048576  # 1MB


class CVEConfig(BaseModel):
    """CVE 操作配置 (对应 core.defaults.CVEDefaults)"""

    search_limit: int = 20
    cache_days: int = 7
    sync_batch_size: int = 100
    sync_timeout: float = 60.0


class CredentialConfig(BaseModel):
    """凭证操作配置 (对应 core.defaults.CredentialDefaults)"""

    dump_timeout: int = 60
    search_timeout: int = 30


class DNSConfig(BaseModel):
    """DNS 操作配置 (对应 core.defaults.DNSDefaults)"""

    timeout: float = 5.0
    max_retries: int = 3


class PerformanceConfig(BaseModel):
    """性能相关配置 (对应 core.defaults.PerformanceDefaults)"""

    max_threads: int = 16
    max_async_tasks: int = 100
    rate_limit_per_second: int = 100
    memory_limit_mb: int = 512


class AIConfig(BaseModel):
    """AI 引擎配置 (对应 core.defaults.AIDefaults + config.yaml ai 段)"""

    provider: str = "openai"
    model: str = "gpt-4"
    api_key: str = ""
    temperature: float = 0.7
    max_tokens: int = 4000
    request_timeout: float = 30.0
    max_input_length: int = 200
    max_output_length: int = 2000
    max_context_length: int = 2000
    max_sanitized_length: int = 50
    base_estimate_minutes: int = 30


class LLMConfig(BaseModel):
    """统一 LLM Provider 配置 (对应 core.llm.provider 环境变量)"""

    provider: str = "none"  # openai / anthropic / ollama / deepseek / none
    model: str = ""  # 空字符串表示使用 provider 默认模型
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.3
    max_tokens: int = 2000


class ToolManagerConfig(BaseModel):
    """外部工具管理器配置 (对应 core.defaults.ToolManagerDefaults)"""

    subprocess_timeout: float = 30.0
    default_chunk_size: int = 1024
    max_scan_rate: int = 10000
    max_port: int = 65535
    masscan_default_rate: int = 1000


class GitConfig(BaseModel):
    """Git 操作配置 (对应 core.defaults.GitDefaults)"""

    max_commits: int = 100


class AuthConfig(BaseModel):
    """MCP 认证配置 (对应 .env AUTOREDTEAM_AUTH_MODE / API_KEY)"""

    mode: str = "strict"  # strict / permissive / disabled
    api_key: str = ""
    master_key: str = ""


class ServerConfig(BaseModel):
    """MCP 服务器配置 (对应 config.yaml server 段)"""

    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    threaded: bool = True


class LoggingConfig(BaseModel):
    """日志配置 (对应 config.yaml logging 段)"""

    level: str = "INFO"
    file_logging: bool = True
    console_logging: bool = True
    log_rotation: bool = True
    max_file_size: str = "10MB"
    backup_count: int = 5


class CacheConfig(BaseModel):
    """缓存配置 (对应 utils.config.GlobalConfig 缓存字段)"""

    enabled: bool = True
    ttl: int = 3600


# ---------------------------------------------------------------------------
# 法律免责声明
# ---------------------------------------------------------------------------

LEGAL_DISCLAIMER = (
    "\u26a0\ufe0f WARNING: This tool is for AUTHORIZED penetration testing only. "
    "Unauthorized use may violate applicable laws. "
    "Ensure you have written permission before testing any target."
)

# ---------------------------------------------------------------------------
# RFC 1918 + 云元数据 + 环回地址 — 默认阻止列表
# ---------------------------------------------------------------------------

_DEFAULT_BLOCKED_TARGETS: List[str] = [
    # 环回地址
    "127.0.0.1",
    "localhost",
    "::1",
    # 云元数据端点
    "169.254.169.254",
    "metadata.google.internal",
    # RFC 1918 内网网段
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]


class SecurityConfig(BaseModel):
    """安全配置 (对应 config.yaml security 段)"""

    allowed_targets: List[str] = Field(default_factory=list)
    blocked_targets: List[str] = Field(
        default_factory=lambda: list(_DEFAULT_BLOCKED_TARGETS)
    )
    dangerous_operations: List[str] = Field(
        default_factory=lambda: ["exploit", "brute_force", "dos"]
    )


class WordlistsConfig(BaseModel):
    """字典路径配置 (对应 config.yaml wordlists 段)"""

    directories: str = "wordlists/directories.txt"
    passwords: str = "wordlists/passwords.txt"
    usernames: str = "wordlists/usernames.txt"
    subdomains: str = "wordlists/subdomains.txt"


class ReportingConfig(BaseModel):
    """报告配置 (对应 config.yaml reporting 段)"""

    output_dir: str = "reports"
    default_format: str = "html"
    include_raw_output: bool = False


class ToolsConfig(BaseModel):
    """工具配置 (对应 config.yaml tools 段)"""

    default_timeout: int = 300
    max_concurrent: int = 5
    root_required: List[str] = Field(
        default_factory=lambda: ["nmap_scan", "nmap_os", "masscan"]
    )


class ScanningConfig(BaseModel):
    """扫描调度配置 (对应 config.yaml scanning 段)"""

    default_threads: int = 10
    default_delay: int = 100  # 毫秒
    rate_limit: int = 150


# ---------------------------------------------------------------------------
# 根配置
# ---------------------------------------------------------------------------


class AutoRTConfig(BaseModel):
    """
    AutoRedTeam-Orchestrator 统一配置根模型

    集成所有子系统配置，支持从 YAML + 环境变量加载。
    """

    # 核心子系统
    scan: ScanConfig = Field(default_factory=ScanConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    c2: C2Config = Field(default_factory=C2Config)
    lateral: LateralConfig = Field(default_factory=LateralConfig)
    detector: DetectorConfig = Field(default_factory=DetectorConfig)
    cve: CVEConfig = Field(default_factory=CVEConfig)
    credential: CredentialConfig = Field(default_factory=CredentialConfig)
    dns: DNSConfig = Field(default_factory=DNSConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    tool_manager: ToolManagerConfig = Field(default_factory=ToolManagerConfig)
    git: GitConfig = Field(default_factory=GitConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)

    # 服务器 & 基础设施
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    wordlists: WordlistsConfig = Field(default_factory=WordlistsConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)

    # 沙箱隔离
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)

    # API 密钥 (独立存储)
    api_keys: Dict[str, str] = Field(default_factory=dict)
