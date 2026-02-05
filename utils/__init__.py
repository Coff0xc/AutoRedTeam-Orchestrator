#!/usr/bin/env python3
"""
AutoRedTeam-Orchestrator 工具函数层

提供统一的工具函数接口，包括：
- logger: 日志系统
- config: 配置管理
- validators: 输入验证
- encoding: 编码工具
- crypto: 加密工具
- file_utils: 文件操作
- net_utils: 网络工具
- async_utils: 异步工具
- decorators: 装饰器集合

使用示例:
    from utils import (
        get_logger, logger,
        get_config,
        validate_url, validate_ip,
        base64_encode, url_encode,
        md5, sha256, random_string,
        safe_write, safe_read, temp_file,
        is_port_open, resolve_hostname,
        run_sync, gather_with_limit,
        timer, retry, cache, rate_limit
    )
"""

# =============================================================================
# Async Utils - 异步工具
# =============================================================================
from utils.async_utils import (
    AsyncBatcher,
    AsyncThrottle,
    async_filter,
    async_first,
    async_map,
    async_race,
)
from utils.async_utils import async_retry as async_retry_util
from utils.async_utils import (
    ensure_async,
    ensure_sync,
    gather_with_limit,
    run_in_executor,
    run_sync,
    timeout_wrapper,
)

# =============================================================================
# Config - 配置管理
# =============================================================================
from utils.config import (
    GlobalConfig,
    get_config,
    get_config_value,
    reload_config,
    set_config,
)

# =============================================================================
# Crypto - 加密工具
# =============================================================================
from utils.crypto import (
    blake2b,
    blake2s,
    caesar_cipher,
    hash_file,
    hmac_md5,
    hmac_sha1,
    hmac_sha256,
    hmac_sha512,
    md5,
    password_strength,
    random_bytes,
    random_hex,
    random_int,
    random_string,
    random_token,
    random_uuid,
    rolling_xor,
    sha1,
    sha256,
    sha384,
    sha512,
    single_byte_xor,
    verify_hmac,
    vigenere_cipher,
    xor_encrypt,
    xor_encrypt_str,
)

# =============================================================================
# Decorators - 装饰器集合
# =============================================================================
from utils.decorators import (
    async_retry,
    async_timer,
    cache,
    cache_result,
    deprecated,
    log_execution,
    measure_time,
    memoize,
    rate_limit,
    retry,
    safe_execute,
    singleton,
    synchronized,
    timer,
    validate_args,
)

# =============================================================================
# Encoding - 编码工具
# =============================================================================
from utils.encoding import (
    MultiEncoder,
    ascii_decode,
    ascii_encode,
    base64_decode,
    base64_decode_str,
    base64_encode,
    base64_url_decode,
    base64_url_encode,
    binary_decode,
    binary_encode,
    double_url_encode,
    hex_decode,
    hex_decode_str,
    hex_encode,
    html_decode,
    html_encode,
    html_encode_all,
    html_encode_hex,
    multi_encode,
    octal_encode,
    rot13,
    unicode_decode,
    unicode_encode,
    unicode_encode_wide,
    url_decode,
    url_decode_plus,
    url_encode,
    url_encode_all,
    url_encode_plus,
)

# =============================================================================
# File Utils - 文件操作
# =============================================================================
from utils.file_utils import (
    copy_file,
    create_temp_dir,
    create_temp_file,
    delete_dir,
    delete_file,
    ensure_dir,
    file_info,
    find_files,
    get_project_root,
    get_temp_dir,
    iter_dirs,
    iter_files,
    move_file,
    safe_read,
    safe_read_bytes,
    safe_read_json,
    safe_write,
    safe_write_json,
    temp_dir,
    temp_file,
)

# =============================================================================
# Logger - 日志系统
# =============================================================================
from utils.logger import (
    ColoredFormatter,
    SecureFileHandler,
    add_file_handler,
    get_logger,
    logger,
    set_log_level,
    setup_logger,
)

# =============================================================================
# Net Utils - 网络工具
# =============================================================================
from utils.net_utils import (
    cidr_to_hosts,
    extract_domain,
    extract_root_domain,
    get_all_local_ips,
    get_fqdn,
    get_hostname,
    get_local_ip,
    get_service_banner,
    ip_in_network,
    is_loopback_ip,
    is_port_open,
    is_private_ip,
    is_reserved_ip,
    is_valid_mac,
    normalize_url,
    parse_port_range,
    parse_target,
    resolve_hostname,
    reverse_dns,
    scan_ports,
)

# =============================================================================
# 向后兼容导入
# =============================================================================
# 保持与旧版本的兼容性
from utils.report_generator import ReportGenerator

# =============================================================================
# Responses - 统一响应格式化
# =============================================================================
from utils.responses import error as resp_error
from utils.responses import import_error as resp_import_error
from utils.responses import success as resp_success
from utils.responses import tool_not_found as resp_tool_not_found
from utils.responses import validation_error as resp_validation_error
from utils.scan_monitor import (
    ScanStatus,
    ScanTask,
    cancel_scan,
    get_scan_status,
    list_running_scans,
    run_monitored_scan,
    scan_monitor,
)
from utils.terminal_output import TerminalLogger, run_with_realtime_output, terminal

# =============================================================================
# Tool Checker - 工具可用性检查（带缓存）
# =============================================================================
from utils.tool_checker import ToolChecker

# =============================================================================
# Validators - 输入验证
# =============================================================================
from utils.validators import (
    InputValidator,
    ValidationError,
    sanitize_command,
    sanitize_filename,
    sanitize_path,
    validate_and_raise,
    validate_cidr,
    validate_domain,
    validate_email,
    validate_ip,
    validate_ipv4,
    validate_ipv6,
    validate_port,
    validate_port_range,
    validate_url,
)

# =============================================================================
# 公共导出
# =============================================================================
__all__ = [
    # Logger
    "get_logger",
    "setup_logger",
    "set_log_level",
    "add_file_handler",
    "logger",
    "ColoredFormatter",
    "SecureFileHandler",
    # Config
    "GlobalConfig",
    "get_config",
    "set_config",
    "reload_config",
    "get_config_value",
    # Validators
    "ValidationError",
    "validate_url",
    "validate_ip",
    "validate_ipv4",
    "validate_ipv6",
    "validate_cidr",
    "validate_port",
    "validate_port_range",
    "validate_domain",
    "validate_email",
    "sanitize_path",
    "sanitize_command",
    "sanitize_filename",
    "InputValidator",
    "validate_and_raise",
    # Encoding
    "base64_encode",
    "base64_decode",
    "base64_decode_str",
    "base64_url_encode",
    "base64_url_decode",
    "hex_encode",
    "hex_decode",
    "hex_decode_str",
    "url_encode",
    "url_decode",
    "url_encode_plus",
    "url_decode_plus",
    "url_encode_all",
    "double_url_encode",
    "html_encode",
    "html_decode",
    "html_encode_all",
    "html_encode_hex",
    "unicode_encode",
    "unicode_decode",
    "unicode_encode_wide",
    "rot13",
    "binary_encode",
    "binary_decode",
    "octal_encode",
    "ascii_encode",
    "ascii_decode",
    "MultiEncoder",
    "multi_encode",
    # Crypto
    "md5",
    "sha1",
    "sha256",
    "sha384",
    "sha512",
    "blake2b",
    "blake2s",
    "hash_file",
    "hmac_md5",
    "hmac_sha1",
    "hmac_sha256",
    "hmac_sha512",
    "verify_hmac",
    "random_string",
    "random_bytes",
    "random_hex",
    "random_int",
    "random_uuid",
    "random_token",
    "xor_encrypt",
    "xor_encrypt_str",
    "single_byte_xor",
    "rolling_xor",
    "caesar_cipher",
    "vigenere_cipher",
    "password_strength",
    # File Utils
    "ensure_dir",
    "safe_write",
    "safe_read",
    "safe_read_bytes",
    "safe_read_json",
    "safe_write_json",
    "temp_file",
    "temp_dir",
    "create_temp_file",
    "create_temp_dir",
    "iter_files",
    "iter_dirs",
    "copy_file",
    "move_file",
    "delete_file",
    "delete_dir",
    "file_info",
    "find_files",
    "get_project_root",
    "get_temp_dir",
    # Net Utils
    "is_port_open",
    "scan_ports",
    "resolve_hostname",
    "reverse_dns",
    "get_local_ip",
    "get_all_local_ips",
    "get_hostname",
    "get_fqdn",
    "parse_target",
    "cidr_to_hosts",
    "ip_in_network",
    "is_private_ip",
    "is_reserved_ip",
    "is_loopback_ip",
    "parse_port_range",
    "normalize_url",
    "extract_domain",
    "extract_root_domain",
    "get_service_banner",
    "is_valid_mac",
    # Async Utils
    "run_sync",
    "ensure_async",
    "ensure_sync",
    "gather_with_limit",
    "timeout_wrapper",
    "async_retry_util",
    "run_in_executor",
    "async_map",
    "async_filter",
    "AsyncThrottle",
    "AsyncBatcher",
    "async_first",
    "async_race",
    # Decorators
    "timer",
    "async_timer",
    "retry",
    "async_retry",
    "cache",
    "deprecated",
    "synchronized",
    "rate_limit",
    "log_execution",
    "safe_execute",
    "singleton",
    "validate_args",
    "memoize",
    "measure_time",
    "cache_result",
    # 向后兼容
    "ReportGenerator",
    "terminal",
    "TerminalLogger",
    "run_with_realtime_output",
    "scan_monitor",
    "run_monitored_scan",
    "get_scan_status",
    "cancel_scan",
    "list_running_scans",
    "ScanStatus",
    "ScanTask",
    # Responses - 统一响应格式化
    "resp_success",
    "resp_error",
    "resp_tool_not_found",
    "resp_validation_error",
    "resp_import_error",
    # Tool Checker - 工具检查
    "ToolChecker",
]

# =============================================================================
# 版本信息
# =============================================================================
__version__ = "3.0.2"
__author__ = "AutoRedTeam"
