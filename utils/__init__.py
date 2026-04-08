#!/usr/bin/env python3
"""
AutoRedTeam-Orchestrator 工具函数层

提供统一的工具函数接口。所有导入采用惰性加载 (lazy import),
避免 `import utils` 时产生不必要的副作用。

使用示例:
    from utils import validate_url, md5, safe_write
    from utils import get_logger, logger
"""

from __future__ import annotations

__version__ = "3.0.2"
__author__ = "AutoRedTeam"

# ── 惰性导入映射: attr_name → (module_path, original_name | None) ──

_LAZY_IMPORTS: dict[str, tuple[str, str | None]] = {
    # Logger
    "get_logger": ("utils.logger", None),
    "setup_logger": ("utils.logger", None),
    "set_log_level": ("utils.logger", None),
    "add_file_handler": ("utils.logger", None),
    "logger": ("utils.logger", None),
    "configure_root_logger": ("utils.logger", None),
    "ColoredFormatter": ("utils.logger", None),
    "SecureFileHandler": ("utils.logger", None),
    # Config
    "GlobalConfig": ("utils.config", None),
    "get_config": ("utils.config", None),
    "set_config": ("utils.config", None),
    "reload_config": ("utils.config", None),
    "get_config_value": ("utils.config", None),
    # Validators
    "ValidationError": ("utils.validators", None),
    "validate_url": ("utils.validators", None),
    "validate_ip": ("utils.validators", None),
    "validate_ipv4": ("utils.validators", None),
    "validate_ipv6": ("utils.validators", None),
    "validate_cidr": ("utils.validators", None),
    "validate_port": ("utils.validators", None),
    "validate_port_range": ("utils.validators", None),
    "validate_domain": ("utils.validators", None),
    "validate_email": ("utils.validators", None),
    "sanitize_path": ("utils.validators", None),
    "sanitize_command": ("utils.validators", None),
    "sanitize_filename": ("utils.validators", None),
    "InputValidator": ("utils.validators", None),
    "validate_and_raise": ("utils.validators", None),
    # Encoding
    "base64_encode": ("utils.encoding", None),
    "base64_decode": ("utils.encoding", None),
    "base64_decode_str": ("utils.encoding", None),
    "base64_url_encode": ("utils.encoding", None),
    "base64_url_decode": ("utils.encoding", None),
    "hex_encode": ("utils.encoding", None),
    "hex_decode": ("utils.encoding", None),
    "hex_decode_str": ("utils.encoding", None),
    "url_encode": ("utils.encoding", None),
    "url_decode": ("utils.encoding", None),
    "url_encode_plus": ("utils.encoding", None),
    "url_decode_plus": ("utils.encoding", None),
    "url_encode_all": ("utils.encoding", None),
    "double_url_encode": ("utils.encoding", None),
    "html_encode": ("utils.encoding", None),
    "html_decode": ("utils.encoding", None),
    "html_encode_all": ("utils.encoding", None),
    "html_encode_hex": ("utils.encoding", None),
    "unicode_encode": ("utils.encoding", None),
    "unicode_decode": ("utils.encoding", None),
    "unicode_encode_wide": ("utils.encoding", None),
    "rot13": ("utils.encoding", None),
    "binary_encode": ("utils.encoding", None),
    "binary_decode": ("utils.encoding", None),
    "octal_encode": ("utils.encoding", None),
    "ascii_encode": ("utils.encoding", None),
    "ascii_decode": ("utils.encoding", None),
    "MultiEncoder": ("utils.encoding", None),
    "multi_encode": ("utils.encoding", None),
    # Crypto
    "md5": ("utils.crypto", None),
    "sha1": ("utils.crypto", None),
    "sha256": ("utils.crypto", None),
    "sha384": ("utils.crypto", None),
    "sha512": ("utils.crypto", None),
    "blake2b": ("utils.crypto", None),
    "blake2s": ("utils.crypto", None),
    "hash_file": ("utils.crypto", None),
    "hmac_md5": ("utils.crypto", None),
    "hmac_sha1": ("utils.crypto", None),
    "hmac_sha256": ("utils.crypto", None),
    "hmac_sha512": ("utils.crypto", None),
    "verify_hmac": ("utils.crypto", None),
    "random_string": ("utils.crypto", None),
    "random_bytes": ("utils.crypto", None),
    "random_hex": ("utils.crypto", None),
    "random_int": ("utils.crypto", None),
    "random_uuid": ("utils.crypto", None),
    "random_token": ("utils.crypto", None),
    "xor_encrypt": ("utils.crypto", None),
    "xor_encrypt_str": ("utils.crypto", None),
    "single_byte_xor": ("utils.crypto", None),
    "rolling_xor": ("utils.crypto", None),
    "caesar_cipher": ("utils.crypto", None),
    "vigenere_cipher": ("utils.crypto", None),
    "password_strength": ("utils.crypto", None),
    # File Utils
    "ensure_dir": ("utils.file_utils", None),
    "safe_write": ("utils.file_utils", None),
    "safe_read": ("utils.file_utils", None),
    "safe_read_bytes": ("utils.file_utils", None),
    "safe_read_json": ("utils.file_utils", None),
    "safe_write_json": ("utils.file_utils", None),
    "temp_file": ("utils.file_utils", None),
    "temp_dir": ("utils.file_utils", None),
    "create_temp_file": ("utils.file_utils", None),
    "create_temp_dir": ("utils.file_utils", None),
    "iter_files": ("utils.file_utils", None),
    "iter_dirs": ("utils.file_utils", None),
    "copy_file": ("utils.file_utils", None),
    "move_file": ("utils.file_utils", None),
    "delete_file": ("utils.file_utils", None),
    "delete_dir": ("utils.file_utils", None),
    "file_info": ("utils.file_utils", None),
    "find_files": ("utils.file_utils", None),
    "get_project_root": ("utils.file_utils", None),
    "get_temp_dir": ("utils.file_utils", None),
    # Net Utils
    "is_port_open": ("utils.net_utils", None),
    "scan_ports": ("utils.net_utils", None),
    "resolve_hostname": ("utils.net_utils", None),
    "reverse_dns": ("utils.net_utils", None),
    "get_local_ip": ("utils.net_utils", None),
    "get_all_local_ips": ("utils.net_utils", None),
    "get_hostname": ("utils.net_utils", None),
    "get_fqdn": ("utils.net_utils", None),
    "parse_target": ("utils.net_utils", None),
    "cidr_to_hosts": ("utils.net_utils", None),
    "ip_in_network": ("utils.net_utils", None),
    "is_private_ip": ("utils.net_utils", None),
    "is_reserved_ip": ("utils.net_utils", None),
    "is_loopback_ip": ("utils.net_utils", None),
    "parse_port_range": ("utils.net_utils", None),
    "normalize_url": ("utils.net_utils", None),
    "extract_domain": ("utils.net_utils", None),
    "extract_root_domain": ("utils.net_utils", None),
    "get_service_banner": ("utils.net_utils", None),
    "is_valid_mac": ("utils.net_utils", None),
    # Async Utils
    "run_sync": ("utils.async_utils", None),
    "ensure_async": ("utils.async_utils", None),
    "ensure_sync": ("utils.async_utils", None),
    "gather_with_limit": ("utils.async_utils", None),
    "timeout_wrapper": ("utils.async_utils", None),
    "async_retry_util": ("utils.async_utils", "async_retry"),
    "run_in_executor": ("utils.async_utils", None),
    "async_map": ("utils.async_utils", None),
    "async_filter": ("utils.async_utils", None),
    "AsyncThrottle": ("utils.async_utils", None),
    "AsyncBatcher": ("utils.async_utils", None),
    "async_first": ("utils.async_utils", None),
    "async_race": ("utils.async_utils", None),
    # Decorators
    "timer": ("utils.decorators", None),
    "async_timer": ("utils.decorators", None),
    "retry": ("utils.decorators", None),
    "async_retry": ("utils.decorators", None),
    "cache": ("utils.decorators", None),
    "deprecated": ("utils.decorators", None),
    "synchronized": ("utils.decorators", None),
    "rate_limit": ("utils.decorators", None),
    "log_execution": ("utils.decorators", None),
    "safe_execute": ("utils.decorators", None),
    "singleton": ("utils.decorators", None),
    "validate_args": ("utils.decorators", None),
    "memoize": ("utils.decorators", None),
    "measure_time": ("utils.decorators", None),
    "cache_result": ("utils.decorators", None),
    # Report
    "ReportGenerator": ("utils.report_generator", None),
    # Terminal
    "terminal": ("utils.terminal_output", None),
    "TerminalLogger": ("utils.terminal_output", None),
    "run_with_realtime_output": ("utils.terminal_output", None),
    # Scan Monitor
    "scan_monitor": ("utils.scan_monitor", None),
    "run_monitored_scan": ("utils.scan_monitor", None),
    "get_scan_status": ("utils.scan_monitor", None),
    "cancel_scan": ("utils.scan_monitor", None),
    "list_running_scans": ("utils.scan_monitor", None),
    "ScanStatus": ("utils.scan_monitor", None),
    "ScanTask": ("utils.scan_monitor", None),
    # Responses
    "resp_success": ("utils.responses", "success"),
    "resp_error": ("utils.responses", "error"),
    "resp_tool_not_found": ("utils.responses", "tool_not_found"),
    "resp_validation_error": ("utils.responses", "validation_error"),
    "resp_import_error": ("utils.responses", "import_error"),
    # Tool Checker
    "ToolChecker": ("utils.tool_checker", None),
}

__all__ = list(_LAZY_IMPORTS.keys())


def __getattr__(name: str):
    """惰性加载: 仅在首次访问属性时才导入对应模块"""
    if name in _LAZY_IMPORTS:
        module_path, original_name = _LAZY_IMPORTS[name]
        import importlib

        mod = importlib.import_module(module_path)
        attr = getattr(mod, original_name or name)
        # 缓存到模块命名空间, 后续访问不再经过 __getattr__
        globals()[name] = attr
        return attr
    raise AttributeError(f"module 'utils' has no attribute {name!r}")
