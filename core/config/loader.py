"""
配置加载器

加载优先级（高 → 低）:
    1. 环境变量 (AUTORT_ 前缀)
    2. config/config.yaml
    3. Pydantic 模型默认值 (= 原 core/defaults.py 的值)

使用:
    from core.config import get_config

    cfg = get_config()
    cfg.scan.timeout  # 30.0 (或环境变量 AUTORT_SCAN_TIMEOUT 覆盖)
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .models import AutoRTConfig

logger = logging.getLogger(__name__)

# 全局单例
_config: Optional[AutoRTConfig] = None

# 配置文件搜索路径（相对于项目根）
_YAML_SEARCH_PATHS = [
    "config/config.yaml",
    "config/config.yml",
    "config.yaml",
    "config.yml",
]


def _find_yaml() -> Optional[Path]:
    """查找 YAML 配置文件"""
    # 环境变量指定的路径最优先
    env_path = os.environ.get("AUTORT_CONFIG")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p

    # 从项目根目录搜索
    project_root = Path(__file__).resolve().parent.parent.parent
    for rel in _YAML_SEARCH_PATHS:
        candidate = project_root / rel
        if candidate.is_file():
            return candidate

    return None


def _load_yaml(path: Path) -> Dict[str, Any]:
    """安全加载 YAML 文件"""
    try:
        import yaml

        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else {}
    except ImportError:
        logger.warning("pyyaml 未安装，跳过 YAML 配置: %s", path)
        return {}
    except Exception as e:
        logger.warning("加载 YAML 失败 %s: %s", path, e)
        return {}


def _env_override(key: str, default: Any) -> Any:
    """从 AUTORT_ 环境变量获取值，保持类型"""
    val = os.environ.get(f"AUTORT_{key}")
    if val is None:
        return default

    # 根据默认值类型转换
    if isinstance(default, bool):
        return val.lower() in ("true", "1", "yes")
    if isinstance(default, int):
        try:
            return int(val)
        except ValueError:
            return default
    if isinstance(default, float):
        try:
            return float(val)
        except ValueError:
            return default
    return val


def _apply_env_overrides(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 AUTORT_ 前缀的环境变量映射到配置字典。

    映射规则（与 core/defaults.py 的 env key 保持一致）:
        AUTORT_SCAN_TIMEOUT       → data["scan"]["timeout"]
        AUTORT_HTTP_TIMEOUT       → data["http"]["timeout"]
        AUTORT_C2_SHELL_TIMEOUT   → data["c2"]["shell_timeout"]
        ...
    """
    # 定义 env_key → (section, field, type_default) 的映射表
    _ENV_MAP: list[tuple[str, str, str, Any]] = [
        # scan
        ("SCAN_TIMEOUT", "scan", "timeout", 30.0),
        ("SCAN_PORT_TIMEOUT", "scan", "port_timeout", 3.0),
        ("SCAN_MAX_WORKERS", "scan", "max_workers", 20),
        ("SCAN_MAX_PAYLOADS", "scan", "max_payloads", 50),
        ("SCAN_MAX_RETRIES", "scan", "max_retries", 3),
        # http
        ("HTTP_TIMEOUT", "http", "timeout", 30.0),
        ("HTTP_CONNECT_TIMEOUT", "http", "connect_timeout", 10.0),
        ("HTTP_READ_TIMEOUT", "http", "read_timeout", 30.0),
        ("HTTP_MAX_CONNECTIONS", "http", "max_connections", 100),
        ("HTTP_MAX_CONNECTIONS_PER_HOST", "http", "max_connections_per_host", 30),
        # c2
        ("C2_SHELL_TIMEOUT", "c2", "shell_timeout", 60),
        ("C2_MAX_OUTPUT_SIZE", "c2", "max_output_size", 10000),
        ("C2_BEACON_INTERVAL", "c2", "beacon_interval", 60.0),
        ("C2_JITTER_PERCENT", "c2", "jitter_percent", 20.0),
        ("C2_HEARTBEAT_INTERVAL", "c2", "heartbeat_interval", 30.0),
        # lateral
        ("LATERAL_MAX_WORKERS", "lateral", "max_workers", 10),
        ("LATERAL_CMD_TIMEOUT", "lateral", "command_timeout", 30),
        ("LATERAL_CHUNK_SIZE", "lateral", "file_transfer_chunk_size", 65536),
        # detector
        ("DETECTOR_TIMEOUT", "detector", "timeout", 30.0),
        ("DETECTOR_MAX_PAYLOADS", "detector", "max_payloads", 50),
        ("DETECTOR_OOB_WAIT", "detector", "oob_wait_time", 3.0),
        ("DETECTOR_MAX_RESPONSE", "detector", "max_response_size", 1048576),
        # cve
        ("CVE_SEARCH_LIMIT", "cve", "search_limit", 20),
        ("CVE_CACHE_DAYS", "cve", "cache_days", 7),
        ("CVE_SYNC_BATCH", "cve", "sync_batch_size", 100),
        ("CVE_SYNC_TIMEOUT", "cve", "sync_timeout", 60.0),
        # credential
        ("CRED_DUMP_TIMEOUT", "credential", "dump_timeout", 60),
        ("CRED_SEARCH_TIMEOUT", "credential", "search_timeout", 30),
        # dns
        ("DNS_TIMEOUT", "dns", "timeout", 5.0),
        ("DNS_MAX_RETRIES", "dns", "max_retries", 3),
        # performance
        ("PERF_MAX_THREADS", "performance", "max_threads", 16),
        ("PERF_MAX_ASYNC_TASKS", "performance", "max_async_tasks", 100),
        ("PERF_RATE_LIMIT", "performance", "rate_limit_per_second", 100),
        ("PERF_MEMORY_LIMIT_MB", "performance", "memory_limit_mb", 512),
        # ai
        ("AI_REQUEST_TIMEOUT", "ai", "request_timeout", 30.0),
        ("AI_MAX_TOKENS", "ai", "max_tokens", 2000),
        ("AI_MAX_INPUT_LENGTH", "ai", "max_input_length", 200),
        ("AI_MAX_OUTPUT_LENGTH", "ai", "max_output_length", 2000),
        ("AI_MAX_CONTEXT_LENGTH", "ai", "max_context_length", 2000),
        ("AI_MAX_SANITIZED_LENGTH", "ai", "max_sanitized_length", 50),
        ("AI_BASE_ESTIMATE_MINUTES", "ai", "base_estimate_minutes", 30),
        # tool_manager
        ("TOOL_SUBPROCESS_TIMEOUT", "tool_manager", "subprocess_timeout", 30.0),
        ("TOOL_CHUNK_SIZE", "tool_manager", "default_chunk_size", 1024),
        ("TOOL_MAX_SCAN_RATE", "tool_manager", "max_scan_rate", 10000),
        ("TOOL_MASSCAN_RATE", "tool_manager", "masscan_default_rate", 1000),
        # git
        ("GIT_MAX_COMMITS", "git", "max_commits", 100),
    ]

    for env_key, section, field_name, type_default in _ENV_MAP:
        val = _env_override(env_key, None)
        if val is not None:
            data.setdefault(section, {})[field_name] = val
        else:
            # 确保 section 的 field 有值（_env_override 返回 None = 环境变量不存在）
            pass

    # 特殊的非 AUTORT_ 前缀变量
    auth_mode = os.environ.get("AUTOREDTEAM_AUTH_MODE")
    if auth_mode:
        data.setdefault("auth", {})["mode"] = auth_mode

    api_key = os.environ.get("AUTOREDTEAM_API_KEY")
    if api_key:
        data.setdefault("auth", {})["api_key"] = api_key

    master_key = os.environ.get("REDTEAM_MASTER_KEY")
    if master_key:
        data.setdefault("auth", {})["master_key"] = master_key

    return data


def _yaml_to_flat(yaml_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 config.yaml 的结构映射到 AutoRTConfig 的字段名。

    config.yaml 的顶层 key 与 AutoRTConfig field 名大多一致，
    这里只处理需要重映射的少数 case。
    """
    result: Dict[str, Any] = {}

    # 直接映射的 section
    direct_keys = {
        "server", "logging", "security", "wordlists", "reporting",
        "tools", "scanning", "scan", "http", "c2", "lateral",
        "detector", "cve", "credential", "dns", "performance",
        "ai", "tool_manager", "git", "auth", "cache",
    }

    for key in direct_keys:
        if key in yaml_data and isinstance(yaml_data[key], dict):
            result[key] = yaml_data[key]

    # api_keys 是 flat dict
    if "api_keys" in yaml_data and isinstance(yaml_data["api_keys"], dict):
        result["api_keys"] = yaml_data["api_keys"]

    return result


def _build_config() -> AutoRTConfig:
    """构建配置：YAML defaults → env overrides → Pydantic 验证"""
    data: Dict[str, Any] = {}

    # 1) 加载 YAML
    yaml_path = _find_yaml()
    if yaml_path:
        raw = _load_yaml(yaml_path)
        data = _yaml_to_flat(raw)
        logger.debug("从 YAML 加载配置: %s", yaml_path)

    # 2) 环境变量覆盖
    data = _apply_env_overrides(data)

    # 3) 构建 Pydantic 模型（字段验证 + 默认值填充）
    try:
        config = AutoRTConfig(**data)
    except Exception as e:
        logger.warning("配置验证失败，使用纯默认值: %s", e)
        config = AutoRTConfig()

    return config


# 线程安全单例
_config_lock = threading.Lock()


def get_config() -> AutoRTConfig:
    """
    获取全局配置单例 (线程安全)

    Returns:
        AutoRTConfig 实例
    """
    global _config
    if _config is not None:
        return _config
    with _config_lock:
        if _config is None:
            _config = _build_config()
    return _config


def reload_config() -> AutoRTConfig:
    """
    重新加载配置（丢弃缓存）

    Returns:
        新的 AutoRTConfig 实例
    """
    global _config
    with _config_lock:
        _config = _build_config()
    return _config


def reset_config() -> None:
    """重置配置单例（主要用于测试）"""
    global _config
    with _config_lock:
        _config = None
