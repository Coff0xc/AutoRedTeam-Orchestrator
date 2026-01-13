#!/usr/bin/env python3
"""
配置管理器 - 统一配置加载和管理
优化点: 统一配置管理，支持环境变量覆盖，跨平台路径支持
"""

import os
import sys
import yaml
import logging
import tempfile
from typing import Any, Dict, Optional
from pathlib import Path
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


def _get_project_root() -> Path:
    """获取项目根目录"""
    return Path(__file__).parent.parent


def _get_default_wordlist_dir() -> Path:
    """获取默认字典目录 (跨平台)"""
    # 优先使用项目内的 wordlists 目录
    project_wordlists = _get_project_root() / "wordlists"
    if project_wordlists.exists():
        return project_wordlists

    # Linux/macOS 系统字典路径
    if sys.platform != "win32":
        linux_paths = [
            Path("/usr/share/wordlists"),
            Path("/usr/share/seclists"),
            Path.home() / "wordlists",
        ]
        for path in linux_paths:
            if path.exists():
                return path

    # Windows 或找不到时，使用项目目录
    return project_wordlists


def _get_platform_wordlist_path(filename: str, subdir: str = "") -> str:
    """获取跨平台字典文件路径"""
    base_dir = _get_default_wordlist_dir()

    if subdir:
        full_path = base_dir / subdir / filename
    else:
        full_path = base_dir / filename

    # 如果文件存在，返回绝对路径
    if full_path.exists():
        return str(full_path)

    # 否则返回相对路径（允许用户后续配置）
    return str(full_path)


def _get_default_output_dir() -> str:
    """获取默认输出目录 (跨平台)"""
    # 优先使用项目内的 reports 目录
    project_reports = _get_project_root() / "reports"
    return str(project_reports)


def _get_temp_dir() -> str:
    """获取跨平台临时目录"""
    return tempfile.gettempdir()


@dataclass
class ServerConfig:
    """服务器配置"""
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False
    threaded: bool = True


@dataclass
class AIConfig:
    """AI配置"""
    provider: str = "openai"
    model: str = "gpt-4"
    api_key: str = ""
    temperature: float = 0.7
    max_tokens: int = 4000


@dataclass
class LoggingConfig:
    """日志配置"""
    level: str = "INFO"
    file_logging: bool = True
    console_logging: bool = True
    log_rotation: bool = True
    max_file_size: str = "10MB"
    backup_count: int = 5


@dataclass
class ToolsConfig:
    """工具配置"""
    default_timeout: int = 300
    max_concurrent: int = 5
    root_required: list = field(default_factory=lambda: ["nmap_scan", "masscan"])


@dataclass
class ScanningConfig:
    """扫描配置"""
    default_threads: int = 10
    default_delay: int = 100
    rate_limit: int = 150


@dataclass
class WordlistsConfig:
    """字典配置 (跨平台支持)"""
    directories: str = field(default_factory=lambda: _get_platform_wordlist_path("directory-list-2.3-medium.txt", "dirbuster"))
    passwords: str = field(default_factory=lambda: _get_platform_wordlist_path("rockyou.txt"))
    usernames: str = field(default_factory=lambda: _get_platform_wordlist_path("top-usernames-shortlist.txt", "usernames"))
    subdomains: str = field(default_factory=lambda: _get_platform_wordlist_path("subdomains-top1million-5000.txt", "dns"))


@dataclass
class APIKeysConfig:
    """API密钥配置"""
    shodan: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    virustotal: str = ""


@dataclass
class ReportingConfig:
    """报告配置 (跨平台支持)"""
    output_dir: str = field(default_factory=_get_default_output_dir)
    default_format: str = "html"
    include_raw_output: bool = False


@dataclass
class SecurityConfig:
    """安全配置"""
    allowed_targets: list = field(default_factory=list)
    blocked_targets: list = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    dangerous_operations: list = field(default_factory=lambda: ["exploit", "brute_force", "dos"])


@dataclass
class AppConfig:
    """应用总配置"""
    server: ServerConfig = field(default_factory=ServerConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    wordlists: WordlistsConfig = field(default_factory=WordlistsConfig)
    api_keys: APIKeysConfig = field(default_factory=APIKeysConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)


class ConfigManager:
    """配置管理器"""
    
    _instance = None
    _config: Optional[AppConfig] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self._config = self._load_config()
    
    def _load_config(self) -> AppConfig:
        """加载配置"""
        # 默认配置文件路径
        config_path = self._find_config_file()
        
        if config_path and config_path.exists():
            logger.info(f"加载配置文件: {config_path}")
            config_dict = self._load_yaml(config_path)
        else:
            logger.warning("未找到配置文件，使用默认配置")
            config_dict = {}
        
        # 应用环境变量覆盖
        config_dict = self._apply_env_overrides(config_dict)
        
        # 构建配置对象
        return self._build_config(config_dict)
    
    def _find_config_file(self) -> Optional[Path]:
        """查找配置文件"""
        # 搜索路径
        search_paths = [
            Path.cwd() / "config" / "config.yaml",
            Path.cwd() / "config.yaml",
            Path(__file__).parent.parent / "config" / "config.yaml",
            Path.home() / ".ai-recon-mcp" / "config.yaml",
        ]
        
        # 环境变量指定的配置文件
        env_config = os.getenv("AI_RECON_CONFIG")
        if env_config:
            search_paths.insert(0, Path(env_config))
        
        for path in search_paths:
            if path.exists():
                return path
        
        return None
    
    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """加载YAML文件"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return {}
    
    def _apply_env_overrides(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """应用环境变量覆盖"""
        # 服务器配置
        if os.getenv("SERVER_HOST"):
            config.setdefault("server", {})["host"] = os.getenv("SERVER_HOST")
        if os.getenv("SERVER_PORT"):
            config.setdefault("server", {})["port"] = int(os.getenv("SERVER_PORT"))
        
        # AI配置
        if os.getenv("AI_PROVIDER"):
            config.setdefault("ai", {})["provider"] = os.getenv("AI_PROVIDER")
        if os.getenv("AI_MODEL"):
            config.setdefault("ai", {})["model"] = os.getenv("AI_MODEL")
        if os.getenv("OPENAI_API_KEY"):
            config.setdefault("ai", {})["api_key"] = os.getenv("OPENAI_API_KEY")
        
        # API密钥
        if os.getenv("SHODAN_API_KEY"):
            config.setdefault("api_keys", {})["shodan"] = os.getenv("SHODAN_API_KEY")
        if os.getenv("CENSYS_API_ID"):
            config.setdefault("api_keys", {})["censys_id"] = os.getenv("CENSYS_API_ID")
        if os.getenv("CENSYS_API_SECRET"):
            config.setdefault("api_keys", {})["censys_secret"] = os.getenv("CENSYS_API_SECRET")
        if os.getenv("VT_API_KEY"):
            config.setdefault("api_keys", {})["virustotal"] = os.getenv("VT_API_KEY")
        
        return config
    
    def _build_config(self, config_dict: Dict[str, Any]) -> AppConfig:
        """构建配置对象"""
        return AppConfig(
            server=ServerConfig(**config_dict.get("server", {})),
            ai=AIConfig(**config_dict.get("ai", {})),
            logging=LoggingConfig(**config_dict.get("logging", {})),
            tools=ToolsConfig(**config_dict.get("tools", {})),
            scanning=ScanningConfig(**config_dict.get("scanning", {})),
            wordlists=WordlistsConfig(**config_dict.get("wordlists", {})),
            api_keys=APIKeysConfig(**config_dict.get("api_keys", {})),
            reporting=ReportingConfig(**config_dict.get("reporting", {})),
            security=SecurityConfig(**config_dict.get("security", {}))
        )
    
    @property
    def config(self) -> AppConfig:
        """获取配置"""
        return self._config
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        parts = key.split('.')
        value = self._config
        
        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            else:
                return default
        
        return value
    
    def reload(self):
        """重新加载配置"""
        self._config = self._load_config()
        logger.info("配置已重新加载")
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        def dataclass_to_dict(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {
                    k: dataclass_to_dict(v)
                    for k, v in obj.__dict__.items()
                }
            elif isinstance(obj, list):
                return [dataclass_to_dict(item) for item in obj]
            else:
                return obj
        
        return dataclass_to_dict(self._config)


# 全局配置管理器实例
_config_manager = None


def get_config() -> AppConfig:
    """获取全局配置"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.config


def get_config_value(key: str, default: Any = None) -> Any:
    """获取配置值"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.get(key, default)


def reload_config():
    """重新加载配置"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    _config_manager.reload()
