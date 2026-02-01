#!/usr/bin/env python3
"""
配置管理模块 - AutoRedTeam-Orchestrator

提供统一的配置管理，支持：
- 数据类配置定义
- YAML/JSON配置文件加载
- 环境变量覆盖
- 配置验证
- 单例模式

使用示例:
    from utils.config import get_config, GlobalConfig

    # 获取全局配置
    config = get_config()
    print(config.timeout)

    # 从文件加载配置
    config = GlobalConfig.load(Path("config.yaml"))
"""

import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GlobalConfig:
    """
    全局配置数据类

    包含所有通用配置项，支持从文件和环境变量加载。
    """

    # 调试配置
    debug: bool = False
    log_level: str = "INFO"
    log_dir: Path = field(default_factory=lambda: Path("logs"))

    # 网络配置
    timeout: float = 30.0
    max_retries: int = 3
    retry_delay: float = 1.0
    verify_ssl: bool = True
    proxy: Optional[str] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # 并发配置
    max_workers: int = 10
    rate_limit: float = 10.0  # 请求/秒
    connection_limit: int = 100  # 最大连接数

    # 缓存配置
    cache_enabled: bool = True
    cache_ttl: int = 3600  # 秒
    cache_dir: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "autoredt_cache")

    # 输出配置
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    output_format: str = "json"  # json, html, markdown

    # 安全配置
    allowed_targets: List[str] = field(default_factory=list)
    blocked_targets: List[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    dangerous_operations: List[str] = field(default_factory=lambda: ["exploit", "brute_force"])

    # API配置
    api_keys: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理"""
        # 确保路径是Path对象
        if isinstance(self.log_dir, str):
            self.log_dir = Path(self.log_dir)
        if isinstance(self.cache_dir, str):
            self.cache_dir = Path(self.cache_dir)
        if isinstance(self.output_dir, str):
            self.output_dir = Path(self.output_dir)

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "GlobalConfig":
        """
        从配置文件加载配置

        支持YAML和JSON格式。

        Args:
            config_path: 配置文件路径，为None时自动搜索

        Returns:
            加载的配置实例
        """
        # 自动查找配置文件
        if config_path is None:
            config_path = cls._find_config_file()

        if config_path is None or not config_path.exists():
            # 使用默认配置
            return cls.from_env()

        # 读取配置文件
        config_data = cls._load_file(config_path)

        # 合并环境变量
        config_data = cls._merge_env(config_data)

        # 创建配置实例
        return cls._from_dict(config_data)

    @classmethod
    def from_env(cls) -> "GlobalConfig":
        """
        从环境变量加载配置

        环境变量前缀: AUTOREDT_

        Returns:
            配置实例
        """
        config_data = {}

        # 环境变量映射
        env_mapping = {
            "AUTOREDT_DEBUG": ("debug", lambda x: x.lower() in ("true", "1", "yes")),
            "AUTOREDT_LOG_LEVEL": ("log_level", str),
            "AUTOREDT_LOG_DIR": ("log_dir", Path),
            "AUTOREDT_TIMEOUT": ("timeout", float),
            "AUTOREDT_MAX_RETRIES": ("max_retries", int),
            "AUTOREDT_VERIFY_SSL": ("verify_ssl", lambda x: x.lower() in ("true", "1", "yes")),
            "AUTOREDT_PROXY": ("proxy", str),
            "AUTOREDT_MAX_WORKERS": ("max_workers", int),
            "AUTOREDT_RATE_LIMIT": ("rate_limit", float),
            "AUTOREDT_CACHE_ENABLED": (
                "cache_enabled",
                lambda x: x.lower() in ("true", "1", "yes"),
            ),
            "AUTOREDT_CACHE_TTL": ("cache_ttl", int),
            "AUTOREDT_OUTPUT_DIR": ("output_dir", Path),
            "AUTOREDT_OUTPUT_FORMAT": ("output_format", str),
        }

        for env_key, (config_key, converter) in env_mapping.items():
            value = os.environ.get(env_key)
            if value is not None:
                try:
                    config_data[config_key] = converter(value)
                except (ValueError, TypeError):
                    pass  # 忽略无效的环境变量

        # 加载API密钥
        api_keys = {}
        api_key_prefixes = ["SHODAN", "VIRUSTOTAL", "CENSYS", "OPENAI", "ANTHROPIC"]
        for prefix in api_key_prefixes:
            key = os.environ.get(f"{prefix}_API_KEY")
            if key:
                api_keys[prefix.lower()] = key

        if api_keys:
            config_data["api_keys"] = api_keys

        return cls(**config_data)

    @classmethod
    def _find_config_file(cls) -> Optional[Path]:
        """查找配置文件"""
        search_paths = [
            # 当前目录
            Path.cwd() / "config.yaml",
            Path.cwd() / "config.yml",
            Path.cwd() / "config.json",
            # config目录
            Path.cwd() / "config" / "config.yaml",
            Path.cwd() / "config" / "config.yml",
            Path.cwd() / "config" / "config.json",
            # 项目根目录
            Path(__file__).parent.parent / "config.yaml",
            Path(__file__).parent.parent / "config" / "config.yaml",
            # 用户目录
            Path.home() / ".autoredt" / "config.yaml",
            Path.home() / ".config" / "autoredt" / "config.yaml",
        ]

        # 检查环境变量指定的路径
        env_config = os.environ.get("AUTOREDT_CONFIG")
        if env_config:
            search_paths.insert(0, Path(env_config))

        for path in search_paths:
            if path.exists():
                return path

        return None

    @classmethod
    def _load_file(cls, path: Path) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            content = path.read_text(encoding="utf-8")

            if path.suffix in (".yaml", ".yml"):
                try:
                    import yaml

                    return yaml.safe_load(content) or {}
                except ImportError:
                    raise ImportError("需要安装 pyyaml: pip install pyyaml")

            elif path.suffix == ".json":
                return json.loads(content)

            else:
                # 尝试作为YAML解析
                try:
                    import yaml

                    return yaml.safe_load(content) or {}
                except ImportError:
                    return json.loads(content)

        except Exception as e:
            logger.warning(f"加载配置文件失败 {path}: {e}")
            return {}

    @classmethod
    def _merge_env(cls, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """合并环境变量到配置"""
        env_config = cls.from_env()
        env_dict = asdict(env_config)

        # 环境变量覆盖文件配置
        for key, value in env_dict.items():
            if key not in config_data:
                config_data[key] = value
            elif os.environ.get(f"AUTOREDT_{key.upper()}"):
                # 显式设置的环境变量优先
                config_data[key] = value

        return config_data

    @classmethod
    def _from_dict(cls, data: Dict[str, Any]) -> "GlobalConfig":
        """从字典创建配置"""
        # 过滤未知字段
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = asdict(self)
        # 将Path转换为字符串
        for key, value in result.items():
            if isinstance(value, Path):
                result[key] = str(value)
        return result

    def save(self, path: Path) -> None:
        """
        保存配置到文件

        Args:
            path: 保存路径
        """
        data = self.to_dict()
        content = None

        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml

                content = yaml.dump(data, allow_unicode=True, default_flow_style=False)
            except ImportError:
                path = path.with_suffix(".json")

        if content is None:
            content = json.dumps(data, indent=2, ensure_ascii=False)

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def validate(self) -> List[str]:
        """
        验证配置

        Returns:
            错误消息列表，空列表表示配置有效
        """
        errors = []

        # 验证超时
        if self.timeout <= 0:
            errors.append("timeout 必须大于 0")

        # 验证重试次数
        if self.max_retries < 0:
            errors.append("max_retries 不能为负数")

        # 验证并发数
        if self.max_workers <= 0:
            errors.append("max_workers 必须大于 0")

        # 验证速率限制
        if self.rate_limit <= 0:
            errors.append("rate_limit 必须大于 0")

        # 验证缓存TTL
        if self.cache_ttl < 0:
            errors.append("cache_ttl 不能为负数")

        # 验证日志级别
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_levels:
            errors.append(f"log_level 必须是 {valid_levels} 之一")

        # 验证输出格式
        valid_formats = ["json", "html", "markdown", "xml"]
        if self.output_format.lower() not in valid_formats:
            errors.append(f"output_format 必须是 {valid_formats} 之一")

        return errors

    def get_api_key(self, service: str) -> Optional[str]:
        """
        获取API密钥

        Args:
            service: 服务名称（如 shodan, virustotal）

        Returns:
            API密钥，不存在返回None
        """
        return self.api_keys.get(service.lower())

    def set_api_key(self, service: str, key: str) -> None:
        """
        设置API密钥

        Args:
            service: 服务名称
            key: API密钥
        """
        self.api_keys[service.lower()] = key


# 全局配置单例
_config: Optional[GlobalConfig] = None


def get_config() -> GlobalConfig:
    """
    获取全局配置单例

    Returns:
        全局配置实例
    """
    global _config
    if _config is None:
        _config = GlobalConfig.load()
    return _config


def set_config(config: GlobalConfig) -> None:
    """
    设置全局配置

    Args:
        config: 配置实例
    """
    global _config
    _config = config


def reload_config() -> GlobalConfig:
    """
    重新加载配置

    Returns:
        重新加载的配置实例
    """
    global _config
    _config = GlobalConfig.load()
    return _config


def get_config_value(key: str, default: Any = None) -> Any:
    """
    获取配置值

    支持点号分隔的嵌套键。

    Args:
        key: 配置键（如 'timeout' 或 'api_keys.shodan'）
        default: 默认值

    Returns:
        配置值
    """
    config = get_config()

    parts = key.split(".")
    value = config

    for part in parts:
        if hasattr(value, part):
            value = getattr(value, part)
        elif isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return default

    return value


__all__ = [
    "GlobalConfig",
    "get_config",
    "set_config",
    "reload_config",
    "get_config_value",
]
