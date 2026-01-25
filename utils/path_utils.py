#!/usr/bin/env python3
"""
跨平台路径工具 - Cross-Platform Path Utilities

提供跨平台的路径处理函数，避免硬编码路径
"""

import os
import tempfile
from pathlib import Path
from typing import Optional


def get_temp_dir() -> Path:
    """
    获取临时目录（跨平台）

    Returns:
        临时目录的Path对象
    """
    return Path(tempfile.gettempdir())


def get_temp_file(suffix: str = "", prefix: str = "art_") -> Path:
    """
    创建临时文件（跨平台）

    Args:
        suffix: 文件后缀（如 .txt）
        prefix: 文件前缀

    Returns:
        临时文件的Path对象
    """
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    os.close(fd)
    return Path(path)


def get_log_dir() -> Path:
    """
    获取日志目录（跨平台）

    Returns:
        日志目录的Path对象
    """
    if os.name == 'nt':  # Windows
        log_dir = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'AutoRedTeam' / 'logs'
    else:  # Linux/macOS
        log_dir = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local' / 'state')) / 'autoredteam' / 'logs'

    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def get_data_dir() -> Path:
    """
    获取数据目录（跨平台）

    Returns:
        数据目录的Path对象
    """
    if os.name == 'nt':  # Windows
        data_dir = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'AutoRedTeam' / 'data'
    else:  # Linux/macOS
        data_dir = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'autoredteam'

    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_config_dir() -> Path:
    """
    获取配置目录（跨平台）

    Returns:
        配置目录的Path对象
    """
    if os.name == 'nt':  # Windows
        config_dir = Path(os.environ.get('APPDATA', Path.home())) / 'AutoRedTeam'
    else:  # Linux/macOS
        config_dir = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'autoredteam'

    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_cache_dir() -> Path:
    """
    获取缓存目录（跨平台）

    Returns:
        缓存目录的Path对象
    """
    if os.name == 'nt':  # Windows
        cache_dir = Path(os.environ.get('LOCALAPPDATA', Path.home())) / 'AutoRedTeam' / 'cache'
    else:  # Linux/macOS
        cache_dir = Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'autoredteam'

    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def normalize_path(path: str) -> Path:
    """
    规范化路径（跨平台）

    Args:
        path: 路径字符串

    Returns:
        规范化的Path对象
    """
    return Path(path).resolve()


def ensure_dir(path: Path) -> Path:
    """
    确保目录存在

    Args:
        path: 目录路径

    Returns:
        目录的Path对象
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_join(*parts: str) -> Path:
    """
    安全地连接路径（防止路径遍历）

    Args:
        *parts: 路径部分

    Returns:
        连接后的Path对象

    Raises:
        ValueError: 如果检测到路径遍历尝试
    """
    result = Path(parts[0])
    for part in parts[1:]:
        # 检查路径遍历
        if '..' in Path(part).parts:
            raise ValueError(f"路径遍历检测: {part}")
        result = result / part
    return result


# 常用路径常量
TEMP_DIR = get_temp_dir()
LOG_DIR = get_log_dir()
DATA_DIR = get_data_dir()
CONFIG_DIR = get_config_dir()
CACHE_DIR = get_cache_dir()


__all__ = [
    'get_temp_dir',
    'get_temp_file',
    'get_log_dir',
    'get_data_dir',
    'get_config_dir',
    'get_cache_dir',
    'normalize_path',
    'ensure_dir',
    'safe_join',
    'TEMP_DIR',
    'LOG_DIR',
    'DATA_DIR',
    'CONFIG_DIR',
    'CACHE_DIR',
]
