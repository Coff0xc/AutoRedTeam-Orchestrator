#!/usr/bin/env python3
"""
统一日志系统 - AutoRedTeam-Orchestrator

提供彩色日志输出、文件日志记录、日志轮转等功能。
支持跨平台（Windows/Linux/macOS），自动检测终端颜色支持。

使用示例:
    from utils.logger import get_logger, logger

    # 使用预配置的默认日志器
    logger.info("这是一条信息")

    # 创建自定义日志器
    my_logger = get_logger("my_module", level=logging.DEBUG)
    my_logger.debug("调试信息")
"""

import logging
import sys
import os
from pathlib import Path
from typing import Optional, Union
from datetime import datetime
from logging.handlers import RotatingFileHandler


class ColoredFormatter(logging.Formatter):
    """
    彩色日志格式化器

    根据日志级别为日志消息添加ANSI颜色代码。
    自动检测终端是否支持颜色输出。
    """

    # ANSI颜色代码
    COLORS = {
        'DEBUG': '\033[36m',     # 青色
        'INFO': '\033[32m',      # 绿色
        'WARNING': '\033[33m',   # 黄色
        'ERROR': '\033[31m',     # 红色
        'CRITICAL': '\033[35m',  # 紫色
    }
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # 时间戳颜色
    TIME_COLOR = '\033[90m'  # 灰色
    NAME_COLOR = '\033[94m'  # 蓝色

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        colored: bool = True
    ):
        """
        初始化彩色格式化器

        Args:
            fmt: 日志格式字符串
            datefmt: 时间格式字符串
            colored: 是否启用颜色
        """
        super().__init__(fmt, datefmt)
        self.colored = colored and self._supports_color()

    @staticmethod
    def _supports_color() -> bool:
        """检测终端是否支持颜色"""
        # 检查是否在TTY中运行
        if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
            return False

        # Windows 10+ 支持ANSI颜色
        if sys.platform == 'win32':
            try:
                # 尝试启用Windows ANSI支持
                import ctypes
                kernel32 = ctypes.windll.kernel32
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(
                    kernel32.GetStdHandle(-11),
                    0x0001 | 0x0002 | 0x0004
                )
                return True
            except Exception:
                # 检查环境变量
                return os.environ.get('TERM') or os.environ.get('ANSICON')

        # Unix系统通常支持
        return True

    def format(self, record: logging.LogRecord) -> str:
        """格式化日志记录"""
        if self.colored:
            # 获取级别对应的颜色
            level_color = self.COLORS.get(record.levelname, '')

            # 保存原始值
            original_levelname = record.levelname
            original_name = record.name
            original_msg = record.msg

            # 应用颜色
            record.levelname = f"{level_color}{self.BOLD}{record.levelname:8}{self.RESET}"
            record.name = f"{self.NAME_COLOR}{record.name}{self.RESET}"

            # 格式化消息
            result = super().format(record)

            # 恢复原始值（避免影响其他handler）
            record.levelname = original_levelname
            record.name = original_name
            record.msg = original_msg

            return result

        return super().format(record)


class SecureFileHandler(RotatingFileHandler):
    """
    安全的文件日志处理器

    继承RotatingFileHandler，添加：
    - 自动创建日志目录
    - UTF-8编码支持
    - 敏感信息过滤
    """

    # 敏感关键词列表（用于过滤）
    SENSITIVE_PATTERNS = [
        'password', 'passwd', 'secret', 'token', 'api_key',
        'apikey', 'credential', 'private_key', 'auth'
    ]

    def __init__(
        self,
        filename: Union[str, Path],
        maxBytes: int = 10 * 1024 * 1024,  # 10MB
        backupCount: int = 5,
        filter_sensitive: bool = True
    ):
        """
        初始化安全文件处理器

        Args:
            filename: 日志文件路径
            maxBytes: 单个日志文件最大大小
            backupCount: 保留的备份文件数量
            filter_sensitive: 是否过滤敏感信息
        """
        # 确保目录存在
        log_path = Path(filename)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        super().__init__(
            str(log_path),
            maxBytes=maxBytes,
            backupCount=backupCount,
            encoding='utf-8'
        )

        self.filter_sensitive = filter_sensitive

    def emit(self, record: logging.LogRecord) -> None:
        """发送日志记录"""
        if self.filter_sensitive:
            # 过滤敏感信息
            msg = str(record.msg)
            for pattern in self.SENSITIVE_PATTERNS:
                if pattern.lower() in msg.lower():
                    # 用星号替换敏感值
                    record.msg = self._mask_sensitive(msg)
                    break

        super().emit(record)

    @staticmethod
    def _mask_sensitive(msg: str) -> str:
        """掩盖敏感信息"""
        import re
        # 匹配常见的敏感信息模式
        patterns = [
            (r'(password|passwd|secret|token|api_key|apikey)[\s]*[=:]\s*["\']?([^"\'\s]+)', r'\1=***'),
            (r'Bearer\s+[A-Za-z0-9\-_\.]+', 'Bearer ***'),
            (r'Basic\s+[A-Za-z0-9+/=]+', 'Basic ***'),
        ]

        for pattern, replacement in patterns:
            msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)

        return msg


def get_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    colored: bool = True,
    log_to_file: bool = True,
    log_to_console: bool = True,
    max_file_size: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    filter_sensitive: bool = True
) -> logging.Logger:
    """
    获取配置好的日志器

    Args:
        name: 日志器名称
        level: 日志级别（默认INFO）
        log_file: 日志文件路径（默认自动生成）
        colored: 是否启用彩色输出
        log_to_file: 是否输出到文件
        log_to_console: 是否输出到控制台
        max_file_size: 单个日志文件最大大小（字节）
        backup_count: 保留的备份文件数量
        filter_sensitive: 是否过滤敏感信息

    Returns:
        配置好的Logger实例

    使用示例:
        >>> logger = get_logger("my_module")
        >>> logger.info("这是一条信息日志")
        >>> logger.warning("这是一条警告日志")

        >>> debug_logger = get_logger("debug", level=logging.DEBUG)
        >>> debug_logger.debug("调试信息")
    """
    # 获取或创建日志器
    logger = logging.getLogger(name)

    # 如果已配置，直接返回
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False  # 防止重复日志

    # 日志格式
    console_fmt = '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    file_fmt = '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s'
    date_fmt = '%Y-%m-%d %H:%M:%S'

    # 控制台处理器
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = ColoredFormatter(
            fmt=console_fmt,
            datefmt=date_fmt,
            colored=colored
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # 文件处理器
    if log_to_file:
        # 确定日志文件路径
        if log_file is None:
            # 使用默认路径：项目根目录/logs/name_date.log
            project_root = Path(__file__).parent.parent
            log_dir = project_root / 'logs'
            date_str = datetime.now().strftime('%Y%m%d')
            log_file = log_dir / f'{name}_{date_str}.log'

        file_handler = SecureFileHandler(
            filename=log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            filter_sensitive=filter_sensitive
        )
        file_handler.setLevel(logging.DEBUG)  # 文件记录所有级别
        file_formatter = logging.Formatter(fmt=file_fmt, datefmt=date_fmt)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def configure_root_logger(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    colored: bool = True,
    log_to_file: bool = True,
    log_to_console: bool = True,
    max_file_size: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    filter_sensitive: bool = True,
    stream = sys.stderr,
    force: bool = False
) -> logging.Logger:
    """
    配置根日志器，确保全局日志有统一输出（文件 + 控制台）

    Args:
        level: 日志级别
        log_file: 日志文件路径（默认自动生成）
        colored: 是否启用彩色输出
        log_to_file: 是否输出到文件
        log_to_console: 是否输出到控制台
        max_file_size: 单个日志文件最大大小（字节）
        backup_count: 保留的备份文件数量
        filter_sensitive: 是否过滤敏感信息
        stream: 控制台输出流
        force: 是否强制重置已有handler
    """
    root_logger = logging.getLogger()

    if root_logger.handlers and not force:
        return root_logger

    if force:
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)

    root_logger.setLevel(level)

    console_fmt = '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    file_fmt = '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s'
    date_fmt = '%Y-%m-%d %H:%M:%S'

    if log_to_console:
        console_handler = logging.StreamHandler(stream)
        console_handler.setLevel(level)
        console_formatter = ColoredFormatter(
            fmt=console_fmt,
            datefmt=date_fmt,
            colored=colored
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    if log_to_file:
        if log_file is None:
            project_root = Path(__file__).parent.parent
            log_dir = project_root / 'logs'
            date_str = datetime.now().strftime('%Y%m%d')
            log_file = log_dir / f'root_{date_str}.log'

        file_handler = SecureFileHandler(
            filename=log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            filter_sensitive=filter_sensitive
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(fmt=file_fmt, datefmt=date_fmt))
        root_logger.addHandler(file_handler)

    root_logger.info("Root logger configured")
    return root_logger


def set_log_level(logger_name: str, level: Union[int, str]) -> None:
    """
    动态设置日志级别

    Args:
        logger_name: 日志器名称
        level: 日志级别（可以是int或字符串如'DEBUG'）
    """
    logger = logging.getLogger(logger_name)

    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)


def add_file_handler(
    logger_name: str,
    log_file: Path,
    level: int = logging.DEBUG
) -> None:
    """
    为已存在的日志器添加文件处理器

    Args:
        logger_name: 日志器名称
        log_file: 日志文件路径
        level: 日志级别
    """
    logger = logging.getLogger(logger_name)

    file_handler = SecureFileHandler(filename=log_file)
    file_handler.setLevel(level)

    file_fmt = '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s'
    file_handler.setFormatter(logging.Formatter(file_fmt))

    logger.addHandler(file_handler)


# 创建预配置的默认日志器
logger = get_logger('autoredt', level=logging.INFO)


# 向后兼容：保留旧的 setup_logger 函数
def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    配置日志器（向后兼容）

    Args:
        name: 日志器名称
        level: 日志级别字符串

    Returns:
        配置好的Logger实例
    """
    log_level = getattr(logging, level.upper(), logging.INFO)
    return get_logger(name, level=log_level)


__all__ = [
    'ColoredFormatter',
    'SecureFileHandler',
    'get_logger',
    'configure_root_logger',
    'set_log_level',
    'add_file_handler',
    'logger',
    'setup_logger',
]
