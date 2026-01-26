#!/usr/bin/env python3
"""
文件操作工具模块 - AutoRedTeam-Orchestrator

提供安全的文件操作功能，包括：
- 安全读写（原子操作）
- 目录操作
- 临时文件管理
- 文件遍历
- 文件信息获取

跨平台兼容（Windows/Linux/macOS）

使用示例:
    from utils.file_utils import safe_write, safe_read, ensure_dir, temp_file

    # 安全写入
    safe_write(Path("output.txt"), "content")

    # 创建临时文件
    with temp_file(suffix=".txt") as f:
        f.write("temp content")
"""

import os
import shutil
import tempfile
import json
from pathlib import Path
from typing import Union, Optional, Iterator, List, Any, Generator
from contextlib import contextmanager
from datetime import datetime


def ensure_dir(path: Union[str, Path]) -> Path:
    """
    确保目录存在

    如果目录不存在则创建（包括所有父目录）

    Args:
        path: 目录路径

    Returns:
        Path对象
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_write(
    path: Union[str, Path],
    content: Union[str, bytes],
    encoding: str = 'utf-8',
    atomic: bool = True
) -> None:
    """
    安全写入文件

    使用原子写入（先写临时文件，再重命名），确保写入失败不会损坏原文件

    Args:
        path: 文件路径
        content: 要写入的内容（字符串或字节）
        encoding: 字符串编码方式
        atomic: 是否使用原子写入
    """
    path = Path(path)

    # 确保父目录存在
    ensure_dir(path.parent)

    if atomic:
        # 原子写入：先写临时文件，再重命名
        temp_path = path.with_suffix(path.suffix + '.tmp')

        try:
            if isinstance(content, bytes):
                temp_path.write_bytes(content)
            else:
                temp_path.write_text(content, encoding=encoding)

            # 重命名（原子操作）
            temp_path.replace(path)

        except (IOError, OSError, PermissionError):
            # 清理临时文件
            if temp_path.exists():
                temp_path.unlink()
            raise
    else:
        # 直接写入
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding=encoding)


def safe_read(
    path: Union[str, Path],
    encoding: str = 'utf-8',
    default: Optional[str] = None
) -> Optional[str]:
    """
    安全读取文件

    Args:
        path: 文件路径
        encoding: 字符串编码方式
        default: 文件不存在或读取失败时的默认值

    Returns:
        文件内容，失败时返回默认值
    """
    path = Path(path)

    try:
        return path.read_text(encoding=encoding)
    except FileNotFoundError:
        return default
    except (IOError, OSError, UnicodeDecodeError):
        return default


def safe_read_bytes(
    path: Union[str, Path],
    default: Optional[bytes] = None
) -> Optional[bytes]:
    """
    安全读取文件（字节模式）

    Args:
        path: 文件路径
        default: 文件不存在或读取失败时的默认值

    Returns:
        文件内容，失败时返回默认值
    """
    path = Path(path)

    try:
        return path.read_bytes()
    except (FileNotFoundError, PermissionError):
        return default


def safe_read_json(
    path: Union[str, Path],
    default: Optional[Any] = None,
    encoding: str = 'utf-8'
) -> Any:
    """
    安全读取JSON文件

    Args:
        path: 文件路径
        default: 文件不存在或解析失败时的默认值
        encoding: 文件编码

    Returns:
        解析后的JSON对象，失败时返回默认值
    """
    content = safe_read(path, encoding=encoding)

    if content is None:
        return default

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return default


def safe_write_json(
    path: Union[str, Path],
    data: Any,
    encoding: str = 'utf-8',
    indent: int = 2,
    ensure_ascii: bool = False
) -> None:
    """
    安全写入JSON文件

    Args:
        path: 文件路径
        data: 要写入的数据
        encoding: 文件编码
        indent: 缩进空格数
        ensure_ascii: 是否转义非ASCII字符
    """
    content = json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)
    safe_write(path, content, encoding=encoding)


@contextmanager
def temp_file(
    suffix: str = '',
    prefix: str = 'art_',
    dir: Optional[Union[str, Path]] = None,
    delete: bool = True
) -> Generator[Path, None, None]:
    """
    创建临时文件上下文管理器

    Args:
        suffix: 文件后缀
        prefix: 文件前缀
        dir: 临时目录
        delete: 退出时是否删除

    Yields:
        临时文件Path对象

    使用示例:
        with temp_file(suffix=".txt") as f:
            f.write_text("content")
            print(f.read_text())
    """
    if dir:
        dir = str(dir)

    fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
    temp_path = Path(temp_path)

    try:
        os.close(fd)  # 关闭文件描述符，允许后续操作
        yield temp_path
    finally:
        if delete and temp_path.exists():
            temp_path.unlink()


@contextmanager
def temp_dir(
    prefix: str = 'art_',
    dir: Optional[Union[str, Path]] = None,
    delete: bool = True
) -> Generator[Path, None, None]:
    """
    创建临时目录上下文管理器

    Args:
        prefix: 目录前缀
        dir: 父目录
        delete: 退出时是否删除

    Yields:
        临时目录Path对象

    使用示例:
        with temp_dir() as d:
            (d / "file.txt").write_text("content")
    """
    if dir:
        dir = str(dir)

    temp_path = Path(tempfile.mkdtemp(prefix=prefix, dir=dir))

    try:
        yield temp_path
    finally:
        if delete and temp_path.exists():
            shutil.rmtree(temp_path, ignore_errors=True)


def create_temp_file(
    suffix: str = '',
    prefix: str = 'art_',
    dir: Optional[Union[str, Path]] = None,
    content: Optional[Union[str, bytes]] = None
) -> Path:
    """
    创建临时文件（不自动删除）

    Args:
        suffix: 文件后缀
        prefix: 文件前缀
        dir: 临时目录
        content: 初始内容

    Returns:
        临时文件Path对象
    """
    if dir:
        dir = str(dir)

    fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
    temp_path = Path(temp_path)
    os.close(fd)

    if content is not None:
        if isinstance(content, bytes):
            temp_path.write_bytes(content)
        else:
            temp_path.write_text(content, encoding='utf-8')

    return temp_path


def create_temp_dir(
    prefix: str = 'art_',
    dir: Optional[Union[str, Path]] = None
) -> Path:
    """
    创建临时目录（不自动删除）

    Args:
        prefix: 目录前缀
        dir: 父目录

    Returns:
        临时目录Path对象
    """
    if dir:
        dir = str(dir)

    return Path(tempfile.mkdtemp(prefix=prefix, dir=dir))


def iter_files(
    directory: Union[str, Path],
    pattern: str = '*',
    recursive: bool = False,
    exclude_dirs: Optional[List[str]] = None
) -> Iterator[Path]:
    """
    迭代目录中的文件

    Args:
        directory: 目录路径
        pattern: 匹配模式（glob语法）
        recursive: 是否递归子目录
        exclude_dirs: 要排除的目录名列表

    Yields:
        匹配的文件Path对象
    """
    directory = Path(directory)
    exclude_dirs = set(exclude_dirs or [])

    if recursive:
        # 递归匹配
        for item in directory.rglob(pattern):
            # 检查是否在排除目录中
            if exclude_dirs:
                parts = item.relative_to(directory).parts
                if any(part in exclude_dirs for part in parts[:-1]):
                    continue

            if item.is_file():
                yield item
    else:
        # 非递归匹配
        for item in directory.glob(pattern):
            if item.is_file():
                yield item


def iter_dirs(
    directory: Union[str, Path],
    recursive: bool = False,
    exclude: Optional[List[str]] = None
) -> Iterator[Path]:
    """
    迭代目录中的子目录

    Args:
        directory: 目录路径
        recursive: 是否递归
        exclude: 要排除的目录名列表

    Yields:
        子目录Path对象
    """
    directory = Path(directory)
    exclude = set(exclude or [])

    if recursive:
        for item in directory.rglob('*'):
            if item.is_dir() and item.name not in exclude:
                yield item
    else:
        for item in directory.iterdir():
            if item.is_dir() and item.name not in exclude:
                yield item


def copy_file(
    src: Union[str, Path],
    dst: Union[str, Path],
    overwrite: bool = False
) -> Path:
    """
    复制文件

    Args:
        src: 源文件路径
        dst: 目标路径
        overwrite: 是否覆盖已存在的文件

    Returns:
        目标文件Path对象

    Raises:
        FileExistsError: 目标已存在且overwrite=False
    """
    src = Path(src)
    dst = Path(dst)

    if dst.exists() and not overwrite:
        raise FileExistsError(f"目标文件已存在: {dst}")

    # 确保目标目录存在
    ensure_dir(dst.parent)

    shutil.copy2(src, dst)
    return dst


def move_file(
    src: Union[str, Path],
    dst: Union[str, Path],
    overwrite: bool = False
) -> Path:
    """
    移动文件

    Args:
        src: 源文件路径
        dst: 目标路径
        overwrite: 是否覆盖已存在的文件

    Returns:
        目标文件Path对象
    """
    src = Path(src)
    dst = Path(dst)

    if dst.exists() and not overwrite:
        raise FileExistsError(f"目标文件已存在: {dst}")

    ensure_dir(dst.parent)
    shutil.move(str(src), str(dst))
    return dst


def delete_file(path: Union[str, Path], missing_ok: bool = True) -> bool:
    """
    删除文件

    Args:
        path: 文件路径
        missing_ok: 文件不存在时是否忽略

    Returns:
        是否成功删除
    """
    path = Path(path)

    try:
        path.unlink(missing_ok=missing_ok)
        return True
    except Exception:
        return False


def delete_dir(
    path: Union[str, Path],
    missing_ok: bool = True,
    recursive: bool = True
) -> bool:
    """
    删除目录

    Args:
        path: 目录路径
        missing_ok: 目录不存在时是否忽略
        recursive: 是否递归删除

    Returns:
        是否成功删除
    """
    path = Path(path)

    if not path.exists():
        return missing_ok

    try:
        if recursive:
            shutil.rmtree(path)
        else:
            path.rmdir()
        return True
    except Exception:
        return False


def file_info(path: Union[str, Path]) -> dict:
    """
    获取文件信息

    Args:
        path: 文件路径

    Returns:
        文件信息字典
    """
    path = Path(path)

    if not path.exists():
        return {'exists': False}

    stat = path.stat()

    return {
        'exists': True,
        'name': path.name,
        'stem': path.stem,
        'suffix': path.suffix,
        'path': str(path.absolute()),
        'parent': str(path.parent),
        'is_file': path.is_file(),
        'is_dir': path.is_dir(),
        'is_symlink': path.is_symlink(),
        'size': stat.st_size,
        'size_human': _human_readable_size(stat.st_size),
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
    }


def _human_readable_size(size: int) -> str:
    """转换为人类可读的大小"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def find_files(
    directory: Union[str, Path],
    name: Optional[str] = None,
    extension: Optional[str] = None,
    min_size: Optional[int] = None,
    max_size: Optional[int] = None,
    modified_after: Optional[datetime] = None,
    modified_before: Optional[datetime] = None,
    recursive: bool = True
) -> List[Path]:
    """
    查找文件

    Args:
        directory: 搜索目录
        name: 文件名匹配（支持glob通配符）
        extension: 扩展名过滤（如 '.txt'）
        min_size: 最小文件大小（字节）
        max_size: 最大文件大小（字节）
        modified_after: 修改时间晚于
        modified_before: 修改时间早于
        recursive: 是否递归搜索

    Returns:
        匹配的文件列表
    """
    directory = Path(directory)
    results = []

    # 确定匹配模式
    pattern = name if name else '*'
    if extension:
        if not extension.startswith('.'):
            extension = '.' + extension
        pattern = f'*{extension}' if pattern == '*' else pattern

    # 遍历文件
    for file_path in iter_files(directory, pattern, recursive):
        stat = file_path.stat()

        # 大小过滤
        if min_size is not None and stat.st_size < min_size:
            continue
        if max_size is not None and stat.st_size > max_size:
            continue

        # 时间过滤
        mtime = datetime.fromtimestamp(stat.st_mtime)
        if modified_after is not None and mtime < modified_after:
            continue
        if modified_before is not None and mtime > modified_before:
            continue

        results.append(file_path)

    return results


def get_project_root() -> Path:
    """
    获取项目根目录

    通过查找常见的项目标记文件来确定

    Returns:
        项目根目录Path对象
    """
    markers = [
        'pyproject.toml', 'setup.py', 'setup.cfg',
        '.git', 'requirements.txt', 'Makefile'
    ]

    current = Path(__file__).resolve().parent

    while current != current.parent:
        for marker in markers:
            if (current / marker).exists():
                return current
        current = current.parent

    # 找不到标记，返回utils目录的父目录
    return Path(__file__).resolve().parent.parent


def get_temp_dir() -> Path:
    """
    获取跨平台临时目录

    Returns:
        临时目录Path对象
    """
    return Path(tempfile.gettempdir())


__all__ = [
    'ensure_dir',
    'safe_write',
    'safe_read',
    'safe_read_bytes',
    'safe_read_json',
    'safe_write_json',
    'temp_file',
    'temp_dir',
    'create_temp_file',
    'create_temp_dir',
    'iter_files',
    'iter_dirs',
    'copy_file',
    'move_file',
    'delete_file',
    'delete_dir',
    'file_info',
    'find_files',
    'get_project_root',
    'get_temp_dir',
]
