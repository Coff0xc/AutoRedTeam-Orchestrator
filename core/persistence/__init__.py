# -*- coding: utf-8 -*-
"""
持久化模块 (Persistence Module)
ATT&CK Tactic: TA0003 - Persistence

提供多种持久化技术:
- Windows持久化 (注册表/计划任务/服务/WMI)
- Linux持久化 (crontab/systemd/SSH/LD_PRELOAD)
- Webshell管理 (PHP/JSP/ASPX/内存马)
"""

from .windows_persistence import (
    WindowsPersistence,
    PersistenceMethod,
    PersistenceResult,
    windows_persist
)

from .linux_persistence import (
    LinuxPersistence,
    LinuxPersistMethod,
    PersistenceResult as LinuxPersistenceResult
)

from .webshell_manager import (
    WebshellGenerator,
    WebshellType,
    ObfuscationLevel,
    WebshellResult,
    generate_webshell
)

__all__ = [
    # Windows
    'WindowsPersistence',
    'PersistenceMethod',
    'PersistenceResult',
    'windows_persist',
    # Linux
    'LinuxPersistence',
    'LinuxPersistMethod',
    'LinuxPersistenceResult',
    # Webshell
    'WebshellGenerator',
    'WebshellType',
    'ObfuscationLevel',
    'WebshellResult',
    'generate_webshell',
]
