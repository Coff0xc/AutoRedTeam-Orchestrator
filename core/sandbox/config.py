"""
沙箱配置模型与命令执行结果

定义 SandboxConfig（Pydantic 模型）和 CommandResult（dataclass）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List

from pydantic import BaseModel, Field


class SandboxConfig(BaseModel):
    """沙箱配置"""

    enabled: bool = False  # 默认关闭, 保持轻量
    image: str = "python:3.12-slim"
    network_mode: str = "host"  # host 模式允许扫描目标
    timeout: int = 300  # 秒
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    auto_remove: bool = True
    volumes: List[str] = Field(default_factory=list)  # 额外挂载


@dataclass
class CommandResult:
    """命令执行结果"""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0
