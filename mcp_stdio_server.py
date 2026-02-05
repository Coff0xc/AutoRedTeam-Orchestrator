#!/usr/bin/env python3
"""
AutoRedTeam-Orchestrator MCP Server
AI驱动的自动化渗透测试框架 - MCP协议服务端

版本: 3.0.2
作者: AutoRedTeam Team
许可: 仅限授权安全测试使用

功能:
    - 纯Python安全工具 (工具数量由 handlers/ 自动统计)
    - 覆盖 OWASP Top 10、API安全、供应链安全、云原生安全
    - 支持 Cursor / Windsurf / Kiro 等AI编辑器

架构:
    - 工具按功能模块化拆分到 handlers/ 目录
    - 主文件仅负责 MCP 服务器初始化和工具注册调度
    - 工具数量以 ToolCounter 运行时统计为准
"""

from __future__ import annotations

import sys
import os
import logging

# 确保项目根目录在路径中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from mcp.server.fastmcp import FastMCP
from utils.logger import configure_root_logger


# ==================== 日志配置 ====================

configure_root_logger(level=logging.INFO, log_to_file=True, log_to_console=True)
logger = logging.getLogger("AutoRedTeam")


# ==================== MCP服务器实例 ====================

mcp = FastMCP("AutoRedTeam")


# ==================== 工具计数器 ====================

class ToolCounter:
    """工具注册计数器"""

    def __init__(self):
        self.counts = {
            'recon': 0,
            'detector': 0,
            'cve': 0,
            'redteam': 0,
            'orchestration': 0,  # 自动化编排
            'api_security': 0,
            'cloud_security': 0,
            'supply_chain': 0,
            'lateral': 0,        # 横向移动
            'persistence': 0,    # 持久化
            'ad': 0,             # AD攻击
            'external_tools': 0, # 外部工具集成
            'session': 0,
            'report': 0,
            'ai': 0,
            'misc': 0,
        }
        self.total = 0

    def add(self, category: str, count: int = 1):
        if category in self.counts:
            self.counts[category] += count
        else:
            self.counts['misc'] += count
        self.total += count

    def summary(self) -> str:
        parts = [f"{k}={v}" for k, v in self.counts.items() if v > 0]
        return f"总计 {self.total} 个工具 ({', '.join(parts)})"


_counter = ToolCounter()


# ==================== 工具注册入口 ====================

def register_all_tools():
    """注册所有工具到MCP"""
    from handlers import register_all_handlers

    logger.info("=" * 60)
    logger.info("AutoRedTeam MCP Server v3.0.2 - 工具注册")
    logger.info("=" * 60)

    # 使用模块化的 handlers 注册所有工具
    register_all_handlers(mcp, _counter, logger)

    logger.info("=" * 60)
    logger.info(f"工具注册完成: {_counter.summary()}")
    logger.info("=" * 60)


# ==================== 主入口 ====================

def main():
    """主入口函数"""

    # 注册所有工具
    register_all_tools()

    # 启动MCP服务器
    logger.info("AutoRedTeam MCP Server v3.0.2 启动中...")
    logger.info("支持: Cursor / Windsurf / Kiro 等AI编辑器")
    logger.info("-" * 60)

    # 根据命令行参数决定传输方式
    if len(sys.argv) > 1 and sys.argv[1] == '--stdio':
        mcp.run(transport='stdio')
    else:
        mcp.run()


if __name__ == "__main__":
    main()
