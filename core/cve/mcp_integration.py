#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE管理器 - MCP集成示例
展示如何在MCP Server中集成CVE管理功能
"""

import asyncio
from typing import Dict, Optional

from core.cve import CVEUpdateManager

# 全局实例 (在MCP服务器启动时初始化)
cve_manager = None


def init_cve_manager(db_path: Optional[str] = None) -> CVEUpdateManager:
    """
    初始化CVE管理器

    在 mcp_stdio_server.py 的启动代码中调用此函数
    """
    global cve_manager
    if cve_manager is None:
        cve_manager = CVEUpdateManager(db_path=db_path)
    return cve_manager


# ============================================================================
# MCP工具函数 (复制到 mcp_stdio_server.py)
# ============================================================================


async def cve_sync_all(days_back: int = 7) -> Dict:
    """
    MCP工具: 同步所有CVE数据源

    Args:
        days_back: 同步最近N天的CVE (默认7天)

    Returns:
        {
            "status": "success",
            "results": {
                "NVD": [new_count, updated_count],
                "Nuclei": [new_count, updated_count],
                "Exploit-DB": [new_count, updated_count]
            },
            "stats": {
                "total_cves": 1234,
                "poc_available": 567
            }
        }
    """
    manager = init_cve_manager()

    try:
        results = await manager.sync_all(days_back=days_back)
        stats = manager.get_stats()

        return {
            "status": "success",
            "results": {k: list(v) for k, v in results.items()},
            "stats": stats,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def cve_search(
    keyword: str = "",
    severity: str = "",
    min_cvss: float = 0.0,
    poc_only: bool = False,
    limit: int = 50,
) -> Dict:
    """
    MCP工具: 搜索CVE

    Args:
        keyword: 关键词 (搜索CVE ID或描述)
        severity: 严重性过滤 (CRITICAL/HIGH/MEDIUM/LOW)
        min_cvss: 最低CVSS分数
        poc_only: 仅显示有PoC的CVE
        limit: 最多返回结果数

    Returns:
        {
            "status": "success",
            "total": 123,
            "cves": [...]
        }
    """
    manager = init_cve_manager()

    try:
        results = manager.search(
            keyword=keyword,
            severity=severity.upper() if severity else None,
            min_cvss=min_cvss,
            poc_only=poc_only,
        )

        return {
            "status": "success",
            "total": len(results),
            "cves": [cve.to_dict() for cve in results[:limit]],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def cve_stats() -> Dict:
    """
    MCP工具: 获取CVE数据库统计信息

    Returns:
        {
            "status": "success",
            "total_cves": 1234,
            "poc_available": 567,
            "by_severity": {...},
            "by_source": {...},
            "last_sync": {...}
        }
    """
    manager = init_cve_manager()

    try:
        stats = manager.get_stats()
        return {"status": "success", **stats}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def cve_get(cve_id: str) -> Dict:
    """
    MCP工具: 获取单个CVE详细信息

    Args:
        cve_id: CVE ID (如: CVE-2024-1234)

    Returns:
        {
            "status": "success",
            "cve": {...}
        }
    """
    manager = init_cve_manager()

    try:
        cve = manager._get_cve(cve_id.upper())

        if cve:
            return {"status": "success", "cve": cve.to_dict()}
        else:
            return {"status": "not_found", "message": f"CVE {cve_id} not found in database"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ============================================================================
# mcp_stdio_server.py 集成代码 (添加到工具注册部分)
# ============================================================================

"""
# 1. 在 mcp_stdio_server.py 顶部导入
from core.cve.mcp_integration import (
    init_cve_manager,
    cve_sync_all,
    cve_search,
    cve_stats,
    cve_get
)

# 2. 在服务器启动时初始化
if __name__ == "__main__":
    # 初始化CVE管理器
    init_cve_manager()

    # 启动MCP服务器
    mcp.run()

# 3. 注册MCP工具
@mcp.tool()
async def cve_sync(days_back: int = 7) -> dict:
    '''同步CVE数据库 (NVD/Nuclei/Exploit-DB)'''
    return await cve_sync_all(days_back=days_back)

@mcp.tool()
def cve_search_tool(
    keyword: str = "",
    severity: str = "",
    min_cvss: float = 0.0,
    poc_only: bool = False
) -> dict:
    '''搜索CVE漏洞'''
    return cve_search(keyword, severity, min_cvss, poc_only)

@mcp.tool()
def cve_statistics() -> dict:
    '''获取CVE数据库统计'''
    return cve_stats()

@mcp.tool()
def cve_detail(cve_id: str) -> dict:
    '''获取CVE详细信息'''
    return cve_get(cve_id)
"""


# ============================================================================
# 使用示例 (AI对话场景)
# ============================================================================

"""
# 场景1: 用户请求同步CVE数据
用户: "更新CVE数据库"
AI调用: cve_sync(days_back=7)

# 场景2: 用户搜索特定漏洞
用户: "搜索Apache的严重漏洞"
AI调用: cve_search_tool(keyword="Apache", severity="CRITICAL", poc_only=True)

# 场景3: 用户查看统计
用户: "CVE数据库有多少条记录?"
AI调用: cve_statistics()

# 场景4: 用户查询特定CVE
用户: "CVE-2024-1234的详细信息"
AI调用: cve_detail(cve_id="CVE-2024-1234")

# 场景5: 复合查询
用户: "给我找CVSS大于9分且有PoC的SQL注入漏洞"
AI调用: cve_search_tool(keyword="SQL injection", min_cvss=9.0, poc_only=True)
"""


if __name__ == "__main__":
    """测试MCP集成函数"""
    import asyncio

    async def test():
        print("测试MCP集成函数...\n")

        # 测试初始化
        print("1. 初始化管理器")
        init_cve_manager()
        print("   ✓ 初始化成功\n")

        # 测试统计
        print("2. 获取统计信息")
        result = cve_stats()
        print(f"   总CVE数: {result.get('total_cves', 0)}")
        print(f"   有PoC: {result.get('poc_available', 0)}\n")

        # 测试同步 (仅NVD, 1天)
        print("3. 测试同步 (最近1天)")
        result = await cve_sync_all(days_back=1)
        print(f"   状态: {result['status']}")
        if result["status"] == "success":
            for source, counts in result["results"].items():
                print(f"   {source}: 新增 {counts[0]}, 更新 {counts[1]}")
        print()

        # 测试搜索
        print("4. 测试搜索 (CRITICAL)")
        result = cve_search(severity="CRITICAL", limit=5)
        print(f"   找到 {result['total']} 条结果")
        for cve in result.get("cves", [])[:3]:
            print(f"   • {cve['cve_id']} [CVSS: {cve['cvss']}]")

    asyncio.run(test())
