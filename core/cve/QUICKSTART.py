#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE多源同步管理器 - 快速开始指南
5分钟掌握核心功能
"""

"""
==========================================
📦 文件结构
==========================================

core/cve/
├── update_manager.py          # 核心模块 (约400行)
├── __init__.py                # 模块导出
├── mcp_integration.py         # MCP集成示例
├── examples.py                # 使用示例集合
├── test_update_manager.py     # 单元测试
├── README.md                  # 完整文档
├── QUICKREF.md                # 快速参考
├── DELIVERY.md                # 交付文档
└── config.env.example         # 配置示例

data/
└── cve_index.db               # SQLite数据库 (自动创建)

==========================================
🚀 快速开始 (3步)
==========================================

步骤1: 导入模块
"""

from core.cve import CVEUpdateManager
import asyncio

# 步骤2: 初始化管理器
manager = CVEUpdateManager()

# 步骤3: 使用功能
# (见下方示例)

"""
==========================================
📊 示例1: 同步CVE数据
==========================================
"""

async def example_sync():
    # 同步最近7天的数据
    results = await manager.sync_all(days_back=7)

    # 结果示例:
    # {
    #     "NVD": (50, 10),           # 新增50, 更新10
    #     "Nuclei": (100, 20),       # 新增100, 更新20
    #     "Exploit-DB": (200, 5)     # 新增200, 更新5
    # }

    print(f"同步完成: {results}")


"""
==========================================
🔍 示例2: 搜索CVE
==========================================
"""

def example_search():
    # 搜索严重漏洞
    critical = manager.search(severity="CRITICAL", min_cvss=9.0)

    # 搜索特定产品
    apache = manager.search(keyword="Apache", poc_only=True)

    # 复合查询
    results = manager.search(
        keyword="SQL injection",
        severity="HIGH",
        min_cvss=7.0,
        poc_only=True
    )

    for cve in results[:5]:
        print(f"{cve.cve_id} [CVSS: {cve.cvss}]")
        print(f"  {cve.description[:100]}...")
        if cve.poc_available:
            print(f"  PoC: {cve.poc_path}")


"""
==========================================
📈 示例3: 统计分析
==========================================
"""

def example_stats():
    stats = manager.get_stats()

    print(f"总CVE数: {stats['total_cves']}")
    print(f"有PoC: {stats['poc_available']}")

    print("\n按严重性:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity}: {count}")

    print("\n按来源:")
    for source, count in stats['by_source'].items():
        print(f"  {source}: {count}")


"""
==========================================
🔧 CLI命令
==========================================

# 同步所有数据源
python core/cve/update_manager.py sync

# 搜索CVE
python core/cve/update_manager.py search "Apache"

# 查看统计
python core/cve/update_manager.py stats

# 运行示例
python core/cve/examples.py

# 运行测试
python core/cve/test_update_manager.py

==========================================
⚙️ 配置 (可选)
==========================================

# 提升NVD速率限制 (5 -> 50 req/30s)
export NVD_API_KEY="your_api_key"

# 提升GitHub速率限制 (60 -> 5000 req/hour)
export GITHUB_TOKEN="ghp_your_token"

申请地址:
- NVD: https://nvd.nist.gov/developers/request-an-api-key
- GitHub: https://github.com/settings/tokens

==========================================
🔌 MCP集成 (3步)
==========================================

步骤1: 导入模块
"""

from core.cve.mcp_integration import (
    init_cve_manager,
    cve_sync_all,
    cve_search,
    cve_stats
)

"""
步骤2: 初始化 (在服务器启动时)
"""

if __name__ == "__main__":
    init_cve_manager()

"""
步骤3: 注册MCP工具
"""

# @mcp.tool()
# async def cve_sync(days_back: int = 7) -> dict:
#     '''同步CVE数据库'''
#     return await cve_sync_all(days_back=days_back)

# @mcp.tool()
# def cve_search_tool(keyword: str = "", severity: str = "") -> dict:
#     '''搜索CVE漏洞'''
#     return cve_search(keyword, severity)

"""
==========================================
💡 使用场景
==========================================

场景1: 每日威胁情报收集
"""

async def daily_intel():
    manager = CVEUpdateManager()

    # 同步最新数据
    await manager.sync_all(days_back=1)

    # 收集高危CVE
    critical = manager.search(severity="CRITICAL", poc_only=True)

    # 生成报告
    print(f"今日新增严重漏洞: {len(critical)} 个")


"""
场景2: 产品安全监控
"""

def monitor_products():
    manager = CVEUpdateManager()

    products = ["Apache", "nginx", "MySQL", "Docker"]

    for product in products:
        cves = manager.search(keyword=product, severity="HIGH", poc_only=True)
        if cves:
            print(f"[警告] {product}: {len(cves)} 个高危漏洞")


"""
场景3: 导出JSON报告
"""

def export_report():
    import json
    manager = CVEUpdateManager()

    results = manager.search(severity="CRITICAL", min_cvss=9.0)

    report = {
        "date": datetime.now().isoformat(),
        "total": len(results),
        "cves": [cve.to_dict() for cve in results]
    }

    with open("cve_report.json", "w", encoding='utf-8') as f:
        json.dump(report, f, indent=2)


"""
==========================================
📚 数据源说明
==========================================

1. NVD (National Vulnerability Database)
   - 官方CVE数据库
   - CVSS分数、严重性、受影响产品
   - 速率限制: 5 req/30s (无Key) / 50 req/30s (有Key)

2. Nuclei Templates (ProjectDiscovery)
   - 社区驱动的漏洞验证模板
   - YAML格式PoC (可直接执行)
   - 速率限制: 60 req/hour (无Token) / 5000 req/hour (有Token)

3. Exploit-DB (Offensive Security)
   - 业界知名Exploit数据库
   - 可执行的Exploit代码
   - 速率限制: 无严格限制

==========================================
🛠️ 故障排查
==========================================

问题1: API速率限制
现象: "触发速率限制 [nvd], 等待 XX.Xs"
解决: 设置API Key或减少同步频率

问题2: 数据库锁定
现象: "database is locked"
解决: 避免多进程同时访问数据库

问题3: 网络超时
现象: "TimeoutError"
解决: 检查网络连接或使用代理

==========================================
✅ 功能验证
==========================================
"""

if __name__ == "__main__":
    print("=" * 60)
    print("CVE Manager - Quick Start Guide")
    print("=" * 60)

    # 初始化测试
    print("\n1. Initializing...")
    manager = CVEUpdateManager()
    print(f"   Database: {manager.db_path}")

    # 统计测试
    print("\n2. Statistics:")
    stats = manager.get_stats()
    print(f"   Total CVEs: {stats['total_cves']}")
    print(f"   PoC Available: {stats['poc_available']}")

    # 搜索测试
    print("\n3. Search Test:")
    results = manager.search(severity="CRITICAL")
    print(f"   Found {len(results)} critical CVEs")

    print("\n" + "=" * 60)
    print("Quick Start Guide Complete!")
    print("=" * 60)

    print("\nNext Steps:")
    print("  1. Sync data: asyncio.run(manager.sync_all())")
    print("  2. Search CVE: manager.search(keyword='Apache')")
    print("  3. View stats: manager.get_stats()")
    print("  4. Read docs: core/cve/README.md")

"""
==========================================
📖 更多资源
==========================================

- 完整文档: core/cve/README.md
- 快速参考: core/cve/QUICKREF.md
- 使用示例: core/cve/examples.py
- MCP集成: core/cve/mcp_integration.py
- 交付文档: core/cve/DELIVERY.md

==========================================
🎯 核心API速查
==========================================

# 同步
await manager.sync_all(days_back=7)
await manager.sync_nvd(days_back=7)
await manager.sync_nuclei_templates()
await manager.sync_exploit_db()

# 搜索
manager.search(keyword="", severity="", min_cvss=0.0, poc_only=False)

# 统计
manager.get_stats()

# 获取单个CVE
manager._get_cve(cve_id)

==========================================
END
==========================================
"""
