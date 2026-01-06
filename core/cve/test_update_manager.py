#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE更新管理器测试脚本
测试多数据源同步功能
"""

import asyncio
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.cve.update_manager import CVEUpdateManager


async def test_basic_functionality():
    """测试基本功能"""
    print("=" * 60)
    print("CVE更新管理器 - 功能测试")
    print("=" * 60)

    # 初始化管理器
    manager = CVEUpdateManager()

    print("\n1. 数据库初始化")
    print(f"   数据库路径: {manager.db_path}")
    print(f"   缓存目录: {manager.cache_dir}")

    # 查看初始统计
    print("\n2. 初始统计信息")
    stats = manager.get_stats()
    print(f"   总CVE数: {stats.get('total_cves', 0)}")
    print(f"   有PoC: {stats.get('poc_available', 0)}")

    # 测试NVD同步 (最近3天)
    print("\n3. 测试NVD同步 (最近3天)")
    try:
        new, updated = await manager.sync_nvd(days_back=3)
        print(f"   ✓ 新增: {new}, 更新: {updated}")
    except Exception as e:
        print(f"   ✗ 失败: {e}")

    # 测试Nuclei Templates同步
    print("\n4. 测试Nuclei Templates同步")
    try:
        new, updated = await manager.sync_nuclei_templates()
        print(f"   ✓ 新增: {new}, 更新: {updated}")
    except Exception as e:
        print(f"   ✗ 失败: {e}")

    # 测试Exploit-DB同步
    print("\n5. 测试Exploit-DB同步")
    try:
        new, updated = await manager.sync_exploit_db()
        print(f"   ✓ 新增: {new}, 更新: {updated}")
    except Exception as e:
        print(f"   ✗ 失败: {e}")

    # 查看最终统计
    print("\n6. 同步后统计信息")
    stats = manager.get_stats()
    print(f"   总CVE数: {stats.get('total_cves', 0)}")
    print(f"   有PoC: {stats.get('poc_available', 0)}")
    print(f"\n   按严重性:")
    for severity, count in stats.get('by_severity', {}).items():
        print(f"     {severity}: {count}")
    print(f"\n   按来源:")
    for source, count in stats.get('by_source', {}).items():
        print(f"     {source}: {count}")

    # 测试搜索功能
    print("\n7. 测试搜索功能")

    # 搜索CRITICAL级别CVE
    print("\n   搜索: 严重性=CRITICAL, 有PoC")
    results = manager.search(severity="CRITICAL", poc_only=True)
    print(f"   找到 {len(results)} 条结果")
    for cve in results[:5]:
        print(f"     [{cve.severity}] {cve.cve_id} (CVSS: {cve.cvss})")
        print(f"       {cve.description[:80]}...")

    # 搜索特定关键词
    print("\n   搜索: 关键词=SQL injection")
    results = manager.search(keyword="SQL injection", min_cvss=7.0)
    print(f"   找到 {len(results)} 条结果")
    for cve in results[:3]:
        print(f"     {cve.cve_id}: {cve.description[:80]}...")

    print("\n" + "=" * 60)
    print("测试完成!")
    print("=" * 60)


async def test_full_sync():
    """测试全量同步"""
    print("=" * 60)
    print("CVE更新管理器 - 全量同步测试")
    print("=" * 60)

    manager = CVEUpdateManager()

    print("\n开始全量同步...")
    results = await manager.sync_all(days_back=7)

    print("\n同步结果:")
    for source, (new, updated) in results.items():
        print(f"  {source}: 新增 {new}, 更新 {updated}")

    stats = manager.get_stats()
    print(f"\n总计: {stats.get('total_cves', 0)} CVE, {stats.get('poc_available', 0)} 有PoC")


async def test_search_queries():
    """测试各种搜索查询"""
    print("=" * 60)
    print("CVE更新管理器 - 搜索查询测试")
    print("=" * 60)

    manager = CVEUpdateManager()

    # 测试用例
    test_cases = [
        {"keyword": "Apache", "desc": "Apache相关CVE"},
        {"severity": "HIGH", "min_cvss": 8.0, "desc": "高危CVE (CVSS >= 8.0)"},
        {"poc_only": True, "desc": "仅显示有PoC的CVE"},
        {"keyword": "RCE", "poc_only": True, "desc": "RCE漏洞且有PoC"},
    ]

    for case in test_cases:
        desc = case.pop("desc")
        print(f"\n搜索: {desc}")
        results = manager.search(**case)
        print(f"  找到 {len(results)} 条结果")

        for cve in results[:3]:
            print(f"    {cve.cve_id} [{cve.severity}] CVSS:{cve.cvss}")
            if cve.poc_path:
                print(f"      PoC: {cve.poc_path}")


if __name__ == "__main__":
    print("\nCVE更新管理器测试菜单:")
    print("1. 基本功能测试")
    print("2. 全量同步测试")
    print("3. 搜索查询测试")
    print("4. 全部运行")

    choice = input("\n请选择 (1-4): ").strip()

    if choice == "1":
        asyncio.run(test_basic_functionality())
    elif choice == "2":
        asyncio.run(test_full_sync())
    elif choice == "3":
        asyncio.run(test_search_queries())
    elif choice == "4":
        asyncio.run(test_basic_functionality())
        asyncio.run(test_full_sync())
        asyncio.run(test_search_queries())
    else:
        print("无效选择")
