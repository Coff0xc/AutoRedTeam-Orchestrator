#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE管理器使用示例
展示常见使用场景
"""

import asyncio
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.cve import CVEUpdateManager


async def example_basic_sync():
    """示例1: 基础同步"""
    print("\n" + "=" * 60)
    print("示例1: 基础CVE同步")
    print("=" * 60)

    manager = CVEUpdateManager()

    # 同步最近3天的NVD数据
    print("\n同步NVD (最近3天)...")
    new, updated = await manager.sync_nvd(days_back=3)
    print(f"完成: 新增 {new} CVE, 更新 {updated} CVE")


async def example_search_critical():
    """示例2: 搜索严重漏洞"""
    print("\n" + "=" * 60)
    print("示例2: 搜索严重漏洞 (CVSS >= 9.0)")
    print("=" * 60)

    manager = CVEUpdateManager()

    # 搜索高危CVE
    results = manager.search(severity="CRITICAL", min_cvss=9.0)

    print(f"\n找到 {len(results)} 个严重漏洞:\n")
    for i, cve in enumerate(results[:10], 1):
        print(f"{i}. {cve.cve_id} [CVSS: {cve.cvss}]")
        print(f"   {cve.description[:100]}...")
        if cve.poc_available:
            print(f"   ✓ PoC可用: {cve.poc_path}")
        print()


async def example_search_product():
    """示例3: 搜索特定产品漏洞"""
    print("\n" + "=" * 60)
    print("示例3: 搜索Apache相关漏洞")
    print("=" * 60)

    manager = CVEUpdateManager()

    # 搜索Apache相关CVE
    results = manager.search(keyword="Apache", poc_only=True)

    print(f"\n找到 {len(results)} 个Apache漏洞(有PoC):\n")
    for cve in results[:5]:
        print(f"• {cve.cve_id} [{cve.severity}]")
        print(f"  {cve.description[:80]}...")
        print(f"  PoC: {cve.poc_path}")
        print()


async def example_full_workflow():
    """示例4: 完整工作流"""
    print("\n" + "=" * 60)
    print("示例4: 完整CVE情报收集工作流")
    print("=" * 60)

    manager = CVEUpdateManager()

    # Step 1: 查看当前状态
    print("\n[1/4] 当前数据库状态:")
    stats = manager.get_stats()
    print(f"  总CVE数: {stats.get('total_cves', 0)}")
    print(f"  有PoC: {stats.get('poc_available', 0)}")

    # Step 2: 全量同步
    print("\n[2/4] 同步所有数据源 (最近7天)...")
    results = await manager.sync_all(days_back=7)

    for source, (new, updated) in results.items():
        print(f"  {source}: 新增 {new}, 更新 {updated}")

    # Step 3: 生成报告
    print("\n[3/4] 生成高危漏洞报告...")

    critical_cves = manager.search(severity="CRITICAL", poc_only=True)

    report_file = Path(__file__).parent / "critical_report.txt"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("严重漏洞报告 (有PoC可用)\n")
        f.write("=" * 80 + "\n\n")

        for cve in critical_cves[:50]:
            f.write(f"CVE ID: {cve.cve_id}\n")
            f.write(f"CVSS: {cve.cvss} | 严重性: {cve.severity}\n")
            f.write(f"描述: {cve.description}\n")
            f.write(f"PoC: {cve.poc_path}\n")
            f.write(f"更新时间: {cve.last_updated}\n")
            f.write("-" * 80 + "\n\n")

    print(f"  报告已保存: {report_file}")

    # Step 4: 统计分析
    print("\n[4/4] 统计分析:")
    stats = manager.get_stats()

    print(f"\n  总计: {stats.get('total_cves', 0)} CVE")
    print(f"\n  按严重性:")
    for severity, count in stats.get("by_severity", {}).items():
        print(f"    {severity}: {count}")

    print(f"\n  按来源:")
    for source, count in stats.get("by_source", {}).items():
        print(f"    {source}: {count}")


async def example_monitor_keywords():
    """示例5: 关键词监控"""
    print("\n" + "=" * 60)
    print("示例5: 关键词监控 (SQL注入)")
    print("=" * 60)

    manager = CVEUpdateManager()

    # 监控关键词列表
    keywords = ["SQL injection", "RCE", "authentication bypass"]

    for keyword in keywords:
        results = manager.search(keyword=keyword, min_cvss=7.0, poc_only=True)

        print(f"\n关键词: {keyword}")
        print(f"  发现 {len(results)} 个相关CVE (CVSS >= 7.0, 有PoC)")

        if results:
            print(f"  最新漏洞:")
            for cve in results[:3]:
                print(f"    • {cve.cve_id} [CVSS: {cve.cvss}]")


async def example_export_json():
    """示例6: 导出JSON"""
    print("\n" + "=" * 60)
    print("示例6: 导出高危漏洞为JSON")
    print("=" * 60)

    import json

    manager = CVEUpdateManager()

    # 搜索高危CVE
    results = manager.search(severity="HIGH", min_cvss=8.0, poc_only=True)

    # 导出JSON
    output_file = Path(__file__).parent / "high_severity.json"

    data = {
        "metadata": {
            "total": len(results),
            "filter": {"severity": "HIGH", "min_cvss": 8.0, "poc_only": True},
        },
        "cves": [cve.to_dict() for cve in results[:100]],
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"  导出 {len(results)} 个CVE到: {output_file}")


def show_menu():
    """显示菜单"""
    print("\n" + "=" * 60)
    print("CVE管理器使用示例")
    print("=" * 60)
    print("\n请选择示例:")
    print("1. 基础同步")
    print("2. 搜索严重漏洞")
    print("3. 搜索特定产品漏洞")
    print("4. 完整工作流")
    print("5. 关键词监控")
    print("6. 导出JSON")
    print("7. 运行所有示例")
    print("0. 退出")


async def main():
    """主函数"""
    examples = {
        "1": example_basic_sync,
        "2": example_search_critical,
        "3": example_search_product,
        "4": example_full_workflow,
        "5": example_monitor_keywords,
        "6": example_export_json,
    }

    while True:
        show_menu()
        choice = input("\n请选择 (0-7): ").strip()

        if choice == "0":
            print("\n再见!")
            break
        elif choice == "7":
            # 运行所有示例
            for example_func in examples.values():
                await example_func()
                input("\n按Enter继续...")
        elif choice in examples:
            await examples[choice]()
            input("\n按Enter继续...")
        else:
            print("无效选择!")


if __name__ == "__main__":
    asyncio.run(main())
