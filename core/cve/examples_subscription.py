#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE订阅管理器 - 完整示例
展示订阅创建、CVE检查、通知等完整流程
"""

import asyncio
import sys
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from core.cve.subscription_manager import FilterType, NotifyMethod, SubscriptionManager


async def demo_basic_usage():
    """演示基础用法"""
    print("=" * 80)
    print("示例1: 基础订阅管理")
    print("=" * 80)

    manager = SubscriptionManager()

    # 添加订阅
    print("\n[1] 添加订阅")

    sub1 = manager.add_subscription(
        filter_type=FilterType.KEYWORD.value,
        filter_value="RCE",
        min_cvss=7.0,
        notify_method=NotifyMethod.CONSOLE.value,
    )
    print(f"  订阅1 (关键词 'RCE'): ID={sub1}")

    sub2 = manager.add_subscription(
        filter_type=FilterType.SEVERITY.value,
        filter_value="CRITICAL",
        min_cvss=0.0,
        notify_method=NotifyMethod.CONSOLE.value,
    )
    print(f"  订阅2 (严重性 CRITICAL): ID={sub2}")

    # 列出订阅
    print("\n[2] 当前订阅列表")
    subs = manager.list_subscriptions()
    for sub in subs:
        status = "启用" if sub.enabled else "禁用"
        print(
            f"  ID={sub.id} | {sub.filter_type}={sub.filter_value} | CVSS>={sub.min_cvss} | [{status}]"
        )


async def demo_cve_check():
    """演示CVE检查"""
    print("\n" + "=" * 80)
    print("示例2: CVE检查和通知")
    print("=" * 80)

    manager = SubscriptionManager()

    # 先同步CVE数据 (最近1天)
    print("\n[1] 同步CVE数据")
    print("  正在同步NVD数据 (最近1天)...")

    try:
        new, updated = await manager.cve_manager.sync_nvd(days_back=1)
        print(f"  ✓ NVD同步完成: 新增 {new}, 更新 {updated}")
    except Exception as e:
        print(f"  ✗ NVD同步失败: {e}")
        print("  (可能是网络问题或API限流,跳过此步骤)")
        return

    # 检查订阅匹配
    print("\n[2] 检查订阅匹配")
    matches = manager.check_new_cves()

    if matches:
        print(f"  ✓ 发现 {len(matches)} 个订阅匹配到新CVE")
        for sub_id, cves in matches.items():
            print(f"\n  订阅 ID={sub_id}: {len(cves)} 个CVE")
            for cve in cves[:3]:  # 只显示前3个
                print(f"    - {cve.cve_id} (CVSS: {cve.cvss}) {cve.severity}")
    else:
        print("  没有订阅匹配到新CVE")


async def demo_file_notification():
    """演示文件通知"""
    print("\n" + "=" * 80)
    print("示例3: 文件通知")
    print("=" * 80)

    import tempfile

    manager = SubscriptionManager()
    log_file = Path(tempfile.gettempdir()) / "apache_cves.log"

    # 添加文件通知订阅
    print(f"\n[1] 添加文件通知订阅 (输出到: {log_file})")
    sub_id = manager.add_subscription(
        filter_type=FilterType.KEYWORD.value,
        filter_value="Apache",
        min_cvss=5.0,
        notify_method=NotifyMethod.FILE.value,
        notify_target=str(log_file),
    )
    print(f"  订阅ID: {sub_id}")

    # 检查CVE
    print("\n[2] 检查CVE并写入文件")
    matches = manager.check_new_cves()

    if sub_id in matches:
        print(f"  ✓ 匹配到 {len(matches[sub_id])} 个CVE")
        print(f"  ✓ 通知已写入: {log_file}")

        # 显示文件内容 (前20行)
        if log_file.exists():
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[:20]
                print("\n  文件内容预览:")
                for line in lines:
                    print(f"    {line.rstrip()}")
    else:
        print("  未匹配到CVE")


async def demo_advanced_filters():
    """演示高级过滤"""
    print("\n" + "=" * 80)
    print("示例4: 高级过滤")
    print("=" * 80)

    manager = SubscriptionManager()

    # 产品过滤
    print("\n[1] 产品过滤 (nginx)")
    sub1 = manager.add_subscription(
        filter_type=FilterType.PRODUCT.value,
        filter_value="nginx",
        min_cvss=6.0,
        notify_method=NotifyMethod.CONSOLE.value,
    )
    print(f"  订阅ID: {sub1}")

    # CVSS范围过滤
    print("\n[2] CVSS范围过滤 (9.0-10.0)")
    sub2 = manager.add_subscription(
        filter_type=FilterType.CVSS_RANGE.value,
        filter_value="9.0-10.0",
        min_cvss=0.0,
        notify_method=NotifyMethod.CONSOLE.value,
    )
    print(f"  订阅ID: {sub2}")

    # 组合条件 (通过多个订阅实现)
    print("\n[3] 组合条件 (Apache + CVSS>=8.0)")
    sub3 = manager.add_subscription(
        filter_type=FilterType.KEYWORD.value,
        filter_value="Apache",
        min_cvss=8.0,
        notify_method=NotifyMethod.CONSOLE.value,
    )
    print(f"  订阅ID: {sub3}")


async def demo_subscription_management():
    """演示订阅管理"""
    print("\n" + "=" * 80)
    print("示例5: 订阅管理")
    print("=" * 80)

    manager = SubscriptionManager()

    # 添加多个订阅
    print("\n[1] 添加3个订阅")
    subs = []
    for i, keyword in enumerate(["SQLi", "XSS", "SSRF"], 1):
        sub_id = manager.add_subscription(
            filter_type=FilterType.KEYWORD.value,
            filter_value=keyword,
            min_cvss=5.0,
            notify_method=NotifyMethod.CONSOLE.value,
        )
        subs.append(sub_id)
        print(f"  订阅{i} (关键词 '{keyword}'): ID={sub_id}")

    # 禁用一个订阅
    print(f"\n[2] 禁用订阅 ID={subs[1]}")
    manager.disable_subscription(subs[1])
    print("  ✓ 已禁用")

    # 列出启用的订阅
    print("\n[3] 列出启用的订阅")
    active_subs = manager.list_subscriptions(enabled_only=True)
    print(f"  共 {len(active_subs)} 个启用的订阅:")
    for sub in active_subs:
        print(f"    ID={sub.id} | {sub.filter_type}={sub.filter_value}")

    # 获取统计
    print("\n[4] 订阅统计")
    for sub_id in subs:
        stats = manager.get_subscription_stats(sub_id)
        print(f"  订阅 ID={sub_id}:")
        print(f"    总通知: {stats['total_notifications']}")
        print(f"    最近7天: {stats['recent_notifications_7d']}")

    # 删除订阅
    print(f"\n[5] 删除订阅 ID={subs[2]}")
    manager.remove_subscription(subs[2])
    print("  ✓ 已删除")


async def demo_error_handling():
    """演示错误处理"""
    print("\n" + "=" * 80)
    print("示例6: 错误处理")
    print("=" * 80)

    manager = SubscriptionManager()

    # 测试无效过滤类型
    print("\n[1] 测试无效过滤类型")
    try:
        manager.add_subscription(
            filter_type="invalid_type",
            filter_value="test",
            notify_method=NotifyMethod.CONSOLE.value,
        )
    except ValueError as e:
        print(f"  ✓ 正确捕获异常: {e}")

    # 测试无效严重性
    print("\n[2] 测试无效严重性")
    try:
        manager.add_subscription(
            filter_type=FilterType.SEVERITY.value,
            filter_value="INVALID",
            notify_method=NotifyMethod.CONSOLE.value,
        )
    except ValueError as e:
        print(f"  ✓ 正确捕获异常: {e}")

    # 测试无效CVSS范围
    print("\n[3] 测试无效CVSS范围")
    try:
        manager.add_subscription(
            filter_type=FilterType.CVSS_RANGE.value,
            filter_value="invalid",
            notify_method=NotifyMethod.CONSOLE.value,
        )
    except ValueError as e:
        print(f"  ✓ 正确捕获异常: {e}")


async def main():
    """主函数"""
    print("\n" + "#" * 80)
    print("# CVE订阅管理器 - 完整示例")
    print("#" * 80)

    # 基础用法
    await demo_basic_usage()

    # 高级过滤
    await demo_advanced_filters()

    # 订阅管理
    await demo_subscription_management()

    # 错误处理
    await demo_error_handling()

    # 文件通知
    await demo_file_notification()

    # CVE检查 (需要网络)
    print("\n[注意] 以下示例需要网络连接,将尝试从NVD同步数据...")
    response = input("是否执行? (y/n): ")
    if response.lower() == "y":
        await demo_cve_check()
    else:
        print("跳过CVE检查示例")

    print("\n" + "#" * 80)
    print("# 所有示例完成!")
    print("#" * 80)


if __name__ == "__main__":
    asyncio.run(main())
