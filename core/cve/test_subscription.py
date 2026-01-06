#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE订阅管理器测试脚本
"""

import sys
import asyncio
from pathlib import Path
import tempfile

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from core.cve.subscription_manager import SubscriptionManager, FilterType, NotifyMethod


async def test_subscription_manager():
    """测试订阅管理器功能"""
    print("="*80)
    print("CVE订阅管理器功能测试")
    print("="*80)

    # 使用临时数据库
    test_db = Path(tempfile.gettempdir()) / "test_subscription.db"
    print(f"\n[1] 初始化订阅管理器")
    print(f"    数据库: {test_db}")

    manager = SubscriptionManager(db_path=str(test_db))
    print("    ✓ 初始化成功")

    # 测试添加订阅
    print(f"\n[2] 添加订阅")

    # 订阅1: 关键词 "Apache" + 高危
    sub1 = manager.add_subscription(
        filter_type=FilterType.KEYWORD.value,
        filter_value="Apache",
        min_cvss=7.0,
        notify_method=NotifyMethod.CONSOLE.value
    )
    print(f"    ✓ 订阅1: 关键词'Apache' CVSS>=7.0 (控制台通知) - ID={sub1}")

    # 订阅2: 产品 "nginx"
    sub2 = manager.add_subscription(
        filter_type=FilterType.PRODUCT.value,
        filter_value="nginx",
        min_cvss=5.0,
        notify_method=NotifyMethod.FILE.value,
        notify_target=str(Path(tempfile.gettempdir()) / "nginx_cves.log")
    )
    print(f"    ✓ 订阅2: 产品'nginx' CVSS>=5.0 (文件通知) - ID={sub2}")

    # 订阅3: 严重性 CRITICAL
    sub3 = manager.add_subscription(
        filter_type=FilterType.SEVERITY.value,
        filter_value="CRITICAL",
        min_cvss=0.0,
        notify_method=NotifyMethod.CONSOLE.value
    )
    print(f"    ✓ 订阅3: 严重性'CRITICAL' (控制台通知) - ID={sub3}")

    # 订阅4: CVSS范围 8.0-10.0
    sub4 = manager.add_subscription(
        filter_type=FilterType.CVSS_RANGE.value,
        filter_value="8.0-10.0",
        min_cvss=0.0,
        notify_method=NotifyMethod.CONSOLE.value
    )
    print(f"    ✓ 订阅4: CVSS范围8.0-10.0 (控制台通知) - ID={sub4}")

    # 测试列出订阅
    print(f"\n[3] 列出所有订阅")
    subscriptions = manager.list_subscriptions()
    print(f"    共 {len(subscriptions)} 个订阅:")
    for sub in subscriptions:
        status = "启用" if sub.enabled else "禁用"
        print(f"      - ID={sub.id} | {sub.filter_type}={sub.filter_value} | {status}")

    # 测试禁用订阅
    print(f"\n[4] 禁用订阅 ID={sub2}")
    manager.disable_subscription(sub2)
    print(f"    ✓ 订阅已禁用")

    # 测试启用订阅
    print(f"\n[5] 重新启用订阅 ID={sub2}")
    manager.enable_subscription(sub2)
    print(f"    ✓ 订阅已启用")

    # 测试检查新CVE (需要先同步CVE数据)
    print(f"\n[6] 同步CVE数据 (测试用)")
    print(f"    正在同步NVD数据 (最近7天)...")

    try:
        new, updated = await manager.cve_manager.sync_nvd(days_back=7)
        print(f"    ✓ NVD同步完成: 新增 {new}, 更新 {updated}")
    except Exception as e:
        print(f"    ⚠ NVD同步失败 (可能是网络问题): {e}")
        print(f"    跳过CVE检查测试")
        return

    # 测试检查新CVE
    print(f"\n[7] 检查新CVE匹配")
    matches = manager.check_new_cves()
    print(f"    ✓ 检查完成: {len(matches)} 个订阅匹配到新CVE")

    for sub_id, cves in matches.items():
        print(f"      - 订阅 ID={sub_id}: 匹配 {len(cves)} 个CVE")

    # 测试订阅统计
    print(f"\n[8] 订阅统计")
    for sub_id in [sub1, sub2, sub3, sub4]:
        stats = manager.get_subscription_stats(sub_id)
        print(f"    订阅 ID={sub_id}:")
        print(f"      总通知: {stats.get('total_notifications', 0)}")
        print(f"      最近7天: {stats.get('recent_notifications_7d', 0)}")

    # 测试删除订阅
    print(f"\n[9] 删除订阅 ID={sub4}")
    manager.remove_subscription(sub4)
    print(f"    ✓ 订阅已删除")

    # 验证删除
    subscriptions = manager.list_subscriptions()
    print(f"    剩余订阅数: {len(subscriptions)}")

    print(f"\n{'='*80}")
    print("测试完成!")
    print(f"{'='*80}")

    # 清理测试数据库
    print(f"\n[清理] 删除测试数据库: {test_db}")
    if test_db.exists():
        test_db.unlink()
        print("    ✓ 清理完成")


async def test_error_handling():
    """测试错误处理"""
    print("\n" + "="*80)
    print("错误处理测试")
    print("="*80)

    test_db = Path(tempfile.gettempdir()) / "test_subscription_error.db"
    manager = SubscriptionManager(db_path=str(test_db))

    # 测试无效过滤类型
    print("\n[1] 测试无效过滤类型")
    try:
        manager.add_subscription(
            filter_type="invalid_type",
            filter_value="test",
            notify_method="console"
        )
        print("    ✗ 应该抛出异常")
    except ValueError as e:
        print(f"    ✓ 正确捕获异常: {e}")

    # 测试无效通知方式
    print("\n[2] 测试无效通知方式")
    try:
        manager.add_subscription(
            filter_type="keyword",
            filter_value="test",
            notify_method="invalid_method"
        )
        print("    ✗ 应该抛出异常")
    except ValueError as e:
        print(f"    ✓ 正确捕获异常: {e}")

    # 测试无效CVSS范围
    print("\n[3] 测试无效CVSS范围")
    try:
        manager.add_subscription(
            filter_type="cvss_range",
            filter_value="invalid",
            notify_method="console"
        )
        print("    ✗ 应该抛出异常")
    except ValueError as e:
        print(f"    ✓ 正确捕获异常: {e}")

    # 测试删除不存在的订阅
    print("\n[4] 测试删除不存在的订阅")
    result = manager.remove_subscription(99999)
    print(f"    ✓ 返回值: {result} (应为False)")

    # 清理
    if test_db.exists():
        test_db.unlink()

    print(f"\n{'='*80}")
    print("错误处理测试完成!")
    print(f"{'='*80}")


async def main():
    """主测试入口"""
    # 基础功能测试
    await test_subscription_manager()

    # 错误处理测试
    await test_error_handling()


if __name__ == "__main__":
    asyncio.run(main())
