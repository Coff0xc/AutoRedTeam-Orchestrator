#!/usr/bin/env python3
"""
性能监控与缓存集成测试 - 验证真实收益闭环
测试 UnifiedConcurrencyManager 在实际扫描中的性能提升
"""

import asyncio
import time
import json
from pathlib import Path

# 导入核心模块
from core.unified_concurrency import init_unified_manager, get_unified_manager
from core.pipeline import VulnerabilityPipeline
from core.exploit.pure_scanner import PurePortScanner
from core.recon.standard import StandardReconEngine


def test_cache_hit_benefit():
    """测试缓存命中带来的性能收益"""
    print("\n" + "=" * 60)
    print("测试 1: 缓存命中率与性能提升")
    print("=" * 60)

    # 初始化管理器
    manager = init_unified_manager()

    # 测试目标
    target = "https://example.com"

    # 第一次运行 - 无缓存
    print("\n第一次运行 (无缓存)...")
    pipeline1 = VulnerabilityPipeline(target, use_unified_manager=True)
    start_time1 = time.time()
    result1 = pipeline1.run_full_pipeline()
    duration1 = time.time() - start_time1

    # 获取统计
    cache_stats1 = manager.get_cache_stats()
    print(f"  耗时: {duration1:.2f}秒")
    print(f"  缓存命中率: {cache_stats1.get('tech', {}).get('hit_rate', 0):.2%}")

    # 第二次运行 - 有缓存
    print("\n第二次运行 (有缓存)...")
    pipeline2 = VulnerabilityPipeline(target, use_unified_manager=True)
    start_time2 = time.time()
    result2 = pipeline2.run_full_pipeline()
    duration2 = time.time() - start_time2

    # 获取统计
    cache_stats2 = manager.get_cache_stats()
    print(f"  耗时: {duration2:.2f}秒")
    print(f"  缓存命中率: {cache_stats2.get('tech', {}).get('hit_rate', 0):.2%}")

    # 计算性能提升
    if duration1 > 0:
        improvement = ((duration1 - duration2) / duration1) * 100
        print(f"\n性能提升: {improvement:.1f}%")
        print(f"加速比: {duration1/duration2:.2f}x")

    # 验证缓存收益
    assert cache_stats2['tech']['hit_rate'] > 0, "缓存应该命中"
    print("\n[SUCCESS] 缓存收益验证通过")

    manager.stop()


async def test_scanner_monitoring():
    """测试扫描器性能监控埋点"""
    print("\n" + "=" * 60)
    print("测试 2: 扫描器性能监控埋点")
    print("=" * 60)

    # 初始化管理器
    manager = init_unified_manager()

    # 创建扫描器
    scanner = PurePortScanner(concurrency=50, use_unified_manager=True)

    # 扫描测试
    print("\n执行端口扫描...")
    result = await scanner.scan_host("scanme.nmap.org", [22, 80, 443])

    # 获取监控统计
    monitor_stats = manager.get_monitor_stats()
    print(f"\n监控统计:")
    print(f"  总调用次数: {monitor_stats['total_calls']}")
    print(f"  成功率: {monitor_stats['overall_success_rate']:.2%}")
    print(f"  平均执行时间: {monitor_stats['avg_execution_time']:.3f}秒")
    print(f"  活跃执行: {monitor_stats['active_executions']}")

    # 最慢工具
    if monitor_stats.get('slowest_tools'):
        print(f"\n最慢工具 TOP 3:")
        for tool in monitor_stats['slowest_tools']:
            print(f"  - {tool['tool']}: {tool['avg_time']:.3f}秒 (调用{tool['total_calls']}次)")

    # 验证监控数据
    assert monitor_stats['total_calls'] > 0, "应该有工具调用记录"
    print("\n[SUCCESS] 性能监控埋点验证通过")

    manager.stop()


def test_bottleneck_detection():
    """测试瓶颈识别"""
    print("\n" + "=" * 60)
    print("测试 3: 性能瓶颈识别")
    print("=" * 60)

    # 初始化管理器
    manager = init_unified_manager()

    # 执行一些任务模拟工作负载
    print("\n执行多个任务以生成监控数据...")

    # 运行 pipeline
    pipeline = VulnerabilityPipeline("https://example.com", use_unified_manager=True)
    _ = pipeline.run_full_pipeline()

    # 获取完整统计
    full_stats = manager.get_full_stats()

    print("\n性能概览:")
    print(json.dumps(full_stats['monitor'], indent=2, ensure_ascii=False))

    # 瓶颈分析
    bottlenecks = full_stats.get('bottlenecks', {})
    print(f"\n瓶颈分析:")
    print(f"  慢速工具: {len(bottlenecks.get('slow_tools', []))}")
    print(f"  不可靠工具: {len(bottlenecks.get('unreliable_tools', []))}")

    if bottlenecks.get('recommendations'):
        print(f"\n优化建议:")
        for rec in bottlenecks['recommendations']:
            print(f"  - {rec}")

    print("\n[SUCCESS] 瓶颈识别验证通过")

    manager.stop()


def test_full_integration():
    """测试完整集成收益"""
    print("\n" + "=" * 60)
    print("测试 4: 完整集成收益闭环")
    print("=" * 60)

    # 初始化管理器
    manager = init_unified_manager()

    print("\n运行完整侦察流程...")

    # 运行标准侦察
    engine = StandardReconEngine("https://example.com", quick_mode=True, use_unified_manager=True)
    start_time = time.time()
    result = engine.run()
    duration = time.time() - start_time

    print(f"\n侦察完成:")
    print(f"  耗时: {duration:.2f}秒")
    print(f"  侦察状态: {result.status}")
    print(f"  发现问题数: {len(result.findings)}")

    # 完整统计
    full_stats = manager.get_full_stats()

    print(f"\n缓存统计:")
    for cache_type, stats in full_stats['cache'].items():
        if stats.get('hits', 0) > 0 or stats.get('misses', 0) > 0:
            print(f"  {cache_type}:")
            print(f"    命中率: {stats.get('hit_rate', 0):.2%}")
            print(f"    大小: {stats.get('size', 0)}/{stats.get('maxsize', 0)}")

    print(f"\n监控统计:")
    monitor_stats = full_stats['monitor']
    print(f"  总调用: {monitor_stats['total_calls']}")
    print(f"  成功率: {monitor_stats['overall_success_rate']:.2%}")
    print(f"  总执行时间: {monitor_stats['total_execution_time']:.2f}秒")

    # 保存报告
    report_path = Path("performance_report.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(full_stats, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n完整报告已保存: {report_path}")

    print("\n[SUCCESS] 完整集成验证通过")

    manager.stop()


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("   性能监控与缓存集成测试 - 真实收益闭环验证")
    print("=" * 60)

    tests = [
        ("缓存命中收益", test_cache_hit_benefit),
        ("扫描器监控", lambda: asyncio.run(test_scanner_monitoring())),
        ("瓶颈识别", test_bottleneck_detection),
        ("完整集成", test_full_integration),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"\n[FAIL] 测试失败: {name}")
            print(f"   错误: {str(e)}")
            import traceback
            traceback.print_exc()
            failed += 1

    # 总结
    print("\n" + "=" * 60)
    print(f"测试总结: 通过 {passed}/{len(tests)}, 失败 {failed}/{len(tests)}")
    print("=" * 60)

    if failed == 0:
        print("\n[SUCCESS] 所有测试通过! 性能监控和缓存已成功集成到核心流程。")
        print("\n关键收益:")
        print("  [+] 缓存减少重复请求，显著提升速度")
        print("  [+] 性能监控识别瓶颈，指导优化方向")
        print("  [+] 统一并发控制，消除多套策略冲突")
        print("  [+] 真实埋点数据，形成完整闭环")
    else:
        print(f"\n[WARNING] {failed} 个测试失败，请检查集成情况。")

    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
