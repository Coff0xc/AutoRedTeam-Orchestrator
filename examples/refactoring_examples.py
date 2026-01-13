#!/usr/bin/env python3
"""
重构示例 - 展示如何使用新架构
演示工厂模式、策略模式、异步执行等
"""

import asyncio
import logging
from pathlib import Path

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def example_1_detector_factory():
    """示例1: 使用检测器工厂"""
    print("\n" + "="*60)
    print("示例1: 使用检测器工厂创建检测器")
    print("="*60)

    from tools.detectors.factory import DetectorFactory

    # 列出所有可用检测器
    detectors = DetectorFactory.list_detectors()
    print(f"\n可用检测器 ({len(detectors)}个):")
    for name in detectors:
        print(f"  - {name}")

    # 创建 SQLi 检测器
    print("\n创建 SQLi 检测器...")
    sqli_detector = DetectorFactory.create("sqli", timeout=15)
    print(f"✓ 创建成功: {sqli_detector.__class__.__name__}")

    # 使用别名创建
    print("\n使用别名创建 XSS 检测器...")
    xss_detector = DetectorFactory.create("cross_site_scripting")
    print(f"✓ 创建成功: {xss_detector.__class__.__name__}")

    # 获取检测器信息
    info = DetectorFactory.get_detector_info("sqli")
    print(f"\n检测器信息:")
    print(f"  名称: {info['name']}")
    print(f"  类: {info['class']}")
    print(f"  模块: {info['module']}")


async def example_2_detection_strategy():
    """示例2: 使用检测策略"""
    print("\n" + "="*60)
    print("示例2: 使用不同的检测策略")
    print("="*60)

    from tools.detectors.factory import DetectorFactory
    from tools.strategies.detection_strategy import (
        StrategyFactory, DetectionContext
    )

    # 创建检测器
    detector = DetectorFactory.create("sqli")

    # 创建检测上下文
    context = DetectionContext(
        url="https://example.com/page?id=1",
        params=["id", "page"],
        deep_scan=False
    )

    # 策略1: 快速扫描
    print("\n执行快速扫描策略...")
    quick_strategy = StrategyFactory.create("quick")
    result = quick_strategy.execute(detector, context)
    print(f"✓ 快速扫描完成: 发现 {result['total']} 个漏洞")

    # 策略2: 智能扫描
    print("\n执行智能扫描策略...")
    smart_strategy = StrategyFactory.create("smart")
    result = smart_strategy.execute(detector, context)
    print(f"✓ 智能扫描完成: 发现 {result['total']} 个漏洞")

    # 策略3: 定向扫描
    print("\n执行定向扫描策略 (只测试 error_based)...")
    targeted_strategy = StrategyFactory.create(
        "targeted",
        target_categories=["error_based"]
    )
    result = targeted_strategy.execute(detector, context)
    print(f"✓ 定向扫描完成: 发现 {result['total']} 个漏洞")


async def example_3_async_http_client():
    """示例3: 使用异步 HTTP 客户端"""
    print("\n" + "="*60)
    print("示例3: 使用异步 HTTP 客户端进行高并发扫描")
    print("="*60)

    from core.async_http_client import AsyncHTTPClient

    async with AsyncHTTPClient(concurrency=100, timeout=10) as client:
        # 单个请求
        print("\n发送单个请求...")
        response = await client.get("https://httpbin.org/get")
        print(f"✓ 状态码: {response.status}, 耗时: {response.elapsed:.2f}秒")

        # 批量请求
        print("\n发送批量请求 (100个)...")
        urls = [f"https://httpbin.org/delay/{i%3}" for i in range(100)]
        responses = await client.batch_get(urls)

        success_count = sum(1 for r in responses if r.success)
        print(f"✓ 完成: {success_count}/{len(responses)} 成功")

        # 统计信息
        stats = client.get_stats()
        print(f"\n统计信息:")
        print(f"  总请求数: {stats['total_requests']}")
        print(f"  成功率: {stats['success_rate']:.1%}")
        print(f"  平均耗时: {stats['average_time']:.2f}秒")


async def example_4_async_executor():
    """示例4: 使用异步执行器"""
    print("\n" + "="*60)
    print("示例4: 使用异步执行器进行任务编排")
    print("="*60)

    from core.async_executor import AsyncExecutor

    executor = AsyncExecutor(max_concurrency=10, enable_progress=True)

    # 定义任务函数
    async def scan_url(url: str):
        await asyncio.sleep(0.5)  # 模拟扫描
        return {"url": url, "status": "scanned"}

    def analyze_result(data: dict):
        import time
        time.sleep(0.2)  # 模拟分析
        return {"analyzed": True, **data}

    # 添加异步任务
    print("\n添加 20 个扫描任务...")
    for i in range(20):
        executor.add_task(
            f"scan_{i}",
            scan_url,
            f"https://example.com/page{i}",
            priority=i % 3
        )

    # 添加同步任务
    print("添加 10 个分析任务...")
    for i in range(10):
        executor.add_task(
            f"analyze_{i}",
            analyze_result,
            {"id": i},
            priority=2
        )

    # 执行所有任务
    print("\n开始执行任务...")
    results = await executor.execute_all()

    # 获取结果
    success_results = executor.get_results(success_only=True)
    print(f"\n✓ 完成: {len(success_results)}/{len(results)} 成功")

    # 统计信息
    stats = executor.get_stats()
    print(f"\n统计信息:")
    print(f"  总任务数: {stats['total']}")
    print(f"  成功率: {stats['success_rate']:.1%}")


async def example_5_result_aggregator():
    """示例5: 使用结果聚合器"""
    print("\n" + "="*60)
    print("示例5: 使用结果聚合器收集和分析结果")
    print("="*60)

    from core.result_aggregator import ResultAggregator

    aggregator = ResultAggregator()

    # 添加模拟结果
    print("\n添加漏洞结果...")
    aggregator.add_result({
        "type": "SQL Injection",
        "severity": "CRITICAL",
        "url": "https://example.com/page?id=1",
        "param": "id",
        "payload": "' OR '1'='1",
        "confidence": 0.9,
        "verified": True
    }, source="sqli_detector")

    aggregator.add_result({
        "type": "XSS",
        "severity": "HIGH",
        "url": "https://example.com/search?q=test",
        "param": "q",
        "payload": "<script>alert(1)</script>",
        "confidence": 0.8,
        "verified": False
    }, source="xss_detector")

    aggregator.add_result({
        "type": "SSRF",
        "severity": "HIGH",
        "url": "https://example.com/fetch?url=internal",
        "param": "url",
        "confidence": 0.7,
        "verified": True
    }, source="ssrf_detector")

    # 统计信息
    stats = aggregator.get_statistics()
    print(f"\n统计信息:")
    print(f"  总漏洞数: {stats['total']}")
    print(f"  已验证: {stats['verified_count']} ({stats['verified_rate']:.1%})")
    print(f"  高置信度: {stats['high_confidence_count']}")

    print(f"\n按严重程度:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity}: {count}")

    print(f"\n按类型:")
    for vuln_type, count in stats['by_type'].items():
        print(f"  {vuln_type}: {count}")

    # 导出结果
    print("\n导出结果...")
    output_dir = Path("E:/A-2026-project/Github-project/AutoRedTeam-Orchestrator/reports")
    output_dir.mkdir(exist_ok=True)

    aggregator.export_json(str(output_dir / "results.json"))
    aggregator.export_markdown(str(output_dir / "report.md"))
    print(f"✓ 结果已导出到: {output_dir}")


async def example_6_complete_workflow():
    """示例6: 完整的扫描工作流"""
    print("\n" + "="*60)
    print("示例6: 完整的扫描工作流 (工厂+策略+异步+聚合)")
    print("="*60)

    from tools.detectors.factory import DetectorFactory
    from tools.strategies.detection_strategy import StrategyFactory, DetectionContext
    from core.async_executor import AsyncExecutor
    from core.result_aggregator import ResultAggregator

    # 1. 创建执行器和聚合器
    executor = AsyncExecutor(max_concurrency=5)
    aggregator = ResultAggregator()

    # 2. 定义扫描任务
    async def scan_with_detector(detector_name: str, url: str):
        detector = DetectorFactory.create(detector_name)
        context = DetectionContext(url=url, params=["id", "page"])
        strategy = StrategyFactory.create("quick")
        result = strategy.execute(detector, context)
        return result

    # 3. 添加多个检测任务
    targets = [
        "https://example.com/page1",
        "https://example.com/page2",
        "https://example.com/page3"
    ]

    detectors_to_use = ["sqli", "xss", "ssrf"]

    print(f"\n创建 {len(targets) * len(detectors_to_use)} 个扫描任务...")
    for target in targets:
        for detector_name in detectors_to_use:
            executor.add_task(
                f"{detector_name}_{target}",
                scan_with_detector,
                detector_name,
                target
            )

    # 4. 执行所有任务
    print("\n执行扫描任务...")
    results = await executor.execute_all()

    # 5. 聚合结果
    print("\n聚合扫描结果...")
    for result in results:
        if result.success and result.result:
            scan_result = result.result
            if scan_result.get("success"):
                aggregator.add_batch(
                    scan_result.get("vulnerabilities", []),
                    source=result.task_name
                )

    # 6. 输出统计
    stats = aggregator.get_statistics()
    print(f"\n✓ 扫描完成!")
    print(f"  发现漏洞: {stats['total']}")
    print(f"  已验证: {stats['verified_count']}")
    print(f"  高置信度: {stats['high_confidence_count']}")


async def main():
    """主函数 - 运行所有示例"""
    print("\n" + "="*60)
    print("AutoRedTeam-Orchestrator 架构重构示例")
    print("="*60)

    try:
        # 运行示例
        await example_1_detector_factory()
        await example_2_detection_strategy()
        # await example_3_async_http_client()  # 需要网络连接
        await example_4_async_executor()
        await example_5_result_aggregator()
        # await example_6_complete_workflow()  # 完整工作流

        print("\n" + "="*60)
        print("所有示例执行完成!")
        print("="*60)

    except Exception as e:
        logger.error(f"示例执行失败: {e}", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
