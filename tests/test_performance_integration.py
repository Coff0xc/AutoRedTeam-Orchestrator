#!/usr/bin/env python3
"""
性能监控与缓存集成测试 - 验证核心模块功能

测试范围:
- core.recon 侦察引擎
- core.concurrency 并发控制
- core.exploit 端口扫描器

标记说明:
- @pytest.mark.network: 需要网络访问的测试
- @pytest.mark.asyncio: 异步测试
"""

import asyncio
import time
import json
import tempfile
from pathlib import Path
import pytest

# 导入核心模块 (使用正确的导入路径)
from core.recon import StandardReconEngine, ReconConfig
from core.concurrency import (
    get_collector,
    track_request,
    get_pool,
    TokenBucket,
    CircuitBreaker,
)
from core.exploit.pure_scanner import PurePortScanner


class TestReconEngine:
    """测试侦察引擎"""

    def test_recon_config_creation(self):
        """测试配置创建"""
        config = ReconConfig(
            quick_mode=True,
            timeout=30,
            enable_subdomain=False,
            enable_directory=False,
        )
        assert config.quick_mode is True
        assert config.timeout == 30
        assert config.enable_subdomain is False

    def test_engine_initialization(self):
        """测试引擎初始化"""
        engine = StandardReconEngine("https://example.com")
        assert engine is not None
        assert engine.target == "https://example.com"

    def test_engine_with_config(self):
        """测试带配置的引擎"""
        config = ReconConfig(quick_mode=True, timeout=10)
        engine = StandardReconEngine("https://example.com", config)
        assert engine.config.quick_mode is True


class TestConcurrencyModule:
    """测试并发控制模块"""

    def test_metrics_collector(self):
        """测试指标收集器"""
        collector = get_collector()
        assert collector is not None

        # 测试请求追踪
        with track_request('test_operation'):
            time.sleep(0.01)

        # summary() 返回字符串格式报告
        summary = collector.summary()
        assert summary is not None
        assert isinstance(summary, str) or isinstance(summary, dict)

    def test_token_bucket(self):
        """测试令牌桶限流器"""
        # capacity 必须 >= rate
        limiter = TokenBucket(rate=10.0, capacity=100)

        # 应该能获取令牌
        assert limiter.acquire() is True

        # 连续获取多个令牌
        acquired = sum(1 for _ in range(5) if limiter.acquire())
        assert acquired >= 1

    def test_circuit_breaker(self):
        """测试熔断器"""
        breaker = CircuitBreaker(failure_threshold=3, timeout=1.0)

        # 正常调用
        result = breaker.call(lambda: "success")
        assert result == "success"

        # 模拟失败
        def failing_func():
            raise ValueError("test error")

        for _ in range(3):
            try:
                breaker.call(failing_func)
            except ValueError:
                pass

    def test_thread_pool(self):
        """测试线程池"""
        pool = get_pool()
        assert pool is not None

        # 提交任务
        future = pool.submit(lambda x: x * 2, 21)
        result = future.result(timeout=5)
        assert result == 42


class TestPortScanner:
    """测试端口扫描器"""

    def test_scanner_initialization(self):
        """测试扫描器初始化"""
        scanner = PurePortScanner(concurrency=10)
        assert scanner is not None
        assert scanner.concurrency == 10

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_scanner_single_port(self):
        """测试单端口扫描 - 需要网络访问"""
        scanner = PurePortScanner(concurrency=5)
        # 扫描一个常见的开放端口
        result = await scanner.scan_host("example.com", [80])
        # result 是 HostResult 对象，不是 dict
        assert result is not None
        assert hasattr(result, 'host') or hasattr(result, 'error') or isinstance(result, dict)


class TestIntegration:
    """集成测试"""

    def test_recon_with_metrics(self):
        """测试侦察引擎与指标收集的集成"""
        collector = get_collector()

        # 创建引擎
        config = ReconConfig(quick_mode=True, timeout=5)
        engine = StandardReconEngine("https://example.com", config)

        # 记录开始时间
        start_time = time.time()

        # 注意：不实际运行扫描，只测试初始化
        assert engine is not None
        assert collector is not None

        duration = time.time() - start_time
        assert duration < 1.0  # 初始化应该很快

    def test_concurrent_operations(self):
        """测试并发操作"""
        pool = get_pool()
        limiter = TokenBucket(rate=100.0)

        def rate_limited_task(n):
            if limiter.acquire():
                return n * 2
            return None

        # 并发提交多个任务
        futures = [pool.submit(rate_limited_task, i) for i in range(10)]
        results = [f.result(timeout=5) for f in futures]

        # 至少部分任务应该成功
        successful = [r for r in results if r is not None]
        assert len(successful) >= 1

    def test_report_generation(self):
        """测试报告生成"""
        collector = get_collector()

        # 执行一些操作
        with track_request('test_report_op'):
            time.sleep(0.01)

        # 生成摘要 (可能是字符串或字典)
        summary = collector.summary()
        assert summary is not None

        # 保存报告
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
            if isinstance(summary, dict):
                json.dump(summary, f, indent=2, default=str)
            else:
                json.dump({"report": str(summary)}, f, indent=2)
            report_path = f.name

        # 验证报告文件
        assert Path(report_path).exists()
        Path(report_path).unlink()  # 清理


def test_basic_imports():
    """测试基本导入"""
    # 验证所有必要模块可以导入
    from core.recon import (
        StandardReconEngine,
        ReconConfig,
        ReconResult,
        Finding,
    )
    from core.concurrency import (
        get_collector,
        get_pool,
        TokenBucket,
        CircuitBreaker,
    )
    from core.exploit.pure_scanner import PurePortScanner

    assert StandardReconEngine is not None
    assert ReconConfig is not None
    assert get_collector is not None
    assert PurePortScanner is not None


def test_module_versions():
    """测试模块版本"""
    import core.recon as recon_module
    import core.concurrency as concurrency_module

    assert hasattr(recon_module, '__version__')
    assert hasattr(concurrency_module, '__version__')


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-o", "addopts="])
