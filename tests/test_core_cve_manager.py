#!/usr/bin/env python3
"""
test_core_cve_manager.py - CVE 管理器单元测试

测试覆盖:
- CVEManager 单例模式
- CVE 数据搜索
- 数据源管理
- 线程安全
"""

import tempfile
import threading
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

# 导入被测试的模块
from core.cve.manager import CVEManager
from core.cve.models import CVSS, CVEEntry, CVEStats, Severity
from core.cve.search import SearchFilter, SearchOptions

# ============== 测试夹具 ==============


@pytest.fixture
def temp_db_path():
    """临时数据库路径"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name


@pytest.fixture
def clean_manager():
    """清理单例实例"""
    CVEManager._instance = None
    yield
    CVEManager._instance = None


@pytest.fixture
def mock_cve_entry():
    """模拟 CVE 条目"""
    return CVEEntry(
        cve_id="CVE-2024-1234",
        title="Test Vulnerability",
        description="Test vulnerability",
        severity=Severity.HIGH,
        cvss=CVSS.from_score(7.5),
        published_date=datetime(2024, 1, 1),
        modified_date=datetime(2024, 1, 2),
        affected_products=["Product A", "Product B"],
        cwe_ids=["CWE-79"],
        exploit_available=True,
        poc_urls=["https://github.com/test/poc"],
    )


# ============== CVEManager 单例测试 ==============


class TestCVEManagerSingleton:
    """CVEManager 单例模式测试"""

    def test_singleton_same_instance(self, clean_manager):
        """测试单例返回相同实例"""
        manager1 = CVEManager()
        manager2 = CVEManager()

        assert manager1 is manager2

    def test_singleton_thread_safe(self, clean_manager):
        """测试单例的线程安全性"""
        instances = []

        def create_manager():
            manager = CVEManager()
            instances.append(manager)

        threads = [threading.Thread(target=create_manager) for _ in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 所有实例应该是同一个对象
        assert len(set(id(inst) for inst in instances)) == 1

    def test_singleton_initialization_once(self, clean_manager):
        """测试单例只初始化一次"""
        manager1 = CVEManager()
        initial_sources = len(manager1._sources)

        manager2 = CVEManager()
        # 第二次获取不应该重新初始化
        assert len(manager2._sources) == initial_sources


# ============== CVE 搜索测试 ==============


class TestCVESearch:
    """CVE 搜索测试"""

    @pytest.fixture
    def manager_with_data(self, clean_manager, temp_db_path):
        """带测试数据的管理器"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()

            # 模拟搜索结果
            mock_cve = CVEEntry(
                cve_id="CVE-2024-1234",
                title="SQL Injection Vulnerability",
                description="SQL Injection vulnerability",
                severity=Severity.HIGH,
                cvss=CVSS.from_score(8.5),
                published_date=datetime(2024, 1, 1),
                affected_products=["MySQL"],
            )

            mock_storage_instance.get.return_value = mock_cve
            mock_storage_instance.stats.return_value = CVEStats(
                total_count=100,
                by_severity={"high": 30, "medium": 50, "low": 20},
            )

            mock_storage.return_value = mock_storage_instance

            manager = CVEManager(db_path=temp_db_path)

            # 在 search_engine 层 mock，绕过直接 SQLite 调用
            from core.cve.search import SearchResult
            manager._search_engine.advanced_search = Mock(
                return_value=SearchResult(entries=[mock_cve], total_count=1, returned_count=1)
            )

            yield manager

    def test_search_by_keyword(self, manager_with_data):
        """测试关键词搜索"""
        results = manager_with_data.search("SQL Injection")

        assert len(results) > 0
        assert any("SQL" in r.description for r in results)

    def test_search_by_cve_id(self, manager_with_data):
        """测试 CVE ID 搜索"""
        result = manager_with_data.get("CVE-2024-1234")

        assert result is not None
        assert result.cve_id == "CVE-2024-1234"

    def test_search_by_severity(self, manager_with_data):
        """测试按严重程度搜索"""
        results = manager_with_data.search(severity=Severity.HIGH)

        assert len(results) > 0
        assert all(r.severity == Severity.HIGH for r in results)

    def test_search_by_product(self, manager_with_data):
        """测试按产品搜索"""
        results = manager_with_data.search(keyword="MySQL")

        assert len(results) > 0

    def test_search_with_limit(self, manager_with_data):
        """测试限制搜索结果数量"""
        results = manager_with_data.search("vulnerability", limit=5)

        assert len(results) <= 5

    def test_search_empty_results(self, manager_with_data):
        """测试空搜索结果"""
        from core.cve.search import SearchResult
        with patch.object(manager_with_data._search_engine, "advanced_search",
                          return_value=SearchResult(entries=[], total_count=0, returned_count=0)):
            results = manager_with_data.search("nonexistent-keyword")
            assert results == []


# ============== CVE 数据同步测试 ==============


class TestCVESync:
    """CVE 数据同步测试"""

    @pytest.fixture
    def manager_with_mock_sources(self, clean_manager):
        """带模拟数据源的管理器"""
        with patch("core.cve.manager.NVDSource") as mock_nvd:
            with patch("core.cve.manager.NucleiSource") as mock_nuclei:
                with patch("core.cve.manager.get_storage") as mock_storage:
                    # 模拟数据源
                    mock_nvd_instance = Mock()
                    mock_nvd_instance.fetch_recent.return_value = []
                    mock_nvd.return_value = mock_nvd_instance

                    mock_nuclei_instance = Mock()
                    mock_nuclei_instance.fetch_recent.return_value = []
                    mock_nuclei.return_value = mock_nuclei_instance

                    # 模拟存储
                    mock_storage_instance = Mock()
                    mock_storage_instance.save.return_value = True
                    mock_storage_instance.save_batch.return_value = (0, 0)
                    mock_storage_instance.log_sync.return_value = None
                    mock_storage.return_value = mock_storage_instance

                    manager = CVEManager()
                    yield manager

    @pytest.mark.asyncio
    async def test_async_sync(self, manager_with_mock_sources):
        """测试异步同步"""
        status = await manager_with_mock_sources.sync(days=1)
        assert status is not None
        assert isinstance(status, dict)

    @pytest.mark.asyncio
    async def test_sync_error_handling(self, manager_with_mock_sources):
        """测试同步错误处理"""
        if manager_with_mock_sources._sources:
            manager_with_mock_sources._sources[0].fetch_recent = Mock(
                side_effect=Exception("Network error")
            )
        # 不应该因为单个数据源失败而崩溃
        status = await manager_with_mock_sources.sync(days=1)
        assert status is not None


# ============== 统计信息测试 ==============


class TestCVEStats:
    """CVE 统计信息测试"""

    @pytest.fixture
    def manager_with_stats(self, clean_manager):
        """带统计数据的管理器"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()

            stats = CVEStats(
                total_count=1000,
                poc_available_count=200,
                by_severity={
                    "critical": 50,
                    "high": 200,
                    "medium": 500,
                    "low": 250,
                },
                by_year={
                    2024: 300,
                    2023: 400,
                    2022: 300,
                },
            )

            mock_storage_instance.stats.return_value = stats
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            yield manager

    def test_get_stats(self, manager_with_stats):
        """测试获取统计信息"""
        stats = manager_with_stats.stats()

        assert stats is not None
        assert stats.total_count == 1000
        assert stats.by_severity["high"] == 200

    def test_get_severity_distribution(self, manager_with_stats):
        """测试获取严重程度分布"""
        stats = manager_with_stats.stats()
        distribution = stats.by_severity

        assert "critical" in distribution
        assert "high" in distribution

    def test_get_yearly_stats(self, manager_with_stats):
        """测试获取年度统计"""
        stats = manager_with_stats.stats()
        yearly = stats.by_year

        assert 2024 in yearly
        assert yearly[2024] == 300


# ============== 线程安全测试 ==============


class TestThreadSafety:
    """线程安全测试"""

    def test_concurrent_search(self, clean_manager):
        """测试并发搜索"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = []
            errors = []

            def search_cve():
                try:
                    res = manager.search("test")
                    results.append(res)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=search_cve) for _ in range(10)]

            for t in threads:
                t.start()

            for t in threads:
                t.join()

            # 所有搜索都应该成功
            assert len(results) == 10
            assert len(errors) == 0


# ============== 边界条件测试 ==============


class TestEdgeCases:
    """边界条件测试"""

    def test_search_empty_keyword(self, clean_manager):
        """测试空关键词搜索"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = manager.search("")

            assert isinstance(results, list)

    def test_search_special_characters(self, clean_manager):
        """测试特殊字符搜索"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = manager.search("<script>alert(1)</script>")

            assert isinstance(results, list)

    def test_search_unicode(self, clean_manager):
        """测试 Unicode 搜索"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = manager.search("漏洞")

            assert isinstance(results, list)

    def test_get_nonexistent_cve(self, clean_manager):
        """测试获取不存在的 CVE"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.get.return_value = None
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            result = manager.get("CVE-9999-9999")

            assert result is None

    def test_invalid_cve_id_format(self, clean_manager):
        """测试无效的 CVE ID 格式"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.get.return_value = None
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            result = manager.get("invalid-id")

            assert result is None


# ============== 集成测试 ==============


class TestIntegration:
    """集成测试"""

    def test_full_workflow(self, clean_manager):
        """测试完整工作流"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()

            # 模拟 CVE 数据
            mock_cve = CVEEntry(
                cve_id="CVE-2024-1234",
                title="Test Vulnerability",
                description="Test vulnerability",
                severity=Severity.HIGH,
                cvss=CVSS.from_score(8.0),
                published_date=datetime(2024, 1, 1),
            )

            mock_storage_instance.get.return_value = mock_cve
            mock_storage_instance.save.return_value = True
            mock_storage_instance.stats.return_value = CVEStats(
                total_count=1,
                by_severity={"high": 1},
            )

            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()

            from core.cve.search import SearchResult
            manager._search_engine.advanced_search = Mock(
                return_value=SearchResult(entries=[mock_cve], total_count=1, returned_count=1)
            )

            # 1. 搜索 CVE
            results = manager.search("Test")
            assert len(results) > 0

            # 2. 获取特定 CVE
            cve = manager.get("CVE-2024-1234")
            assert cve is not None
            assert cve.cve_id == "CVE-2024-1234"

            # 3. 获取统计信息
            stats = manager.stats()
            assert stats.total_count == 1

    def test_search_and_filter(self, clean_manager):
        """测试搜索和过滤"""
        with patch("core.cve.manager.get_storage") as mock_storage:
            mock_storage_instance = Mock()
            mock_storage.return_value = mock_storage_instance

            # 创建多个 CVE
            cves = [
                CVEEntry(
                    cve_id=f"CVE-2024-{i}",
                    title=f"Vulnerability {i}",
                    description=f"Vulnerability {i}",
                    severity=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM,
                    cvss=CVSS.from_score(7.0 + i * 0.1),
                    published_date=datetime(2024, 1, i),
                )
                for i in range(1, 6)
            ]

            manager = CVEManager()

            from core.cve.search import SearchResult
            manager._search_engine.advanced_search = Mock(
                return_value=SearchResult(entries=cves, total_count=5, returned_count=5)
            )

            # 搜索所有
            all_results = manager.search("Vulnerability")
            assert len(all_results) == 5

            # 按严重程度过滤
            high_severity = [cve for cve in all_results if cve.severity == Severity.HIGH]
            assert len(high_severity) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
