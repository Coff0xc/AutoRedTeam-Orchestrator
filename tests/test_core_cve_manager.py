#!/usr/bin/env python3
"""
test_core_cve_manager.py - CVE 管理器单元测试

测试覆盖:
- CVEManager 单例模式
- CVE 数据同步
- CVE 搜索
- 数据源管理
- 线程安全
"""

import pytest
import threading
import tempfile
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import List, Dict, Any
from datetime import datetime

# 导入被测试的模块
from core.cve.manager import CVEManager
from core.cve.models import CVEEntry, Severity, CVEStats, SyncStatus
from core.cve.search import SearchFilter, SearchOptions, SearchResult


# ============== 测试夹具 ==============

@pytest.fixture
def temp_db_path():
    """临时数据库路径"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
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
        cve_id='CVE-2024-1234',
        description='Test vulnerability',
        severity=Severity.HIGH,
        cvss_score=7.5,
        published_date=datetime(2024, 1, 1),
        modified_date=datetime(2024, 1, 2),
        affected_products=['Product A', 'Product B'],
        references=['https://example.com/cve-2024-1234'],
        cwe_ids=['CWE-79'],
        exploit_available=True,
        poc_url='https://github.com/test/poc',
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
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()

            # 模拟搜索结果
            mock_cve = CVEEntry(
                cve_id='CVE-2024-1234',
                description='SQL Injection vulnerability',
                severity=Severity.HIGH,
                cvss_score=8.5,
                published_date=datetime(2024, 1, 1),
                affected_products=['MySQL'],
            )

            mock_storage_instance.search.return_value = [mock_cve]
            mock_storage_instance.get_by_id.return_value = mock_cve
            mock_storage_instance.get_stats.return_value = CVEStats(
                total_cves=100,
                by_severity={Severity.HIGH: 30, Severity.MEDIUM: 50, Severity.LOW: 20},
            )

            mock_storage.return_value = mock_storage_instance

            manager = CVEManager(db_path=temp_db_path)
            yield manager

    def test_search_by_keyword(self, manager_with_data):
        """测试关键词搜索"""
        results = manager_with_data.search('SQL Injection')

        assert len(results) > 0
        assert any('SQL' in r.description for r in results)

    def test_search_by_cve_id(self, manager_with_data):
        """测试 CVE ID 搜索"""
        result = manager_with_data.get_cve('CVE-2024-1234')

        assert result is not None
        assert result.cve_id == 'CVE-2024-1234'

    def test_search_by_severity(self, manager_with_data):
        """测试按严重程度搜索"""
        filter_obj = SearchFilter(severity=Severity.HIGH)
        results = manager_with_data.search_advanced(filter_obj)

        assert len(results) > 0
        assert all(r.severity == Severity.HIGH for r in results)

    def test_search_by_product(self, manager_with_data):
        """测试按产品搜索"""
        filter_obj = SearchFilter(product='MySQL')
        results = manager_with_data.search_advanced(filter_obj)

        assert len(results) > 0

    def test_search_with_date_range(self, manager_with_data):
        """测试日期范围搜索"""
        filter_obj = SearchFilter(
            start_date=datetime(2024, 1, 1),
            end_date=datetime(2024, 12, 31),
        )
        results = manager_with_data.search_advanced(filter_obj)

        assert isinstance(results, list)

    def test_search_empty_results(self, manager_with_data):
        """测试空搜索结果"""
        with patch.object(manager_with_data._storage, 'search', return_value=[]):
            results = manager_with_data.search('nonexistent-keyword')
            assert results == []

    def test_search_with_limit(self, manager_with_data):
        """测试限制搜索结果数量"""
        options = SearchOptions(limit=5)
        results = manager_with_data.search('vulnerability', options=options)

        assert len(results) <= 5


# ============== CVE 数据同步测试 ==============

class TestCVESync:
    """CVE 数据同步测试"""

    @pytest.fixture
    def manager_with_mock_sources(self, clean_manager):
        """带模拟数据源的管理器"""
        with patch('core.cve.manager.NVDSource') as mock_nvd:
            with patch('core.cve.manager.NucleiSource') as mock_nuclei:
                with patch('core.cve.manager.get_storage') as mock_storage:
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
                    mock_storage.return_value = mock_storage_instance

                    manager = CVEManager()
                    yield manager

    def test_sync_all_sources(self, manager_with_mock_sources):
        """测试同步所有数据源"""
        status = manager_with_mock_sources.sync_all()

        assert status is not None
        assert isinstance(status, dict)

    def test_sync_single_source(self, manager_with_mock_sources):
        """测试同步单个数据源"""
        status = manager_with_mock_sources.sync_source('nvd')

        assert status is not None

    def test_sync_with_date_range(self, manager_with_mock_sources):
        """测试指定日期范围同步"""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 12, 31)

        status = manager_with_mock_sources.sync_all(
            start_date=start_date,
            end_date=end_date
        )

        assert status is not None

    @pytest.mark.asyncio
    async def test_async_sync(self, manager_with_mock_sources):
        """测试异步同步"""
        with patch.object(manager_with_mock_sources, 'sync_all', return_value={'status': 'success'}):
            status = await manager_with_mock_sources.async_sync_all()
            assert status is not None

    def test_sync_error_handling(self, manager_with_mock_sources):
        """测试同步错误处理"""
        with patch.object(manager_with_mock_sources._sources[0], 'fetch_recent', side_effect=Exception('Network error')):
            # 不应该因为单个数据源失败而崩溃
            status = manager_with_mock_sources.sync_all()
            assert status is not None


# ============== 数据源管理测试 ==============

class TestDataSourceManagement:
    """数据源管理测试"""

    def test_list_sources(self, clean_manager):
        """测试列出数据源"""
        manager = CVEManager()
        sources = manager.list_sources()

        assert isinstance(sources, list)
        assert len(sources) > 0

    def test_get_source_info(self, clean_manager):
        """测试获取数据源信息"""
        manager = CVEManager()
        sources = manager.list_sources()

        if sources:
            info = manager.get_source_info(sources[0])
            assert info is not None

    def test_enable_disable_source(self, clean_manager):
        """测试启用/禁用数据源"""
        manager = CVEManager()
        sources = manager.list_sources()

        if sources:
            source_name = sources[0]

            # 禁用
            manager.disable_source(source_name)
            # 启用
            manager.enable_source(source_name)


# ============== 统计信息测试 ==============

class TestCVEStats:
    """CVE 统计信息测试"""

    @pytest.fixture
    def manager_with_stats(self, clean_manager):
        """带统计数据的管理器"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()

            stats = CVEStats(
                total_cves=1000,
                by_severity={
                    Severity.CRITICAL: 50,
                    Severity.HIGH: 200,
                    Severity.MEDIUM: 500,
                    Severity.LOW: 250,
                },
                by_year={
                    2024: 300,
                    2023: 400,
                    2022: 300,
                },
                with_exploit=150,
                with_poc=200,
            )

            mock_storage_instance.get_stats.return_value = stats
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            yield manager

    def test_get_stats(self, manager_with_stats):
        """测试获取统计信息"""
        stats = manager_with_stats.get_stats()

        assert stats is not None
        assert stats.total_cves == 1000
        assert stats.by_severity[Severity.HIGH] == 200

    def test_get_severity_distribution(self, manager_with_stats):
        """测试获取严重程度分布"""
        stats = manager_with_stats.get_stats()
        distribution = stats.by_severity

        assert Severity.CRITICAL in distribution
        assert Severity.HIGH in distribution
        assert sum(distribution.values()) == 1000

    def test_get_yearly_stats(self, manager_with_stats):
        """测试获取年度统计"""
        stats = manager_with_stats.get_stats()
        yearly = stats.by_year

        assert 2024 in yearly
        assert yearly[2024] == 300


# ============== 线程安全测试 ==============

class TestThreadSafety:
    """线程安全测试"""

    def test_concurrent_search(self, clean_manager):
        """测试并发搜索"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = []
            errors = []

            def search_cve():
                try:
                    res = manager.search('test')
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

    def test_concurrent_sync(self, clean_manager):
        """测试并发同步"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.save.return_value = True
            mock_storage.return_value = mock_storage_instance

            with patch('core.cve.manager.NVDSource') as mock_nvd:
                mock_nvd_instance = Mock()
                mock_nvd_instance.fetch_recent.return_value = []
                mock_nvd.return_value = mock_nvd_instance

                manager = CVEManager()
                results = []

                def sync_data():
                    status = manager.sync_all()
                    results.append(status)

                # 只有一个同步应该执行（由于同步锁）
                threads = [threading.Thread(target=sync_data) for _ in range(5)]

                for t in threads:
                    t.start()

                for t in threads:
                    t.join()

                # 至少有一个同步成功
                assert len(results) > 0


# ============== 边界条件测试 ==============

class TestEdgeCases:
    """边界条件测试"""

    def test_search_empty_keyword(self, clean_manager):
        """测试空关键词搜索"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = manager.search('')

            assert isinstance(results, list)

    def test_search_special_characters(self, clean_manager):
        """测试特殊字符搜索"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = manager.search('<script>alert(1)</script>')

            assert isinstance(results, list)

    def test_search_unicode(self, clean_manager):
        """测试 Unicode 搜索"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.search.return_value = []
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            results = manager.search('漏洞')

            assert isinstance(results, list)

    def test_get_nonexistent_cve(self, clean_manager):
        """测试获取不存在的 CVE"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.get_by_id.return_value = None
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            result = manager.get_cve('CVE-9999-9999')

            assert result is None

    def test_invalid_cve_id_format(self, clean_manager):
        """测试无效的 CVE ID 格式"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()
            mock_storage_instance.get_by_id.return_value = None
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()
            result = manager.get_cve('invalid-id')

            assert result is None


# ============== 集成测试 ==============

class TestIntegration:
    """集成测试"""

    def test_full_workflow(self, clean_manager):
        """测试完整工作流"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()

            # 模拟 CVE 数据
            mock_cve = CVEEntry(
                cve_id='CVE-2024-1234',
                description='Test vulnerability',
                severity=Severity.HIGH,
                cvss_score=8.0,
                published_date=datetime(2024, 1, 1),
            )

            mock_storage_instance.search.return_value = [mock_cve]
            mock_storage_instance.get_by_id.return_value = mock_cve
            mock_storage_instance.save.return_value = True
            mock_storage_instance.get_stats.return_value = CVEStats(
                total_cves=1,
                by_severity={Severity.HIGH: 1},
            )

            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()

            # 1. 搜索 CVE
            results = manager.search('Test')
            assert len(results) > 0

            # 2. 获取特定 CVE
            cve = manager.get_cve('CVE-2024-1234')
            assert cve is not None
            assert cve.cve_id == 'CVE-2024-1234'

            # 3. 获取统计信息
            stats = manager.get_stats()
            assert stats.total_cves == 1

    def test_search_and_filter(self, clean_manager):
        """测试搜索和过滤"""
        with patch('core.cve.manager.get_storage') as mock_storage:
            mock_storage_instance = Mock()

            # 创建多个 CVE
            cves = [
                CVEEntry(
                    cve_id=f'CVE-2024-{i}',
                    description=f'Vulnerability {i}',
                    severity=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM,
                    cvss_score=7.0 + i * 0.1,
                    published_date=datetime(2024, 1, i),
                )
                for i in range(1, 6)
            ]

            mock_storage_instance.search.return_value = cves
            mock_storage.return_value = mock_storage_instance

            manager = CVEManager()

            # 搜索所有
            all_results = manager.search('Vulnerability')
            assert len(all_results) == 5

            # 按严重程度过滤
            high_severity = [cve for cve in all_results if cve.severity == Severity.HIGH]
            assert len(high_severity) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
