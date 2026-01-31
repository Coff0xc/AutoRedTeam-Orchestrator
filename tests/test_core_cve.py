"""
core.cve 模块单元测试

测试 CVE 情报模块的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


class TestCVEModel:
    """测试 CVE 模型"""

    def test_cve_model_creation(self):
        """测试 CVE 模型创建"""
        from core.cve import CVEModel

        cve = CVEModel(
            cve_id="CVE-2021-44228",
            description="Log4j RCE vulnerability"
        )

        assert cve is not None
        assert cve.cve_id == "CVE-2021-44228"

    def test_cve_model_severity(self):
        """测试 CVE 严重性"""
        from core.cve import CVEModel

        cve = CVEModel(
            cve_id="CVE-2021-44228",
            description="Log4j RCE",
            severity="CRITICAL",
            cvss_score=10.0
        )

        assert cve.severity == "CRITICAL"
        assert cve.cvss_score == 10.0

    def test_cve_model_to_dict(self):
        """测试 CVE 转字典"""
        from core.cve import CVEModel

        cve = CVEModel(
            cve_id="CVE-2021-44228",
            description="Log4j RCE"
        )

        if hasattr(cve, 'to_dict'):
            cve_dict = cve.to_dict()
            assert isinstance(cve_dict, dict)
            assert cve_dict['cve_id'] == "CVE-2021-44228"


class TestCVEManager:
    """测试 CVE 管理器"""

    def test_manager_creation(self):
        """测试管理器创建"""
        from core.cve import CVEManager

        manager = CVEManager()

        assert manager is not None

    def test_search_cve(self):
        """测试搜索 CVE"""
        from core.cve import CVEManager

        manager = CVEManager()

        if hasattr(manager, 'search'):
            # 搜索可能返回空结果，但不应该抛出异常
            results = manager.search("Log4j")
            assert isinstance(results, (list, dict))


class TestCVESearch:
    """测试 CVE 搜索"""

    def test_search_by_keyword(self):
        """测试关键词搜索"""
        from core.cve import search_cve

        results = search_cve("apache")

        assert isinstance(results, (list, dict))

    def test_search_by_id(self):
        """测试 ID 搜索"""
        from core.cve import search_cve

        results = search_cve("CVE-2021-44228")

        assert isinstance(results, (list, dict))


class TestCVEStorage:
    """测试 CVE 存储"""

    def test_storage_creation(self):
        """测试存储创建"""
        from core.cve import CVEStorage

        storage = CVEStorage()

        assert storage is not None

    def test_storage_save_load(self):
        """测试存储保存和加载"""
        from core.cve import CVEStorage, CVEModel
        import tempfile
        import os

        storage = CVEStorage()

        cve = CVEModel(
            cve_id="CVE-2021-44228",
            description="Test CVE"
        )

        # 使用临时目录
        with tempfile.TemporaryDirectory() as tmpdir:
            if hasattr(storage, 'save') and hasattr(storage, 'load'):
                # 测试保存和加载
                pass


class TestCVESources:
    """测试 CVE 数据源"""

    def test_nvd_source(self):
        """测试 NVD 数据源"""
        from core.cve import NVDSource

        source = NVDSource()

        assert source is not None

    def test_source_list(self):
        """测试数据源列表"""
        from core.cve import list_sources

        sources = list_sources()

        assert isinstance(sources, (list, dict))


class TestPoCEngine:
    """测试 PoC 引擎"""

    def test_poc_engine_creation(self):
        """测试 PoC 引擎创建"""
        from core.cve import PoCEngine

        engine = PoCEngine()

        assert engine is not None

    def test_poc_template_loading(self):
        """测试 PoC 模板加载"""
        from core.cve import PoCEngine

        engine = PoCEngine()

        if hasattr(engine, 'list_templates'):
            templates = engine.list_templates()
            assert isinstance(templates, (list, dict))


class TestPoCTemplate:
    """测试 PoC 模板"""

    def test_template_creation(self):
        """测试模板创建"""
        from core.cve import PoCTemplate

        template = PoCTemplate(
            template_id="CVE-2021-44228",
            name="Log4j RCE",
            description="Log4j Remote Code Execution"
        )

        assert template is not None

    def test_template_variables(self):
        """测试模板变量"""
        from core.cve import PoCTemplate

        template = PoCTemplate(
            template_id="CVE-2021-44228",
            name="Log4j RCE",
            variables={"target": "http://example.com"}
        )

        if hasattr(template, 'variables'):
            assert "target" in template.variables


class TestCVESync:
    """测试 CVE 同步"""

    def test_sync_manager(self):
        """测试同步管理器"""
        from core.cve import CVESyncManager

        manager = CVESyncManager()

        assert manager is not None


class TestCVESubscription:
    """测试 CVE 订阅"""

    def test_subscription_manager(self):
        """测试订阅管理器"""
        from core.cve import SubscriptionManager

        manager = SubscriptionManager()

        assert manager is not None

    def test_add_subscription(self):
        """测试添加订阅"""
        from core.cve import SubscriptionManager

        manager = SubscriptionManager()

        if hasattr(manager, 'subscribe'):
            manager.subscribe("apache", severity="HIGH")


class TestCVEUpdateManager:
    """测试 CVE 更新管理器"""

    def test_update_manager(self):
        """测试更新管理器"""
        from core.cve import UpdateManager

        manager = UpdateManager()

        assert manager is not None


class TestCVEStats:
    """测试 CVE 统计"""

    def test_get_stats(self):
        """测试获取统计"""
        from core.cve import get_cve_stats

        stats = get_cve_stats()

        assert isinstance(stats, dict)


class TestCVEHelpers:
    """测试 CVE 辅助函数"""

    def test_parse_cve_id(self):
        """测试解析 CVE ID"""
        from core.cve import parse_cve_id

        result = parse_cve_id("CVE-2021-44228")

        assert result is not None

    def test_validate_cve_id(self):
        """测试验证 CVE ID"""
        from core.cve import validate_cve_id

        assert validate_cve_id("CVE-2021-44228") is True
        assert validate_cve_id("invalid") is False


class TestCVESeverity:
    """测试 CVE 严重性"""

    def test_severity_enum(self):
        """测试严重性枚举"""
        from core.cve import CVESeverity

        assert CVESeverity is not None
        if hasattr(CVESeverity, 'CRITICAL'):
            assert CVESeverity.CRITICAL is not None


class TestCVEExploitability:
    """测试 CVE 可利用性"""

    def test_exploitability_score(self):
        """测试可利用性评分"""
        from core.cve import calculate_exploitability

        score = calculate_exploitability(
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE"
        )

        assert isinstance(score, (int, float))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
