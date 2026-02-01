"""
core.cve 模块单元测试

测试 CVE 情报模块的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


class TestCVEEntry:
    """测试 CVE 数据模型"""

    def test_cve_entry_creation(self):
        """测试 CVE 条目创建"""
        from core.cve import CVEEntry, Severity

        cve = CVEEntry(
            cve_id="CVE-2021-44228",
            title="Log4j RCE vulnerability",
            description="Apache Log4j2 远程代码执行漏洞",
            severity=Severity.CRITICAL,
        )

        assert cve is not None
        assert cve.cve_id == "CVE-2021-44228"
        assert cve.severity == Severity.CRITICAL

    def test_severity_enum(self):
        """测试严重性枚举"""
        from core.cve import Severity

        assert Severity.CRITICAL is not None
        assert Severity.HIGH is not None
        assert Severity.MEDIUM is not None
        assert Severity.LOW is not None


class TestCVEManager:
    """测试 CVE 管理器"""

    def test_manager_creation(self):
        """测试管理器创建"""
        from core.cve import CVEManager

        manager = CVEManager()

        assert manager is not None

    def test_get_manager(self):
        """测试获取管理器单例"""
        from core.cve import get_cve_manager

        manager = get_cve_manager()

        assert manager is not None

    def test_search_cve(self):
        """测试搜索 CVE"""
        from core.cve import CVEManager

        manager = CVEManager()

        if hasattr(manager, 'search'):
            # 搜索可能返回空结果，但不应该抛出异常
            results = manager.search("Log4j")
            assert isinstance(results, (list, dict, type(None)))


class TestCVEStorage:
    """测试 CVE 存储"""

    def test_storage_creation(self):
        """测试存储创建"""
        from core.cve import CVEStorage

        storage = CVEStorage()

        assert storage is not None

    def test_get_storage(self):
        """测试获取存储单例"""
        from core.cve import get_storage

        storage = get_storage()

        assert storage is not None


class TestCVESources:
    """测试 CVE 数据源"""

    def test_nvd_source(self):
        """测试 NVD 数据源"""
        from core.cve import NVDSource

        source = NVDSource()

        assert source is not None

    def test_nuclei_source(self):
        """测试 Nuclei 数据源"""
        from core.cve import NucleiSource

        source = NucleiSource()

        assert source is not None

    def test_exploitdb_source(self):
        """测试 Exploit-DB 数据源"""
        from core.cve import ExploitDBSource

        source = ExploitDBSource()

        assert source is not None

    def test_github_poc_source(self):
        """测试 GitHub PoC 数据源"""
        from core.cve import GitHubPoCSource

        source = GitHubPoCSource()

        assert source is not None

    def test_aggregated_source(self):
        """测试聚合数据源"""
        from core.cve import AggregatedSource, NVDSource

        # AggregatedSource 需要 sources 参数
        source = AggregatedSource(sources=[NVDSource()])

        assert source is not None


class TestPoCEngine:
    """测试 PoC 引擎"""

    def test_poc_engine_creation(self):
        """测试 PoC 引擎创建"""
        from core.cve import PoCEngine

        engine = PoCEngine()

        assert engine is not None

    def test_get_poc_engine(self):
        """测试获取 PoC 引擎单例"""
        from core.cve import get_poc_engine

        engine = get_poc_engine()

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

        # PoCTemplate 是 dataclass，使用正确的字段名
        template = PoCTemplate(
            id="CVE-2021-44228",
            name="Log4j RCE",
        )

        assert template is not None
        assert template.id == "CVE-2021-44228"


class TestCVESearchEngine:
    """测试 CVE 搜索引擎"""

    def test_search_engine_creation(self):
        """测试搜索引擎创建"""
        from core.cve import CVESearchEngine, get_storage

        # CVESearchEngine 需要 storage 参数
        storage = get_storage()
        engine = CVESearchEngine(storage=storage)

        assert engine is not None

    def test_create_search_engine(self):
        """测试创建搜索引擎"""
        from core.cve import create_search_engine

        engine = create_search_engine()

        assert engine is not None


class TestAIPoCGenerator:
    """测试 AI PoC 生成器"""

    def test_ai_poc_generator_creation(self):
        """测试 AI PoC 生成器创建"""
        from core.cve import AIPoCGenerator

        generator = AIPoCGenerator()

        assert generator is not None


class TestCVEAutoExploit:
    """测试 CVE 自动利用"""

    def test_auto_exploit_engine_creation(self):
        """测试自动利用引擎创建"""
        from core.cve import CVEAutoExploitEngine

        engine = CVEAutoExploitEngine()

        assert engine is not None

    def test_get_auto_exploit_engine(self):
        """测试获取自动利用引擎"""
        from core.cve import get_auto_exploit_engine

        engine = get_auto_exploit_engine()

        assert engine is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
