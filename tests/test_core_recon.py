"""
core.recon 模块单元测试

测试侦察引擎的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock


class TestReconConfig:
    """测试 ReconConfig 配置类"""

    def test_default_config(self):
        """测试默认配置"""
        from core.recon import ReconConfig

        config = ReconConfig()

        assert config is not None

    def test_quick_mode_config(self):
        """测试快速模式配置"""
        from core.recon import ReconConfig

        config = ReconConfig(quick_mode=True)

        assert config.quick_mode is True

    def test_custom_timeout(self):
        """测试自定义超时"""
        from core.recon import ReconConfig

        config = ReconConfig(timeout=60)

        assert config.timeout == 60


class TestReconResult:
    """测试 ReconResult 结果类"""

    def test_result_creation(self):
        """测试结果创建"""
        from core.recon import ReconResult

        result = ReconResult(target="https://example.com")

        assert result is not None
        assert result.target == "https://example.com"

    def test_result_to_dict(self):
        """测试结果转字典"""
        from core.recon import ReconResult

        result = ReconResult(target="https://example.com")

        if hasattr(result, 'to_dict'):
            result_dict = result.to_dict()
            assert isinstance(result_dict, dict)


class TestStandardReconEngine:
    """测试 StandardReconEngine 类"""

    def test_engine_creation(self):
        """测试引擎创建"""
        from core.recon import StandardReconEngine, ReconConfig

        config = ReconConfig(quick_mode=True)
        engine = StandardReconEngine("https://example.com", config)

        assert engine is not None

    def test_engine_target(self):
        """测试引擎目标"""
        from core.recon import StandardReconEngine, ReconConfig

        config = ReconConfig()
        engine = StandardReconEngine("https://example.com", config)

        assert engine.target == "https://example.com"


class TestReconPhase:
    """测试 ReconPhase 枚举"""

    def test_recon_phases(self):
        """测试侦察阶段"""
        from core.recon import ReconPhase

        assert ReconPhase is not None
        # 检查常见阶段
        if hasattr(ReconPhase, 'DNS'):
            assert ReconPhase.DNS is not None
        if hasattr(ReconPhase, 'PORT_SCAN'):
            assert ReconPhase.PORT_SCAN is not None
        if hasattr(ReconPhase, 'FINGERPRINT'):
            assert ReconPhase.FINGERPRINT is not None


class TestDNSResolver:
    """测试 DNS 解析器"""

    def test_resolver_creation(self):
        """测试解析器创建"""
        from core.recon import DNSResolver

        resolver = DNSResolver()

        assert resolver is not None

    def test_resolver_with_nameservers(self):
        """测试自定义 DNS 服务器"""
        from core.recon import DNSResolver

        resolver = DNSResolver(nameservers=["8.8.8.8", "8.8.4.4"])

        assert resolver is not None


class TestPortScanner:
    """测试端口扫描器"""

    def test_scanner_creation(self):
        """测试扫描器创建"""
        from core.recon import PortScanner

        scanner = PortScanner()

        assert scanner is not None

    def test_scanner_with_ports(self):
        """测试指定端口"""
        from core.recon import PortScanner

        scanner = PortScanner(ports=[80, 443, 8080])

        assert scanner is not None


class TestFingerprinter:
    """测试指纹识别器"""

    def test_fingerprinter_creation(self):
        """测试指纹识别器创建"""
        from core.recon import Fingerprinter

        fingerprinter = Fingerprinter()

        assert fingerprinter is not None


class TestTechDetector:
    """测试技术检测器"""

    def test_tech_detector_creation(self):
        """测试技术检测器创建"""
        from core.recon import TechDetector

        detector = TechDetector()

        assert detector is not None


class TestWAFDetector:
    """测试 WAF 检测器"""

    def test_waf_detector_creation(self):
        """测试 WAF 检测器创建"""
        from core.recon import WAFDetector

        detector = WAFDetector()

        assert detector is not None


class TestSubdomainEnumerator:
    """测试子域名枚举器"""

    def test_enumerator_creation(self):
        """测试枚举器创建"""
        from core.recon import SubdomainEnumerator

        enumerator = SubdomainEnumerator()

        assert enumerator is not None

    def test_enumerator_with_wordlist(self):
        """测试自定义字典"""
        from core.recon import SubdomainEnumerator

        enumerator = SubdomainEnumerator(wordlist=["www", "api", "admin"])

        assert enumerator is not None


class TestDirectoryScanner:
    """测试目录扫描器"""

    def test_scanner_creation(self):
        """测试扫描器创建"""
        from core.recon import DirectoryScanner

        scanner = DirectoryScanner()

        assert scanner is not None


class TestReconPhases:
    """测试侦察阶段定义"""

    def test_phases_module(self):
        """测试阶段模块"""
        from core.recon import phases

        assert phases is not None

    def test_phase_definitions(self):
        """测试阶段定义"""
        from core.recon.phases import RECON_PHASES

        if 'RECON_PHASES' in dir():
            assert isinstance(RECON_PHASES, (list, dict))


class TestReconBase:
    """测试侦察基类"""

    def test_base_recon_class(self):
        """测试基类"""
        from core.recon.base import BaseRecon

        assert BaseRecon is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
