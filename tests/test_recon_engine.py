#!/usr/bin/env python3
"""
test_recon_engine.py - StandardReconEngine 单元测试

测试覆盖:
- StandardReconEngine 类的初始化
- 目标URL解析和规范化
- 阶段管理器配置
- 各阶段执行流程
- 进度回调
- 停止机制
- 结果导出
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# 导入被测试的模块
from core.recon.engine import StandardReconEngine, create_recon_engine
from core.recon.base import ReconConfig, ReconResult, Finding, Severity
from core.recon.phases import (
    ReconPhase,
    PhaseResult,
    PhaseStatus,
    PhaseManager,
    DEFAULT_PHASE_ORDER,
    QUICK_PHASE_ORDER,
)


# ============== 测试夹具 ==============

@pytest.fixture
def basic_config():
    """基础配置夹具"""
    return ReconConfig(
        timeout=10.0,
        max_threads=5,
        enable_port_scan=False,
        enable_subdomain=False,
        enable_directory=False,
        enable_waf_detect=False,
        enable_fingerprint=False,
        enable_tech_detect=False,
        enable_sensitive=False,
    )


@pytest.fixture
def quick_config():
    """快速模式配置夹具"""
    return ReconConfig(quick_mode=True)


@pytest.fixture
def mock_dns_resolver():
    """模拟DNS解析器"""
    with patch('core.recon.engine.DNSResolver') as mock:
        resolver_instance = Mock()
        resolver_instance.get_all_records.return_value = Mock(
            ip_addresses=['192.168.1.1', '192.168.1.2'],
            ipv6_addresses=['::1'],
            nameservers=['ns1.example.com'],
            mail_servers=[(10, 'mail.example.com')],
            txt_records=['v=spf1 include:example.com'],
        )
        mock.return_value = resolver_instance
        yield mock


@pytest.fixture
def mock_port_scanner():
    """模拟端口扫描器"""
    with patch('core.recon.engine.PortScanner') as mock:
        scanner_instance = Mock()
        port_result = Mock()
        port_result.port = 80
        port_result.service = 'http'
        port_result.to_dict.return_value = {'port': 80, 'service': 'http', 'state': 'open'}
        scanner_instance.scan_top_ports.return_value = [port_result]
        mock.return_value = scanner_instance
        yield mock


@pytest.fixture
def mock_fingerprint_engine():
    """模拟指纹识别引擎"""
    with patch('core.recon.engine.FingerprintEngine') as mock:
        engine_instance = Mock()
        fingerprint = Mock()
        fingerprint.category = 'server'
        fingerprint.name = 'nginx'
        fingerprint.version = '1.18.0'
        fingerprint.confidence = 0.95
        fingerprint.to_dict.return_value = {
            'category': 'server',
            'name': 'nginx',
            'version': '1.18.0',
        }
        fingerprint.__str__ = lambda self: 'nginx/1.18.0'
        engine_instance.identify.return_value = [fingerprint]
        mock.return_value = engine_instance
        yield mock


@pytest.fixture
def mock_tech_detector():
    """模拟技术栈检测器"""
    with patch('core.recon.engine.TechDetector') as mock:
        detector_instance = Mock()
        tech = Mock()
        tech.name = 'PHP'
        tech.to_dict.return_value = {'name': 'PHP', 'version': '7.4'}
        detector_instance.detect.return_value = [tech]
        mock.return_value = detector_instance
        yield mock


@pytest.fixture
def mock_waf_detector():
    """模拟WAF检测器"""
    with patch('core.recon.engine.WAFDetector') as mock:
        detector_instance = Mock()
        waf = Mock()
        waf.name = 'Cloudflare'
        waf.vendor = 'Cloudflare Inc.'
        waf.evidence = ['cf-ray header detected']
        waf.bypass_hints = ['Use IP directly']
        waf.to_dict.return_value = {'name': 'Cloudflare', 'vendor': 'Cloudflare Inc.'}
        detector_instance.detect.return_value = waf
        mock.return_value = detector_instance
        yield mock


@pytest.fixture
def mock_subdomain_enumerator():
    """模拟子域名枚举器"""
    with patch('core.recon.engine.SubdomainEnumerator') as mock:
        enumerator_instance = Mock()
        subdomain = Mock()
        subdomain.subdomain = 'api.example.com'
        subdomain.to_dict.return_value = {'subdomain': 'api.example.com', 'ip': '192.168.1.3'}
        enumerator_instance.enumerate.return_value = [subdomain]
        mock.return_value = enumerator_instance
        yield mock


@pytest.fixture
def mock_directory_scanner():
    """模拟目录扫描器"""
    with patch('core.recon.engine.DirectoryScanner') as mock:
        scanner_instance = Mock()
        directory = Mock()
        directory.path = '/admin'
        directory.to_dict.return_value = {'path': '/admin', 'status': 200}
        scanner_instance.scan.return_value = [directory]
        mock.return_value = scanner_instance
        yield mock


# ============== StandardReconEngine 初始化测试 ==============

class TestStandardReconEngineInit:
    """StandardReconEngine 初始化测试"""

    def test_init_with_url(self):
        """测试使用URL初始化"""
        engine = StandardReconEngine('https://example.com')

        assert engine.target == 'https://example.com'
        assert engine.hostname == 'example.com'
        assert engine.scheme == 'https'
        assert engine.base_url == 'https://example.com'

    def test_init_with_domain_only(self):
        """测试仅使用域名初始化"""
        engine = StandardReconEngine('example.com')

        assert engine.target == 'https://example.com'
        assert engine.hostname == 'example.com'
        assert engine.scheme == 'https'

    def test_init_with_http_url(self):
        """测试使用HTTP URL初始化"""
        engine = StandardReconEngine('http://example.com')

        assert engine.target == 'http://example.com'
        assert engine.scheme == 'http'

    def test_init_with_port(self):
        """测试带端口的URL初始化"""
        engine = StandardReconEngine('https://example.com:8443')

        assert engine.hostname == 'example.com'
        assert engine.port == 8443

    def test_init_with_path(self):
        """测试带路径的URL初始化"""
        engine = StandardReconEngine('https://example.com/api/v1')

        assert engine.target == 'https://example.com/api/v1'
        assert engine.base_url == 'https://example.com'

    def test_init_with_trailing_slash(self):
        """测试URL末尾斜杠处理"""
        engine = StandardReconEngine('https://example.com/')

        assert engine.target == 'https://example.com'

    def test_init_with_config(self):
        """测试使用配置初始化"""
        config = ReconConfig(
            timeout=60.0,
            max_threads=20,
            verify_ssl=True,
        )
        engine = StandardReconEngine('https://example.com', config)

        assert engine.config.timeout == 60.0
        assert engine.config.max_threads == 20
        assert engine.config.verify_ssl is True

    def test_init_default_config(self):
        """测试默认配置"""
        engine = StandardReconEngine('https://example.com')

        assert engine.config is not None
        assert isinstance(engine.config, ReconConfig)

    def test_init_result_object(self):
        """测试结果对象初始化"""
        engine = StandardReconEngine('https://example.com')

        assert engine.result is not None
        assert isinstance(engine.result, ReconResult)
        assert engine.result.target == 'https://example.com'

    def test_init_phase_manager(self):
        """测试阶段管理器初始化"""
        engine = StandardReconEngine('https://example.com')

        assert engine._phase_manager is not None
        assert isinstance(engine._phase_manager, PhaseManager)


# ============== 配置影响测试 ==============

class TestConfigurationEffects:
    """配置对引擎行为的影响测试"""

    def test_quick_mode_disables_phases(self):
        """测试快速模式禁用阶段"""
        config = ReconConfig(quick_mode=True)
        engine = StandardReconEngine('https://example.com', config)

        phase_order = engine._phase_manager.get_phase_order()

        # 快速模式应该跳过子域名和目录扫描
        assert ReconPhase.SUBDOMAIN not in phase_order
        assert ReconPhase.DIRECTORY not in phase_order

    def test_disable_port_scan(self):
        """测试禁用端口扫描"""
        config = ReconConfig(enable_port_scan=False)
        engine = StandardReconEngine('https://example.com', config)

        assert not engine._phase_manager.is_enabled(ReconPhase.PORT_SCAN)

    def test_disable_subdomain(self):
        """测试禁用子域名枚举"""
        config = ReconConfig(enable_subdomain=False)
        engine = StandardReconEngine('https://example.com', config)

        assert not engine._phase_manager.is_enabled(ReconPhase.SUBDOMAIN)

    def test_disable_directory(self):
        """测试禁用目录扫描"""
        config = ReconConfig(enable_directory=False)
        engine = StandardReconEngine('https://example.com', config)

        assert not engine._phase_manager.is_enabled(ReconPhase.DIRECTORY)

    def test_disable_waf_detect(self):
        """测试禁用WAF检测"""
        config = ReconConfig(enable_waf_detect=False)
        engine = StandardReconEngine('https://example.com', config)

        assert not engine._phase_manager.is_enabled(ReconPhase.WAF_DETECT)

    def test_disable_fingerprint(self):
        """测试禁用指纹识别"""
        config = ReconConfig(enable_fingerprint=False)
        engine = StandardReconEngine('https://example.com', config)

        assert not engine._phase_manager.is_enabled(ReconPhase.FINGERPRINT)

    def test_disable_tech_detect(self):
        """测试禁用技术栈识别"""
        config = ReconConfig(enable_tech_detect=False)
        engine = StandardReconEngine('https://example.com', config)

        assert not engine._phase_manager.is_enabled(ReconPhase.TECH_DETECT)

    def test_disable_sensitive(self):
        """测试禁用敏感信息扫描"""
        config = ReconConfig(enable_sensitive=False)
        engine = StandardReconEngine('https://example.com', config)

        assert not engine._phase_manager.is_enabled(ReconPhase.SENSITIVE)


# ============== 阶段执行测试 ==============

class TestPhaseExecution:
    """阶段执行测试"""

    def test_phase_init(self):
        """测试初始化阶段"""
        engine = StandardReconEngine('https://example.com:8080/api')

        result = engine._phase_init()

        assert result.success is True
        assert result.phase == ReconPhase.INIT
        assert result.data['hostname'] == 'example.com'
        assert result.data['scheme'] == 'https'
        assert result.data['port'] == 8080
        assert result.data['path'] == '/api'

    def test_phase_dns(self, mock_dns_resolver):
        """测试DNS解析阶段"""
        engine = StandardReconEngine('https://example.com')

        result = engine._phase_dns()

        assert result.success is True
        assert result.phase == ReconPhase.DNS
        assert '192.168.1.1' in result.data['ip_addresses']
        assert engine.result.ip_addresses == ['192.168.1.1', '192.168.1.2']

    def test_phase_dns_failure(self):
        """测试DNS解析失败"""
        with patch('core.recon.engine.DNSResolver') as mock:
            mock.return_value.get_all_records.side_effect = Exception('DNS lookup failed')

            engine = StandardReconEngine('https://example.com')
            result = engine._phase_dns()

            assert result.success is False
            assert len(result.errors) > 0

    def test_phase_port_scan(self, mock_dns_resolver, mock_port_scanner):
        """测试端口扫描阶段"""
        engine = StandardReconEngine('https://example.com')

        # 先执行DNS解析获取IP
        engine._phase_dns()

        result = engine._phase_port_scan()

        assert result.success is True
        assert result.phase == ReconPhase.PORT_SCAN
        assert len(engine.result.open_ports) > 0

    def test_phase_port_scan_no_ip(self):
        """测试无IP时跳过端口扫描"""
        engine = StandardReconEngine('https://example.com')
        # 不执行DNS解析，IP列表为空

        result = engine._phase_port_scan()

        assert result.status == PhaseStatus.SKIPPED

    def test_phase_fingerprint(self, mock_fingerprint_engine):
        """测试指纹识别阶段"""
        engine = StandardReconEngine('https://example.com')

        result = engine._phase_fingerprint()

        assert result.success is True
        assert result.phase == ReconPhase.FINGERPRINT
        assert 'server' in engine.result.fingerprints

    def test_phase_tech_detect(self, mock_tech_detector):
        """测试技术栈识别阶段"""
        engine = StandardReconEngine('https://example.com')

        result = engine._phase_tech_detect()

        assert result.success is True
        assert result.phase == ReconPhase.TECH_DETECT
        assert 'PHP' in engine.result.technologies

    def test_phase_waf_detect(self, mock_waf_detector):
        """测试WAF检测阶段"""
        engine = StandardReconEngine('https://example.com')

        result = engine._phase_waf_detect()

        assert result.success is True
        assert result.phase == ReconPhase.WAF_DETECT
        assert engine.result.waf_detected == 'Cloudflare'

    def test_phase_waf_detect_no_waf(self):
        """测试未检测到WAF"""
        with patch('core.recon.engine.WAFDetector') as mock:
            mock.return_value.detect.return_value = None

            engine = StandardReconEngine('https://example.com')
            result = engine._phase_waf_detect()

            assert result.success is True
            assert result.data['waf'] is None

    def test_phase_subdomain(self, mock_subdomain_enumerator):
        """测试子域名枚举阶段"""
        engine = StandardReconEngine('https://example.com')

        result = engine._phase_subdomain()

        assert result.success is True
        assert result.phase == ReconPhase.SUBDOMAIN
        assert 'api.example.com' in engine.result.subdomains

    def test_phase_directory(self, mock_directory_scanner):
        """测试目录扫描阶段"""
        engine = StandardReconEngine('https://example.com')

        result = engine._phase_directory()

        assert result.success is True
        assert result.phase == ReconPhase.DIRECTORY
        assert '/admin' in engine.result.directories

    def test_phase_complete(self):
        """测试完成阶段"""
        engine = StandardReconEngine('https://example.com')

        # 添加一些发现
        engine._add_finding(Finding(
            type='test',
            severity=Severity.HIGH,
            title='Test Finding',
            description='Test description',
        ))

        result = engine._phase_complete()

        assert result.success is True
        assert result.phase == ReconPhase.COMPLETE
        assert result.data['risk_level'] == 'high'
        assert result.data['total_findings'] == 1


# ============== 完整运行测试 ==============

class TestFullRun:
    """完整运行测试"""

    def test_run_minimal(self, basic_config):
        """测试最小配置运行"""
        engine = StandardReconEngine('https://example.com', basic_config)

        result = engine.run()

        assert result is not None
        assert isinstance(result, ReconResult)
        assert result.target == 'https://example.com'
        assert result.end_time is not None
        assert result.duration > 0

    def test_run_records_duration(self, basic_config):
        """测试运行时间记录"""
        engine = StandardReconEngine('https://example.com', basic_config)

        result = engine.run()

        assert result.duration >= 0
        assert result.start_time is not None
        assert result.end_time is not None

    def test_run_phase_results(self, basic_config):
        """测试阶段结果记录"""
        engine = StandardReconEngine('https://example.com', basic_config)

        result = engine.run()

        assert len(result.phase_results) > 0
        # 至少应该有INIT和COMPLETE阶段
        phases = [pr.phase for pr in result.phase_results]
        assert ReconPhase.INIT in phases
        assert ReconPhase.COMPLETE in phases

    @pytest.mark.asyncio
    async def test_async_run(self, basic_config):
        """测试异步运行"""
        engine = StandardReconEngine('https://example.com', basic_config)

        result = await engine.async_run()

        assert result is not None
        assert isinstance(result, ReconResult)


# ============== 停止机制测试 ==============

class TestStopMechanism:
    """停止机制测试"""

    def test_stop_flag(self):
        """测试停止标志"""
        engine = StandardReconEngine('https://example.com')

        assert engine.is_stopped() is False

        engine.stop()

        assert engine.is_stopped() is True
        assert engine.result.success is False

    def test_stop_during_run(self, basic_config):
        """测试运行中停止"""
        engine = StandardReconEngine('https://example.com', basic_config)

        # 在初始化后立即停止
        engine.stop()

        result = engine.run()

        # 应该提前终止
        assert engine.is_stopped() is True


# ============== 进度回调测试 ==============

class TestProgressCallback:
    """进度回调测试"""

    def test_set_progress_callback(self):
        """测试设置进度回调"""
        engine = StandardReconEngine('https://example.com')
        callback = Mock()

        engine.set_progress_callback(callback)

        assert engine._progress_callback is callback

    def test_progress_callback_called(self, basic_config):
        """测试进度回调被调用"""
        engine = StandardReconEngine('https://example.com', basic_config)
        callback = Mock()
        engine.set_progress_callback(callback)

        engine.run()

        # 回调应该被调用多次
        assert callback.call_count > 0

    def test_progress_callback_exception_handled(self, basic_config):
        """测试进度回调异常处理"""
        engine = StandardReconEngine('https://example.com', basic_config)

        def bad_callback(phase, progress, message):
            raise RuntimeError('Callback error')

        engine.set_progress_callback(bad_callback)

        # 不应该因为回调异常而崩溃
        result = engine.run()
        assert result is not None


# ============== 结果导出测试 ==============

class TestResultExport:
    """结果导出测试"""

    def test_export_json(self, basic_config):
        """测试JSON导出"""
        engine = StandardReconEngine('https://example.com', basic_config)
        engine.run()

        json_str = engine.export_json()

        assert isinstance(json_str, str)
        assert 'example.com' in json_str

    def test_export_dict(self, basic_config):
        """测试字典导出"""
        engine = StandardReconEngine('https://example.com', basic_config)
        engine.run()

        result_dict = engine.export_dict()

        assert isinstance(result_dict, dict)
        assert result_dict['target'] == 'https://example.com'

    def test_get_result(self, basic_config):
        """测试获取结果"""
        engine = StandardReconEngine('https://example.com', basic_config)
        engine.run()

        result = engine.get_result()

        assert result is engine.result


# ============== 工厂函数测试 ==============

class TestFactoryFunction:
    """工厂函数测试"""

    def test_create_recon_engine_default(self):
        """测试默认创建引擎"""
        engine = create_recon_engine('https://example.com')

        assert isinstance(engine, StandardReconEngine)
        assert engine.target == 'https://example.com'

    def test_create_recon_engine_with_config(self):
        """测试使用配置创建引擎"""
        config = ReconConfig(timeout=120.0)
        engine = create_recon_engine('https://example.com', config)

        assert engine.config.timeout == 120.0

    def test_create_recon_engine_quick_mode(self):
        """测试快速模式创建引擎"""
        engine = create_recon_engine('https://example.com', quick_mode=True)

        assert engine.config.quick_mode is True

    def test_create_recon_engine_quick_mode_override(self):
        """测试快速模式覆盖配置"""
        config = ReconConfig(quick_mode=False)
        engine = create_recon_engine('https://example.com', config, quick_mode=True)

        assert engine.config.quick_mode is True


# ============== 边界条件测试 ==============

class TestEdgeCases:
    """边界条件测试"""

    def test_ip_address_target(self):
        """测试IP地址作为目标"""
        engine = StandardReconEngine('192.168.1.1')

        assert engine.hostname == '192.168.1.1'

    def test_localhost_target(self):
        """测试localhost作为目标"""
        engine = StandardReconEngine('http://localhost:8080')

        assert engine.hostname == 'localhost'
        assert engine.port == 8080

    def test_subdomain_extraction(self):
        """测试子域名提取"""
        engine = StandardReconEngine('https://api.v2.example.com')

        # 在子域名枚举阶段应该正确提取根域名
        assert engine.hostname == 'api.v2.example.com'

    def test_unicode_domain(self):
        """测试Unicode域名"""
        engine = StandardReconEngine('https://例え.jp')

        assert engine.hostname == '例え.jp'

    def test_very_long_url(self):
        """测试超长URL"""
        long_path = '/a' * 1000
        engine = StandardReconEngine(f'https://example.com{long_path}')

        assert engine.hostname == 'example.com'


# ============== 敏感文件检测测试 ==============

class TestSensitiveFileDetection:
    """敏感文件检测测试"""

    def test_check_sensitive_file_found(self):
        """测试发现敏感文件"""
        engine = StandardReconEngine('https://example.com')

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.read.return_value = b'[core]\nrepositoryformatversion = 0'
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = engine._check_sensitive_file(
                'https://example.com/.git/config',
                '.git/config'
            )

            assert result is not None
            assert result['path'] == '.git/config'
            assert result['status'] == 200

    def test_check_sensitive_file_not_found(self):
        """测试未发现敏感文件"""
        engine = StandardReconEngine('https://example.com')

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = Exception('404 Not Found')

            result = engine._check_sensitive_file(
                'https://example.com/.env',
                '.env'
            )

            assert result is None

    def test_check_sensitive_file_404_page(self):
        """测试404伪装页面"""
        engine = StandardReconEngine('https://example.com')

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = Mock()
            mock_response.status = 200
            mock_response.read.return_value = b'<html><title>404 Not Found</title></html>'
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = engine._check_sensitive_file(
                'https://example.com/.env',
                '.env'
            )

            # 应该识别为404伪装页面
            assert result is None


# ============== 线程安全测试 ==============

class TestThreadSafety:
    """线程安全测试"""

    def test_add_finding_thread_safe(self):
        """测试添加发现的线程安全性"""
        engine = StandardReconEngine('https://example.com')

        import threading

        def add_findings():
            for i in range(100):
                engine._add_finding(Finding(
                    type='test',
                    severity=Severity.INFO,
                    title=f'Finding {i}',
                    description='Test',
                ))

        threads = [threading.Thread(target=add_findings) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 应该有500个发现
        assert len(engine.result.findings) == 500

    def test_add_error_thread_safe(self):
        """测试添加错误的线程安全性"""
        engine = StandardReconEngine('https://example.com')

        import threading

        def add_errors():
            for i in range(100):
                engine._add_error(f'Error {i}')

        threads = [threading.Thread(target=add_errors) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(engine.result.errors) == 500


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
