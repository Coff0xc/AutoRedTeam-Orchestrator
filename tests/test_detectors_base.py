#!/usr/bin/env python3
"""
test_detectors_base.py - BaseDetector 和 CompositeDetector 单元测试

测试覆盖:
- BaseDetector 类的初始化和配置
- 检测结果创建
- 日志记录方法
- CompositeDetector 组合检测器
- StreamingDetector 流式检测器
- ContextAwareDetector 上下文感知检测器
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from typing import List

# 导入被测试的模块
from core.detectors.base import (
    BaseDetector,
    CompositeDetector,
    StreamingDetector,
    ContextAwareDetector,
)
from core.detectors.result import (
    DetectionResult,
    Severity,
    DetectorType,
    RequestInfo,
    ResponseInfo,
)


# ============== 测试用的具体检测器实现 ==============

class MockDetector(BaseDetector):
    """用于测试的模拟检测器"""

    name = 'mock_detector'
    description = '模拟检测器'
    vuln_type = 'mock_vuln'
    severity = Severity.MEDIUM
    detector_type = DetectorType.MISC
    version = '1.0.0'

    def __init__(self, config=None, should_find_vuln=False, raise_exception=False):
        super().__init__(config)
        self.should_find_vuln = should_find_vuln
        self.raise_exception = raise_exception
        self.detect_called = False

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """模拟检测方法"""
        self.detect_called = True

        if self.raise_exception:
            raise RuntimeError("模拟检测异常")

        self._log_detection_start(url)
        results = []

        if self.should_find_vuln:
            result = self._create_result(
                url=url,
                vulnerable=True,
                param='test_param',
                payload='<script>alert(1)</script>',
                evidence='发现XSS漏洞',
                confidence=0.9,
            )
            results.append(result)

        self._log_detection_end(url, results)
        return results


class MockStreamingDetector(StreamingDetector):
    """用于测试的流式检测器"""

    name = 'mock_streaming'
    vuln_type = 'streaming_vuln'

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        return [
            self._create_result(url=url, vulnerable=True, evidence='Result 1'),
            self._create_result(url=url, vulnerable=True, evidence='Result 2'),
        ]


class MockContextAwareDetector(ContextAwareDetector):
    """用于测试的上下文感知检测器"""

    name = 'mock_context_aware'
    vuln_type = 'context_vuln'

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        results = []
        # 根据上下文调整检测行为
        waf = self.get_context('waf')
        if waf:
            # 如果检测到WAF，使用不同的检测策略
            results.append(self._create_result(
                url=url,
                vulnerable=True,
                evidence=f'WAF detected: {waf}, using bypass technique',
            ))
        else:
            results.append(self._create_result(
                url=url,
                vulnerable=True,
                evidence='No WAF detected',
            ))
        return results


# ============== BaseDetector 测试 ==============

class TestBaseDetector:
    """BaseDetector 基类测试"""

    def test_init_default_config(self):
        """测试默认配置初始化"""
        detector = MockDetector()

        assert detector.config['timeout'] == 30
        assert detector.config['max_payloads'] == 50
        assert detector.config['verify_ssl'] is False
        assert detector.config['follow_redirects'] is True
        assert detector.config['max_redirects'] == 5
        assert detector.results == []
        assert detector._http_client is None

    def test_init_custom_config(self):
        """测试自定义配置初始化"""
        custom_config = {
            'timeout': 60,
            'max_payloads': 100,
            'verify_ssl': True,
            'custom_option': 'test_value',
        }
        detector = MockDetector(config=custom_config)

        assert detector.config['timeout'] == 60
        assert detector.config['max_payloads'] == 100
        assert detector.config['verify_ssl'] is True
        assert detector.config['custom_option'] == 'test_value'
        # 默认值应该保留
        assert detector.config['follow_redirects'] is True

    def test_class_attributes(self):
        """测试类属性"""
        detector = MockDetector()

        assert detector.name == 'mock_detector'
        assert detector.description == '模拟检测器'
        assert detector.vuln_type == 'mock_vuln'
        assert detector.severity == Severity.MEDIUM
        assert detector.detector_type == DetectorType.MISC
        assert detector.version == '1.0.0'

    def test_detect_no_vulnerability(self):
        """测试检测无漏洞情况"""
        detector = MockDetector(should_find_vuln=False)
        results = detector.detect('https://example.com')

        assert detector.detect_called is True
        assert len(results) == 0

    def test_detect_with_vulnerability(self):
        """测试检测发现漏洞情况"""
        detector = MockDetector(should_find_vuln=True)
        results = detector.detect('https://example.com')

        assert len(results) == 1
        result = results[0]
        assert result.vulnerable is True
        assert result.vuln_type == 'mock_vuln'
        assert result.severity == Severity.MEDIUM
        assert result.param == 'test_param'
        assert result.payload == '<script>alert(1)</script>'
        assert result.confidence == 0.9
        assert result.detector == 'mock_detector'
        assert result.detector_version == '1.0.0'

    @pytest.mark.asyncio
    async def test_async_detect(self):
        """测试异步检测方法"""
        detector = MockDetector(should_find_vuln=True)
        results = await detector.async_detect('https://example.com')

        assert len(results) == 1
        assert results[0].vulnerable is True

    def test_verify_default(self):
        """测试默认验证方法"""
        detector = MockDetector()
        result = DetectionResult(
            vulnerable=True,
            vuln_type='test',
            severity=Severity.HIGH,
            url='https://example.com',
        )

        # 默认实现返回False
        assert detector.verify(result) is False

    def test_get_payloads_default(self):
        """测试默认payload获取方法"""
        detector = MockDetector()
        payloads = detector.get_payloads()

        assert payloads == []

    def test_create_result(self):
        """测试创建检测结果"""
        detector = MockDetector()

        result = detector._create_result(
            url='https://example.com/test',
            vulnerable=True,
            param='id',
            payload="1' OR '1'='1",
            evidence='SQL error in response',
            confidence=0.85,
            verified=True,
            remediation='使用参数化查询',
            references=['https://owasp.org/sqli'],
            extra={'db_type': 'mysql'},
        )

        assert result.vulnerable is True
        assert result.vuln_type == 'mock_vuln'
        assert result.severity == Severity.MEDIUM
        assert result.url == 'https://example.com/test'
        assert result.param == 'id'
        assert result.payload == "1' OR '1'='1"
        assert result.evidence == 'SQL error in response'
        assert result.confidence == 0.85
        assert result.verified is True
        assert result.detector == 'mock_detector'
        assert result.detector_version == '1.0.0'
        assert result.remediation == '使用参数化查询'
        assert 'https://owasp.org/sqli' in result.references
        assert result.extra['db_type'] == 'mysql'

    def test_create_result_with_request_response(self):
        """测试创建包含请求响应信息的检测结果"""
        detector = MockDetector()

        request = RequestInfo(
            method='POST',
            url='https://example.com/login',
            headers={'Content-Type': 'application/json'},
            body='{"username": "admin"}',
        )
        response = ResponseInfo(
            status_code=200,
            headers={'Server': 'nginx'},
            body='Login successful',
            elapsed_ms=150.5,
        )

        result = detector._create_result(
            url='https://example.com/login',
            vulnerable=True,
            request=request,
            response=response,
        )

        assert result.request is not None
        assert result.request.method == 'POST'
        assert result.response is not None
        assert result.response.status_code == 200

    def test_log_detection_timing(self):
        """测试检测时间记录"""
        detector = MockDetector(should_find_vuln=True)

        assert detector._start_time is None
        assert detector._end_time is None

        detector.detect('https://example.com')

        assert detector._start_time is not None
        assert detector._end_time is not None
        assert detector._end_time >= detector._start_time

    def test_safe_request_success(self):
        """测试安全请求封装 - 成功情况"""
        detector = MockDetector()

        # Mock HTTP客户端
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'OK'

        mock_client = Mock()
        mock_client.request.return_value = mock_response
        detector._http_client = mock_client

        response = detector._safe_request('GET', 'https://example.com')

        assert response is not None
        assert response.status_code == 200
        mock_client.request.assert_called_once_with('GET', 'https://example.com')

    def test_safe_request_failure(self):
        """测试安全请求封装 - 失败情况"""
        detector = MockDetector()

        mock_client = Mock()
        mock_client.request.side_effect = Exception('Connection error')
        detector._http_client = mock_client

        response = detector._safe_request('GET', 'https://example.com')

        assert response is None

    def test_str_repr(self):
        """测试字符串表示"""
        detector = MockDetector()

        assert str(detector) == 'mock_detector (mock_vuln)'
        assert 'MockDetector' in repr(detector)
        assert 'mock_detector' in repr(detector)


# ============== CompositeDetector 测试 ==============

class TestCompositeDetector:
    """CompositeDetector 组合检测器测试"""

    def test_init(self):
        """测试组合检测器初始化"""
        detector1 = MockDetector(should_find_vuln=True)
        detector2 = MockDetector(should_find_vuln=False)

        composite = CompositeDetector([detector1, detector2])

        assert len(composite.detectors) == 2
        assert composite.name == 'composite'
        assert composite.vuln_type == 'multiple'

    def test_detect_combines_results(self):
        """测试组合检测器合并结果"""
        detector1 = MockDetector(should_find_vuln=True)
        detector1.name = 'detector1'
        detector1.vuln_type = 'vuln1'

        detector2 = MockDetector(should_find_vuln=True)
        detector2.name = 'detector2'
        detector2.vuln_type = 'vuln2'

        composite = CompositeDetector([detector1, detector2])
        results = composite.detect('https://example.com')

        assert len(results) == 2
        assert detector1.detect_called is True
        assert detector2.detect_called is True

    def test_detect_handles_exception(self):
        """测试组合检测器处理子检测器异常"""
        detector1 = MockDetector(should_find_vuln=True)
        detector2 = MockDetector(raise_exception=True)
        detector3 = MockDetector(should_find_vuln=True)

        composite = CompositeDetector([detector1, detector2, detector3])
        results = composite.detect('https://example.com')

        # 即使detector2抛出异常，其他检测器的结果仍应返回
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_async_detect_parallel(self):
        """测试异步并行检测"""
        detector1 = MockDetector(should_find_vuln=True)
        detector2 = MockDetector(should_find_vuln=True)

        composite = CompositeDetector([detector1, detector2])
        results = await composite.async_detect('https://example.com')

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_async_detect_handles_exception(self):
        """测试异步检测处理异常"""
        detector1 = MockDetector(should_find_vuln=True)
        detector2 = MockDetector(raise_exception=True)

        composite = CompositeDetector([detector1, detector2])
        results = await composite.async_detect('https://example.com')

        # 应该只返回成功的结果
        assert len(results) == 1

    def test_add_detector(self):
        """测试添加子检测器"""
        composite = CompositeDetector([])
        assert len(composite.detectors) == 0

        detector = MockDetector()
        composite.add_detector(detector)

        assert len(composite.detectors) == 1
        assert composite.detectors[0] is detector

    def test_remove_detector_success(self):
        """测试移除子检测器 - 成功"""
        detector1 = MockDetector()
        detector1.name = 'detector1'
        detector2 = MockDetector()
        detector2.name = 'detector2'

        composite = CompositeDetector([detector1, detector2])

        result = composite.remove_detector('detector1')

        assert result is True
        assert len(composite.detectors) == 1
        assert composite.detectors[0].name == 'detector2'

    def test_remove_detector_not_found(self):
        """测试移除子检测器 - 未找到"""
        detector = MockDetector()
        detector.name = 'detector1'

        composite = CompositeDetector([detector])

        result = composite.remove_detector('nonexistent')

        assert result is False
        assert len(composite.detectors) == 1


# ============== StreamingDetector 测试 ==============

class TestStreamingDetector:
    """StreamingDetector 流式检测器测试"""

    @pytest.mark.asyncio
    async def test_stream_detect(self):
        """测试流式检测"""
        detector = MockStreamingDetector()

        results = []
        async for result in detector.stream_detect('https://example.com'):
            results.append(result)

        assert len(results) == 2
        assert results[0].evidence == 'Result 1'
        assert results[1].evidence == 'Result 2'


# ============== ContextAwareDetector 测试 ==============

class TestContextAwareDetector:
    """ContextAwareDetector 上下文感知检测器测试"""

    def test_set_get_context(self):
        """测试设置和获取上下文"""
        detector = MockContextAwareDetector()

        detector.set_context('waf', 'Cloudflare')
        detector.set_context('tech_stack', ['PHP', 'MySQL'])

        assert detector.get_context('waf') == 'Cloudflare'
        assert detector.get_context('tech_stack') == ['PHP', 'MySQL']
        assert detector.get_context('nonexistent') is None
        assert detector.get_context('nonexistent', 'default') == 'default'

    def test_detect_with_context(self):
        """测试带上下文的检测"""
        detector = MockContextAwareDetector()

        # 无WAF上下文
        results1 = detector.detect('https://example.com')
        assert 'No WAF detected' in results1[0].evidence

        # 设置WAF上下文
        detector.set_context('waf', 'ModSecurity')
        results2 = detector.detect('https://example.com')
        assert 'WAF detected: ModSecurity' in results2[0].evidence

    def test_detect_with_context_method(self):
        """测试 detect_with_context 方法"""
        detector = MockContextAwareDetector()

        context = {
            'waf': 'Cloudflare',
            'tech_stack': ['Node.js'],
        }

        results = detector.detect_with_context('https://example.com', context)

        assert 'WAF detected: Cloudflare' in results[0].evidence
        assert detector.get_context('tech_stack') == ['Node.js']


# ============== 边界条件测试 ==============

class TestEdgeCases:
    """边界条件测试"""

    def test_empty_url(self):
        """测试空URL"""
        detector = MockDetector(should_find_vuln=True)
        results = detector.detect('')

        # 应该正常处理空URL
        assert isinstance(results, list)

    def test_special_characters_in_url(self):
        """测试URL中的特殊字符"""
        detector = MockDetector(should_find_vuln=True)
        url = 'https://example.com/path?param=value&special=<script>'
        results = detector.detect(url)

        assert len(results) == 1
        assert results[0].url == url

    def test_unicode_in_url(self):
        """测试URL中的Unicode字符"""
        detector = MockDetector(should_find_vuln=True)
        url = 'https://example.com/路径/测试'
        results = detector.detect(url)

        assert len(results) == 1

    def test_none_config(self):
        """测试None配置"""
        detector = MockDetector(config=None)

        assert detector.config is not None
        assert detector.config['timeout'] == 30

    def test_empty_config(self):
        """测试空配置"""
        detector = MockDetector(config={})

        # 应该使用默认配置
        assert detector.config['timeout'] == 30

    def test_composite_empty_detectors(self):
        """测试空检测器列表的组合检测器"""
        composite = CompositeDetector([])
        results = composite.detect('https://example.com')

        assert results == []

    @pytest.mark.asyncio
    async def test_async_composite_empty_detectors(self):
        """测试空检测器列表的异步组合检测"""
        composite = CompositeDetector([])
        results = await composite.async_detect('https://example.com')

        assert results == []


# ============== 集成测试 ==============

class TestIntegration:
    """集成测试"""

    def test_full_detection_workflow(self):
        """测试完整检测工作流"""
        # 创建多个检测器
        sqli_detector = MockDetector(should_find_vuln=True)
        sqli_detector.name = 'sqli_detector'
        sqli_detector.vuln_type = 'sqli'
        sqli_detector.severity = Severity.HIGH

        xss_detector = MockDetector(should_find_vuln=True)
        xss_detector.name = 'xss_detector'
        xss_detector.vuln_type = 'xss'
        xss_detector.severity = Severity.MEDIUM

        # 创建组合检测器
        composite = CompositeDetector([sqli_detector, xss_detector])

        # 执行检测
        results = composite.detect('https://example.com/api?id=1')

        # 验证结果
        assert len(results) == 2

        vuln_types = [r.vuln_type for r in results]
        assert 'sqli' in vuln_types
        assert 'xss' in vuln_types

        # 验证严重程度
        severities = {r.vuln_type: r.severity for r in results}
        assert severities['sqli'] == Severity.HIGH
        assert severities['xss'] == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_async_full_detection_workflow(self):
        """测试异步完整检测工作流"""
        detector1 = MockDetector(should_find_vuln=True)
        detector2 = MockDetector(should_find_vuln=False)
        detector3 = MockDetector(should_find_vuln=True)

        composite = CompositeDetector([detector1, detector2, detector3])
        results = await composite.async_detect('https://example.com')

        assert len(results) == 2
        assert all(r.vulnerable for r in results)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
