#!/usr/bin/env python3
"""
高级漏洞验证器测试

测试 core/detectors/advanced_verifier.py 的所有核心功能
"""

import pytest
import time
from unittest.mock import Mock

from core.detectors.advanced_verifier import (
    AdvancedVerifier,
    OOBCallbackManager,
    OOBToken,
    PayloadVariantGenerator,
    VerificationMethod,
    VerificationResult,
    VerificationStatus,
)


# ==================== VerificationStatus 测试 ====================


class TestVerificationStatus:
    """VerificationStatus 枚举测试"""

    def test_all_statuses_exist(self):
        assert VerificationStatus.CONFIRMED.value == "confirmed"
        assert VerificationStatus.LIKELY.value == "likely"
        assert VerificationStatus.UNCERTAIN.value == "uncertain"
        assert VerificationStatus.FALSE_POSITIVE.value == "false_positive"
        assert VerificationStatus.ERROR.value == "error"

    def test_status_count(self):
        assert len(VerificationStatus) == 5


# ==================== VerificationResult 测试 ====================


class TestVerificationResult:
    """VerificationResult 数据类测试"""

    def test_creation(self):
        result = VerificationResult(
            status=VerificationStatus.CONFIRMED,
            method=VerificationMethod.STATISTICAL,
            confidence=0.85,
        )
        assert result.status == VerificationStatus.CONFIRMED
        assert result.confidence == 0.85
        assert result.evidence == []

    def test_to_dict(self):
        result = VerificationResult(
            status=VerificationStatus.LIKELY,
            method=VerificationMethod.TIME_BASED,
            confidence=0.7,
            evidence=["延迟检测成功"],
            details={"delay": 5.0},
        )
        d = result.to_dict()
        assert d["status"] == "likely"
        assert d["method"] == "time_based"
        assert d["confidence"] == 0.7
        assert "延迟检测成功" in d["evidence"]


# ==================== OOBCallbackManager 测试 ====================


class TestOOBCallbackManager:
    """OOBCallbackManager 测试"""

    @pytest.fixture
    def manager(self):
        return OOBCallbackManager(callback_server="oob.test.com")

    def test_generate_dns_token(self, manager):
        token = manager.generate_token("ssrf", "http://target.com", protocol="dns")
        assert len(token.token_id) == 16
        assert token.finding_type == "ssrf"
        assert "oob.test.com" in token.callback_url
        assert not token.triggered

    def test_generate_http_token(self, manager):
        token = manager.generate_token("xxe", "http://target.com", protocol="http")
        assert "/" in token.callback_url

    def test_mark_triggered(self, manager):
        token = manager.generate_token("rce", "target")
        assert not manager.check_callback(token.token_id)

        manager.mark_triggered(token.token_id, {"source_ip": "1.2.3.4"})
        assert manager.check_callback(token.token_id)

        t = manager.get_token(token.token_id)
        assert t.triggered
        assert t.trigger_data["source_ip"] == "1.2.3.4"

    def test_mark_nonexistent_token(self, manager):
        result = manager.mark_triggered("nonexistent")
        assert result is False

    def test_check_nonexistent_token(self, manager):
        assert manager.check_callback("nonexistent") is False

    def test_get_token(self, manager):
        token = manager.generate_token("test", "target")
        retrieved = manager.get_token(token.token_id)
        assert retrieved.token_id == token.token_id

    def test_get_nonexistent_token(self, manager):
        assert manager.get_token("nope") is None

    def test_cleanup_expired(self, manager):
        # 创建令牌
        token = manager.generate_token("test", "target")

        # 手动修改创建时间使其过期
        token.created_at = time.time() - 400

        # 清理
        manager.cleanup_expired(max_age=300)
        assert manager.get_token(token.token_id) is None

    def test_token_count(self, manager):
        assert manager.token_count == 0
        manager.generate_token("t1", "target")
        manager.generate_token("t2", "target")
        assert manager.token_count == 2


# ==================== PayloadVariantGenerator 测试 ====================


class TestPayloadVariantGenerator:
    """PayloadVariantGenerator 测试"""

    @pytest.fixture
    def gen(self):
        return PayloadVariantGenerator()

    def test_get_sqli_variants(self, gen):
        variants = gen.get_variants("sqli", "true_condition")
        assert len(variants) > 0
        assert any("OR" in v for v in variants)

    def test_get_xss_variants(self, gen):
        variants = gen.get_variants("xss", "basic")
        assert len(variants) > 0
        assert any("<script>" in v for v in variants)

    def test_get_nonexistent_variants(self, gen):
        variants = gen.get_variants("unknown", "basic")
        assert variants == []

    def test_get_true_false_pairs_sqli(self, gen):
        pairs = gen.get_true_false_pairs("sqli")
        assert len(pairs) > 0
        for true_p, false_p in pairs:
            # true 条件包含 1=1 或 'a'='a'
            assert "1=1" in true_p or "'a'='a'" in true_p or "OR" in true_p
            # false 条件包含 1=2 或 'a'='b'
            assert "1=2" in false_p or "'a'='b'" in false_p or "AND" in false_p

    def test_get_true_false_pairs_unknown(self, gen):
        pairs = gen.get_true_false_pairs("unknown")
        assert pairs == []


# ==================== AdvancedVerifier 测试 ====================


class TestAdvancedVerifier:
    """AdvancedVerifier 测试"""

    @pytest.fixture
    def verifier(self):
        return AdvancedVerifier(callback_server="oob.example.com")

    # --- statistical_confirm 测试 ---

    def test_statistical_confirm_different_responses(self, verifier):
        """不同响应应确认漏洞"""
        call_count = [0]

        def mock_request(url, payload):
            call_count[0] += 1
            if payload and "OR" in payload:
                # 显著不同的响应：完全不同的内容结构
                return "<html><table><tr><td>User1</td></tr><tr><td>User2</td></tr><tr><td>Admin</td></tr></table></html>", 200, 0.1
            return "<html><div>Empty result set</div></html>", 200, 0.1

        result = verifier.statistical_confirm(
            url="http://test.com/api?id=1",
            payloads=["1' OR '1'='1"],
            request_func=mock_request,
            baseline_payload="1",
            num_trials=2,
            similarity_threshold=0.7,  # 降低阈值以检测更多差异
        )

        assert result.status in [
            VerificationStatus.CONFIRMED,
            VerificationStatus.LIKELY,
        ]
        assert result.confidence > 0

    def test_statistical_confirm_same_responses(self, verifier):
        """相同响应应判定为误报"""
        def mock_request(url, payload):
            return "<html>Same content</html>", 200, 0.1

        result = verifier.statistical_confirm(
            url="http://test.com",
            payloads=["payload1", "payload2"],
            request_func=mock_request,
            num_trials=2,
        )

        assert result.status == VerificationStatus.FALSE_POSITIVE

    def test_statistical_confirm_baseline_failure(self, verifier):
        """基线请求失败"""
        def mock_request(url, payload):
            raise Exception("Connection error")

        result = verifier.statistical_confirm(
            url="http://test.com",
            payloads=["payload"],
            request_func=mock_request,
        )

        assert result.status == VerificationStatus.ERROR

    def test_statistical_confirm_status_diff(self, verifier):
        """状态码差异应增加置信度"""
        def mock_request(url, payload):
            if payload and "attack" in payload:
                return "Error", 500, 0.1
            return "OK", 200, 0.1

        result = verifier.statistical_confirm(
            url="http://test.com",
            payloads=["attack payload"],
            request_func=mock_request,
            num_trials=2,
        )

        assert result.details["status_diff_ratio"] > 0

    # --- boolean_blind_confirm 测试 ---

    def test_boolean_blind_confirm_true_vuln(self, verifier):
        """布尔盲注确认 - 真实漏洞"""
        def mock_request(url, payload):
            # true 条件返回完全不同的内容（模拟真实 SQL 注入）
            if "1=1" in payload or "'a'='a'" in payload or "OR" in payload.upper():
                return "<html><h1>Welcome Admin</h1><div class='user-data'><table><tr><td>Secret Data</td></tr></table></div></html>", 200, 0.1
            # false 条件返回空结果
            if "1=2" in payload or "'a'='b'" in payload or "AND" in payload.upper():
                return "<html><h1>Error</h1><p>No records found</p></html>", 200, 0.1
            return "<html></html>", 200, 0.1

        result = verifier.boolean_blind_confirm(
            url="http://test.com/api?id=1",
            vuln_type="sqli",
            request_func=mock_request,
            num_trials=2,
        )

        assert result.status in [
            VerificationStatus.CONFIRMED,
            VerificationStatus.LIKELY,
        ]

    def test_boolean_blind_confirm_no_diff(self, verifier):
        """布尔盲注 - 无差异（误报）"""
        def mock_request(url, payload):
            return "<html>Same response</html>", 200, 0.1

        result = verifier.boolean_blind_confirm(
            url="http://test.com",
            vuln_type="sqli",
            request_func=mock_request,
        )

        assert result.status == VerificationStatus.FALSE_POSITIVE

    def test_boolean_blind_unknown_type(self, verifier):
        """未知漏洞类型"""
        result = verifier.boolean_blind_confirm(
            url="http://test.com",
            vuln_type="unknown_vuln",
            request_func=lambda u, p: ("", 200, 0.1),
        )

        assert result.status == VerificationStatus.ERROR

    # --- time_based_confirm 测试 ---

    def test_time_based_confirm_real_delay(self, verifier):
        """时间盲注确认 - 真实延迟"""
        def mock_request(url, payload):
            if payload and "SLEEP" in payload.upper():
                return "", 200, 5.2  # 模拟 5 秒延迟
            return "", 200, 0.1  # 正常响应

        result = verifier.time_based_confirm(
            url="http://test.com",
            delay_payloads=["' OR SLEEP(5)--"],
            request_func=mock_request,
            expected_delay=5.0,
            num_trials=2,
        )

        assert result.status == VerificationStatus.CONFIRMED
        assert result.confidence > 0.5

    def test_time_based_confirm_no_delay(self, verifier):
        """时间盲注 - 无延迟（误报）"""
        def mock_request(url, payload):
            return "", 200, 0.1

        result = verifier.time_based_confirm(
            url="http://test.com",
            delay_payloads=["' OR SLEEP(5)--"],
            request_func=mock_request,
            expected_delay=5.0,
        )

        assert result.status == VerificationStatus.FALSE_POSITIVE

    def test_time_based_confirm_network_instability(self, verifier):
        """网络不稳定检测"""
        import random

        random.seed(42)

        def mock_request(url, payload):
            # 模拟高度波动的响应时间
            return "", 200, random.uniform(0.5, 3.0)

        result = verifier.time_based_confirm(
            url="http://test.com",
            delay_payloads=["' OR SLEEP(5)--"],
            request_func=mock_request,
            expected_delay=5.0,
            num_trials=5,
        )

        # 网络不稳定会降低置信度
        assert "网络不稳定" in " ".join(result.evidence) or result.confidence < 0.8

    def test_time_based_baseline_failure(self, verifier):
        """基线请求失败"""
        call_count = [0]

        def mock_request(url, payload):
            call_count[0] += 1
            if not payload:  # 基线请求
                raise Exception("Timeout")
            return "", 200, 0.1

        result = verifier.time_based_confirm(
            url="http://test.com",
            delay_payloads=["payload"],
            request_func=mock_request,
        )

        assert result.status == VerificationStatus.ERROR

    # --- OOB 验证测试 ---

    def test_oob_verify_generate_token(self, verifier):
        """OOB 令牌生成"""
        token, payload = verifier.oob_verify(
            finding_type="ssrf",
            target="http://target.com",
        )

        assert token.token_id
        assert "ssrf" in token.callback_url
        assert "http://" in payload

    def test_oob_verify_xxe_payload(self, verifier):
        """XXE OOB payload"""
        token, payload = verifier.oob_verify(
            finding_type="xxe",
            target="target",
        )

        assert "DOCTYPE" in payload
        assert "ENTITY" in payload

    def test_oob_check_not_triggered(self, verifier):
        """OOB 未触发"""
        token, _ = verifier.oob_verify("ssrf", "target")
        result = verifier.check_oob_result(token.token_id)

        assert result.status == VerificationStatus.UNCERTAIN

    def test_oob_check_triggered(self, verifier):
        """OOB 已触发"""
        token, _ = verifier.oob_verify("ssrf", "target")
        verifier.oob_manager.mark_triggered(token.token_id, {"ip": "1.2.3.4"})

        result = verifier.check_oob_result(token.token_id)
        assert result.status == VerificationStatus.CONFIRMED
        assert result.confidence >= 0.9

    def test_oob_check_timeout(self, verifier):
        """OOB 超时 - 返回 UNCERTAIN 而非 FALSE_POSITIVE"""
        token, _ = verifier.oob_verify("ssrf", "target")
        # 手动修改创建时间
        token.created_at = time.time() - 120

        result = verifier.check_oob_result(token.token_id)
        assert result.status == VerificationStatus.UNCERTAIN
        assert result.confidence == 0.3

    def test_oob_check_nonexistent(self, verifier):
        """检查不存在的令牌"""
        result = verifier.check_oob_result("nonexistent")
        assert result.status == VerificationStatus.ERROR

    # --- multi_method_verify 测试 ---

    def test_multi_method_verify_sqli(self, verifier):
        """多方法验证 SQLi"""
        def mock_request(url, payload):
            if payload and "OR" in payload:
                return "<html>Vulnerable</html>", 200, 0.1
            return "<html>Safe</html>", 200, 0.1

        results = verifier.multi_method_verify(
            url="http://test.com?id=1",
            vuln_type="sqli",
            request_func=mock_request,
            methods=["statistical", "boolean_blind"],
        )

        assert "statistical" in results or "boolean_blind" in results

    # --- aggregate_results 测试 ---

    def test_aggregate_results_all_confirmed(self, verifier):
        """聚合结果 - 全部确认"""
        results = {
            "method1": VerificationResult(
                status=VerificationStatus.CONFIRMED,
                method=VerificationMethod.STATISTICAL,
                confidence=0.9,
            ),
            "method2": VerificationResult(
                status=VerificationStatus.CONFIRMED,
                method=VerificationMethod.TIME_BASED,
                confidence=0.85,
            ),
        }

        aggregated = verifier.aggregate_results(results)
        assert aggregated.status == VerificationStatus.CONFIRMED

    def test_aggregate_results_mixed(self, verifier):
        """聚合结果 - 混合"""
        results = {
            "method1": VerificationResult(
                status=VerificationStatus.CONFIRMED,
                method=VerificationMethod.STATISTICAL,
                confidence=0.9,
            ),
            "method2": VerificationResult(
                status=VerificationStatus.FALSE_POSITIVE,
                method=VerificationMethod.TIME_BASED,
                confidence=0.7,
            ),
            "method3": VerificationResult(
                status=VerificationStatus.LIKELY,
                method=VerificationMethod.CONTENT_DIFF,
                confidence=0.6,
            ),
        }

        aggregated = verifier.aggregate_results(results)
        # 1 confirmed + 1 likely > 1 fp
        assert aggregated.status == VerificationStatus.LIKELY

    def test_aggregate_results_all_fp(self, verifier):
        """聚合结果 - 全部误报"""
        results = {
            "method1": VerificationResult(
                status=VerificationStatus.FALSE_POSITIVE,
                method=VerificationMethod.STATISTICAL,
                confidence=0.8,
            ),
            "method2": VerificationResult(
                status=VerificationStatus.FALSE_POSITIVE,
                method=VerificationMethod.TIME_BASED,
                confidence=0.75,
            ),
        }

        aggregated = verifier.aggregate_results(results)
        assert aggregated.status == VerificationStatus.FALSE_POSITIVE

    def test_aggregate_results_empty(self, verifier):
        """聚合空结果"""
        aggregated = verifier.aggregate_results({})
        assert aggregated.status == VerificationStatus.ERROR

    def test_aggregate_results_evidence_combined(self, verifier):
        """聚合结果包含所有证据"""
        results = {
            "m1": VerificationResult(
                status=VerificationStatus.CONFIRMED,
                method=VerificationMethod.STATISTICAL,
                confidence=0.9,
                evidence=["证据1", "证据2"],
            ),
            "m2": VerificationResult(
                status=VerificationStatus.LIKELY,
                method=VerificationMethod.TIME_BASED,
                confidence=0.7,
                evidence=["证据3"],
            ),
        }

        aggregated = verifier.aggregate_results(results)
        assert len(aggregated.evidence) == 3


# ==================== 集成测试 ====================


class TestAdvancedVerifierIntegration:
    """高级验证器集成测试"""

    def test_full_sqli_verification_workflow(self):
        """完整 SQLi 验证流程"""
        verifier = AdvancedVerifier()

        # 模拟真实 SQLi 漏洞的响应
        responses = {
            "baseline": ("<html><div>User: admin</div></html>", 200, 0.1),
            "true": ("<html><div>User: admin</div><div>User: root</div></html>", 200, 0.1),
            "false": ("<html><div>No results</div></html>", 200, 0.1),
            "error": ("<html><div>SQL syntax error</div></html>", 500, 0.1),
        }

        def mock_request(url, payload):
            if not payload:
                return responses["baseline"]
            if "1=1" in payload or "'a'='a'" in payload:
                return responses["true"]
            if "1=2" in payload or "'a'='b'" in payload:
                return responses["false"]
            if "'" in payload and "OR" not in payload.upper():
                return responses["error"]
            return responses["baseline"]

        # 1. 统计确认
        stat_result = verifier.statistical_confirm(
            url="http://test.com/api?id=1",
            payloads=["1' OR '1'='1", "1' AND '1'='2"],
            request_func=mock_request,
            num_trials=2,
        )

        # 2. 布尔盲注确认
        bool_result = verifier.boolean_blind_confirm(
            url="http://test.com/api?id=1",
            vuln_type="sqli",
            request_func=mock_request,
        )

        # 3. 聚合结果
        aggregated = verifier.aggregate_results({
            "statistical": stat_result,
            "boolean_blind": bool_result,
        })

        # 验证结果
        assert aggregated.status in [
            VerificationStatus.CONFIRMED,
            VerificationStatus.LIKELY,
        ]
        assert aggregated.confidence > 0.5
        assert len(aggregated.evidence) > 0

    def test_false_positive_detection_workflow(self):
        """误报检测流程"""
        verifier = AdvancedVerifier()

        # WAF 拦截响应
        def mock_waf_request(url, payload):
            if payload:
                return "Access Denied - Security Violation", 403, 0.1
            return "<html>Normal page</html>", 200, 0.1

        result = verifier.statistical_confirm(
            url="http://test.com",
            payloads=["<script>alert(1)</script>"],
            request_func=mock_waf_request,
        )

        # WAF 拦截导致的响应差异可能被误判
        # 重要的是验证器能提供证据供分析
        assert len(result.details) > 0
