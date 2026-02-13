#!/usr/bin/env python3
"""
自动化渗透编排工具处理器单元测试
测试 handlers/orchestration_handlers.py 中的 11 个工具注册和执行
仅测 handler 层，所有 core 调用均 mock
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any
from core.security.mcp_auth_middleware import AuthMode


# ==================== 辅助函数 ====================


def _make_mcp_and_register():
    """创建 mock MCP 并注册 Orchestration 工具

    通过 patch _wrap_tool_func 为 identity，使注册的工具直接返回 handler 原始 dict。
    同时 mock auth 装饰器为透传，避免 auth 检查阻断测试。
    """
    mock_mcp = MagicMock()
    mock_counter = MagicMock()
    mock_logger = MagicMock()

    registered_tools: Dict[str, Any] = {}

    def capture_tool():
        def decorator(func):
            registered_tools[func.__name__] = func
            return func
        return decorator

    mock_mcp.tool = capture_tool

    # mock auth 装饰器为透传
    def passthrough_decorator(func):
        return func

    with patch('utils.mcp_tooling._wrap_tool_func', side_effect=lambda f: f), \
         patch('core.security.require_critical_auth', side_effect=passthrough_decorator), \
         patch('core.security.require_dangerous_auth', side_effect=passthrough_decorator), \
         patch('core.security.mcp_auth_middleware._auth_config', {"mode": AuthMode.DISABLED, "manager": None, "audit_enabled": False}):
        from handlers.orchestration_handlers import register_orchestration_tools
        register_orchestration_tools(mock_mcp, mock_counter, mock_logger)

    return registered_tools, mock_counter, mock_logger


# ==================== 注册测试 ====================


class TestOrchestrationHandlersRegistration:
    """测试编排工具注册"""

    def test_register_orchestration_tools(self):
        """测试注册函数是否正确注册 11 个工具"""
        registered_tools, mock_counter, mock_logger = _make_mcp_and_register()

        mock_counter.add.assert_called_once_with('orchestration', 11)
        mock_logger.info.assert_called_once()
        assert "11 个" in str(mock_logger.info.call_args)

    def test_all_tools_registered(self):
        """验证所有预期工具均已注册"""
        registered_tools, _, _ = _make_mcp_and_register()

        expected_tools = [
            'auto_pentest', 'pentest_resume', 'pentest_status', 'pentest_phase',
            'exploit_vulnerability', 'exploit_by_cve', 'get_attack_paths',
            'exploit_orchestrate', 'exploit_with_retry', 'verify_and_exploit',
            'analyze_exploit_failure',
        ]
        for tool_name in expected_tools:
            assert tool_name in registered_tools, f"工具 {tool_name} 未注册"


# ==================== auto_pentest 测试 ====================


class TestAutoPentestTool:
    """测试 auto_pentest 全自动渗透测试工具"""

    @pytest.mark.asyncio
    async def test_auto_pentest_success(self):
        """测试正常执行"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            'status': 'completed',
            'findings': [{'vuln': 'sqli', 'severity': 'high'}],
            'duration': 3600,
        }

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.OrchestratorConfig'):
            orch_instance = MagicMock()
            orch_instance.run = AsyncMock(return_value=mock_result)
            MockOrch.return_value = orch_instance

            result = await registered_tools['auto_pentest'](
                target="https://example.com",
                quick_mode=True,
            )

            assert result['success'] is True
            assert result['status'] == 'completed'
            assert 'findings' in result

    @pytest.mark.asyncio
    async def test_auto_pentest_failed_status(self):
        """测试返回非 completed 状态"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            'status': 'failed',
            'error': 'Target unreachable',
        }

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.OrchestratorConfig'):
            orch_instance = MagicMock()
            orch_instance.run = AsyncMock(return_value=mock_result)
            MockOrch.return_value = orch_instance

            result = await registered_tools['auto_pentest'](
                target="https://example.com"
            )

            assert result['success'] is False
            assert result['status'] == 'failed'

    @pytest.mark.asyncio
    async def test_auto_pentest_exception(self):
        """测试执行异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.OrchestratorConfig'):
            MockOrch.side_effect = ImportError("orchestrator module missing")

            result = await registered_tools['auto_pentest'](
                target="https://example.com"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== pentest_resume 测试 ====================


class TestPentestResumeTool:
    """测试 pentest_resume 恢复渗透测试工具"""

    @pytest.mark.asyncio
    async def test_resume_success(self):
        """测试正常恢复"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = {
            'status': 'completed',
            'resumed_from': 'vuln_scan',
            'findings': [],
        }

        with patch('core.orchestrator.resume_pentest', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = mock_result

            result = await registered_tools['pentest_resume'](
                session_id="abc123def456789012345678abcdef01"
            )

            assert result['success'] is True
            assert result['resumed_from'] == 'vuln_scan'

    @pytest.mark.asyncio
    async def test_resume_exception(self):
        """测试恢复异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.orchestrator.resume_pentest', new_callable=AsyncMock) as mock_fn:
            mock_fn.side_effect = FileNotFoundError("Session checkpoint not found")

            result = await registered_tools['pentest_resume'](
                session_id="abc123def456789012345678abcdef01"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== pentest_status 测试 ====================


class TestPentestStatusTool:
    """测试 pentest_status 查询状态工具"""

    @pytest.mark.asyncio
    async def test_status_success(self):
        """测试正常查询状态"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_state = {
            'target': 'https://example.com',
            'current_phase': 'exploit',
            'phase_status': 'in_progress',
        }
        mock_findings = [
            {'vuln': 'sqli', 'severity': 'high'},
            {'vuln': 'xss', 'severity': 'medium'},
            {'vuln': 'rce', 'severity': 'critical'},
        ]
        mock_paths = [
            {'path': 'sqli -> rce', 'score': 0.9},
            {'path': 'xss -> session_hijack', 'score': 0.7},
        ]

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch:
            orch_instance = MagicMock()
            orch_instance.get_state.return_value = mock_state
            orch_instance.get_findings.return_value = mock_findings
            orch_instance.get_attack_paths.return_value = mock_paths
            MockOrch.resume.return_value = orch_instance

            result = await registered_tools['pentest_status'](
                session_id="abc123def456789012345678abcdef01"
            )

            assert result['success'] is True
            assert result['target'] == 'https://example.com'
            assert result['current_phase'] == 'exploit'
            assert result['findings_count'] == 3
            assert result['high_value_findings'] == 2  # 1 critical + 1 high

    @pytest.mark.asyncio
    async def test_status_exception(self):
        """测试查询异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch:
            MockOrch.resume.side_effect = FileNotFoundError("Session not found")

            result = await registered_tools['pentest_status'](
                session_id="abc123def456789012345678abcdef01"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== pentest_phase 测试 ====================


class TestPentestPhaseTool:
    """测试 pentest_phase 单阶段执行工具"""

    @pytest.mark.asyncio
    async def test_phase_success(self):
        """测试正常执行单阶段"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_phase_result = MagicMock()
        mock_phase_result.success = True
        mock_phase_result.data = {'ports': [80, 443, 8080]}
        mock_phase_result.findings = [MagicMock()]
        mock_phase_result.errors = []
        mock_phase_result.duration = 120

        mock_state = MagicMock()
        mock_state.session_id = "new-session-001"

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.OrchestratorConfig'), \
             patch('core.orchestrator.PentestPhase'):
            orch_instance = MagicMock()
            orch_instance.execute_phase = AsyncMock(return_value=mock_phase_result)
            orch_instance.state = mock_state
            MockOrch.return_value = orch_instance

            result = await registered_tools['pentest_phase'](
                target="https://example.com",
                phase="recon"
            )

            assert result['success'] is True
            assert result['phase'] == 'recon'
            assert result['findings_count'] == 1
            assert result['errors'] == []

    @pytest.mark.asyncio
    async def test_phase_with_session(self):
        """测试使用已有会话执行阶段"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_phase_result = MagicMock()
        mock_phase_result.success = True
        mock_phase_result.data = {}
        mock_phase_result.findings = []
        mock_phase_result.errors = []
        mock_phase_result.duration = 60

        mock_state = MagicMock()
        mock_state.session_id = "existing-session"

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.PentestPhase'):
            orch_instance = MagicMock()
            orch_instance.execute_phase = AsyncMock(return_value=mock_phase_result)
            orch_instance.state = mock_state
            MockOrch.resume.return_value = orch_instance

            result = await registered_tools['pentest_phase'](
                target="https://example.com",
                phase="vuln_scan",
                session_id="existing-session"
            )

            assert result['success'] is True
            assert result['session_id'] == 'existing-session'
            MockOrch.resume.assert_called_once_with("existing-session")


# ==================== exploit_vulnerability 测试 ====================


class TestExploitVulnerabilityTool:
    """测试 exploit_vulnerability 漏洞利用工具"""

    @pytest.mark.asyncio
    async def test_exploit_direct_success(self):
        """测试直接利用成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.status = MagicMock(value='success')
        mock_result.exploit_type = MagicMock(value='sqli_dump')
        mock_result.vuln_type = 'sqli'
        mock_result.url = 'https://example.com/login'
        mock_result.evidence = 'Dumped 100 rows'
        mock_result.payload_used = "1' UNION SELECT..."
        mock_result.data = {'rows': 100}
        mock_result.shell = None
        mock_result.files = None
        mock_result.execution_time_ms = 500
        mock_result.error = None

        detection = {
            'vulnerable': True,
            'vuln_type': 'sqli',
            'url': 'https://example.com/login',
            'param': 'id',
            'payload': "1' OR '1'='1",
            'evidence': 'SQL error',
        }

        with patch('core.exploit.ExploitEngine') as MockEngine:
            engine = MagicMock()
            engine.async_exploit = AsyncMock(return_value=mock_result)
            MockEngine.return_value = engine

            result = await registered_tools['exploit_vulnerability'](
                detection_result=detection
            )

            assert result['success'] is True
            assert result['status'] == 'success'
            assert result['vuln_type'] == 'sqli'
            assert result['shell'] is None

    @pytest.mark.asyncio
    async def test_exploit_with_feedback(self):
        """测试带反馈循环的利用"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_exploit_result = MagicMock()
        mock_exploit_result.success = True
        mock_exploit_result.status = MagicMock(value='success')
        mock_exploit_result.exploit_type = MagicMock(value='rce_exec')
        mock_exploit_result.vuln_type = 'rce'
        mock_exploit_result.url = 'https://example.com/cmd'
        mock_exploit_result.evidence = 'whoami output'
        mock_exploit_result.payload_used = '; whoami'
        mock_exploit_result.data = {}
        mock_exploit_result.shell = None
        mock_exploit_result.files = None
        mock_exploit_result.execution_time_ms = 800
        mock_exploit_result.error = None

        mock_feedback_result = MagicMock()
        mock_feedback_result.success = True
        mock_feedback_result.result = mock_exploit_result
        mock_feedback_result.attempts = 2
        mock_feedback_result.adjustments_made = ['encoding_change']
        mock_feedback_result.final_strategy = 'url_encoded'

        detection = {
            'vulnerable': True,
            'vuln_type': 'rce',
            'url': 'https://example.com/cmd',
            'param': 'cmd',
        }

        with patch('core.exploit.ExploitEngine'), \
             patch('core.feedback.FeedbackLoopEngine') as MockFeedback:
            feedback_engine = MagicMock()
            feedback_engine.execute_with_feedback = AsyncMock(
                return_value=mock_feedback_result
            )
            MockFeedback.return_value = feedback_engine

            result = await registered_tools['exploit_vulnerability'](
                detection_result=detection,
                use_feedback=True,
                max_retries=3,
            )

            assert result['success'] is True
            assert result['feedback']['attempts'] == 2

    @pytest.mark.asyncio
    async def test_exploit_exception(self):
        """测试利用异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        detection = {
            'vulnerable': True,
            'vuln_type': 'sqli',
            'url': 'https://example.com',
        }

        with patch('core.exploit.ExploitEngine') as MockEngine:
            MockEngine.side_effect = ImportError("exploit module missing")

            result = await registered_tools['exploit_vulnerability'](
                detection_result=detection
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== exploit_by_cve 测试 ====================


class TestExploitByCveTool:
    """测试 exploit_by_cve CVE 利用工具"""

    @pytest.mark.asyncio
    async def test_exploit_by_cve_success(self):
        """测试 CVE 利用成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.status = MagicMock(value='success')
        mock_result.vuln_type = 'rce'
        mock_result.url = 'https://example.com'
        mock_result.evidence = 'Log4Shell confirmed'
        mock_result.payload_used = '${jndi:ldap://...}'
        mock_result.data = {}
        mock_result.execution_time_ms = 1500
        mock_result.metadata = {'cve': 'CVE-2021-44228'}
        mock_result.error = None

        with patch('core.exploit.ExploitEngine') as MockEngine:
            engine = MagicMock()
            engine.exploit_cve.return_value = mock_result
            MockEngine.return_value = engine

            result = await registered_tools['exploit_by_cve'](
                target="https://example.com",
                cve_id="CVE-2021-44228"
            )

            assert result['success'] is True
            assert result['vuln_type'] == 'rce'

    @pytest.mark.asyncio
    async def test_exploit_by_cve_exception(self):
        """测试 CVE 利用异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.exploit.ExploitEngine') as MockEngine:
            MockEngine.side_effect = RuntimeError("No PoC available")

            result = await registered_tools['exploit_by_cve'](
                target="https://example.com",
                cve_id="CVE-2024-0000"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== get_attack_paths 测试 ====================


class TestGetAttackPathsTool:
    """测试 get_attack_paths 攻击路径推荐工具"""

    @pytest.mark.asyncio
    async def test_attack_paths_new_target(self):
        """测试新目标的攻击路径"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_paths = [
            {'path': 'sqli -> data_dump', 'score': 0.95},
            {'path': 'xss -> session_hijack', 'score': 0.7},
        ]

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.OrchestratorConfig'):
            orch_instance = MagicMock()
            orch_instance.get_attack_paths.return_value = mock_paths
            MockOrch.return_value = orch_instance

            result = await registered_tools['get_attack_paths'](
                target="https://example.com"
            )

            assert result['success'] is True
            assert result['count'] == 2
            assert result['attack_paths'][0]['score'] == 0.95

    @pytest.mark.asyncio
    async def test_attack_paths_empty(self):
        """测试无攻击路径"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.OrchestratorConfig'):
            orch_instance = MagicMock()
            orch_instance.get_attack_paths.return_value = []
            MockOrch.return_value = orch_instance

            result = await registered_tools['get_attack_paths'](
                target="https://example.com"
            )

            assert result['success'] is True
            assert result['count'] == 0

    @pytest.mark.asyncio
    async def test_attack_paths_exception(self):
        """测试获取攻击路径异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.orchestrator.AutoPentestOrchestrator') as MockOrch, \
             patch('core.orchestrator.OrchestratorConfig'):
            MockOrch.side_effect = ImportError("orchestrator not available")

            result = await registered_tools['get_attack_paths'](
                target="https://example.com"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== exploit_orchestrate 测试 ====================


class TestExploitOrchestrateTool:
    """测试 exploit_orchestrate 多漏洞编排利用工具"""

    @pytest.mark.asyncio
    async def test_orchestrate_success(self):
        """测试多漏洞编排成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_single = MagicMock()
        mock_single.vuln_type = 'sqli'
        mock_single.url = 'https://example.com'
        mock_single.success = True
        mock_single.status = MagicMock(value='success')
        mock_single.evidence = 'Exploited'
        mock_single.error = None

        mock_orch_result = MagicMock()
        mock_orch_result.success = True
        mock_orch_result.total_detections = 3
        mock_orch_result.exploited_count = 2
        mock_orch_result.successful_count = 1
        mock_orch_result.results = [mock_single]
        mock_orch_result.execution_time_ms = 5000

        detections = [
            {'vulnerable': True, 'vuln_type': 'sqli', 'url': 'https://example.com', 'severity': 'high'},
            {'vulnerable': True, 'vuln_type': 'xss', 'url': 'https://example.com', 'severity': 'medium'},
        ]

        with patch('core.exploit.ExploitOrchestrator') as MockOrch, \
             patch('core.exploit.OrchestrationStrategy') as MockStrategy:
            MockStrategy.PARALLEL = MagicMock(value='parallel')
            orch = MagicMock()
            orch.orchestrate = AsyncMock(return_value=mock_orch_result)
            MockOrch.return_value = orch

            result = await registered_tools['exploit_orchestrate'](
                detections=detections,
                top_n=2,
                parallel=True,
            )

            assert result['success'] is True
            assert result['total_detections'] == 3
            assert result['successful_count'] == 1

    @pytest.mark.asyncio
    async def test_orchestrate_exception(self):
        """测试编排异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.exploit.ExploitOrchestrator') as MockOrch, \
             patch('core.exploit.OrchestrationStrategy'):
            MockOrch.side_effect = ImportError("exploit module missing")

            result = await registered_tools['exploit_orchestrate'](
                detections=[{'vulnerable': True, 'vuln_type': 'sqli'}]
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== exploit_with_retry 测试 ====================


class TestExploitWithRetryTool:
    """测试 exploit_with_retry 带重试的利用工具"""

    @pytest.mark.asyncio
    async def test_retry_success(self):
        """测试重试后成功"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_inner = MagicMock()
        mock_inner.to_dict.return_value = {'status': 'success'}

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.result = mock_inner
        mock_result.attempts = 2
        mock_result.failure_reasons = ['waf_block']
        mock_result.adjustments_made = ['encoding_change']
        mock_result.final_strategy = 'double_url_encode'
        mock_result.total_time_ms = 3000
        mock_result.error = None

        with patch('core.exploit.exploit_with_retry', new_callable=AsyncMock) as mock_fn:
            mock_fn.return_value = mock_result

            result = await registered_tools['exploit_with_retry'](
                detection_result={'vulnerable': True, 'vuln_type': 'sqli'},
                max_retries=3
            )

            assert result['success'] is True
            assert result['attempts'] == 2

    @pytest.mark.asyncio
    async def test_retry_exception(self):
        """测试重试异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.exploit.exploit_with_retry', new_callable=AsyncMock) as mock_fn:
            mock_fn.side_effect = RuntimeError("All retries exhausted")

            result = await registered_tools['exploit_with_retry'](
                detection_result={'vulnerable': True, 'vuln_type': 'sqli'}
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== verify_and_exploit 测试 ====================


class TestVerifyAndExploitTool:
    """测试 verify_and_exploit 验证并利用工具"""

    @pytest.mark.asyncio
    async def test_verify_and_exploit_success(self):
        """测试验证通过并成功利用"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_exploit_result = MagicMock()
        mock_exploit_result.success = True
        mock_exploit_result.status = MagicMock(value='success')
        mock_exploit_result.vuln_type = 'sqli'
        mock_exploit_result.url = 'https://example.com'
        mock_exploit_result.evidence = 'Exploited'
        mock_exploit_result.payload_used = "1' UNION..."
        mock_exploit_result.data = {}
        mock_exploit_result.shell = None
        mock_exploit_result.files = None
        mock_exploit_result.execution_time_ms = 600
        mock_exploit_result.error = None

        detection = {
            'vulnerable': True,
            'vuln_type': 'sqli',
            'url': 'https://example.com',
            'param': 'id',
        }

        with patch('core.exploit.ExploitEngine') as MockEngine, \
             patch('modules.vuln_verifier.VulnerabilityVerifier') as MockVerifier:
            mock_vr = MagicMock()
            mock_vr.is_vulnerable = True
            mock_vr.verification_method = 'oob'
            mock_vr.confidence = 'high'
            verifier = MagicMock()
            verifier.batch_verify = MagicMock(return_value=[mock_vr])
            MockVerifier.return_value = verifier

            engine = MagicMock()
            engine.async_exploit = AsyncMock(return_value=mock_exploit_result)
            MockEngine.return_value = engine

            result = await registered_tools['verify_and_exploit'](
                detection_result=detection
            )

            assert result['success'] is True
            assert result['verified'] is True
            assert result['verification_confidence'] == 'high'

    @pytest.mark.asyncio
    async def test_verify_failed(self):
        """测试验证失败（可能是误报）"""
        registered_tools, _, _ = _make_mcp_and_register()

        detection = {
            'vulnerable': True,
            'vuln_type': 'sqli',
            'url': 'https://example.com',
        }

        with patch('modules.vuln_verifier.VulnerabilityVerifier') as MockVerifier:
            mock_vr = MagicMock()
            mock_vr.is_vulnerable = False
            mock_vr.verification_method = 'statistical'
            mock_vr.confidence = 'low'
            verifier = MagicMock()
            verifier.batch_verify = MagicMock(return_value=[mock_vr])
            MockVerifier.return_value = verifier

            result = await registered_tools['verify_and_exploit'](
                detection_result=detection
            )

            assert result['success'] is False
            assert result['verified'] is False
            assert '误报' in result['error']


# ==================== analyze_exploit_failure 测试 ====================


class TestAnalyzeExploitFailureTool:
    """测试 analyze_exploit_failure 失败分析工具"""

    @pytest.mark.asyncio
    async def test_analyze_failure_success(self):
        """测试正常分析失败原因"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_reason1 = MagicMock(value='waf_block')
        mock_reason2 = MagicMock(value='payload_filtered')

        mock_analysis = MagicMock()
        mock_analysis.primary_reason = mock_reason1
        mock_analysis.failure_reasons = [mock_reason1, mock_reason2]
        mock_analysis.confidence = 0.85
        mock_analysis.waf_detected = True
        mock_analysis.waf_type = 'cloudflare'
        mock_analysis.rate_limited = False
        mock_analysis.payload_filtered = True
        mock_analysis.is_false_positive = False
        mock_analysis.error_details = 'WAF returned 403'
        mock_analysis.suggestions = ['Try URL encoding', 'Use chunked transfer']

        mock_strategy = MagicMock()
        mock_strategy.name = 'double_url_encode'
        mock_strategy.description = 'Apply double URL encoding'
        mock_strategy.parameters = {'encoding': 'double_url'}

        with patch('core.feedback.FailureAnalyzer') as MockAnalyzer, \
             patch('core.feedback.StrategyRegistry') as MockRegistry:
            analyzer = MagicMock()
            analyzer.analyze.return_value = mock_analysis
            MockAnalyzer.return_value = analyzer

            registry = MagicMock()
            registry.get_strategies.return_value = [mock_strategy]
            MockRegistry.return_value = registry

            failed_result = {
                'success': False,
                'error': 'WAF blocked request',
                'status': 'failed',
            }

            result = await registered_tools['analyze_exploit_failure'](
                failed_result=failed_result,
                context={'waf': 'cloudflare'}
            )

            assert result['success'] is True
            assert result['analysis']['primary_reason'] == 'waf_block'
            assert result['analysis']['waf_detected'] is True
            assert len(result['recommended_strategies']) > 0
            assert result['suggestions'] == ['Try URL encoding', 'Use chunked transfer']

    @pytest.mark.asyncio
    async def test_analyze_failure_exception(self):
        """测试分析异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.feedback.FailureAnalyzer') as MockAnalyzer:
            MockAnalyzer.side_effect = ImportError("feedback module missing")

            result = await registered_tools['analyze_exploit_failure'](
                failed_result={'success': False}
            )

            assert result['success'] is False
            assert 'error' in result
