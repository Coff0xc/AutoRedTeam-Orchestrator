#!/usr/bin/env python3
"""
test_orchestrator_fixes.py - 验证编排器修复的单元测试

测试内容:
1. [P0] VulnScan 目标规范化
2. [P1] config 优先级
3. [P2] Exfiltrate 配置生效

运行方式:
    pytest tests/test_orchestrator_fixes.py -v
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any


class TestURLNormalization:
    """测试 URL 规范化功能"""

    def test_normalize_url_adds_https_protocol(self):
        """测试: 无协议域名自动添加 https://"""
        from core.orchestrator.phases import BasePhaseExecutor
        from core.orchestrator.state import PentestState

        # 创建一个具体的执行器实例用于测试
        state = MagicMock(spec=PentestState)
        state.target = "example.com"

        # 创建具体子类来测试基类方法
        class TestExecutor(BasePhaseExecutor):
            @property
            def phase(self):
                from core.orchestrator.state import PentestPhase
                return PentestPhase.RECON

            async def execute(self):
                pass

        executor = TestExecutor(state)

        # 验证规范化
        result = executor._normalize_url("example.com")
        assert result == "https://example.com"

    def test_normalize_url_preserves_http_protocol(self):
        """测试: 保留 http:// 协议"""
        from core.orchestrator.phases import BasePhaseExecutor
        from core.orchestrator.state import PentestState

        state = MagicMock(spec=PentestState)
        state.target = "http://example.com"

        class TestExecutor(BasePhaseExecutor):
            @property
            def phase(self):
                from core.orchestrator.state import PentestPhase
                return PentestPhase.RECON

            async def execute(self):
                pass

        executor = TestExecutor(state)

        result = executor._normalize_url("http://example.com")
        assert result == "http://example.com"

    def test_normalize_url_strips_trailing_slash(self):
        """测试: 移除尾部斜杠"""
        from core.orchestrator.phases import BasePhaseExecutor
        from core.orchestrator.state import PentestState

        state = MagicMock(spec=PentestState)
        state.target = "https://example.com/"

        class TestExecutor(BasePhaseExecutor):
            @property
            def phase(self):
                from core.orchestrator.state import PentestPhase
                return PentestPhase.RECON

            async def execute(self):
                pass

        executor = TestExecutor(state)

        result = executor._normalize_url("https://example.com/")
        assert result == "https://example.com"

    def test_get_normalized_target_caches_result(self):
        """测试: get_normalized_target 缓存结果"""
        from core.orchestrator.phases import BasePhaseExecutor
        from core.orchestrator.state import PentestState

        state = MagicMock(spec=PentestState)
        state.target = "example.com"

        class TestExecutor(BasePhaseExecutor):
            @property
            def phase(self):
                from core.orchestrator.state import PentestPhase
                return PentestPhase.RECON

            async def execute(self):
                pass

        executor = TestExecutor(state)

        # 第一次调用
        result1 = executor.get_normalized_target()
        # 第二次调用应返回缓存结果
        result2 = executor.get_normalized_target()

        assert result1 == result2 == "https://example.com"
        assert executor._normalized_target == "https://example.com"


class TestVulnScanTargetNormalization:
    """测试 VulnScan 阶段使用规范化目标"""

    def test_get_scan_targets_uses_normalized_url(self):
        """测试: _get_scan_targets 使用规范化后的 URL"""
        from core.orchestrator.phases import VulnScanPhaseExecutor
        from core.orchestrator.state import PentestState, PentestPhase

        # 创建状态，使用无协议域名
        state = MagicMock(spec=PentestState)
        state.target = "example.com"  # 无协议
        state.recon_data = {'directories': []}
        state.is_phase_completed = lambda p: p == PentestPhase.RECON

        executor = VulnScanPhaseExecutor(state, {})
        targets = executor._get_scan_targets()

        # 第一个目标应该是规范化后的 URL
        assert targets[0] == "https://example.com"
        assert targets[0].startswith("https://")

    def test_get_scan_targets_with_directories(self):
        """测试: _get_scan_targets 正确组合目录路径"""
        from core.orchestrator.phases import VulnScanPhaseExecutor
        from core.orchestrator.state import PentestState, PentestPhase

        state = MagicMock(spec=PentestState)
        state.target = "example.com"
        state.recon_data = {'directories': ['admin', 'api/v1']}
        state.is_phase_completed = lambda p: p == PentestPhase.RECON

        executor = VulnScanPhaseExecutor(state, {})
        targets = executor._get_scan_targets()

        assert "https://example.com" in targets
        assert "https://example.com/admin" in targets
        assert "https://example.com/api/v1" in targets


class TestConfigPriority:
    """测试配置优先级"""

    @pytest.mark.asyncio
    async def test_phase_config_overrides_global_config(self):
        """测试: 阶段配置覆盖全局配置"""
        from core.orchestrator.orchestrator import (
            AutoPentestOrchestrator,
            OrchestratorConfig
        )
        from core.orchestrator.state import PentestPhase

        # 全局配置
        global_config = OrchestratorConfig(
            quick_mode=False,
            timeout=3600
        )

        orchestrator = AutoPentestOrchestrator(
            target="https://example.com",
            config=global_config
        )

        # 模拟阶段执行器
        with patch('core.orchestrator.orchestrator.PHASE_EXECUTORS') as mock_executors:
            mock_executor_class = MagicMock()
            mock_executor_instance = MagicMock()
            mock_executor_instance.can_execute.return_value = True
            mock_executor_instance.execute = AsyncMock(return_value=MagicMock(
                success=True, to_dict=lambda: {'test': True}, errors=[]
            ))
            mock_executor_class.return_value = mock_executor_instance
            mock_executors.get.return_value = mock_executor_class

            # 传入阶段特定配置
            phase_config = {'quick_mode': True, 'custom_option': 'value'}
            await orchestrator.execute_phase(PentestPhase.RECON, config=phase_config)

            # 验证传给执行器的配置
            call_args = mock_executor_class.call_args
            actual_config = call_args[0][1]  # 第二个参数是 config

            # 阶段配置应该覆盖全局配置
            assert actual_config['quick_mode'] is True  # 阶段配置
            assert actual_config['custom_option'] == 'value'  # 阶段配置
            assert actual_config['timeout'] == 3600  # 全局配置


class TestExfiltrateConfig:
    """测试 Exfiltrate 阶段配置"""

    @pytest.mark.asyncio
    async def test_skip_exfiltrate_config_respected(self):
        """测试: skip_exfiltrate=True 时跳过阶段"""
        from core.orchestrator.phases import ExfiltratePhaseExecutor
        from core.orchestrator.state import PentestState, PentestPhase

        state = MagicMock(spec=PentestState)
        state.recon_data = {}
        state.credentials = []
        state.is_phase_completed = lambda p: True

        # skip_exfiltrate=True (默认)
        executor = ExfiltratePhaseExecutor(state, {'skip_exfiltrate': True})
        result = await executor.execute()

        assert result.success is True
        assert result.data.get('skipped') is True
        assert 'skip_exfiltrate' in result.data.get('reason', '')

    @pytest.mark.asyncio
    async def test_exfiltrate_runs_when_not_skipped(self):
        """测试: skip_exfiltrate=False 时执行阶段"""
        from core.orchestrator.phases import ExfiltratePhaseExecutor
        from core.orchestrator.state import PentestState, PentestPhase

        state = MagicMock(spec=PentestState)
        state.recon_data = {'sensitive_files': ['backup.sql']}
        state.credentials = [{'username': 'admin'}]
        state.is_phase_completed = lambda p: True

        # skip_exfiltrate=False
        executor = ExfiltratePhaseExecutor(state, {'skip_exfiltrate': False})
        result = await executor.execute()

        assert result.success is True
        # 不应该跳过
        assert result.data.get('skipped') is not True
        # 应该有外泄评估数据
        assert 'sensitive_files_count' in result.data
        assert result.data['sensitive_files_count'] == 1

    @pytest.mark.asyncio
    async def test_exfiltrate_skips_when_no_data(self):
        """测试: 无敏感数据时跳过"""
        from core.orchestrator.phases import ExfiltratePhaseExecutor
        from core.orchestrator.state import PentestState, PentestPhase

        state = MagicMock(spec=PentestState)
        state.recon_data = {'sensitive_files': []}
        state.credentials = []
        state.is_phase_completed = lambda p: True

        executor = ExfiltratePhaseExecutor(state, {'skip_exfiltrate': False})
        result = await executor.execute()

        assert result.success is True
        assert result.data.get('skipped') is True
        assert '无敏感数据' in result.data.get('reason', '')


class TestLegacyToolsDeprecation:
    """测试遗留工具弃用警告"""

    def test_register_pentest_tools_shows_deprecation_warning(self):
        """测试: register_pentest_tools 显示弃用警告"""
        import warnings
        from tools.pentest_tools import register_pentest_tools_legacy

        mock_mcp = MagicMock()

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            register_pentest_tools_legacy(mock_mcp)

            # 应该有弃用警告
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "弃用" in str(w[0].message)

    def test_backward_compat_alias_exists(self):
        """测试: 向后兼容别名存在"""
        from tools.pentest_tools import (
            register_pentest_tools,
            register_pentest_tools_legacy
        )

        # 别名应该指向同一个函数
        assert register_pentest_tools is register_pentest_tools_legacy


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
