"""
LLM Provider 单元测试

测试内容:
- graceful degradation (provider=none 时零影响)
- 环境变量配置
- complete() / complete_json() 的 mock 调用
- reset_llm() 单例重置
- DecisionEngine LLM 增强集成
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest


# ==================== 基础功能 ====================


class TestLLMProviderDisabled:
    """provider=none (默认) — 验证零影响"""

    def setup_method(self):
        from core.llm.provider import reset_llm

        reset_llm()

    def teardown_method(self):
        from core.llm.provider import reset_llm

        reset_llm()

    def test_default_provider_is_none(self):
        """默认 provider=none, available=False"""
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("AUTORT_LLM_")
        }
        with patch.dict(os.environ, env, clear=True):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            assert llm.provider == "none"
            assert llm.available is False

    def test_complete_returns_none_when_disabled(self):
        """LLM 不可用时 complete() 返回 None"""
        with patch.dict(os.environ, {"AUTORT_LLM_PROVIDER": "none"}, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            result = llm.complete("test prompt")
            assert result is None

    def test_complete_json_returns_none_when_disabled(self):
        """LLM 不可用时 complete_json() 返回 None"""
        with patch.dict(os.environ, {"AUTORT_LLM_PROVIDER": "none"}, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            result = llm.complete_json("test prompt")
            assert result is None


# ==================== 环境变量配置 ====================


class TestLLMProviderConfig:
    """验证环境变量配置读取"""

    def test_openai_defaults(self):
        env = {
            "AUTORT_LLM_PROVIDER": "openai",
            "AUTORT_LLM_API_KEY": "sk-test",
        }
        with patch.dict(os.environ, env, clear=False):
            # litellm 和 openai 都不可用时仍能初始化
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            assert llm.provider == "openai"
            assert llm.model == "gpt-4o-mini"
            assert llm.api_key == "sk-test"

    def test_anthropic_defaults(self):
        env = {
            "AUTORT_LLM_PROVIDER": "anthropic",
            "AUTORT_LLM_API_KEY": "sk-ant-test",
        }
        with patch.dict(os.environ, env, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            assert llm.provider == "anthropic"
            assert llm.model == "claude-sonnet-4-20250514"

    def test_custom_model(self):
        env = {
            "AUTORT_LLM_PROVIDER": "openai",
            "AUTORT_LLM_MODEL": "gpt-4-turbo",
            "AUTORT_LLM_API_KEY": "sk-test",
        }
        with patch.dict(os.environ, env, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            assert llm.model == "gpt-4-turbo"

    def test_ollama_with_base_url(self):
        env = {
            "AUTORT_LLM_PROVIDER": "ollama",
            "AUTORT_LLM_BASE_URL": "http://localhost:11434",
        }
        with patch.dict(os.environ, env, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            assert llm.provider == "ollama"
            assert llm.model == "llama3.1"
            assert llm.base_url == "http://localhost:11434"


# ==================== Mock LLM 调用 ====================


class TestLLMProviderCalls:
    """Mock LLM 调用测试"""

    def test_complete_via_litellm(self):
        """通过 litellm 调用"""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "test response"

        env = {
            "AUTORT_LLM_PROVIDER": "openai",
            "AUTORT_LLM_API_KEY": "sk-test",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("core.llm.provider.LITELLM_AVAILABLE", True):
                with patch("core.llm.provider.litellm", create=True) as mock_litellm:
                    mock_litellm.completion.return_value = mock_response
                    from core.llm.provider import LLMProvider

                    llm = LLMProvider()
                    llm._available = True  # 强制可用

                    result = llm.complete("test prompt", system="system msg")
                    assert result == "test response"
                    mock_litellm.completion.assert_called_once()
                    call_kwargs = mock_litellm.completion.call_args
                    messages = call_kwargs.kwargs.get("messages", [])
                    assert len(messages) == 2
                    assert messages[0]["role"] == "system"

    def test_complete_json_parses_response(self):
        """complete_json() 正确解析 JSON"""
        json_str = json.dumps({"is_true_positive": True, "confidence": 0.9})

        env = {"AUTORT_LLM_PROVIDER": "openai", "AUTORT_LLM_API_KEY": "sk-test"}
        with patch.dict(os.environ, env, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            llm._available = True

            with patch.object(llm, "complete", return_value=json_str):
                result = llm.complete_json("test")
                assert result is not None
                assert result["is_true_positive"] is True
                assert result["confidence"] == 0.9

    def test_complete_json_handles_code_block(self):
        """complete_json() 处理 ```json 包裹"""
        json_str = '```json\n{"status": "ok"}\n```'

        env = {"AUTORT_LLM_PROVIDER": "openai", "AUTORT_LLM_API_KEY": "sk-test"}
        with patch.dict(os.environ, env, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            llm._available = True

            with patch.object(llm, "complete", return_value=json_str):
                result = llm.complete_json("test")
                assert result == {"status": "ok"}

    def test_complete_json_returns_none_on_invalid_json(self):
        """complete_json() 解析失败时返回 None"""
        env = {"AUTORT_LLM_PROVIDER": "openai", "AUTORT_LLM_API_KEY": "sk-test"}
        with patch.dict(os.environ, env, clear=False):
            from core.llm.provider import LLMProvider

            llm = LLMProvider()
            llm._available = True

            with patch.object(llm, "complete", return_value="not json at all"):
                result = llm.complete_json("test")
                assert result is None

    def test_complete_catches_exceptions(self):
        """complete() 异常时返回 None 而非抛出"""
        env = {"AUTORT_LLM_PROVIDER": "openai", "AUTORT_LLM_API_KEY": "sk-test"}
        with patch.dict(os.environ, env, clear=False):
            with patch("core.llm.provider.LITELLM_AVAILABLE", True):
                with patch("core.llm.provider.litellm", create=True) as mock_litellm:
                    mock_litellm.completion.side_effect = RuntimeError("API error")
                    from core.llm.provider import LLMProvider

                    llm = LLMProvider()
                    llm._available = True

                    result = llm.complete("test")
                    assert result is None


# ==================== 全局单例 ====================


class TestGlobalSingleton:
    """测试全局单例管理"""

    def setup_method(self):
        from core.llm.provider import reset_llm

        reset_llm()

    def teardown_method(self):
        from core.llm.provider import reset_llm

        reset_llm()

    def test_get_llm_returns_same_instance(self):
        from core.llm.provider import get_llm

        a = get_llm()
        b = get_llm()
        assert a is b

    def test_reset_llm_clears_singleton(self):
        from core.llm.provider import get_llm, reset_llm

        a = get_llm()
        reset_llm()
        b = get_llm()
        assert a is not b


# ==================== DecisionEngine 集成 ====================


class TestDecisionEngineLLMIntegration:
    """验证 DecisionEngine.analyze_result() 的 LLM 增强"""

    def _make_engine(self):
        """创建 DecisionEngine 测试实例"""
        from core.orchestrator.state import PentestState

        state = PentestState(target="http://test.example.com")
        from core.orchestrator.decision import DecisionEngine

        return DecisionEngine(state)

    def test_analyze_result_without_llm(self):
        """LLM 不可用时, analyze_result() 行为不变"""
        from core.orchestrator.state import PentestPhase

        engine = self._make_engine()
        result = {"success": True, "findings": []}

        with patch("core.llm.provider._provider", None):
            with patch.dict(os.environ, {"AUTORT_LLM_PROVIDER": "none"}, clear=False):
                from core.llm.provider import reset_llm

                reset_llm()
                analysis = engine.analyze_result(PentestPhase.RECON, result)
                assert analysis["phase"] == "recon"
                assert analysis["success"] is True
                # LLM 不可用时 llm_enhanced=False 或不存在
                assert analysis.get("llm_enhanced") is False or "llm_enhanced" not in analysis

    def test_analyze_result_with_llm_enhancement(self):
        """LLM 可用时, analyze_result() 包含增强数据"""
        from core.orchestrator.state import PentestPhase

        engine = self._make_engine()
        result = {
            "success": True,
            "findings": [{"type": "sqli", "severity": "high"}],
        }

        mock_llm = MagicMock()
        mock_llm.available = True
        mock_llm.complete_json.return_value = {
            "recommended_action": "使用 sqlmap 验证注入点",
            "priority": "high",
            "reasoning": "SQL注入已确认",
            "tools_to_use": ["sqlmap"],
            "evasion_tips": ["使用 tamper 脚本绕过 WAF"],
        }

        with patch("core.llm.get_llm", return_value=mock_llm):
            analysis = engine.analyze_result(PentestPhase.VULN_SCAN, result)
            assert analysis.get("llm_enhanced") is True
            assert "使用 sqlmap 验证注入点" in analysis["recommendations"]
            assert "llm_assessment" in analysis


# ==================== Config ====================


class TestLLMConfig:
    """验证 LLMConfig 集成到 AutoRTConfig"""

    def test_llm_config_in_autort_config(self):
        from core.config.models import AutoRTConfig

        cfg = AutoRTConfig()
        assert hasattr(cfg, "llm")
        assert cfg.llm.provider == "none"
        assert cfg.llm.temperature == 0.3
        assert cfg.llm.max_tokens == 2000
