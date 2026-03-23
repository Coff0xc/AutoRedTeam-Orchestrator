"""
MCP 授权中间件专项测试

覆盖: AuthMode (STRICT/PERMISSIVE/DISABLED)、API Key 校验、
      权限检查、审计日志、_sanitize_params、环境变量初始化
"""

import asyncio
import os
from unittest.mock import MagicMock, patch

import pytest

from core.security.mcp_auth_middleware import (
    AuthMode,
    _auth_config,
    _sanitize_params,
    get_api_key_from_env,
    get_auth_manager,
    require_auth,
    require_critical_auth,
    require_dangerous_auth,
    require_moderate_auth,
    require_safe_auth,
    set_auth_mode,
    set_audit_enabled,
)


# ==================== Fixtures ====================


@pytest.fixture(autouse=True)
def reset_auth_config():
    """每个测试前后重置 auth 配置"""
    original = _auth_config.copy()
    yield
    _auth_config.update(original)


@pytest.fixture
def mock_auth_manager():
    """模拟 AuthManager"""
    mgr = MagicMock()
    mgr.verify_key.return_value = MagicMock(key_id="test-key-001")
    mgr.check_permission.return_value = True
    mgr.audit = MagicMock()
    return mgr


@pytest.fixture
def mock_api_key():
    """模拟有效 API Key"""
    return MagicMock(key_id="test-key-001")


# ==================== AuthMode 切换 ====================


class TestAuthMode:
    """授权模式切换测试"""

    def test_set_auth_mode_strict(self):
        set_auth_mode(AuthMode.STRICT)
        assert _auth_config["mode"] == AuthMode.STRICT

    def test_set_auth_mode_permissive(self):
        set_auth_mode(AuthMode.PERMISSIVE)
        assert _auth_config["mode"] == AuthMode.PERMISSIVE

    def test_set_auth_mode_disabled(self):
        set_auth_mode(AuthMode.DISABLED)
        assert _auth_config["mode"] == AuthMode.DISABLED

    def test_set_audit_enabled(self):
        set_audit_enabled(False)
        assert _auth_config["audit_enabled"] is False
        set_audit_enabled(True)
        assert _auth_config["audit_enabled"] is True


# ==================== get_api_key_from_env ====================


class TestGetApiKey:
    """环境变量 API Key 获取"""

    def test_autoredteam_api_key(self):
        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "key-123"}, clear=False):
            assert get_api_key_from_env() == "key-123"

    def test_mcp_api_key_fallback(self):
        env = {"MCP_API_KEY": "mcp-456"}
        with patch.dict(os.environ, env, clear=False):
            # 移除 AUTOREDTEAM_API_KEY（如果存在）
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AUTOREDTEAM_API_KEY", None)
                assert get_api_key_from_env() == "mcp-456"

    def test_no_api_key(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_API_KEY", None)
            os.environ.pop("MCP_API_KEY", None)
            assert get_api_key_from_env() is None


# ==================== DISABLED 模式 ====================


class TestDisabledMode:
    """AuthMode.DISABLED — 跳过所有检查"""

    async def test_disabled_mode_bypasses_auth(self):
        _auth_config["mode"] = AuthMode.DISABLED

        @require_auth()
        async def my_tool():
            return {"success": True, "data": "ok"}

        result = await my_tool()
        assert result["success"] is True
        assert result["data"] == "ok"

    async def test_disabled_mode_no_key_needed(self):
        _auth_config["mode"] = AuthMode.DISABLED

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_API_KEY", None)
            os.environ.pop("MCP_API_KEY", None)

            @require_auth()
            async def protected_tool():
                return {"success": True}

            result = await protected_tool()
            assert result["success"] is True


# ==================== STRICT 模式 ====================


class TestStrictMode:
    """AuthMode.STRICT — 无 Key 必须拒绝"""

    async def test_strict_no_key_rejects(self):
        _auth_config["mode"] = AuthMode.STRICT

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_API_KEY", None)
            os.environ.pop("MCP_API_KEY", None)

            @require_auth()
            async def secure_tool():
                return {"success": True}

            result = await secure_tool()
            assert result["success"] is False
            assert result["code"] == "AUTH_REQUIRED"

    async def test_strict_invalid_key_rejects(self, mock_auth_manager):
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        mock_auth_manager.verify_key.return_value = None

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "bad-key"}, clear=False):

            @require_auth()
            async def secure_tool():
                return {"success": True}

            result = await secure_tool()
            assert result["success"] is False
            assert result["code"] == "INVALID_KEY"

    async def test_strict_valid_key_allows(self, mock_auth_manager):
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid-key"}, clear=False):

            @require_auth()
            async def secure_tool():
                return {"success": True, "data": "secret"}

            result = await secure_tool()
            assert result["success"] is True
            assert result["data"] == "secret"

    async def test_strict_auth_manager_unavailable(self):
        """STRICT 模式下 AuthManager 不可用应拒绝"""
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = None

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "some-key"}, clear=False):
            with patch(
                "core.security.mcp_auth_middleware.HAS_AUTH_MANAGER", False
            ):

                @require_auth()
                async def secure_tool():
                    return {"success": True}

                result = await secure_tool()
                assert result["success"] is False
                assert result["code"] == "AUTH_UNAVAILABLE"


# ==================== PERMISSIVE 模式 ====================


class TestPermissiveMode:
    """AuthMode.PERMISSIVE — 无 Key 时允许但警告"""

    async def test_permissive_no_key_allows(self):
        _auth_config["mode"] = AuthMode.PERMISSIVE

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_API_KEY", None)
            os.environ.pop("MCP_API_KEY", None)

            @require_auth()
            async def tool_permissive():
                return {"success": True, "data": "allowed"}

            result = await tool_permissive()
            assert result["success"] is True
            assert result["data"] == "allowed"

    async def test_permissive_auth_manager_unavailable_allows(self):
        """PERMISSIVE 模式下 AuthManager 不可用也应放行"""
        _auth_config["mode"] = AuthMode.PERMISSIVE
        _auth_config["manager"] = None

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "some-key"}, clear=False):
            with patch(
                "core.security.mcp_auth_middleware.HAS_AUTH_MANAGER", False
            ):

                @require_auth()
                async def tool_permissive():
                    return {"success": True}

                result = await tool_permissive()
                assert result["success"] is True


# ==================== 权限检查 ====================


class TestPermissionCheck:
    """工具权限检查"""

    async def test_permission_denied(self, mock_auth_manager):
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        mock_auth_manager.check_permission.return_value = False

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid-key"}, clear=False):

            @require_auth(tool_name="restricted_tool")
            async def restricted_tool():
                return {"success": True}

            result = await restricted_tool()
            assert result["success"] is False
            assert result["code"] == "PERMISSION_DENIED"
            assert "restricted_tool" in result["error"]

    async def test_permission_denied_audit_logged(self, mock_auth_manager):
        """权限拒绝时应记录审计日志"""
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        _auth_config["audit_enabled"] = True
        mock_auth_manager.check_permission.return_value = False

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid-key"}, clear=False):

            @require_auth(tool_name="audit_test_tool")
            async def audit_test_tool():
                return {"success": True}

            await audit_test_tool()
            mock_auth_manager.audit.assert_called_once()
            call_args = mock_auth_manager.audit.call_args
            assert call_args[0][1] == "audit_test_tool"
            assert call_args[1]["success"] is False


# ==================== 审计日志 ====================


class TestAudit:
    """审计日志记录"""

    async def test_success_audit(self, mock_auth_manager):
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        _auth_config["audit_enabled"] = True

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid-key"}, clear=False):

            @require_auth()
            async def audited_tool(target: str = "test"):
                return {"success": True}

            await audited_tool(target="192.168.1.1")
            mock_auth_manager.audit.assert_called_once()
            call_args = mock_auth_manager.audit.call_args
            assert call_args[1]["success"] is True

    async def test_exception_audit(self, mock_auth_manager):
        """工具执行异常时也应记录审计"""
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        _auth_config["audit_enabled"] = True

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid-key"}, clear=False):

            @require_auth()
            async def failing_tool():
                raise RuntimeError("boom")

            with pytest.raises(RuntimeError, match="boom"):
                await failing_tool()

            mock_auth_manager.audit.assert_called_once()
            call_args = mock_auth_manager.audit.call_args
            assert call_args[1]["success"] is False
            assert "boom" in call_args[1]["error"]

    async def test_audit_disabled(self, mock_auth_manager):
        """审计禁用时不应调用 audit"""
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        _auth_config["audit_enabled"] = False

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid-key"}, clear=False):

            @require_auth()
            async def no_audit_tool():
                return {"success": True}

            await no_audit_tool()
            mock_auth_manager.audit.assert_not_called()


# ==================== 同步函数支持 ====================


class TestSyncWrapper:
    """同步函数的 require_auth 支持"""

    def test_sync_disabled_mode(self):
        _auth_config["mode"] = AuthMode.DISABLED

        @require_auth()
        def sync_tool():
            return {"success": True}

        result = sync_tool()
        assert result["success"] is True

    def test_sync_strict_no_key(self):
        _auth_config["mode"] = AuthMode.STRICT

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_API_KEY", None)
            os.environ.pop("MCP_API_KEY", None)

            @require_auth()
            def sync_tool():
                return {"success": True}

            result = sync_tool()
            assert result["success"] is False
            assert result["code"] == "AUTH_REQUIRED"

    def test_sync_permissive_no_key(self):
        _auth_config["mode"] = AuthMode.PERMISSIVE

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_API_KEY", None)
            os.environ.pop("MCP_API_KEY", None)

            @require_auth()
            def sync_tool():
                return {"success": True, "data": "ok"}

            result = sync_tool()
            assert result["success"] is True

    def test_sync_valid_key(self, mock_auth_manager):
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid"}, clear=False):

            @require_auth()
            def sync_tool():
                return {"success": True}

            result = sync_tool()
            assert result["success"] is True

    def test_sync_invalid_key(self, mock_auth_manager):
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        mock_auth_manager.verify_key.return_value = None

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "bad"}, clear=False):

            @require_auth()
            def sync_tool():
                return {"success": True}

            result = sync_tool()
            assert result["success"] is False
            assert result["code"] == "INVALID_KEY"

    def test_sync_permission_denied(self, mock_auth_manager):
        _auth_config["mode"] = AuthMode.STRICT
        _auth_config["manager"] = mock_auth_manager
        mock_auth_manager.check_permission.return_value = False

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid"}, clear=False):

            @require_auth()
            def sync_tool():
                return {"success": True}

            result = sync_tool()
            assert result["success"] is False
            assert result["code"] == "PERMISSION_DENIED"


# ==================== _sanitize_params ====================


class TestSanitizeParams:
    """参数清理测试"""

    def test_password_redacted(self):
        result = _sanitize_params({"password": "secret123"})
        assert result["password"] == "***REDACTED***"

    def test_api_key_redacted(self):
        result = _sanitize_params({"api_key": "sk-123456"})
        assert result["api_key"] == "***REDACTED***"

    def test_ntlm_hash_redacted(self):
        result = _sanitize_params({"ntlm_hash": "aad3b435:31d6cfe0"})
        assert result["ntlm_hash"] == "***REDACTED***"

    def test_token_redacted(self):
        result = _sanitize_params({"auth_token": "bearer-xyz"})
        assert result["auth_token"] == "***REDACTED***"

    def test_long_string_truncated(self):
        long_val = "A" * 300
        result = _sanitize_params({"data": long_val})
        assert result["data"].endswith("...[TRUNCATED]")
        assert len(result["data"]) < 300

    def test_normal_params_preserved(self):
        result = _sanitize_params({"target": "192.168.1.1", "port": 443})
        assert result["target"] == "192.168.1.1"
        assert result["port"] == 443

    def test_empty_params(self):
        result = _sanitize_params({})
        assert result == {}

    def test_mixed_params(self):
        result = _sanitize_params({
            "target": "10.0.0.1",
            "password": "pass123",
            "command": "whoami",
            "ssh_key": "-----BEGIN RSA",
        })
        assert result["target"] == "10.0.0.1"
        assert result["password"] == "***REDACTED***"
        assert result["command"] == "whoami"
        assert result["ssh_key"] == "***REDACTED***"

    def test_case_insensitive_key_match(self):
        """敏感 key 匹配应不区分大小写"""
        result = _sanitize_params({"Password": "secret", "API_KEY": "key123"})
        assert result["Password"] == "***REDACTED***"
        assert result["API_KEY"] == "***REDACTED***"


# ==================== 便捷装饰器 ====================


class TestConvenienceDecorators:
    """便捷装饰器 require_*_auth"""

    async def test_require_safe_auth_disabled(self):
        _auth_config["mode"] = AuthMode.DISABLED

        @require_safe_auth
        async def safe_tool():
            return {"success": True}

        result = await safe_tool()
        assert result["success"] is True

    async def test_require_moderate_auth_disabled(self):
        _auth_config["mode"] = AuthMode.DISABLED

        @require_moderate_auth
        async def moderate_tool():
            return {"success": True}

        result = await moderate_tool()
        assert result["success"] is True

    async def test_require_dangerous_auth_disabled(self):
        _auth_config["mode"] = AuthMode.DISABLED

        @require_dangerous_auth
        async def dangerous_tool():
            return {"success": True}

        result = await dangerous_tool()
        assert result["success"] is True

    async def test_require_critical_auth_disabled(self):
        _auth_config["mode"] = AuthMode.DISABLED

        @require_critical_auth
        async def critical_tool():
            return {"success": True}

        result = await critical_tool()
        assert result["success"] is True

    async def test_require_critical_auth_strict_no_key(self):
        _auth_config["mode"] = AuthMode.STRICT

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_API_KEY", None)
            os.environ.pop("MCP_API_KEY", None)

            @require_critical_auth
            async def critical_tool():
                return {"success": True}

            result = await critical_tool()
            assert result["success"] is False
            assert result["code"] == "AUTH_REQUIRED"


# ==================== 环境变量初始化 ====================


class TestEnvInit:
    """模块级环境变量初始化"""

    def test_env_strict_default(self):
        """默认应为 STRICT"""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTOREDTEAM_AUTH_MODE", None)
            import importlib

            import core.security.mcp_auth_middleware as mod

            importlib.reload(mod)
            assert mod._auth_config["mode"].value == "strict"

    def test_env_disabled(self):
        with patch.dict(os.environ, {"AUTOREDTEAM_AUTH_MODE": "disabled"}, clear=False):
            import importlib

            import core.security.mcp_auth_middleware as mod

            importlib.reload(mod)
            assert mod._auth_config["mode"].value == "disabled"

    def test_env_permissive(self):
        with patch.dict(os.environ, {"AUTOREDTEAM_AUTH_MODE": "permissive"}, clear=False):
            import importlib

            import core.security.mcp_auth_middleware as mod

            importlib.reload(mod)
            assert mod._auth_config["mode"].value == "permissive"

    def test_env_unknown_falls_back_to_strict(self):
        with patch.dict(os.environ, {"AUTOREDTEAM_AUTH_MODE": "foobar"}, clear=False):
            import importlib

            import core.security.mcp_auth_middleware as mod

            importlib.reload(mod)
            assert mod._auth_config["mode"].value == "strict"


# ==================== tool_name 参数 ====================


class TestToolNameParam:
    """require_auth 的 tool_name 参数"""

    async def test_custom_tool_name(self, mock_auth_manager):
        # 重新获取模块引用（避免 importlib.reload 导致的 stale reference）
        import core.security.mcp_auth_middleware as mod

        mod._auth_config["mode"] = mod.AuthMode.STRICT
        mod._auth_config["manager"] = mock_auth_manager
        mock_auth_manager.check_permission.return_value = False

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid"}, clear=False):

            @mod.require_auth(tool_name="custom_name")
            async def original_name():
                return {"success": True}

            result = await original_name()
            assert "custom_name" in result["error"]

    async def test_default_tool_name_uses_func_name(self, mock_auth_manager):
        import core.security.mcp_auth_middleware as mod

        mod._auth_config["mode"] = mod.AuthMode.STRICT
        mod._auth_config["manager"] = mock_auth_manager
        mock_auth_manager.check_permission.return_value = False

        with patch.dict(os.environ, {"AUTOREDTEAM_API_KEY": "valid"}, clear=False):

            @mod.require_auth()
            async def my_func_name():
                return {"success": True}

            result = await my_func_name()
            assert "my_func_name" in result["error"]
