#!/usr/bin/env python3
"""
会话管理工具处理器单元测试
测试 handlers/session_handlers.py 中的 4 个工具注册和执行
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any
from datetime import datetime


# ==================== 辅助函数 ====================


def _make_mcp_and_register():
    """创建 mock MCP 并注册 Session 工具，返回 (registered_tools, mock_counter, mock_logger)

    通过 patch _wrap_tool_func 为 identity，使注册的工具直接返回 handler 原始 dict。
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

    with patch('utils.mcp_tooling._wrap_tool_func', side_effect=lambda f: f):
        from handlers.session_handlers import register_session_tools
        register_session_tools(mock_mcp, mock_counter, mock_logger)

    return registered_tools, mock_counter, mock_logger


# ==================== 注册测试 ====================


class TestSessionHandlersRegistration:
    """测试会话管理工具注册"""

    def test_register_session_tools(self):
        """测试注册函数是否正确注册 4 个工具"""
        registered_tools, mock_counter, mock_logger = _make_mcp_and_register()

        mock_counter.add.assert_called_once_with('session', 4)
        mock_logger.info.assert_called_once()
        assert "4 个会话管理工具" in str(mock_logger.info.call_args)

    def test_all_tools_registered(self):
        """验证所有预期工具均已注册"""
        registered_tools, _, _ = _make_mcp_and_register()

        expected_tools = [
            'session_create', 'session_status', 'session_list', 'session_complete',
        ]
        for tool_name in expected_tools:
            assert tool_name in registered_tools, f"工具 {tool_name} 未注册"


# ==================== session_create 测试 ====================


class TestSessionCreateTool:
    """测试 session_create 创建会话工具"""

    @pytest.mark.asyncio
    async def test_create_session_success(self):
        """测试正常创建会话"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_context = MagicMock()
        mock_context.session_id = "abc123def456"
        mock_context.status = MagicMock(value='active')
        mock_context.started_at = datetime(2026, 1, 15, 10, 30, 0)

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.create_session.return_value = mock_context
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_create'](
                target="https://example.com",
                config={"quick_mode": True}
            )

            assert result['success'] is True
            assert result['session_id'] == 'abc123def456'
            assert result['target'] == 'https://example.com'
            assert result['status'] == 'active'
            assert 'created_at' in result
            manager.create_session.assert_called_once_with(
                "https://example.com", {"quick_mode": True}
            )

    @pytest.mark.asyncio
    async def test_create_session_default_config(self):
        """测试使用默认配置创建会话"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_context = MagicMock()
        mock_context.session_id = "session-001"
        mock_context.status = MagicMock(value='active')
        mock_context.started_at = datetime(2026, 1, 15, 10, 0, 0)

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.create_session.return_value = mock_context
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_create'](
                target="https://example.com"
            )

            assert result['success'] is True
            manager.create_session.assert_called_once_with("https://example.com", None)

    @pytest.mark.asyncio
    async def test_create_session_exception(self):
        """测试创建会话异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.session.get_session_manager') as mock_get_mgr:
            mock_get_mgr.side_effect = RuntimeError("Session storage full")

            result = await registered_tools['session_create'](
                target="https://example.com"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== session_status 测试 ====================


class TestSessionStatusTool:
    """测试 session_status 查询会话状态工具"""

    @pytest.mark.asyncio
    async def test_session_status_found(self):
        """测试查询存在的会话"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_context = MagicMock()
        mock_context.target = MagicMock(url="https://example.com")
        mock_context.status = MagicMock(value='active')
        mock_context.phase = MagicMock(value='vuln_scan')
        mock_context.vulnerabilities = [MagicMock(), MagicMock()]

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.get_session.return_value = mock_context
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_status'](
                session_id="abc123def456"
            )

            assert result['success'] is True
            assert result['session_id'] == 'abc123def456'
            assert result['target'] == 'https://example.com'
            assert result['status'] == 'active'
            assert result['phase'] == 'vuln_scan'
            assert result['vulns_found'] == 2

    @pytest.mark.asyncio
    async def test_session_status_not_found(self):
        """测试查询不存在的会话"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.get_session.return_value = None
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_status'](
                session_id="nonexistent"
            )

            assert result['success'] is False
            assert '会话不存在' in result['error']

    @pytest.mark.asyncio
    async def test_session_status_exception(self):
        """测试查询异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.session.get_session_manager') as mock_get_mgr:
            mock_get_mgr.side_effect = RuntimeError("Storage unavailable")

            result = await registered_tools['session_status'](
                session_id="abc123"
            )

            assert result['success'] is False
            assert 'error' in result


# ==================== session_list 测试 ====================


class TestSessionListTool:
    """测试 session_list 列出会话工具"""

    @pytest.mark.asyncio
    async def test_session_list_all(self):
        """测试列出所有会话"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_s1 = MagicMock()
        mock_s1.session_id = "session-001"
        mock_s1.target = MagicMock(url="https://example1.com")
        mock_s1.status = MagicMock(value='active')
        mock_s1.phase = MagicMock(value='recon')

        mock_s2 = MagicMock()
        mock_s2.session_id = "session-002"
        mock_s2.target = MagicMock(url="https://example2.com")
        mock_s2.status = MagicMock(value='completed')
        mock_s2.phase = MagicMock(value='report')

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.list_sessions.return_value = [mock_s1, mock_s2]
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_list']()

            assert result['success'] is True
            assert result['count'] == 2
            assert result['sessions'][0]['session_id'] == 'session-001'
            assert result['sessions'][1]['status'] == 'completed'
            manager.list_sessions.assert_called_once_with(status=None, limit=20)

    @pytest.mark.asyncio
    async def test_session_list_with_filter(self):
        """测试按状态过滤"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.list_sessions.return_value = []
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_list'](
                status="active", limit=5
            )

            assert result['success'] is True
            assert result['count'] == 0
            manager.list_sessions.assert_called_once_with(status="active", limit=5)

    @pytest.mark.asyncio
    async def test_session_list_exception(self):
        """测试列表异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.session.get_session_manager') as mock_get_mgr:
            mock_get_mgr.side_effect = RuntimeError("Storage error")

            result = await registered_tools['session_list']()

            assert result['success'] is False
            assert 'error' in result


# ==================== session_complete 测试 ====================


class TestSessionCompleteTool:
    """测试 session_complete 完成会话工具"""

    @pytest.mark.asyncio
    async def test_complete_session_success(self):
        """测试正常完成会话"""
        registered_tools, _, _ = _make_mcp_and_register()

        mock_result = MagicMock()
        mock_result.total_vulns = 15
        mock_result.critical_count = 2
        mock_result.high_count = 5
        mock_result.medium_count = 6
        mock_result.low_count = 2
        mock_result.duration = 3600

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.complete_session.return_value = mock_result
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_complete'](
                session_id="abc123def456"
            )

            assert result['success'] is True
            assert result['session_id'] == 'abc123def456'
            assert result['total_vulns'] == 15
            assert result['critical'] == 2
            assert result['high'] == 5
            assert result['medium'] == 6
            assert result['low'] == 2
            assert result['duration'] == 3600

    @pytest.mark.asyncio
    async def test_complete_session_not_found(self):
        """测试完成不存在的会话"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.session.get_session_manager') as mock_get_mgr:
            manager = MagicMock()
            manager.complete_session.return_value = None
            mock_get_mgr.return_value = manager

            result = await registered_tools['session_complete'](
                session_id="nonexistent"
            )

            assert result['success'] is False
            assert '会话不存在' in result['error']

    @pytest.mark.asyncio
    async def test_complete_session_exception(self):
        """测试完成会话异常"""
        registered_tools, _, _ = _make_mcp_and_register()

        with patch('core.session.get_session_manager') as mock_get_mgr:
            mock_get_mgr.side_effect = RuntimeError("Cannot complete")

            result = await registered_tools['session_complete'](
                session_id="abc123"
            )

            assert result['success'] is False
            assert 'error' in result
