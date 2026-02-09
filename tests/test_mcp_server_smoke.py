"""
MCP Server Smoke Tests

Verifies that the MCP server can start up and register tools successfully.
This is a critical e2e test that catches import errors, registration failures,
and other catastrophic issues.
"""

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest


class TestMCPServerSmoke:
    """MCP 服务器冒烟测试"""

    def test_mcp_stdio_server_importable(self):
        """Test that mcp_stdio_server module can be imported"""
        # This catches any import-time errors
        try:
            if "mcp_stdio_server" in sys.modules:
                del sys.modules["mcp_stdio_server"]
            import mcp_stdio_server
            assert hasattr(mcp_stdio_server, "main")
        except ImportError as e:
            pytest.fail(f"Failed to import mcp_stdio_server: {e}")

    def test_tool_counter_initialization(self):
        """Test that ToolCounter initializes with expected categories"""
        try:
            from mcp_stdio_server import ToolCounter
        except ImportError:
            pytest.skip("ToolCounter not importable")

        counter = ToolCounter()
        # Should have category tracking
        assert hasattr(counter, "add") or hasattr(counter, "counts")

    def test_handlers_module_importable(self):
        """Test that handlers module can be imported"""
        try:
            from handlers import register_all_handlers
            assert callable(register_all_handlers)
        except ImportError as e:
            pytest.fail(f"Failed to import handlers: {e}")

    def test_core_module_importable(self):
        """Test that core module exports are available"""
        try:
            from core import ToolResult, ToolRegistry
            assert ToolResult is not None
            assert ToolRegistry is not None
        except ImportError as e:
            pytest.fail(f"Failed to import core: {e}")

    def test_core_result_creation(self):
        """Test that ToolResult can be created"""
        try:
            from core import ToolResult
            result = ToolResult.success(data={"test": True})
            assert result is not None
        except Exception as e:
            pytest.fail(f"Failed to create ToolResult: {e}")

    @pytest.mark.integration
    def test_register_all_handlers_with_mock_mcp(self):
        """Test full handler registration with a mock MCP server"""
        try:
            from handlers import register_all_handlers
        except ImportError:
            pytest.skip("handlers not importable")

        mock_mcp = MagicMock()
        mock_mcp.tool = MagicMock(return_value=lambda f: f)

        class MockCounter:
            def __init__(self):
                self.counts = {}
                self.total = 0

            def add(self, category, count=1):
                self.counts[category] = self.counts.get(category, 0) + count
                self.total += count

        counter = MockCounter()

        import logging
        logger = logging.getLogger("test")

        # Should not raise any unhandled exceptions
        register_all_handlers(mock_mcp, counter, logger)

        # Verify at least some tools were registered
        assert counter.total > 0, f"Expected tools to be registered, got {counter.total}"

    def test_version_file_exists(self):
        """Test that VERSION file exists and contains valid version"""
        import os
        version_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "VERSION"
        )
        assert os.path.exists(version_path), "VERSION file should exist"
        with open(version_path) as f:
            version = f.read().strip()
        # Basic semver format check
        parts = version.split(".")
        assert len(parts) >= 2, f"Version should be semver format, got: {version}"
