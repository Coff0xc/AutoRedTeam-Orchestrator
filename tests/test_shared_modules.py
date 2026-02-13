"""
shared 模块测试

测试 SubprocessRunner, ToolResult, validators 等公共组件
"""

import pytest
from shared import ToolResult, validate_domain, validate_ip, validate_url, validate_port
from shared.subprocess_runner import SubprocessRunner, get_subprocess_runner


class TestToolResult:
    """ToolResult 测试"""

    def test_ok(self):
        result = ToolResult.ok(data="test", count=5)
        assert result.success is True
        assert result.data == {"data": "test", "count": 5}
        assert result.error is None

    def test_fail(self):
        result = ToolResult.fail("connection error")
        assert result.success is False
        assert result.error == "connection error"

    def test_timeout(self):
        result = ToolResult.timeout("nmap", 30.0)
        assert result.success is False
        assert "超时" in result.error
        assert "30" in result.error

    def test_not_installed(self):
        result = ToolResult.not_installed("nuclei", "apt install nuclei")
        assert result.success is False
        assert "nuclei" in result.error
        assert "apt install" in result.error

    def test_to_dict_success(self):
        result = ToolResult.ok(items=[1, 2, 3])
        d = result.to_dict()
        assert d["success"] is True
        assert d["items"] == [1, 2, 3]
        assert "error" not in d

    def test_to_dict_failure(self):
        result = ToolResult.fail("error msg")
        d = result.to_dict()
        assert d["success"] is False
        assert d["error"] == "error msg"


class TestValidators:
    """输入验证器测试"""

    def test_validate_domain_valid(self):
        valid, error = validate_domain("example.com")
        assert valid is True
        assert error is None

    def test_validate_domain_subdomain(self):
        valid, error = validate_domain("sub.example.com")
        assert valid is True

    def test_validate_domain_empty(self):
        valid, error = validate_domain("")
        assert valid is False
        assert "空" in error

    def test_validate_domain_dangerous_chars(self):
        valid, error = validate_domain("example.com;whoami")
        assert valid is False
        assert "危险" in error

    def test_validate_ip_valid_v4(self):
        valid, error = validate_ip("192.168.1.1")
        assert valid is True

    def test_validate_ip_valid_v6(self):
        valid, error = validate_ip("::1")
        assert valid is True

    def test_validate_ip_invalid(self):
        valid, error = validate_ip("999.999.999.999")
        assert valid is False

    def test_validate_url_valid(self):
        valid, error = validate_url("https://example.com/path")
        assert valid is True

    def test_validate_url_no_scheme(self):
        valid, error = validate_url("example.com")
        assert valid is False
        assert "协议" in error

    def test_validate_url_require_https(self):
        valid, error = validate_url("http://example.com", require_https=True)
        assert valid is False
        assert "HTTPS" in error

    def test_validate_port_valid(self):
        valid, error = validate_port(80)
        assert valid is True

    def test_validate_port_invalid_range(self):
        valid, error = validate_port(70000)
        assert valid is False


class TestSubprocessRunner:
    """SubprocessRunner 测试"""

    def test_get_subprocess_runner_singleton(self):
        runner1 = get_subprocess_runner()
        runner2 = get_subprocess_runner()
        assert runner1 is runner2

    def test_run_echo(self):
        runner = SubprocessRunner(timeout=5.0)
        # 使用跨平台命令
        import platform
        if platform.system() == "Windows":
            result = runner.run(["cmd", "/c", "echo", "hello"])
        else:
            result = runner.run(["echo", "hello"])
        assert result.success is True

    def test_run_not_installed(self):
        runner = SubprocessRunner()
        result = runner.run(
            ["nonexistent_tool_xyz", "--version"],
            tool_name="nonexistent_tool",
            install_cmd="pip install nonexistent"
        )
        assert result.success is False
        assert "未安装" in result.error

    def test_run_timeout(self):
        runner = SubprocessRunner()
        import platform
        if platform.system() != "Windows":
            result = runner.run(["sleep", "10"], timeout=0.1, tool_name="sleep")
            assert result.success is False
            assert "超时" in result.error

    @pytest.mark.asyncio
    async def test_async_run(self):
        runner = SubprocessRunner(timeout=5.0)
        import platform
        if platform.system() == "Windows":
            result = await runner.async_run(["cmd", "/c", "echo", "async"])
        else:
            result = await runner.async_run(["echo", "async"])
        assert result.success is True
