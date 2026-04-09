"""
CLI 基础测试
验证 cli.main 模块导入、帮助输出、无效目标处理
"""

import pytest
from typer.testing import CliRunner

runner = CliRunner()


class TestCLIImport:
    """测试 CLI 模块导入"""

    def test_cli_main_module_imports(self):
        """cli.main 模块应能正常导入"""
        import cli.main

        assert hasattr(cli.main, "app")
        assert hasattr(cli.main, "main")

    def test_cli_app_is_typer_instance(self):
        """app 应为 Typer 实例"""
        from cli.main import app

        import typer

        assert isinstance(app, typer.Typer)


class TestCLIHelp:
    """测试 CLI 帮助输出"""

    def test_help_output(self):
        """--help 应返回成功并包含工具描述"""
        from cli.main import app

        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "AutoRedTeam" in result.output

    def test_scan_help(self):
        """scan --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "target" in result.output.lower() or "URL" in result.output

    def test_detect_help(self):
        """detect --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["detect", "--help"])
        assert result.exit_code == 0

    def test_pentest_help(self):
        """pentest --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["pentest", "--help"])
        assert result.exit_code == 0

    def test_no_args_shows_help(self):
        """无参数调用应显示帮助信息"""
        from cli.main import app

        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert "AutoRedTeam" in result.output or "Usage" in result.output


class TestCLIInvalidTarget:
    """测试无效目标处理"""

    def test_scan_missing_target(self):
        """scan 缺少 target 参数应报错"""
        from cli.main import app

        result = runner.invoke(app, ["scan"])
        assert result.exit_code != 0

    def test_detect_missing_target(self):
        """detect 缺少 target 参数应报错"""
        from cli.main import app

        result = runner.invoke(app, ["detect"])
        assert result.exit_code != 0

    def test_exploit_no_flags(self):
        """exploit 不指定 --cve 或 --auto 应报错"""
        from cli.main import app

        result = runner.invoke(app, ["exploit", "http://example.com"])
        assert result.exit_code != 0

    def test_unknown_command(self):
        """未知子命令应报错"""
        from cli.main import app

        result = runner.invoke(app, ["nonexistent_command"])
        assert result.exit_code != 0
