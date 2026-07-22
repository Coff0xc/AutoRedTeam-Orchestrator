"""
CLI 基础测试
验证 cli.main 模块导入、帮助输出、无效目标处理
"""

import json

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
        import typer

        from cli.main import app

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

    def test_ai_surface_help(self):
        """ai-surface scan --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["ai-surface", "scan", "--help"])
        assert result.exit_code == 0
        assert "path" in result.output.lower()

    def test_ai_redteam_eval_run_help(self):
        """ai-redteam eval-run --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["ai-redteam", "eval-run", "--help"])
        assert result.exit_code == 0
        assert "run" in result.output.lower()

    def test_ai_redteam_convert_help(self):
        """ai-redteam convert --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["ai-redteam", "convert", "--help"])
        assert result.exit_code == 0
        assert "converter" in result.output.lower()

    def test_code_agent_help(self):
        """code-agent expand --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["code-agent", "expand", "--help"])
        assert result.exit_code == 0
        assert "seed" in result.output.lower()

    def test_runtime_api_serve_help(self):
        """runtime-api serve --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["runtime-api", "serve", "--help"])
        assert result.exit_code == 0
        assert "run-state" in result.output.lower()

    def test_sandbox_docker_smoke_help(self):
        """sandbox docker-smoke --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["sandbox", "docker-smoke", "--help"])
        assert result.exit_code == 0
        assert "image" in result.output.lower()

    def test_capabilities_matrix_help(self):
        """capabilities matrix --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["capabilities", "matrix", "--help"])
        assert result.exit_code == 0
        assert "output" in result.output.lower()

    def test_capabilities_manifest_help(self):
        """capabilities manifest --help 应返回成功"""
        from cli.main import app

        result = runner.invoke(app, ["capabilities", "manifest", "--help"])
        assert result.exit_code == 0
        assert "profile" in result.output.lower()

    def test_no_args_shows_help(self):
        """无参数调用应显示帮助/用法信息"""
        from cli.main import app

        result = runner.invoke(app, [])
        # Typer 在无命令时返回 exit_code 0 或 2（取决于版本/配置）
        assert result.exit_code in (0, 2)
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


class TestCLIAIRedTeamEval:
    """测试 AI red-team 本地评测命令"""

    def test_eval_run_accepts_full_ai_redteam_result_json(self, tmp_path):
        """eval-run 应能读取 ai-redteam run 的完整 JSON 输出"""
        from cli.main import app

        action_id = "action_demo"
        run_file = tmp_path / "run.json"
        run_file.write_text(
            json.dumps(
                {
                    "success": True,
                    "run_state": {
                        "run_id": "run_demo",
                        "mode": "dry-run",
                        "flow": {
                            "flow_id": "flow_demo",
                            "name": "cli-eval",
                            "tasks": [
                                {
                                    "task_id": "task_demo",
                                    "name": "handoff",
                                    "actions": [
                                        {
                                            "action_id": action_id,
                                            "name": "handoff",
                                            "kind": "tool_call",
                                            "inputs": {
                                                "from_role": "planner",
                                                "to_role": "executor",
                                            },
                                            "policy": {
                                                "risk_level": "moderate",
                                                "network_policy": "deny",
                                            },
                                            "status": "skipped",
                                            "output": {},
                                        }
                                    ],
                                }
                            ],
                        },
                        "trace": [
                            {
                                "event_id": "trace_demo",
                                "event_type": "agent_handoff",
                                "message": "handoff recorded",
                                "action_id": action_id,
                                "metadata": {},
                            }
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )

        result = runner.invoke(app, ["ai-redteam", "eval-run", str(run_file)])

        assert result.exit_code == 0
        assert '"passed": true' in result.output
        assert "agent.multi_agent_handoff_trace" in result.output


class TestCLICapabilities:
    """测试 AI 能力矩阵命令"""

    def test_capabilities_matrix_outputs_sources(self):
        from cli.main import app

        result = runner.invoke(app, ["capabilities", "matrix"])
        payload = json.loads(result.output[result.output.index("{") :])

        assert result.exit_code == 0
        assert "PentAGI" in payload["sources"]
        assert "Vulnhuntr" in payload["sources"]
        assert payload["summary"]["blocked"] == 0

    def test_capabilities_readiness_is_ready(self):
        from cli.main import app

        result = runner.invoke(app, ["capabilities", "readiness"])
        payload = json.loads(result.output[result.output.index("{") :])

        assert result.exit_code == 0
        assert payload["ready_for_full_refactor"] is True
        assert any("Docker execution optional" in item for item in payload["constraints"])

    def test_capabilities_manifest_safe_profile(self):
        from cli.main import app

        result = runner.invoke(app, ["capabilities", "manifest", "--profile", "safe"])
        payload = json.loads(result.output[result.output.index("{") :])

        assert result.exit_code == 0
        assert payload["profile"] == "safe"
        assert payload["summary"]["total"] == 23
        assert all("safe" in item["profiles"] for item in payload["capabilities"])

    def test_capabilities_profiles_outputs_boundaries(self):
        from cli.main import app

        result = runner.invoke(app, ["capabilities", "profiles"])
        payload = json.loads(result.output[result.output.index("{") :])

        assert result.exit_code == 0
        assert payload["default_mcp_profile"] == "safe"
        assert [item["surface_count"] for item in payload["profiles"]] == [23, 85, 105, 141]
        assert "do not replace authentication" in payload["security_note"]

    def test_capabilities_manifest_rejects_unknown_profile(self):
        from cli.main import app

        result = runner.invoke(app, ["capabilities", "manifest", "--profile", "unknown"])

        assert result.exit_code != 0
        assert "Unknown capability profile" in result.output


class TestCLIAIRedTeamConvert:
    """测试 AI red-team prompt converter 命令"""

    def test_convert_base64_outputs_converter_result(self):
        from cli.main import app

        result = runner.invoke(
            app,
            ["ai-redteam", "convert", "demo prompt", "--converter", "base64"],
        )
        payload = json.loads(result.output[result.output.index("{") :])

        assert result.exit_code == 0
        assert payload["result"]["converter"] == "base64"
        assert payload["result"]["metadata"]["modifies_payload"] is True
