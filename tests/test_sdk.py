#!/usr/bin/env python3
"""
AutoRedTeam SDK + CLI 测试

测试 autort/ SDK 包 (Scanner, Exploiter, AutoPentest, RedTeam, Reporter)
测试 cli/main.py CLI 包 (typer 应用)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ==================== SDK: Scanner 测试 ====================


class TestScanner:
    """测试 autort.Scanner"""

    def test_scanner_init(self):
        """测试 Scanner 初始化"""
        from autort import Scanner

        s = Scanner("http://example.com")
        assert s.target == "http://example.com"
        assert s._config == {}

    def test_scanner_init_with_config(self):
        """测试 Scanner 带配置初始化"""
        from autort import Scanner

        config = {"quick_mode": True, "timeout": 5}
        s = Scanner("http://example.com", config=config)
        assert s._config == config

    @pytest.mark.asyncio
    async def test_full_recon_success(self):
        """测试完整侦察成功"""
        from autort import Scanner

        s = Scanner("http://example.com", config={"quick_mode": True})

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "dns": {"ip": "1.2.3.4"},
            "ports": [80, 443],
        }

        with (
            patch("core.recon.engine.StandardReconEngine") as MockEngine,
            patch("core.recon.base.ReconConfig"),
        ):
            mock_engine = MagicMock()
            mock_engine.async_run = AsyncMock(return_value=mock_result)
            MockEngine.return_value = mock_engine

            result = await s.full_recon()

            assert result["dns"]["ip"] == "1.2.3.4"
            MockEngine.assert_called_once()

    @pytest.mark.asyncio
    async def test_full_recon_failure(self):
        """测试完整侦察失败"""
        from autort import Scanner

        s = Scanner("http://example.com")

        with patch("core.recon.engine.StandardReconEngine") as MockEngine:
            MockEngine.side_effect = ImportError("module not found")

            result = await s.full_recon()

            assert result["success"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_port_scan_success(self):
        """测试端口扫描成功"""
        from autort import Scanner

        s = Scanner("http://example.com")

        mock_port = MagicMock()
        mock_port.to_dict.return_value = {"port": 80, "state": "open", "service": "http"}

        with (
            patch("core.recon.port_scanner.PortScanner") as MockScanner,
            patch.object(s, "_resolve_ip", return_value="1.2.3.4"),
        ):
            mock_scanner = MagicMock()
            mock_scanner.scan.return_value = [mock_port]
            MockScanner.return_value = mock_scanner

            result = await s.port_scan(ports="80,443")

            assert len(result) == 1
            assert result[0]["port"] == 80

    @pytest.mark.asyncio
    async def test_detect_vulns_success(self):
        """测试漏洞检测成功"""
        from autort import Scanner

        s = Scanner("http://example.com")

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"vuln_type": "sqli", "severity": "high"}

        mock_detector = MagicMock()
        mock_detector.async_detect = AsyncMock(return_value=[mock_result])
        mock_detector.name = "sqli"

        with patch("core.detectors.factory.DetectorFactory") as MockFactory:
            MockFactory.list_detectors.return_value = ["sqli"]
            MockFactory.create.return_value = mock_detector

            result = await s.detect_vulns(categories=["sqli"])

            assert len(result) == 1
            assert result[0]["vuln_type"] == "sqli"

    @pytest.mark.asyncio
    async def test_fingerprint_success(self):
        """测试指纹识别成功"""
        from autort import Scanner

        s = Scanner("http://example.com")

        mock_fp = MagicMock()
        mock_fp.to_dict.return_value = {"name": "nginx", "version": "1.18"}

        with patch("core.recon.fingerprint.FingerprintEngine") as MockEngine:
            mock_engine = MagicMock()
            mock_engine.identify.return_value = [mock_fp]
            MockEngine.return_value = mock_engine

            result = await s.fingerprint()

            assert result["success"] is True
            assert len(result["fingerprints"]) == 1
            assert result["fingerprints"][0]["name"] == "nginx"

    @pytest.mark.asyncio
    async def test_waf_detect_found(self):
        """测试WAF检测 - 发现WAF"""
        from autort import Scanner

        s = Scanner("http://example.com")

        mock_waf = MagicMock()
        mock_waf.to_dict.return_value = {"name": "Cloudflare", "confidence": 0.95}

        with patch("core.recon.waf_detect.WAFDetector") as MockDetector:
            mock_detector = MagicMock()
            mock_detector.detect.return_value = mock_waf
            MockDetector.return_value = mock_detector

            result = await s.waf_detect()

            assert result["success"] is True
            assert result["detected"] is True
            assert result["waf"]["name"] == "Cloudflare"

    @pytest.mark.asyncio
    async def test_waf_detect_not_found(self):
        """测试WAF检测 - 未发现WAF"""
        from autort import Scanner

        s = Scanner("http://example.com")

        with patch("core.recon.waf_detect.WAFDetector") as MockDetector:
            mock_detector = MagicMock()
            mock_detector.detect.return_value = None
            MockDetector.return_value = mock_detector

            result = await s.waf_detect()

            assert result["success"] is True
            assert result["detected"] is False

    def test_resolve_ip_from_ip(self):
        """测试从IP地址直接返回"""
        from autort import Scanner

        s = Scanner("192.168.1.100")
        assert s._resolve_ip() == "192.168.1.100"

    def test_resolve_ip_from_url(self):
        """测试从URL解析IP"""
        from autort import Scanner

        s = Scanner("http://127.0.0.1:8080/path")
        assert s._resolve_ip() == "127.0.0.1"


# ==================== SDK: Exploiter 测试 ====================


class TestExploiter:
    """测试 autort.Exploiter"""

    def test_exploiter_init(self):
        """测试 Exploiter 初始化"""
        from autort import Exploiter

        e = Exploiter("http://example.com")
        assert e.target == "http://example.com"
        assert e._config == {}

    @pytest.mark.asyncio
    async def test_exploit_success(self):
        """测试单漏洞利用成功"""
        from autort import Exploiter

        e = Exploiter("http://example.com")

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"success": True, "status": "success"}

        with patch("core.exploit.engine.ExploitEngine") as MockEngine:
            mock_engine = MagicMock()
            mock_engine.async_exploit = AsyncMock(return_value=mock_result)
            MockEngine.return_value = mock_engine

            result = await e.exploit({"vuln_type": "sqli"})

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_exploit_failure(self):
        """测试单漏洞利用失败"""
        from autort import Exploiter

        e = Exploiter("http://example.com")

        with patch("core.exploit.engine.ExploitEngine") as MockEngine:
            MockEngine.side_effect = RuntimeError("Engine init failed")

            result = await e.exploit({"vuln_type": "sqli"})

            assert result["success"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_cve_search_success(self):
        """测试CVE搜索成功"""
        from autort import Exploiter

        e = Exploiter("")

        mock_entry = MagicMock()
        mock_entry.to_dict.return_value = {"cve_id": "CVE-2024-1234", "severity": "HIGH"}

        with (
            patch("core.cve.storage.CVEStorage"),
            patch("core.cve.search.CVESearchEngine") as MockSearch,
        ):
            mock_search = MagicMock()
            mock_search.search.return_value = [mock_entry]
            MockSearch.return_value = mock_search

            result = await e.cve_search(keyword="apache", limit=10)

            assert len(result) == 1
            assert result[0]["cve_id"] == "CVE-2024-1234"

    @pytest.mark.asyncio
    async def test_cve_exploit_success(self):
        """测试CVE自动利用成功"""
        from autort import Exploiter

        e = Exploiter("http://example.com")

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "success": True,
            "vulnerable": True,
            "cve_id": "CVE-2021-44228",
        }

        with patch("core.cve.auto_exploit.CVEAutoExploitEngine") as MockEngine:
            mock_engine = MagicMock()
            mock_engine.auto_exploit_by_cve = AsyncMock(return_value=mock_result)
            MockEngine.return_value = mock_engine

            result = await e.cve_exploit("CVE-2021-44228")

            assert result["success"] is True
            assert result["cve_id"] == "CVE-2021-44228"


# ==================== SDK: AutoPentest 测试 ====================


class TestAutoPentest:
    """测试 autort.AutoPentest"""

    def test_autopentest_init(self):
        """测试 AutoPentest 初始化"""
        from autort import AutoPentest

        pt = AutoPentest("http://example.com", config={"quick_mode": True})
        assert pt.target == "http://example.com"
        assert pt._config["quick_mode"] is True

    @pytest.mark.asyncio
    async def test_run_success(self):
        """测试完整渗透流程成功"""
        from autort import AutoPentest

        pt = AutoPentest("http://example.com")

        mock_result = {"status": "completed", "findings": [{"vuln": "sqli"}]}

        with (
            patch("core.orchestrator.orchestrator.AutoPentestOrchestrator") as MockOrch,
            patch("core.orchestrator.orchestrator.OrchestratorConfig"),
        ):
            mock_orch = MagicMock()
            mock_orch.run = AsyncMock(return_value=mock_result)
            MockOrch.return_value = mock_orch

            result = await pt.run()

            assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_run_with_phases(self):
        """测试指定阶段执行"""
        from autort import AutoPentest

        pt = AutoPentest("http://example.com")

        with (
            patch("core.orchestrator.orchestrator.AutoPentestOrchestrator") as MockOrch,
            patch("core.orchestrator.orchestrator.OrchestratorConfig") as MockConfig,
        ):
            mock_config_instance = MagicMock()
            mock_config_instance.skip_phases = []
            MockConfig.return_value = mock_config_instance

            mock_orch = MagicMock()
            mock_orch.run = AsyncMock(return_value={"success": True})
            MockOrch.return_value = mock_orch

            result = await pt.run(phases=["recon", "vuln_scan"])

            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_run_failure(self):
        """测试渗透流程失败"""
        from autort import AutoPentest

        pt = AutoPentest("http://example.com")

        with (
            patch("core.orchestrator.orchestrator.AutoPentestOrchestrator") as MockOrch,
            patch("core.orchestrator.orchestrator.OrchestratorConfig"),
        ):
            MockOrch.side_effect = ImportError("orchestrator module missing")

            result = await pt.run()

            assert result["success"] is False
            assert "error" in result

    @pytest.mark.asyncio
    async def test_resume_success(self):
        """测试恢复渗透测试成功"""
        from autort import AutoPentest

        pt = AutoPentest("http://example.com")

        with patch("core.orchestrator.orchestrator.AutoPentestOrchestrator") as MockOrch:
            mock_orch = MagicMock()
            mock_orch.run = AsyncMock(return_value={"status": "completed"})
            MockOrch.resume.return_value = mock_orch

            result = await pt.resume("abc123def456")

            assert result["status"] == "completed"


# ==================== SDK: RedTeam 测试 ====================


class TestRedTeam:
    """测试 autort.RedTeam"""

    def test_redteam_init(self):
        """测试 RedTeam 初始化"""
        from autort import RedTeam

        rt = RedTeam()
        assert rt._config == {}

    @pytest.mark.asyncio
    async def test_lateral_move_success(self):
        """测试横向移动成功"""
        from autort import RedTeam

        rt = RedTeam()

        mock_module = MagicMock()
        mock_module.connect.return_value = True
        mock_exec_result = MagicMock()
        mock_exec_result.output = "root"
        mock_exec_result.exit_code = 0
        mock_module.execute.return_value = mock_exec_result

        with patch.object(rt, "_get_lateral_module", return_value=mock_module):
            result = await rt.lateral_move(
                target="192.168.1.100",
                method="ssh",
                username="root",
                password="pass",
                command="whoami",
            )

            assert result["success"] is True
            assert result["output"] == "root"
            mock_module.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_lateral_move_connect_failed(self):
        """测试横向移动连接失败"""
        from autort import RedTeam

        rt = RedTeam()

        mock_module = MagicMock()
        mock_module.connect.return_value = False

        with patch.object(rt, "_get_lateral_module", return_value=mock_module):
            result = await rt.lateral_move(
                target="192.168.1.100", method="ssh", username="root"
            )

            assert result["success"] is False
            assert "连接失败" in result["error"]

    def test_get_lateral_module_invalid(self):
        """测试不支持的横向移动方法"""
        from autort import RedTeam

        rt = RedTeam()

        with pytest.raises(ValueError, match="不支持的横向移动方法"):
            rt._get_lateral_module("invalid_method")

    @pytest.mark.asyncio
    async def test_persist_unsupported_platform(self):
        """测试持久化不支持的平台"""
        from autort import RedTeam

        rt = RedTeam()

        result = await rt.persist(platform="macos", method="launchd")

        assert result["success"] is False
        assert "不支持的平台" in result["error"]


# ==================== SDK: Reporter 测试 ====================


class TestReporter:
    """测试 autort.Reporter"""

    def test_reporter_init(self):
        """测试 Reporter 初始化"""
        from autort import Reporter

        r = Reporter("session-123")
        assert r.session_id == "session-123"

    @pytest.mark.asyncio
    async def test_generate_success(self):
        """测试报告生成成功"""
        from autort import Reporter

        r = Reporter("session-123")

        with patch("utils.report_generator.ReportGenerator") as MockGen:
            mock_gen = MagicMock()
            mock_gen.generate.return_value = "/path/to/report.html"
            MockGen.return_value = mock_gen

            result = await r.generate(format="html")

            assert result == "/path/to/report.html"

    @pytest.mark.asyncio
    async def test_generate_no_session(self):
        """测试无 session_id 时返回空"""
        from autort import Reporter

        r = Reporter(None)

        result = await r.generate()

        assert result == ""

    @pytest.mark.asyncio
    async def test_export_findings_success(self):
        """测试导出发现成功"""
        from autort import Reporter

        r = Reporter("session-123")

        mock_source = MagicMock()
        mock_report_data = {"findings": [{"vuln": "sqli"}]}

        with patch("utils.report_generator.ReportGenerator") as MockGen:
            mock_gen = MagicMock()
            mock_gen.load_source.return_value = mock_source
            mock_gen._prepare_report_data.return_value = mock_report_data
            MockGen.return_value = mock_gen

            result = await r.export_findings(format="json")

            assert result["success"] is True
            assert result["format"] == "json"

    @pytest.mark.asyncio
    async def test_export_findings_no_session(self):
        """测试无 session_id 导出"""
        from autort import Reporter

        r = Reporter(None)

        result = await r.export_findings()

        assert result["success"] is False
        assert "session_id" in result["error"]


# ==================== SDK: __init__ 测试 ====================


class TestSDKPackage:
    """测试 autort 包初始化"""

    def test_version(self):
        """测试版本号"""
        from autort import __version__

        assert __version__ == "3.1.0"

    def test_exports(self):
        """测试所有公共类均可导入"""
        from autort import AutoPentest, Exploiter, RedTeam, Reporter, Scanner

        assert Scanner is not None
        assert Exploiter is not None
        assert AutoPentest is not None
        assert RedTeam is not None
        assert Reporter is not None


# ==================== CLI 测试 ====================


class TestCLI:
    """测试 cli/main.py CLI 应用"""

    def test_cli_help(self):
        """测试 CLI help 输出"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "AutoRedTeam" in result.output

    def test_cli_version(self):
        """测试 version 命令"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "3.1.0" in result.output

    def test_cli_scan_help(self):
        """测试 scan 子命令 help"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--full" in result.output
        assert "--ports" in result.output

    def test_cli_detect_help(self):
        """测试 detect 子命令 help"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["detect", "--help"])
        assert result.exit_code == 0
        assert "--category" in result.output

    def test_cli_exploit_help(self):
        """测试 exploit 子命令 help"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["exploit", "--help"])
        assert result.exit_code == 0
        assert "--cve" in result.output
        assert "--auto" in result.output

    def test_cli_pentest_help(self):
        """测试 pentest 子命令 help"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["pentest", "--help"])
        assert result.exit_code == 0
        assert "--resume" in result.output
        assert "--timeout" in result.output

    def test_cli_report_help(self):
        """测试 report 子命令 help"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output

    def test_cli_scan_with_full(self):
        """测试 scan --full 执行"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()

        mock_result = {"dns": {"ip": "1.2.3.4"}, "ports": [80]}

        with patch("autort.Scanner") as MockScanner:
            mock_scanner = MagicMock()
            mock_scanner.full_recon = AsyncMock(return_value=mock_result)
            MockScanner.return_value = mock_scanner

            result = runner.invoke(app, ["scan", "http://example.com", "--full"])

            assert result.exit_code == 0
            assert "1.2.3.4" in result.output

    def test_cli_scan_port_scan(self):
        """测试 scan 默认端口扫描"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()

        mock_result = [{"port": 80, "state": "open"}]

        with patch("autort.Scanner") as MockScanner:
            mock_scanner = MagicMock()
            mock_scanner.port_scan = AsyncMock(return_value=mock_result)
            MockScanner.return_value = mock_scanner

            result = runner.invoke(app, ["scan", "http://example.com", "--ports", "80,443"])

            assert result.exit_code == 0

    def test_cli_exploit_no_args(self):
        """测试 exploit 缺少参数退出"""
        from typer.testing import CliRunner

        from cli.main import app

        runner = CliRunner()

        result = runner.invoke(app, ["exploit", "http://example.com"])

        assert result.exit_code == 1

    def test_cli_output_to_file(self, tmp_path):
        """测试输出到文件"""
        from cli.main import _output

        output_file = tmp_path / "output.json"
        _output({"key": "value"}, str(output_file))

        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "key" in content
        assert "value" in content
