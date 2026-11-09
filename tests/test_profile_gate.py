"""Shared capability-profile gate for CLI and SDK entry points."""

from __future__ import annotations

import builtins
from unittest.mock import AsyncMock, patch

import pytest

from core.capability_manifest import (
    CAPABILITY_PROFILE_ENV,
    CapabilityManifestError,
    ProfileDenied,
    require_surface,
)


def _block_import(monkeypatch, module_name: str) -> list[str]:
    imported: list[str] = []
    real_import = builtins.__import__

    def guarded(name, globals=None, locals=None, fromlist=(), level=0):
        if name == module_name:
            imported.append(name)
            raise AssertionError(f"{module_name} imported")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded)
    return imported


def test_explicit_profile_overrides_environment(monkeypatch):
    monkeypatch.setenv(CAPABILITY_PROFILE_ENV, "safe")

    assert require_surface("port_scan", profile="scan") == "scan"
    with pytest.raises(ProfileDenied) as denied:
        require_surface("port_scan")

    assert denied.value.profile == "safe"
    assert denied.value.required_profile == "scan"
    assert CAPABILITY_PROFILE_ENV in str(denied.value)


def test_unknown_surface_still_fails_closed():
    with pytest.raises(CapabilityManifestError):
        require_surface("not_a_surface")


def test_detect_run_and_tool_search_profile_gates(monkeypatch):
    monkeypatch.delenv(CAPABILITY_PROFILE_ENV, raising=False)

    assert require_surface("tool_search") == "safe"
    with pytest.raises(ProfileDenied):
        require_surface("detect_run")
    assert require_surface("detect_run", profile="scan") == "scan"
    assert require_surface("sqli_scan", profile="scan") == "scan"


@pytest.mark.asyncio
async def test_safe_blocks_engine_imports(monkeypatch):
    monkeypatch.delenv(CAPABILITY_PROFILE_ENV, raising=False)
    blocked = (
        "core.recon.port_scanner",
        "core.recon.engine",
        "core.exploit.engine",
        "core.exploit.orchestrator",
        "core.cve.auto_exploit",
        "core.orchestrator.orchestrator",
        "core.c2.beacon",
        "core.lateral.ssh",
        "core.credential.password_finder",
        "utils.report_generator",
    )
    for module_name in blocked:
        _block_import(monkeypatch, module_name)

    from autort import AutoPentest, Exploiter, RedTeam, Reporter, Scanner

    scanner = Scanner("127.0.0.1")
    exploiter = Exploiter("127.0.0.1")
    pentest = AutoPentest("127.0.0.1")
    redteam = RedTeam()

    with pytest.raises(ProfileDenied):
        await scanner.port_scan(ports="80")
    with pytest.raises(ProfileDenied):
        await scanner.full_recon()
    with pytest.raises(ProfileDenied):
        await exploiter.exploit(object())
    with pytest.raises(ProfileDenied):
        await exploiter.auto_exploit(detections=[])
    with pytest.raises(ProfileDenied):
        await exploiter.cve_exploit("CVE-TEST-0001")
    with pytest.raises(ProfileDenied):
        await pentest.run()
    with pytest.raises(ProfileDenied):
        await pentest.resume("abc")
    with pytest.raises(ProfileDenied):
        await redteam.c2_start("127.0.0.1")
    with pytest.raises(ProfileDenied):
        await redteam.lateral_move("127.0.0.1", method="ssh")
    with pytest.raises(ProfileDenied):
        await redteam.credential_find(".")
    with pytest.raises(ProfileDenied):
        await Reporter("session").generate()

    with pytest.raises(ProfileDenied):
        redteam._get_lateral_module("ssh")


@pytest.mark.asyncio
async def test_safe_allows_local_read_surfaces(monkeypatch):
    monkeypatch.delenv(CAPABILITY_PROFILE_ENV, raising=False)

    import core.cve.search as cve_search
    import core.cve.storage as cve_storage
    import core.session.storage as session_storage
    from autort import AutoPentest, Exploiter

    class _Engine:
        def __init__(self, storage):
            self.storage = storage

        def search(self, **kwargs):
            return []

    class _Context:
        def to_dict(self):
            return {"phase": "saved"}

    class _Storage:
        def load_context(self, session_id):
            return _Context()

    monkeypatch.setattr(cve_search, "CVESearchEngine", _Engine)
    monkeypatch.setattr(cve_storage, "CVEStorage", lambda: object())
    monkeypatch.setattr(session_storage, "SessionStorage", _Storage)

    assert await Exploiter("").cve_search(keyword="apache") == []
    status = await AutoPentest("127.0.0.1").status("session")
    assert status["success"] is True


@pytest.mark.asyncio
async def test_scan_profile_allows_port_scan_after_gate(monkeypatch):
    monkeypatch.setenv(CAPABILITY_PROFILE_ENV, "scan")
    from autort import Scanner

    with patch("core.recon.port_scanner.PortScanner") as mock_scanner:
        mock_scanner.return_value.scan.return_value = []
        result = await Scanner("127.0.0.1").port_scan(ports="80")

    assert result == []


def test_cli_uses_the_same_gate(monkeypatch):
    monkeypatch.delenv(CAPABILITY_PROFILE_ENV, raising=False)
    imported = _block_import(monkeypatch, "core.recon.port_scanner")
    imported_tools = _block_import(monkeypatch, "core.tools.tool_manager")
    from typer.testing import CliRunner

    from cli.main import app

    runner = CliRunner()
    blocked = runner.invoke(app, ["scan", "127.0.0.1", "--ports", "80"])
    text = blocked.output + (blocked.stderr or "")

    assert blocked.exit_code == 2
    assert "port_scan" in text
    assert CAPABILITY_PROFILE_ENV in text
    assert imported == []

    missing_flags = runner.invoke(app, ["exploit", "127.0.0.1"])
    assert missing_flags.exit_code == 1

    for args, surface in (
        (["detect", "127.0.0.1"], "vuln_scan"),
        (["nuclei", "127.0.0.1"], "nuclei_scan"),
        (["report", "session"], "generate_report"),
        (["pentest", "127.0.0.1"], "auto_pentest"),
    ):
        result = runner.invoke(app, args)
        result_text = result.output + (result.stderr or "")
        assert result.exit_code == 2
        assert surface in result_text

    import typer

    from cli.main import tools as tools_status

    with pytest.raises(typer.Exit) as tools_exit:
        tools_status()
    assert tools_exit.value.exit_code == 2
    assert imported_tools == []

    with patch("autort.Exploiter") as mock_exploiter:
        mock_exploiter.return_value.cve_search = AsyncMock(return_value=[])
        allowed = runner.invoke(app, ["cve-search", "apache"])

    assert allowed.exit_code == 0
