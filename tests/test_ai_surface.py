from pathlib import Path

from core.ai_surface import SurfaceRiskLevel, scan_handler_surface


def test_scan_handler_surface_finds_tool_risk(tmp_path: Path):
    handler = tmp_path / "demo_handlers.py"
    handler.write_text(
        '''
from handlers.tooling import tool


def register_demo(mcp):
    @tool(mcp)
    async def c2_beacon_start(target: str):
        """Start a C2 beacon."""
        return {"success": True}

    @tool(mcp)
    async def health_check():
        """Return local health."""
        return {"success": True}
''',
        encoding="utf-8",
    )

    result = scan_handler_surface(tmp_path)
    by_name = {finding.tool_name: finding for finding in result.findings}

    assert result.scanned_files == 1
    assert set(by_name) == {"c2_beacon_start", "health_check"}
    assert by_name["c2_beacon_start"].risk_level == SurfaceRiskLevel.CRITICAL
    assert "critical_tool_without_critical_auth" in by_name["c2_beacon_start"].issues
    assert "target_input_without_handler_validator" in by_name["c2_beacon_start"].issues
    assert by_name["health_check"].risk_level == SurfaceRiskLevel.LOW


def test_scan_repo_ai_handlers_includes_surface_tool():
    result = scan_handler_surface("handlers/ai_handlers.py")
    names = {finding.tool_name for finding in result.findings}

    assert "ai_redteam_run_scenario" in names
    assert "ai_surface_scan_handlers" in names
    assert result.to_dict()["summary"]["tools_scanned"] >= 5
    assert result.to_dict()["summary"]["risk_counts"]["moderate"] >= 1


def test_scan_handler_surface_ignores_target_config_dict_false_positive(tmp_path: Path):
    handler = tmp_path / "orchestration_handlers.py"
    handler.write_text(
        '''
from typing import Any, Dict, Optional
from handlers.tooling import tool


def register_demo(mcp):
    @tool(mcp)
    async def exploit_vulnerability(
        detection_result: Dict[str, Any],
        targets: Optional[Dict[str, Any]] = None,
    ):
        """Exploit with target option config, not raw URL targets."""
        return {"success": True}

    @tool(mcp)
    async def poc_list(keyword: str = ""):
        """List local PoC templates."""
        return {"success": True}
''',
        encoding="utf-8",
    )

    result = scan_handler_surface(tmp_path)
    by_name = {finding.tool_name: finding for finding in result.findings}

    assert by_name["exploit_vulnerability"].issues == [
        "high_risk_tool_without_dangerous_auth"
    ]
    assert "target_input_without_handler_validator" not in by_name["exploit_vulnerability"].issues
    assert by_name["poc_list"].risk_level == SurfaceRiskLevel.LOW
    assert by_name["poc_list"].issues == []


def test_scan_repo_handlers_has_no_surface_issues():
    result = scan_handler_surface("handlers")

    assert result.to_dict()["summary"]["issue_count"] == 0
