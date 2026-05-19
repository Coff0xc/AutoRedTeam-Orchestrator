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
