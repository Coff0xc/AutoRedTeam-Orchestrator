from unittest.mock import MagicMock

import pytest


def _register_ai_tools():
    from handlers.ai_handlers import register_ai_tools

    mock_mcp = MagicMock()
    mock_counter = MagicMock()
    mock_logger = MagicMock()
    registered_tools = {}

    def capture_tool(**_kwargs):
        def decorator(func):
            registered_tools[func.__name__] = func
            return func

        return decorator

    mock_mcp.tool = capture_tool
    register_ai_tools(mock_mcp, mock_counter, mock_logger)
    return registered_tools, mock_counter, mock_logger


def test_register_ai_tools_count():
    _, mock_counter, mock_logger = _register_ai_tools()

    mock_counter.add.assert_called_once_with("ai", 5)
    assert any("5 个AI辅助工具" in str(call) for call in mock_logger.info.call_args_list)


@pytest.mark.asyncio
async def test_ai_redteam_run_scenario_from_dict_dry_run():
    registered_tools, _, _ = _register_ai_tools()

    result = await registered_tools["ai_redteam_run_scenario"](
        scenario={
            "name": "mcp-dry-run",
            "mode": "dry-run",
            "targets": [{"id": "demo-agent", "type": "text"}],
            "probes": ["prompt_injection", "tool_injection"],
            "strategies": ["direct"],
            "scorers": ["unsafe_tool_call_detector"],
        }
    )

    assert result["success"] is True
    assert result["data"]["summary"]["attempts_planned"] == 2
    assert result["data"]["summary"]["scores"] == 2
    assert result["data"]["run_state"]["summary"]["action_status"]["skipped"] == 2
    assert result["data"]["run_state"]["flow"]["tasks"][0]["actions"][0]["policy"][
        "network_policy"
    ] == "deny"


@pytest.mark.asyncio
async def test_ai_redteam_run_scenario_rejects_missing_input():
    registered_tools, _, _ = _register_ai_tools()

    result = await registered_tools["ai_redteam_run_scenario"]()

    assert result["success"] is False
    assert result["error_type"] == "ValueError"
    assert "Provide either scenario or scenario_path" in result["error"]


@pytest.mark.asyncio
async def test_high_risk_ai_tools_require_authorization_without_api_key(monkeypatch):
    from core.security.mcp_auth_middleware import AuthMode, _auth_config

    registered_tools, _, _ = _register_ai_tools()
    monkeypatch.delenv("AUTOREDTEAM_API_KEY", raising=False)
    monkeypatch.delenv("MCP_API_KEY", raising=False)
    original_mode = _auth_config["mode"]
    _auth_config["mode"] = AuthMode.STRICT

    try:
        payload_result = await registered_tools["smart_payload"](vuln_type="xss")
        chain_result = await registered_tools["attack_chain_plan"](target="http://example.com")
    finally:
        _auth_config["mode"] = original_mode

    assert payload_result["success"] is False
    assert chain_result["success"] is False
    assert payload_result["data"]["code"] == "AUTH_REQUIRED"
    assert chain_result["data"]["code"] == "AUTH_REQUIRED"
    assert "CRITICAL/DANGEROUS" in payload_result["error"]
    assert "CRITICAL/DANGEROUS" in chain_result["error"]


@pytest.mark.asyncio
async def test_ai_surface_scan_handlers_static_scan():
    registered_tools, _, _ = _register_ai_tools()

    result = await registered_tools["ai_surface_scan_handlers"](path="handlers/ai_handlers.py")

    assert result["success"] is True
    assert result["data"]["summary"]["tools_scanned"] >= 5
    assert result["data"]["summary"]["risk_counts"]["moderate"] >= 1
    assert result["data"]["summary"]["issue_count"] == 0
    names = {finding["tool_name"] for finding in result["data"]["findings"]}
    assert "ai_surface_scan_handlers" in names
