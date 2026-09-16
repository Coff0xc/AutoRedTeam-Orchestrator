"""MCTS 工具输出语义测试：模拟结果必须标注为未验证。"""

from unittest.mock import MagicMock

import pytest


def _register_mcts_tools():
    from handlers.mcts_handlers import register_mcts_tools

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
    register_mcts_tools(mock_mcp, mock_counter, mock_logger)
    return registered_tools, mock_counter


@pytest.mark.asyncio
async def test_plan_attack_path_declares_unverified_provenance():
    tools, _ = _register_mcts_tools()

    raw = await tools["plan_attack_path"](
        target="192.0.2.10",
        open_ports={"22": "ssh", "80": "http"},
        iterations=5,
    )
    payload = raw.to_dict() if hasattr(raw, "to_dict") else raw

    assert payload["data"]["verified"] is False
    assert payload["data"]["probability_source"] == "static-prior"
    assert any("BASE_SUCCESS_RATES" in note for note in payload["data"]["notes"])
    assert "recommended_actions" in payload["data"]


@pytest.mark.asyncio
async def test_plan_attack_path_marks_history_calibration(tmp_path):
    tools, _ = _register_mcts_tools()

    raw = await tools["plan_attack_path"](
        target="192.0.2.11",
        open_ports={"80": "http"},
        iterations=3,
    )
    payload = raw.to_dict() if hasattr(raw, "to_dict") else raw

    # 未传 history 时不得声称经过校准
    assert payload["data"]["probability_source"] == "static-prior"
