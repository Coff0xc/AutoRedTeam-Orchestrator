from core.code_agent import expand_code_context


def test_expand_code_context_uses_seed_and_scores_risky_sink(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        """
def route_handler(target):
    return run_command(target)

def run_command(command):
    import subprocess
    return subprocess.run(command, shell=True)
""",
        encoding="utf-8",
    )

    result = expand_code_context(source, seed="run_command", max_depth=1)
    data = result.to_dict()

    assert data["seed_function"]["qualified_name"].endswith("run_command")
    assert data["summary"]["functions_scanned"] == 2
    assert data["summary"]["context_functions"] == 2
    assert data["confidence"]["level"] in {"medium", "high"}
    assert "seed_calls_risky_sink" in data["confidence"]["reasons"]


def test_expand_code_context_can_select_seed_by_file_and_line(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        """
def first():
    return second()

def second():
    return "ok"
""",
        encoding="utf-8",
    )

    result = expand_code_context(tmp_path, file_path=source, line=5, max_depth=1)

    assert result.seed_function is not None
    assert result.seed_function.qualified_name.endswith("second")
    assert any(edge.call_name == "second" for edge in result.call_edges)


def test_expand_code_context_missing_seed_falls_back_to_highest_risk(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        """
def harmless():
    return "ok"

def risky(payload):
    return eval(payload)
""",
        encoding="utf-8",
    )

    result = expand_code_context(tmp_path, seed="missing")

    assert result.seed_function is not None
    assert result.seed_function.qualified_name.endswith("risky")
    assert result.warnings
