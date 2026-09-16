"""工具面契约 linter 测试。

ToolResult 信封本身不再承载证据字段：领域里已有约定
（``core/detectors/result.py`` 的 ``DetectionResult``、``verify_and_exploit`` 的
``verified`` / ``verification_confidence``），信封层重复命名会吞掉工具自身的输出字段。
"""

from pathlib import Path

from core.tooling import lint_tool_contracts


def _write(tmp_path: Path, source: str) -> Path:
    handler = tmp_path / "demo_handlers.py"
    handler.write_text(source, encoding="utf-8")
    return handler


def test_lint_flags_missing_auth_and_evidence_contract(tmp_path: Path):
    _write(
        tmp_path,
        '''
from handlers.tooling import tool


def register_demo(mcp):
    @tool(mcp)
    async def lateral_psexec(target: str) -> dict:
        """Run a lateral movement action."""
        return {"success": True}
''',
    )

    result = lint_tool_contracts(tmp_path)
    rules = {issue.rule for tool in result.tools for issue in tool.issues}

    assert "critical_tool_without_critical_auth" in rules
    assert "target_input_without_handler_validator" in rules
    assert "no_evidence_contract" in rules
    assert result.summary()["errors"] >= 2


def test_lint_accepts_tool_with_full_contract(tmp_path: Path):
    _write(
        tmp_path,
        '''
from handlers.tooling import tool, validate_inputs
from core.result import ToolResult


def register_demo(mcp):
    @tool(mcp)
    @validate_inputs(target="target")
    async def dns_records(target: str) -> ToolResult:
        """查询 DNS 记录。

        Args:
            target: 目标域名
        """
        return ToolResult.ok(data={"records": []})
''',
    )

    result = lint_tool_contracts(tmp_path)
    summary = result.summary()

    assert summary["tools_scanned"] == 1
    assert summary["errors"] == 0
    assert summary["warnings"] == 0


def test_lint_accepts_evidence_fields_in_plain_dict(tmp_path: Path):
    """领域约定（返回 dict 里带 evidence/verified）同样算已声明证据契约。"""
    _write(
        tmp_path,
        '''
from handlers.tooling import tool, validate_inputs


def register_demo(mcp):
    @tool(mcp)
    @validate_inputs(target="target")
    async def dns_records(target: str) -> dict:
        """查询 DNS 记录。

        Args:
            target: 目标域名
        """
        return {"success": True, "evidence": [], "verified": False}
''',
    )

    result = lint_tool_contracts(tmp_path)
    rules = {issue.rule for tool in result.tools for issue in tool.issues}

    assert "no_evidence_contract" not in rules


def test_lint_flags_untyped_parameters_and_missing_args_doc(tmp_path: Path):
    _write(
        tmp_path,
        '''
from handlers.tooling import tool


def register_demo(mcp):
    @tool(mcp)
    async def dns_records(host):
        """查询 DNS 记录"""
        return {"success": True}
''',
    )

    result = lint_tool_contracts(tmp_path)
    rules = {issue.rule for tool in result.tools for issue in tool.issues}

    assert "untyped_parameters" in rules
    assert "missing_args_doc" in rules


def test_lint_flags_duplicate_tool_names(tmp_path: Path):
    _write(
        tmp_path,
        '''
from handlers.tooling import tool


def register_one(mcp):
    @tool(mcp)
    async def dns_records(target: str):
        """A."""
        return {"success": True}


def register_two(mcp):
    @tool(mcp)
    async def dns_records(target: str):
        """B."""
        return {"success": True}
''',
    )

    result = lint_tool_contracts(tmp_path)
    assert result.summary()["errors"] >= 1
    assert any(
        issue.rule == "duplicate_tool_name" for tool in result.tools for issue in tool.issues
    )


def test_lint_lenient_mode_skips_auth_gate_errors(tmp_path: Path):
    _write(
        tmp_path,
        '''
from handlers.tooling import tool


def register_demo(mcp):
    @tool(mcp)
    async def lateral_psexec(target: str) -> dict:
        """Run a lateral movement action."""
        return {"success": True}
''',
    )

    strict_rules = {
        i.rule
        for t in lint_tool_contracts(tmp_path, flag_missing_auth=True).tools
        for i in t.issues
    }
    lenient_rules = {
        i.rule
        for t in lint_tool_contracts(tmp_path, flag_missing_auth=False).tools
        for i in t.issues
    }

    # lenient 只放过“缺少本项目授权装饰器”这类判定，其余契约问题照旧
    assert "critical_tool_without_critical_auth" in strict_rules
    assert "critical_tool_without_critical_auth" not in lenient_rules
    assert "target_input_without_handler_validator" in lenient_rules


def test_repo_handlers_have_no_contract_errors():
    """本仓库工具面必须保持零 error 级契约问题（CI 门禁）。"""
    root = Path(__file__).resolve().parent.parent
    result = lint_tool_contracts(root / "handlers")

    summary = result.summary()
    assert summary["tools_scanned"] > 0
    assert summary["errors"] == 0, summary["tools_with_errors"]
