"""OWASP MCP Top 10 ledger and static mapping."""

from core.ai_surface import LEDGER_SCHEMA, owasp_mcp_ledger
from core.ai_surface.owasp import OWASP_MCP_ENTRIES


def test_ledger_covers_ten_ids_and_keeps_mcp08_a_gap():
    ledger = owasp_mcp_ledger()
    ids = [entry["id"] for entry in ledger["entries"]]

    assert ledger["schema"] == LEDGER_SCHEMA
    assert ledger["network"] is False
    assert ids == [f"MCP{index:02d}" for index in range(1, 11)]
    assert ledger["summary"]["total"] == 10
    assert ledger["summary"]["gap"] == 1
    assert (
        ledger["summary"]["implemented"] + ledger["summary"]["partial"] + ledger["summary"]["gap"]
        == 10
    )

    by_id = {entry["id"]: entry for entry in ledger["entries"]}
    assert by_id["MCP08"]["status"] == "gap"
    assert by_id["MCP08"]["coverage"] == "none"
    assert by_id["MCP08"]["rules"] == []
    assert "stdio" in by_id["MCP08"]["notes"].lower()
    assert by_id["MCP02"]["status"] == "partial"
    assert by_id["MCP01"]["status"] == "implemented"
    assert by_id["MCP05"]["status"] == "implemented"
    assert by_id["MCP07"]["status"] == "implemented"
    assert by_id["MCP09"]["status"] == "implemented"


def test_ledger_does_not_claim_a_runtime_tofu_wrapper():
    notes = " ".join(entry["notes"].lower() for entry in OWASP_MCP_ENTRIES)
    assert "tofu" in notes
    assert "does not wrap stdio" in notes


def test_ledger_rule_ids_are_unique_per_entry_except_shared_secret_schema():
    seen = {}
    for entry in OWASP_MCP_ENTRIES:
        for rule in entry["rules"]:
            seen.setdefault(rule, []).append(entry["id"])
    shared = {rule: ids for rule, ids in seen.items() if len(ids) > 1}
    assert shared == {"mcp.MCP10.secret-in-schema": ["MCP01", "MCP10"]}
