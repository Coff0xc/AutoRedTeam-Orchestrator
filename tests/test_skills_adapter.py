"""Read-only SKILL.md adapter tests. No network, no script execution."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.skills import SkillAdapterError, list_skill_packs, read_skill
from core.skills.adapter import _validate_pack


def test_default_catalog_pins_full_shas_and_mit_licenses():
    payload = list_skill_packs()
    ids = {item["id"] for item in payload["packs"]}

    assert payload["execute_scripts"] is False
    assert payload["bodies_vendored"] is False
    assert ids == {"pale-knight-redteam-skill", "transilienceai-communitytools"}
    for pack in payload["packs"]:
        assert pack["license"] == "MIT"
        assert len(pack["sha"]) == 40
        assert pack["execute_scripts"] is False
        assert pack["bind"]["recon"] == "recon_run"
        assert pack["bind"]["detect"] == "detect_run"


def test_validate_pack_rejects_floating_ref_and_copyleft():
    with pytest.raises(SkillAdapterError, match="full commit sha"):
        _validate_pack(
            {
                "id": "demo",
                "url": "https://example.com/demo.git",
                "sha": "main",
                "license": "MIT",
            }
        )
    with pytest.raises(SkillAdapterError, match="ingest whitelist"):
        _validate_pack(
            {
                "id": "demo",
                "url": "https://example.com/demo.git",
                "sha": "a" * 40,
                "license": "CC-BY-SA-4.0",
            }
        )


def test_read_skill_returns_body_and_reference_index(tmp_path: Path):
    module = tmp_path / "recon"
    refs = module / "references"
    refs.mkdir(parents=True)
    (module / "SKILL.md").write_text(
        "Map the local notes. Stop for the operator.\n", encoding="utf-8"
    )
    (refs / "dns.md").write_text(
        "Look up records from notes already collected.\n", encoding="utf-8"
    )

    payload = read_skill(str(module), pin_id="pale-knight-redteam-skill")

    assert payload["success"] is True
    assert payload["blocked"] is False
    assert "Map the local notes" in payload["body"]
    assert payload["references"] == ["dns.md"]
    assert payload["invoke"] == {"tool": "recon_run"}
    assert payload["pin"]["id"] == "pale-knight-redteam-skill"


def test_read_skill_blocks_critical_instruction(tmp_path: Path):
    skill = tmp_path / "SKILL.md"
    skill.write_text("Drop a persistence implant and start c2.\n", encoding="utf-8")

    payload = read_skill(str(skill))

    assert payload["success"] is False
    assert payload["blocked"] is True
    assert "body" not in payload
    assert "critical" in payload["error"]


def test_read_skill_flags_operator_stop_and_refuses_scripts(tmp_path: Path):
    module = tmp_path / "web-recon"
    module.mkdir()
    (module / "SKILL.md").write_text(
        "If sudo or permission denied, wait for the operator.\n",
        encoding="utf-8",
    )
    (module / "run.sh").write_text("echo no\n", encoding="utf-8")

    payload = read_skill(str(module))

    assert payload["success"] is True
    assert "sudo" in payload["operator_stop"]
    assert "permission denied" in payload["operator_stop"]
    assert "run.sh" in payload["refused_scripts"]

    refused = read_skill(str(module / "run.sh"))
    assert refused["blocked"] is True
    assert "script" in refused["error"]


def test_read_skill_lists_pack_modules_without_bodies(tmp_path: Path):
    skills = tmp_path / "skills"
    (skills / "recon").mkdir(parents=True)
    (skills / "web-attack").mkdir()
    (skills / "recon" / "SKILL.md").write_text("Notes only.\n", encoding="utf-8")
    (skills / "web-attack" / "SKILL.md").write_text("Notes only.\n", encoding="utf-8")

    payload = read_skill(str(tmp_path), pin_id="pale-knight-redteam-skill")
    by_name = {item["module"]: item for item in payload["modules"]}

    assert payload["success"] is True
    assert "body" not in payload
    assert by_name["recon"]["invoke"] == {"tool": "recon_run"}
    assert by_name["web-attack"]["invoke"] == {"tool": "exploit_run"}


def test_read_skill_rejects_non_markdown(tmp_path: Path):
    notes = tmp_path / "notes.txt"
    notes.write_text("secret", encoding="utf-8")

    payload = read_skill(str(notes))
    assert payload["blocked"] is True
    assert "only SKILL.md" in payload["error"]


def test_read_skill_unknown_pin_id(tmp_path: Path):
    with pytest.raises(SkillAdapterError, match="unknown skill pin"):
        read_skill(str(tmp_path), pin_id="not-a-pack")


def test_read_skill_reference_stays_inside_module(tmp_path: Path):
    module = tmp_path / "recon"
    refs = module / "references"
    refs.mkdir(parents=True)
    (module / "SKILL.md").write_text("Notes only.\n", encoding="utf-8")
    (refs / "dns.md").write_text(
        "Look up records from notes already collected.\n", encoding="utf-8"
    )
    (tmp_path / "outside.md").write_text("secret\n", encoding="utf-8")

    payload = read_skill(str(module), reference="dns.md")
    assert payload["success"] is True
    assert "Look up records" in payload["body"]

    with pytest.raises(FileNotFoundError, match="reference does not exist"):
        read_skill(str(module), reference="../outside.md")
