"""Read-only SKILL.md adapter.

Pinned packs are metadata only. This module never clones, never vendors skill
bodies, and never executes third-party scripts. A local checkout is scanned
before SKILL.md or a references/*.md file is returned.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from core.ai_surface import scan_skill_surface
from core.ai_surface.models import SurfaceRiskLevel

DISTRIBUTABLE_LICENSES = frozenset({"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause"})
FLOATING_REFS = frozenset({"", "main", "master", "head", "latest", "origin/main"})
OPERATOR_STOP_MARKERS = ("sudo", "password", "listener", "permission denied")
SCRIPT_SUFFIXES = frozenset(
    {".py", ".sh", ".ps1", ".exe", ".bat", ".cmd", ".js", ".mjs", ".bin", ".so", ".dll"}
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$", re.IGNORECASE)
_SKILL_NAME = "SKILL.md"
_PINS_PATH = Path(__file__).with_name("pins.yaml")

_RECON_HINTS = ("recon", "osint", "techstack")
_EXPLOIT_HINTS = ("attack", "privesc", "creds", "post", "shell", "tunnel", "edr", "c2")
_VERIFY_HINTS = ("coordination", "validator", "engagement")


class SkillAdapterError(ValueError):
    """Raised when a pin table or skill path is not readable under policy."""


def _stage_for(module: str) -> str:
    key = module.strip().lower().replace("_", "-")
    if any(hint in key for hint in _RECON_HINTS):
        return "recon"
    if any(hint in key for hint in _EXPLOIT_HINTS):
        return "exploit"
    if any(hint in key for hint in _VERIFY_HINTS):
        return "verify"
    return "detect"


def _bind_tool(module: str, bind: dict[str, str]) -> str:
    stage = _stage_for(module)
    return bind.get(module) or bind.get(stage) or "detect_run"


def _validate_pack(raw: dict[str, Any]) -> dict[str, Any]:
    pack_id = str(raw.get("id") or "").strip()
    url = str(raw.get("url") or "").strip()
    sha = str(raw.get("sha") or "").strip()
    license_id = str(raw.get("license") or "").strip()
    if not pack_id or not url:
        raise SkillAdapterError("skill pin is missing id or url")
    if sha.lower() in FLOATING_REFS or not _SHA_RE.fullmatch(sha):
        raise SkillAdapterError(f"skill pin {pack_id!r} must use a full commit sha, not {sha!r}")
    if license_id not in DISTRIBUTABLE_LICENSES:
        raise SkillAdapterError(
            f"skill pin {pack_id!r} license {license_id!r} is not on the ingest whitelist"
        )
    bind = raw.get("bind") or {}
    if not isinstance(bind, dict):
        raise SkillAdapterError(f"skill pin {pack_id!r} bind must be a mapping")
    return {
        "id": pack_id,
        "url": url,
        "sha": sha.lower(),
        "license": license_id,
        "modules_root": str(raw.get("modules_root") or "skills"),
        "bind": {str(key): str(value) for key, value in bind.items()},
        "execute_scripts": False,
    }


@functools.lru_cache(maxsize=1)
def _load_packs() -> tuple[dict[str, Any], ...]:
    try:
        payload = yaml.safe_load(_PINS_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SkillAdapterError(f"skill pin table is unreadable: {exc}") from exc
    packs = payload.get("packs") if isinstance(payload, dict) else None
    if not isinstance(packs, list) or not packs:
        raise SkillAdapterError("skill pin table has no packs")
    return tuple(_validate_pack(item) for item in packs if isinstance(item, dict))


def list_skill_packs() -> dict[str, Any]:
    """Return the distributable pin catalog. No skill bodies, no git fetch."""
    packs = [_validate_pack(dict(item)) for item in _load_packs()]
    return {
        "packs": packs,
        "execute_scripts": False,
        "bodies_vendored": False,
    }


def _pack_by_id(pin_id: Optional[str]) -> Optional[dict[str, Any]]:
    if not pin_id:
        return None
    for pack in _load_packs():
        if pack["id"] == pin_id:
            return pack
    raise SkillAdapterError(f"unknown skill pin {pin_id!r}")


def _is_reference_md(path: Path) -> bool:
    return path.suffix.lower() == ".md" and path.parent.name == "references"


def _skill_file(path: Path) -> Optional[Path]:
    if path.is_file() and path.name == _SKILL_NAME:
        return path
    if path.is_dir() and (path / _SKILL_NAME).is_file():
        return path / _SKILL_NAME
    return None


def _module_dirs(path: Path) -> list[Path]:
    skill = _skill_file(path)
    if skill is not None:
        return [skill.parent]
    roots = [path]
    nested = path / "skills"
    if nested.is_dir():
        roots.append(nested)
    modules: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            children = sorted(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir() or child in seen:
                continue
            if (child / _SKILL_NAME).is_file():
                seen.add(child)
                modules.append(child)
    return modules


def _operator_stop(text: str) -> list[str]:
    lowered = text.lower()
    return [marker for marker in OPERATOR_STOP_MARKERS if marker in lowered]


def _scan_markdown(path: Path) -> dict[str, Any]:
    result = scan_skill_surface(path)
    findings = [item.to_dict() for item in result.findings]
    blocked = any(
        item.risk_level == SurfaceRiskLevel.CRITICAL
        or "critical_skill_instruction_requires_review" in item.issues
        for item in result.findings
    )
    return {
        "blocked": blocked,
        "findings": findings,
        "warnings": list(result.warnings),
        "issue_count": result.issue_count(),
    }


def _refuse_script(path: Path) -> Optional[str]:
    if path.suffix.lower() in SCRIPT_SUFFIXES:
        return f"{path.name} is a script; third-party scripts are not returned or executed"
    return None


def _read_markdown(path: Path) -> dict[str, Any]:
    refused = _refuse_script(path)
    if refused:
        return {"success": False, "blocked": True, "error": refused, "path": str(path)}
    if path.name != _SKILL_NAME and not _is_reference_md(path):
        return {
            "success": False,
            "blocked": True,
            "error": "only SKILL.md or references/*.md may be read",
            "path": str(path),
        }
    scan = _scan_markdown(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    payload: dict[str, Any] = {
        "success": not scan["blocked"],
        "blocked": scan["blocked"],
        "path": str(path),
        "scan": scan,
        "operator_stop": _operator_stop(text),
        "execute_scripts": False,
    }
    if scan["blocked"]:
        payload["error"] = "critical skill instruction blocked returning the body"
        return payload
    payload["body"] = text
    return payload


def _reference_index(module_dir: Path) -> list[str]:
    refs = module_dir / "references"
    if not refs.is_dir():
        return []
    names: list[str] = []
    for child in sorted(refs.iterdir()):
        if child.is_file() and child.suffix.lower() == ".md":
            names.append(child.name)
    return names


def read_skill(
    path: str,
    *,
    pin_id: Optional[str] = None,
    reference: Optional[str] = None,
) -> dict[str, Any]:
    """Scan then return one local SKILL.md (and optional reference)."""
    pack = _pack_by_id(pin_id)
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"skill path does not exist: {root}")

    if root.is_file():
        payload = _read_markdown(root)
        if pack is not None:
            payload["pin"] = {"id": pack["id"], "sha": pack["sha"], "license": pack["license"]}
            payload["invoke"] = {"tool": _bind_tool(root.parent.name, pack["bind"])}
        return payload

    modules = _module_dirs(root)
    if not modules:
        raise SkillAdapterError(f"no SKILL.md under {root}")

    if len(modules) > 1 and _skill_file(root) is None:
        cards = []
        for module_dir in modules:
            bind = pack["bind"] if pack else {}
            cards.append(
                {
                    "module": module_dir.name,
                    "path": str(module_dir / _SKILL_NAME),
                    "invoke": {"tool": _bind_tool(module_dir.name, bind)},
                    "references": _reference_index(module_dir),
                }
            )
        return {
            "success": True,
            "blocked": False,
            "path": str(root),
            "modules": cards,
            "execute_scripts": False,
            "pin": (
                {"id": pack["id"], "sha": pack["sha"], "license": pack["license"]} if pack else None
            ),
        }

    module_dir = modules[0]
    if reference:
        ref_path = (module_dir / "references" / Path(reference).name).resolve()
        if module_dir.resolve() not in ref_path.parents:
            raise SkillAdapterError("reference path escapes the skill module")
        if not ref_path.is_file():
            raise FileNotFoundError(f"reference does not exist: {ref_path}")
        payload = _read_markdown(ref_path)
    else:
        payload = _read_markdown(module_dir / _SKILL_NAME)
        payload["references"] = _reference_index(module_dir)
        refused_scripts = [
            child.name
            for child in sorted(module_dir.rglob("*"))
            if child.is_file() and child.suffix.lower() in SCRIPT_SUFFIXES
        ]
        if refused_scripts:
            payload["refused_scripts"] = refused_scripts
    if pack is not None:
        payload["pin"] = {"id": pack["id"], "sha": pack["sha"], "license": pack["license"]}
        payload["invoke"] = {"tool": _bind_tool(module_dir.name, pack["bind"])}
    return payload
