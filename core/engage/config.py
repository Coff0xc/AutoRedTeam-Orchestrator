"""Engagement config: one authorized target, one permission level, one run file."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urlparse

import yaml

from core.capability_manifest import normalize_profile

ENGAGE_SCHEMA = "autort.engage/v1"
DEFAULT_CONFIG_PATH = Path(".autort") / "engage.yaml"
DEFAULT_STATE_PATH = Path(".autort") / "state.json"
DEFAULT_PHASES = ("recon", "detect", "verify", "export")
ALLOWED_PHASES = frozenset(DEFAULT_PHASES)
ALLOWED_HITL = frozenset({"off", "approval", "review_edit"})


class EngagementError(ValueError):
    """Invalid engagement document or phase list."""


@dataclass
class EngagementConfig:
    """Local engagement file written by ``autort engage init``."""

    target: str
    profile: str = "scan"
    name: str = "engage"
    phases: tuple[str, ...] = DEFAULT_PHASES
    classes: tuple[str, ...] = ()
    recon_modules: tuple[str, ...] = ()
    hitl: str = "off"
    scope_mode: str = "enforce"
    allowlist: tuple[str, ...] = ()
    output_dir: str = ".autort"
    max_steps: int = 16
    quick_mode: bool = True
    use_model: bool = False
    schema: str = ENGAGE_SCHEMA

    def __post_init__(self) -> None:
        self.target = str(self.target or "").strip()
        if not self.target:
            raise EngagementError("engagement target is empty")
        self.profile = normalize_profile(self.profile)
        if self.profile == "safe":
            raise EngagementError(
                "engagement profile must be scan, active-lab, or full; "
                "safe cannot contact a target"
            )
        self.hitl = str(self.hitl or "off").strip().lower().replace("-", "_")
        if self.hitl not in ALLOWED_HITL:
            raise EngagementError("hitl must be off, approval, or review_edit")
        self.scope_mode = str(self.scope_mode or "enforce").strip().lower()
        if self.scope_mode not in {"off", "enforce"}:
            raise EngagementError("scope_mode must be off or enforce")
        self.phases = _normalize_names(self.phases, ALLOWED_PHASES, "phase")
        if not self.phases:
            self.phases = DEFAULT_PHASES
        self.classes = _normalize_names(self.classes, None, "class")
        self.recon_modules = _normalize_names(self.recon_modules, None, "recon module")
        self.allowlist = tuple(self.allowlist) or default_allowlist(self.target)
        self.max_steps = max(1, int(self.max_steps))
        self.schema = ENGAGE_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["phases"] = list(self.phases)
        payload["classes"] = list(self.classes)
        payload["recon_modules"] = list(self.recon_modules)
        payload["allowlist"] = list(self.allowlist)
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EngagementConfig":
        if not isinstance(data, Mapping):
            raise EngagementError("engagement document must be a mapping")
        schema = str(data.get("schema") or ENGAGE_SCHEMA).strip()
        if schema and schema != ENGAGE_SCHEMA:
            raise EngagementError("unsupported engagement schema %r" % schema)
        return cls(
            target=str(data.get("target") or ""),
            profile=str(data.get("profile") or "scan"),
            name=str(data.get("name") or "engage"),
            phases=tuple(data.get("phases") or DEFAULT_PHASES),
            classes=tuple(data.get("classes") or ()),
            recon_modules=tuple(data.get("recon_modules") or ()),
            hitl=str(data.get("hitl") or "off"),
            scope_mode=str(data.get("scope_mode") or "enforce"),
            allowlist=tuple(data.get("allowlist") or ()),
            output_dir=str(data.get("output_dir") or ".autort"),
            max_steps=int(data.get("max_steps") or 16),
            quick_mode=bool(data.get("quick_mode", True)),
            use_model=bool(data.get("use_model", False)),
        )


def default_allowlist(target: str) -> tuple[str, ...]:
    """Host, URL, and loopback CIDR entries for one engagement target."""
    host = host_from_target(target)
    entries = [target.strip(), host]
    if host in {"127.0.0.1", "localhost", "::1"}:
        entries.extend(["127.0.0.1", "127.0.0.0/8", "localhost"])
    seen: list[str] = []
    for item in entries:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.append(text)
    return tuple(seen)


def host_from_target(target: str) -> str:
    text = str(target or "").strip()
    if text.startswith(("http://", "https://")):
        return urlparse(text).hostname or text
    return text.split("/")[0]


def config_path(path: Optional[str | Path] = None) -> Path:
    return Path(path) if path is not None else Path(DEFAULT_CONFIG_PATH)


def state_path(config: EngagementConfig) -> Path:
    return Path(config.output_dir) / "state.json"


def load_config(path: Optional[str | Path] = None) -> EngagementConfig:
    document = config_path(path)
    if not document.is_file():
        raise EngagementError("engagement file not found: %s" % document)
    raw = yaml.safe_load(document.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise EngagementError("engagement file must contain a mapping")
    return EngagementConfig.from_dict(raw)


def save_config(config: EngagementConfig, path: Optional[str | Path] = None) -> Path:
    document = config_path(path)
    document.parent.mkdir(parents=True, exist_ok=True)
    document.write_text(
        yaml.safe_dump(config.to_dict(), sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return document


def _normalize_names(
    values: Sequence[Any] | str | None,
    allowed: Optional[frozenset[str]],
    label: str,
) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        parts = [part.strip() for part in values.replace(";", ",").split(",")]
    else:
        parts = [str(item).strip() for item in values]
    names = tuple(part for part in parts if part)
    if allowed is None:
        return names
    unknown = [name for name in names if name not in allowed]
    if unknown:
        raise EngagementError("unknown %s %s; allowed: %s" % (label, unknown, sorted(allowed)))
    return names
