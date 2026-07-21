"""Plugin registry view for AI red-team components.

This is a metadata registry, not a dynamic code loader. It gives promptfoo-like
plugin organization while keeping execution deterministic and local.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.ai_redteam.catalog import PROBES, SCORERS, STRATEGIES
from core.ai_redteam.converters import CONVERTERS


@dataclass(frozen=True)
class RedTeamPlugin:
    """Metadata for one local red-team plugin component."""

    plugin_id: str
    kind: str
    description: str = ""
    source: str = "builtin"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "kind": self.kind,
            "description": self.description,
            "source": self.source,
            "metadata": self.metadata,
        }


def built_in_plugins() -> List[RedTeamPlugin]:
    """Return metadata for built-in probe/converter/strategy/scorer plugins."""
    plugins: List[RedTeamPlugin] = []
    for plugin_id, metadata in sorted(PROBES.items()):
        plugins.append(
            RedTeamPlugin(
                plugin_id=plugin_id,
                kind="probe",
                description=str(metadata.get("description", "")),
                metadata=metadata,
            )
        )
    for plugin_id, metadata in sorted(CONVERTERS.items()):
        plugins.append(
            RedTeamPlugin(
                plugin_id=plugin_id,
                kind="converter",
                description=str(metadata.get("description", "")),
                metadata=metadata,
            )
        )
    for plugin_id, metadata in sorted(STRATEGIES.items()):
        plugins.append(
            RedTeamPlugin(
                plugin_id=plugin_id,
                kind="strategy",
                description=str(metadata.get("description", "")),
                metadata=metadata,
            )
        )
    for plugin_id, metadata in sorted(SCORERS.items()):
        plugins.append(
            RedTeamPlugin(
                plugin_id=plugin_id,
                kind="scorer",
                description=str(metadata.get("description", "")),
                metadata=metadata,
            )
        )
    return plugins


def plugin_summary() -> Dict[str, Any]:
    """Return promptfoo-style plugin summary for reporting and CLI/API use."""
    plugins = built_in_plugins()
    by_kind: Dict[str, int] = {}
    for plugin in plugins:
        by_kind[plugin.kind] = by_kind.get(plugin.kind, 0) + 1
    return {
        "plugins": len(plugins),
        "by_kind": by_kind,
        "items": [plugin.to_dict() for plugin in plugins],
    }
