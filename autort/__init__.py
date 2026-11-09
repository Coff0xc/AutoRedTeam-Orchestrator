"""AutoRedTeam SDK.

Scanner and Reporter import directly. Exploiter, AutoPentest, and RedTeam load
on first use so a default import does not pull experimental engines.
"""

from __future__ import annotations

import importlib
from typing import Any

from _version import __version__
from autort.report import Reporter
from autort.scanner import Scanner

__all__ = ["Scanner", "Exploiter", "AutoPentest", "RedTeam", "Reporter", "__version__"]

_LAZY_EXPORTS = {
    "Exploiter": "autort.exploiter",
    "AutoPentest": "autort.pentest",
    "RedTeam": "autort.redteam",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value
