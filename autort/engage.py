"""Engagement SDK — authorized recon/detect/verify/export loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from core.engage import EngagementConfig, async_run_engagement, init_engagement


class Engagement:
    """One authorized engagement.

    Args:
        target: Authorized URL or host
        profile: scan, active-lab, or full
        path: Engagement YAML path
    """

    def __init__(
        self,
        target: str,
        *,
        profile: str = "scan",
        path: str | Path = ".autort/engage.yaml",
        phases: Optional[Sequence[str]] = None,
        classes: Optional[Sequence[str]] = None,
        hitl: str = "off",
        quick_mode: bool = True,
    ):
        self.path = str(path)
        payload = init_engagement(
            target,
            profile=profile,
            path=self.path,
            phases=tuple(phases) if phases else None,
            classes=tuple(classes) if classes else None,
            hitl=hitl,
            quick_mode=quick_mode,
        )
        self.config = EngagementConfig.from_dict(payload["config"])

    async def run(
        self, *, dry_run: bool = False, max_steps: Optional[int] = None
    ) -> Dict[str, Any]:
        return await async_run_engagement(self.path, dry_run=dry_run, max_steps=max_steps)
