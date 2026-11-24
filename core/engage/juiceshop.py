"""Juice Shop confirmation-rate demo for an authorized local lab.

Verifies the documented product-search SQLi surface and a homepage XSS
self-report. The scorecard denominator is confirmed vs unconfirmed. This
module does not run exploit, lateral movement, or C2.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from core.engage.config import EngagementConfig, EngagementError, default_allowlist
from core.engage.runner import applied_engagement
from core.engage.scorecard import SCORECARD_SCHEMA, build_scorecard
from core.evidence import enforce_evidence_gate

JUICE_SHOP_DEFAULT = "http://127.0.0.1:3000"
SEARCH_PATH = "/rest/products/search?q=apple"
IDENTIFY_MARK = "juice shop"


class JuiceShopError(EngagementError):
    """Juice Shop is unreachable or is not the expected lab target."""


def normalize_base(url: str) -> str:
    text = str(url or "").strip().rstrip("/")
    if not text:
        raise JuiceShopError("Juice Shop URL is empty")
    parsed = urlparse(text if "://" in text else "http://%s" % text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise JuiceShopError("Juice Shop URL must be http(s) with a host")
    return "%s://%s" % (parsed.scheme, parsed.netloc)


def juice_shop_reachable(base_url: str, *, timeout: float = 3.0) -> bool:
    try:
        return bool(identify_juice_shop(base_url, timeout=timeout)["ok"])
    except (JuiceShopError, OSError, ValueError):
        return False


def identify_juice_shop(base_url: str, *, timeout: float = 3.0) -> Dict[str, Any]:
    """GET the lab root and require a Juice Shop marker. No scan profile needed."""
    base = normalize_base(base_url)
    body, status = _get(base + "/", timeout=timeout)
    snippet = body[:2000].lower()
    ok = status == 200 and IDENTIFY_MARK in snippet
    return {
        "ok": ok,
        "base": base,
        "status": status,
        "reason": "identified" if ok else "response is not OWASP Juice Shop",
    }


def run_juice_shop_confirmation_rate(
    base_url: str = JUICE_SHOP_DEFAULT,
    *,
    output_dir: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Verify known Juice Shop surfaces and return an evidence-gated scorecard."""
    identity = identify_juice_shop(base_url, timeout=timeout)
    if not identity["ok"]:
        raise JuiceShopError(
            "Juice Shop is not reachable at %s (%s). "
            "Start the lab with: docker compose -f docker-compose.lab.yml up -d"
            % (identity["base"], identity["reason"])
        )
    base = identity["base"]
    config = EngagementConfig(
        target=base,
        profile="scan",
        name="juiceshop-confirmation-rate",
        phases=("verify", "export"),
        hitl="off",
        scope_mode="enforce",
        allowlist=default_allowlist(base),
        output_dir=output_dir or ".autort",
        max_steps=8,
    )
    with applied_engagement(config):
        state = _verify_rows(base, config.output_dir)
    findings = [item for item in (state.get("findings") or []) if isinstance(item, dict)]
    gated = [enforce_evidence_gate(dict(item))[0] for item in findings]
    card = build_scorecard(gated)
    rate = card.get("confirmation_rate")
    passed = bool(card.get("confirmed")) and rate not in (None, 0, 0.0)
    return {
        "success": True,
        "passed": passed,
        "target": base,
        "identified": True,
        "schema": SCORECARD_SCHEMA,
        "scorecard": card,
        "findings": gated,
        "hint": (
            "confirmation_rate is confirmed/total after verify receipts. "
            "An empty or all-unconfirmed list is not a clean target."
        ),
    }


def seed_findings(base_url: str) -> List[Dict[str, Any]]:
    """Known lab rows: confirmable search SQLi plus an unconfirmed homepage XSS self-report."""
    base = normalize_base(base_url)
    search = urljoin(base + "/", SEARCH_PATH.lstrip("/"))
    home = urljoin(base + "/", "/")
    return [
        {
            "url": search,
            "param": "q",
            "vuln_type": "sqli",
            "title": "Juice Shop product search SQLi",
            "severity": "high",
        },
        {
            "url": home,
            "param": "q",
            "vuln_type": "xss",
            "title": "Juice Shop home XSS self-report",
            "severity": "high",
            "verified": True,
            "confidence": 0.9,
            "evidence": "detector self-report",
        },
    ]


def _verify_rows(base: str, output_dir: str) -> Dict[str, Any]:
    from core.agent_runtime.aggregators import dispatch_aggregator_step, empty_aggregator_state

    state = empty_aggregator_state()
    state["output_dir"] = output_dir
    rows = seed_findings(base)
    state["findings"] = [dict(item) for item in rows]

    async def _run() -> Dict[str, Any]:
        for item in rows:
            await dispatch_aggregator_step(
                "verify_finding",
                {"finding": item, "target": base},
                state,
                dry_run=False,
            )
        return state

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run())
    raise JuiceShopError("confirmation-rate must run from a sync caller")


def _get(url: str, *, timeout: float) -> tuple[str, int]:
    request = Request(url, method="GET", headers={"User-Agent": "AutoRedTeam-JuiceShop-Lab"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return body, int(getattr(response, "status", 200) or 200)
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise JuiceShopError(
            "Juice Shop is not reachable at %s (%s). "
            "Start the lab with: docker compose -f docker-compose.lab.yml up -d" % (url, reason)
        ) from exc
