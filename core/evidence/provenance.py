"""HTTP request/response receipts bound to a finding as provenance.

A finding is bound when verify stored a request URL plus at least one response
signal (status, body preview, digest, or length). Scan JSON and full bodies
stay out of the world graph; the receipt keeps a short preview and a SHA-256.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, Mapping, Optional

PROVENANCE_SCHEMA = "autort.engage.provenance/v1"
_PREVIEW_LIMIT = 512
_PAYLOAD_LIMIT = 256


def build_provenance_receipt(result: Any, *, source: str = "vuln_verifier") -> Dict[str, Any]:
    """Build a compact receipt from a VerificationResult-like object."""
    url = _text(_get(result, "url"))
    payload = _text(_get(result, "payload"))[:_PAYLOAD_LIMIT]
    evidence = _text(_get(result, "evidence"))
    param = _text(_get(result, "param"))
    method = _text(_get(result, "verification_method") or _get(result, "method"))
    status = _int(_get(result, "response_code"))
    length = _int(_get(result, "response_length")) or len(evidence)
    elapsed = _float(_get(result, "response_time"))
    preview = evidence[:_PREVIEW_LIMIT]
    digest = _digest(evidence)
    request: Dict[str, Any] = {"url": url, "payload": payload}
    if param:
        request["param"] = param
    response = {
        "status": status,
        "length": length,
        "time": elapsed,
        "body_sha256": digest,
        "body_preview": preview,
    }
    return {
        "schema": PROVENANCE_SCHEMA,
        "source": source,
        "bound": _bound(url, status, preview, digest, length),
        "method": method,
        "request": request,
        "response": response,
    }


def receipt_from_results(
    results: Optional[Iterable[Any]],
    *,
    source: str = "vuln_verifier",
    finding: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Pick the first positive result, else the first row, else an unbound stub."""
    rows = [item for item in (results or []) if item is not None]
    if not rows:
        receipt = {
            "schema": PROVENANCE_SCHEMA,
            "source": source,
            "bound": False,
            "method": "",
            "request": {},
            "response": {},
        }
    else:
        chosen = next(
            (item for item in rows if _get(item, "is_vulnerable") is True),
            rows[0],
        )
        receipt = build_provenance_receipt(chosen, source=source)
    if finding and not receipt.get("request", {}).get("param"):
        param = _text(finding.get("param") if isinstance(finding, Mapping) else "")
        if param:
            request = dict(receipt.get("request") or {})
            request["param"] = param
            receipt = dict(receipt)
            receipt["request"] = request
    return receipt


def is_bound(finding: Any) -> bool:
    """True when the finding carries a stored request/response receipt."""
    if not isinstance(finding, Mapping):
        return False
    prov = finding.get("provenance")
    if not isinstance(prov, Mapping) or prov.get("bound") is not True:
        return False
    request = prov.get("request") if isinstance(prov.get("request"), Mapping) else {}
    response = prov.get("response") if isinstance(prov.get("response"), Mapping) else {}
    url = _text(request.get("url"))
    status = _int(response.get("status"))
    preview = _text(response.get("body_preview"))
    digest = _text(response.get("body_sha256"))
    length = _int(response.get("length"))
    return _bound(url, status, preview, digest, length)


def _bound(url: str, status: int, preview: str, digest: str, length: int) -> bool:
    return bool(url) and (bool(status) or bool(preview) or bool(digest) or bool(length))


def _get(source: Any, name: str) -> Any:
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _text(value: Any) -> str:
    if value is None or isinstance(value, bool):
        return ""
    return str(value)


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _digest(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
