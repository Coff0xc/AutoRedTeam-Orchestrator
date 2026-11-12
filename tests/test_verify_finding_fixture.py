"""Authorized loopback lab for verify_finding.

The XSS verifier talks to a local HTTP server. Detector heuristics are not
changed. External targets are not contacted.
"""

from __future__ import annotations

import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest

from core.evidence import enforce_evidence_gate
from handlers.evidence_handlers import register_evidence_tools

pytestmark = [pytest.mark.unit, pytest.mark.security]


def _register_verify_finding():
    mcp = MagicMock()
    registered = {}

    def capture_tool(**_kwargs):
        def decorator(func):
            registered[func.__name__] = func
            return func

        return decorator

    mcp.tool = capture_tool
    register_evidence_tools(mcp, MagicMock(), MagicMock())
    return registered["verify_finding"]


def _handler(mode: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            raw = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0]
            reflected = html.escape(raw) if mode == "escaped" else raw
            body = f"<html><body><div>{reflected}</div></body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    return Handler


def _serve(mode: str) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(mode))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}/reflect"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def raw_lab() -> Iterator[str]:
    yield from _serve("raw")


@pytest.fixture
def escaped_lab() -> Iterator[str]:
    yield from _serve("escaped")


@pytest.mark.asyncio
async def test_verify_finding_confirms_reflected_xss_on_local_lab(raw_lab):
    verify_finding = _register_verify_finding()
    response = await verify_finding(
        finding={"url": f"{raw_lab}?q=test", "param": "q", "vuln_type": "xss"}
    )

    assert response["success"] is True
    data = response["data"]
    assert data["verification_status"] == "verified"
    assert data["verified"] is True
    assert data["assessment"]["status"] == "verified"
    assert data["evidence"]
    assert any(item.get("method") for item in data["evidence"])


@pytest.mark.asyncio
async def test_verify_finding_leaves_escaped_reflection_unverified(escaped_lab):
    verify_finding = _register_verify_finding()
    response = await verify_finding(
        finding={"url": f"{escaped_lab}?q=test", "param": "q", "vuln_type": "xss"}
    )

    assert response["success"] is True
    data = response["data"]
    assert data["verification_status"] == "unverified"
    assert data["verified"] is False
    assert data["assessment"]["status"] != "verified"


@pytest.mark.asyncio
async def test_detector_self_report_is_unconfirmed_until_local_verify(raw_lab):
    url = f"{raw_lab}?q=test"
    detector_finding = {
        "url": url,
        "param": "q",
        "vuln_type": "xss",
        "verified": True,
        "confidence": 0.90,
        "evidence": "<html>reflected q=test</html>",
        "severity": "high",
        "title": "Reflected XSS in q",
    }
    processed, assessment = enforce_evidence_gate(detector_finding)
    assert assessment.status == "unverified"
    assert processed["title"].startswith("[UNCONFIRMED] ")

    verify_finding = _register_verify_finding()
    response = await verify_finding(finding=detector_finding)
    data = response["data"]
    assert data["verification_status"] == "verified"
    assert data["assessment"]["status"] == "verified"

    confirmed = dict(detector_finding)
    confirmed["verified"] = True
    confirmed["confidence"] = data["verification_confidence"]
    confirmed["evidence"] = data["evidence"]
    confirmed["verified_by"] = "vuln_verifier"
    gated, gated_assessment = enforce_evidence_gate(confirmed)
    assert gated_assessment.accepted() is True
    assert gated["severity"] == "high"
    assert not gated["title"].startswith("[UNCONFIRMED] ")


@pytest.mark.asyncio
async def test_verify_finding_respects_target_allowlist(raw_lab, monkeypatch):
    verify_finding = _register_verify_finding()
    monkeypatch.setenv("AUTORT_TARGET_SCOPE", "enforce")
    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "example.com")
    denied = await verify_finding(
        finding={"url": f"{raw_lab}?q=test", "param": "q", "vuln_type": "xss"}
    )
    assert denied["success"] is False
    assert denied["error_type"] == "TargetScopeError"

    monkeypatch.setenv("AUTORT_TARGET_ALLOWLIST", "127.0.0.0/8")
    allowed = await verify_finding(
        finding={"url": f"{raw_lab}?q=test", "param": "q", "vuln_type": "xss"}
    )
    assert allowed["success"] is True
    assert allowed["data"]["verification_status"] == "verified"
