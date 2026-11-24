"""Juice Shop confirmation-rate: mock lab contract plus optional live target."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlparse

import pytest
from typer.testing import CliRunner

from core.engage.juiceshop import (
    JUICE_SHOP_DEFAULT,
    JuiceShopError,
    identify_juice_shop,
    juice_shop_reachable,
    run_juice_shop_confirmation_rate,
    seed_findings,
)

pytestmark = [pytest.mark.unit, pytest.mark.security]
runner = CliRunner()


class _JuiceShopHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        needle = (query.get("q") or [""])[0]
        if parsed.path.rstrip("/") == "/rest/products/search":
            if any(mark in needle for mark in ("'", '"', ";")):
                body = b'{"error":{"message":"SQLITE_ERROR: near \\")\\": syntax error"}}'
                self._send(500, body, "application/json")
                return
            self._send(200, b'{"status":"success","data":[]}', "application/json")
            return
        html = b"<html><head><title>OWASP Juice Shop</title></head><body>Juice Shop</body></html>"
        self._send(200, html, "text/html; charset=utf-8")

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JuiceShopHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield "http://%s:%s" % (host, port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def juice_lab() -> Iterator[str]:
    yield from _serve()


def test_seed_findings_are_search_sqli_and_home_self_report():
    rows = seed_findings("http://127.0.0.1:3000")
    assert rows[0]["vuln_type"] == "sqli"
    assert "/rest/products/search" in rows[0]["url"]
    assert rows[1]["vuln_type"] == "xss"
    assert rows[1]["verified"] is True


def test_identify_rejects_empty_url():
    with pytest.raises(JuiceShopError):
        identify_juice_shop("")


def test_mock_lab_confirmation_rate_is_positive(juice_lab, tmp_path):
    result = run_juice_shop_confirmation_rate(juice_lab, output_dir=str(tmp_path))
    card = result["scorecard"]

    assert result["identified"] is True
    assert result["passed"] is True
    assert card["schema"] == "autort.engage.scorecard/v1"
    assert card["total"] == 2
    assert card["confirmed"] >= 1
    assert card["unconfirmed"] >= 1
    assert card["confirmation_rate"] == card["confirmed"] / card["total"]
    assert card["confirmation_rate"] > 0
    assert card["findings"][0]["proof"] in {"bound", "none"}
    bound = [row for row in card["findings"] if row["proof"] == "bound"]
    assert bound


def test_cli_confirmation_rate_on_mock_lab(juice_lab, tmp_path, monkeypatch):
    from cli.main import app

    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["engage", "confirmation-rate", "--url", juice_lab, "--ci"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["scorecard"]["confirmation_rate"] > 0


def test_cli_confirmation_rate_ci_fails_when_down():
    from cli.main import app

    result = runner.invoke(
        app,
        ["engage", "confirmation-rate", "--url", "http://127.0.0.1:9", "--ci"],
    )
    assert result.exit_code == 2


@pytest.mark.integration
@pytest.mark.network
@pytest.mark.skipif(
    not juice_shop_reachable(JUICE_SHOP_DEFAULT),
    reason="Juice Shop is not running on 127.0.0.1:3000",
)
def test_live_juice_shop_confirmation_rate(tmp_path):
    result = run_juice_shop_confirmation_rate(JUICE_SHOP_DEFAULT, output_dir=str(tmp_path))
    card = result["scorecard"]
    assert result["passed"] is True
    assert card["confirmed"] >= 1
    assert card["total"] >= 1
    assert card["confirmation_rate"] > 0
    assert card["confirmation_rate"] == card["confirmed"] / card["total"]
