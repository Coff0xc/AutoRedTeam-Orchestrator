import json
from urllib.parse import urlparse, parse_qs

from modules.vuln_verifier import VulnerabilityVerifier


def test_prepare_request_get_merges_params():
    verifier = VulnerabilityVerifier()
    url, body, headers = verifier._prepare_request(
        url="https://example.com/path?foo=1",
        param="q",
        payload="x",
        method="GET",
        params={"id": "2"}
    )

    assert body is None
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    assert query["foo"] == ["1"]
    assert query["id"] == ["2"]
    assert query["q"] == ["x"]
    assert headers == {}


def test_prepare_request_post_form_injects_param():
    verifier = VulnerabilityVerifier()
    url, body, headers = verifier._prepare_request(
        url="https://example.com/api",
        param="id",
        payload="1",
        method="POST",
        data={"q": "test"}
    )

    assert url == "https://example.com/api"
    assert "q=test" in body
    assert "id=1" in body
    assert headers == {}


def test_prepare_request_post_json_injects_param():
    verifier = VulnerabilityVerifier()
    url, body, headers = verifier._prepare_request(
        url="https://example.com/api",
        param="id",
        payload="1",
        method="POST",
        json_data={"q": "test"}
    )

    assert url == "https://example.com/api"
    assert headers.get("Content-Type") == "application/json"
    payload = json.loads(body)
    assert payload["q"] == "test"
    assert payload["id"] == "1"
