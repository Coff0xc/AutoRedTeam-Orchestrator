"""verify_finding handler 单测。

全部验证器均被 mock，不发真实网络请求、不执行真实 payload。
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from core.vuln_verifier import StatisticalVerification, VerificationResult
from handlers.evidence_handlers import register_evidence_tools

_VERIFIER = "handlers.evidence_handlers.VulnerabilityVerifier"
_OOB_VERIFIER = "handlers.evidence_handlers.OOBIntegratedVerifier"
_STAT_VERIFIER = "handlers.evidence_handlers.StatisticalVerifier"


def _register_verify_finding():
    mcp = MagicMock()
    registered: Dict[str, Any] = {}

    def capture_tool(**_kwargs):
        def decorator(func):
            registered[func.__name__] = func
            return func

        return decorator

    mcp.tool = capture_tool
    register_evidence_tools(mcp, MagicMock(), MagicMock())
    return registered["verify_finding"]


def _verification_result(**overrides) -> VerificationResult:
    payload: Dict[str, Any] = {
        "vuln_type": "SQLi",
        "payload": "1' OR '1'='1",
        "url": "http://target.test/item?id=1",
        "is_vulnerable": True,
        "confidence": "high",
        "evidence": "timing delta 5.1s across 5 rounds",
        "response_time": 5.1,
        "response_code": 200,
        "response_length": 128,
        "verification_method": "time_based_sqli",
    }
    payload.update(overrides)
    return VerificationResult(**payload)


def _statistical_result(**overrides) -> StatisticalVerification:
    payload: Dict[str, Any] = {
        "vuln_type": "Time-based",
        "url": "http://target.test/item?id=1",
        "param": "id",
        "payload": "1 AND SLEEP(5)",
        "rounds": 10,
        "positive_count": 5,
        "confidence_score": 0.92,
        "is_confirmed": True,
        "details": [],
    }
    payload.update(overrides)
    return StatisticalVerification(**payload)


@pytest.mark.asyncio
async def test_verify_finding_success_reports_evidence():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = [_verification_result()]

    with patch(_VERIFIER, return_value=fake_verifier) as verifier_cls:
        response = await verify_finding(
            finding={"url": "http://target.test/item?id=1", "param": "id", "vuln_type": "sqli"}
        )

    assert response["success"] is True
    data = response["data"]
    assert data["verified"] is True
    assert data["verification_status"] == "verified"
    assert data["verification_confidence"] == "high"
    assert data["evidence"]
    assert data["evidence"][0]["kind"] == "statistical"
    assert data["evidence"][0]["confidence"] == "high"
    assert data["assessment"]["status"] == "verified"
    assert data["missing_checks"] == []
    verifier_cls.assert_called_once_with(timeout=10)

    # batch_verify 依据 finding["type"] 分派，确认归一化后的 type 被传入。
    forwarded = fake_verifier.batch_verify.call_args[0][0][0]
    assert forwarded["type"] == "sqli"
    assert forwarded["url"] == "http://target.test/item?id=1"


@pytest.mark.asyncio
async def test_verify_finding_failure_is_not_verified():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = [
        _verification_result(is_vulnerable=False, confidence="false_positive")
    ]

    with patch(_VERIFIER, return_value=fake_verifier):
        response = await verify_finding(
            finding={"url": "http://target.test/item?id=1", "param": "id", "vuln_type": "sqli"}
        )

    assert response["success"] is True
    data = response["data"]
    assert data["verified"] is False
    assert data["verification_status"] == "contradicted"
    assert data["verification_confidence"] == "false_positive"
    assert data["assessment"]["status"] == "contradicted"


@pytest.mark.asyncio
async def test_verify_finding_missing_url_fails_without_verifier():
    verify_finding = _register_verify_finding()

    with patch(_VERIFIER) as verifier_cls:
        response = await verify_finding(finding={"vuln_type": "sqli", "param": "id"})

    assert response["success"] is False
    assert response["error_type"] == "InvalidFinding"
    verifier_cls.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "http://",
        "ftp://target.test/item",
    ],
)
async def test_verify_finding_rejects_non_http_url(bad_url):
    """只有带主机名的 http(s) 才能进入验证器；file:// 之类不得被 urllib 打开。"""
    verify_finding = _register_verify_finding()

    with patch(_VERIFIER) as verifier_cls:
        response = await verify_finding(
            finding={"url": bad_url, "param": "id", "vuln_type": "sqli"}
        )

    assert response["success"] is False
    assert response["error_type"] == "InvalidFinding"
    verifier_cls.assert_not_called()


@pytest.mark.asyncio
async def test_verify_finding_missing_vuln_type_fails():
    verify_finding = _register_verify_finding()

    with patch(_VERIFIER) as verifier_cls:
        response = await verify_finding(finding={"url": "http://target.test/item?id=1"})

    assert response["success"] is False
    assert response["error_type"] == "InvalidFinding"
    verifier_cls.assert_not_called()


@pytest.mark.asyncio
async def test_verify_finding_no_matching_verifier_is_unverified_not_contradicted():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = []

    with patch(_VERIFIER, return_value=fake_verifier):
        response = await verify_finding(
            finding={"url": "http://target.test/item?id=1", "param": "id", "vuln_type": "ssti"}
        )

    data = response["data"]
    assert data["verified"] is False
    assert data["assessment"]["status"] == "unverified"
    assert "no verifier matched vuln_type=ssti" in data["missing_checks"]


@pytest.mark.asyncio
async def test_verify_finding_oob_no_callback_is_unverified_not_contradicted():
    """OOB 恒返回 is_vulnerable=False（未确认），不得被判成 contradicted。"""
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = []
    fake_oob = MagicMock()
    fake_oob.verify_ssrf_oob.return_value = _verification_result(
        vuln_type="SSRF (Blind/OOB)",
        verification_method="oob_callback",
        is_vulnerable=False,
        confidence="low",
        evidence="OOB callback sent. Check: http://callback.example.com/abc",
    )

    with patch(_VERIFIER, return_value=fake_verifier), patch(_OOB_VERIFIER, return_value=fake_oob):
        response = await verify_finding(
            finding={"url": "http://target.test/fetch?url=1", "param": "url", "vuln_type": "ssrf"},
            oob=True,
        )

    data = response["data"]
    assert data["verified"] is False
    assert data["verification_status"] == "unverified"
    assert data["verification_confidence"] == "low"
    assert data["assessment"]["status"] == "unverified"
    assert data["assessment"]["status"] != "contradicted"
    assert "oob callback not received" in data["missing_checks"]


@pytest.mark.asyncio
async def test_verify_finding_statistical_not_confirmed_is_unverified():
    """统计验证 is_confirmed=False 是"未确认"；它不得被门禁当成"已证伪"。"""
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = []
    fake_stat = MagicMock()
    fake_stat.verify_time_based.return_value = _statistical_result(
        is_confirmed=False, confidence_score=0.0, positive_count=0
    )

    with (
        patch(_VERIFIER, return_value=fake_verifier),
        patch(_STAT_VERIFIER, return_value=fake_stat),
    ):
        response = await verify_finding(
            finding={
                "url": "http://target.test/item?id=1",
                "param": "id",
                "payload": "1 AND SLEEP(5)",
                "vuln_type": "sqli",
            },
            deep=True,
        )

    data = response["data"]
    assert data["verified"] is False
    assert data["verification_status"] == "unverified"
    assert data["assessment"]["status"] == "unverified"
    assert "statistical verification not confirmed" in data["missing_checks"]


@pytest.mark.asyncio
async def test_verify_finding_oob_uses_oob_verifier():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = []
    fake_oob = MagicMock()
    fake_oob.verify_ssrf_oob.return_value = _verification_result(
        vuln_type="SSRF (Blind/OOB)",
        verification_method="oob_callback",
        confidence="high",
    )

    with (
        patch(_VERIFIER, return_value=fake_verifier),
        patch(_OOB_VERIFIER, return_value=fake_oob) as oob_cls,
    ):
        response = await verify_finding(
            finding={"url": "http://target.test/fetch?url=1", "param": "url", "vuln_type": "ssrf"},
            oob=True,
        )

    oob_cls.assert_called_once()
    fake_oob.verify_ssrf_oob.assert_called_once()
    assert response["data"]["verified"] is True
    methods = {item["method"] for item in response["data"]["evidence"]}
    assert "oob_callback" in methods


@pytest.mark.asyncio
async def test_verify_finding_oob_lfi_records_missing_check():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = [_verification_result(confidence="low")]

    with patch(_VERIFIER, return_value=fake_verifier), patch(_OOB_VERIFIER) as oob_cls:
        response = await verify_finding(
            finding={"url": "http://target.test/item?file=1", "param": "file", "vuln_type": "lfi"},
            oob=True,
        )

    oob_cls.assert_not_called()
    assert "oob verification unavailable for lfi" in response["data"]["missing_checks"]


@pytest.mark.asyncio
async def test_verify_finding_oob_unsupported_type_records_missing_check():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = [_verification_result(confidence="low")]

    with patch(_VERIFIER, return_value=fake_verifier), patch(_OOB_VERIFIER) as oob_cls:
        response = await verify_finding(
            finding={"url": "http://target.test/item?id=1", "param": "id", "vuln_type": "sqli"},
            oob=True,
        )

    oob_cls.assert_not_called()
    assert "oob verification unsupported for vuln_type=sqli" in response["data"]["missing_checks"]


@pytest.mark.asyncio
async def test_verify_finding_deep_adds_statistical_evidence():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = []
    fake_stat = MagicMock()
    fake_stat.verify_time_based.return_value = _statistical_result()

    with (
        patch(_VERIFIER, return_value=fake_verifier),
        patch(_STAT_VERIFIER, return_value=fake_stat),
    ):
        response = await verify_finding(
            finding={
                "url": "http://target.test/item?id=1",
                "param": "id",
                "payload": "1 AND SLEEP(5)",
                "vuln_type": "sqli",
            },
            deep=True,
        )

    fake_stat.verify_time_based.assert_called_once()
    assert response["data"]["verified"] is True
    assert response["data"]["verification_confidence"] == "high"
    assert len(response["data"]["evidence"]) == 1


@pytest.mark.asyncio
async def test_verify_finding_deep_without_payload_reports_missing_check():
    verify_finding = _register_verify_finding()
    fake_verifier = MagicMock()
    fake_verifier.batch_verify.return_value = [_verification_result(confidence="low")]

    with patch(_VERIFIER, return_value=fake_verifier), patch(_STAT_VERIFIER) as stat_cls:
        response = await verify_finding(
            finding={"url": "http://target.test/item?id=1", "param": "id", "vuln_type": "sqli"},
            deep=True,
        )

    stat_cls.assert_not_called()
    assert "deep verification requires 'param' and 'payload'" in response["data"]["missing_checks"]
