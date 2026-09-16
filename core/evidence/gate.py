"""证据门禁：把验证结果归一化成证据，并据此判定 finding 是否被证实。

设计约束：
- 不 import ``core.vuln_verifier``（验证器带重依赖），统一用 duck typing 探测
  属性/键名，兼容 ``VerificationResult``、``StatisticalVerification`` 和普通 dict。
- 门禁不修改调用方传入的 dict，只返回副本，避免污染上游聚合结果。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.evidence.models import (
    CONFIDENCE_LEVELS,
    EVIDENCE_KINDS,
    EvidenceAssessment,
    EvidenceItem,
)

# 数字置信度阈值：>=0.7 high，>=0.4 medium，否则 low。
_NUMERIC_HIGH = 0.7
_NUMERIC_MEDIUM = 0.4

# 未确认 finding 的标题前缀（幂等判断依据）。
UNCONFIRMED_PREFIX = "[UNCONFIRMED] "

# 独立验证来源白名单。
#
# 探测器自述的 ``verified=True`` **不算**独立验证：``core/detectors/`` 里有多处 detector
# 在只做了一次语法/回显检查后就自行写上 ``verified=True``。把这类自述当成已验证，会让
# 门禁退化成“字段填没填”，正是 P2 要消除的误报来源。详见
# ``docs/agent-refactor-plan.md`` 的设计修正记录。
PROVENANCE_SOURCES = frozenset(
    {"vuln_verifier", "statistical_verifier", "oob_callback", "manual_review"}
)

# 严重级别排序，用于把未确认 finding 降级到上限。
_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "none": 0,
}

# 从对象上尽力抽取的原始字段，用于填充 EvidenceItem.raw。
_RAW_FIELDS = (
    "vuln_type",
    "type",
    "title",
    "method",
    "verification_method",
    "payload",
    "url",
    "is_vulnerable",
    "verified",
    "confidence",
    "confidence_score",
    "evidence",
    "response_time",
    "response_code",
    "response_length",
    "recommendation",
    "timestamp",
    "rounds",
    "positive_count",
    "is_confirmed",
    "details",
    "param",
)

_MISSING = object()


def _now() -> str:
    return datetime.now().isoformat()


def _numeric_to_level(value: float) -> str:
    """把 0-1 浮点置信度映射成 high/medium/low。"""
    if value >= _NUMERIC_HIGH:
        return "high"
    if value >= _NUMERIC_MEDIUM:
        return "medium"
    return "low"


def _coerce_confidence(value: Any) -> str:
    """把任意来源的 confidence 归一化成 high/medium/low/false_positive/""。"""
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized if normalized in CONFIDENCE_LEVELS else ""
    if isinstance(value, (int, float)):
        return _numeric_to_level(float(value))
    return ""


def _is_non_empty_evidence(value: Any) -> bool:
    """判断证据字段是否"有内容"，类型奇怪时按真值近似处理，不抛异常。"""
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _infer_kind(
    method: str = "",
    *,
    statistical: bool = False,
    response_code: int = 0,
    response_time: float = 0.0,
) -> str:
    """根据验证方法名/响应特征推断证据类型。"""
    if statistical:
        return "statistical"
    lowered = (method or "").lower()
    if any(token in lowered for token in ("statistical", "time_based", "timing", "blind")):
        return "statistical"
    if any(token in lowered for token in ("oob", "callback", "dnslog", "interactsh")):
        return "oob_callback"
    if "replay" in lowered:
        return "replay"
    if any(token in lowered for token in ("command", "rce", "cmd", "exec")):
        return "command"
    if response_code or response_time:
        return "http_response"
    return "unknown"


def _fetch(source: Any, names: Tuple[str, ...], default: Any = None) -> Any:
    """按优先级从 dict 键或对象属性里取第一个非 None 值。"""
    for name in names:
        if isinstance(source, dict):
            value = source.get(name)
        else:
            value = getattr(source, name, None)
        if value is not None:
            return value
    return default


def _build_raw(source: Any) -> Dict[str, Any]:
    """收集原始字段，便于把证据回溯到具体验证器输出。"""
    if isinstance(source, dict):
        return dict(source)
    raw: Dict[str, Any] = {}
    for name in _RAW_FIELDS:
        value = getattr(source, name, None)
        if value is not None:
            raw[name] = value
    return raw


def evidence_from_verification(result: Any) -> EvidenceItem:
    """把 VerificationResult / StatisticalVerification / dict 统一转成 EvidenceItem。

    不 import 验证器本身，用 getattr/键名探测做 duck typing：
    - 含 ``is_confirmed`` / ``rounds`` / ``positive_count`` 视为统计验证；
    - 其余按 ``confidence`` / ``is_vulnerable`` / ``response_*`` 推断；
    - 完全无法识别的对象退化成 ``kind="unknown"``，不抛异常。
    """
    if result is None:
        return EvidenceItem(kind="unknown", summary="no verification object", observed_at=_now())

    vuln_type = _fetch(result, ("vuln_type", "type", "title"), "") or ""
    method = _fetch(result, ("verification_method", "method"), "") or ""
    method = method if isinstance(method, str) else str(method)
    payload = _fetch(result, ("payload",), "") or ""
    payload = payload if isinstance(payload, str) else str(payload)
    url = _fetch(result, ("url",), "") or ""
    url = url if isinstance(url, str) else str(url)
    response_code = _fetch(result, ("response_code",), 0) or 0
    response_time = _fetch(result, ("response_time",), 0.0) or 0.0
    if not isinstance(response_code, int):
        response_code = 0
    if not isinstance(response_time, (int, float)):
        response_time = 0.0

    is_statistical = _fetch(result, ("is_confirmed", "rounds", "positive_count")) is not None

    confidence = ""
    summary = ""
    if is_statistical:
        score = _fetch(result, ("confidence_score",))
        fallback_score = score if score is not None else _fetch(result, ("confidence",))
        confidence = _coerce_confidence(fallback_score)
        is_confirmed = _fetch(result, ("is_confirmed",))
        if is_confirmed is False:
            confidence = "false_positive"
        rounds = _fetch(result, ("rounds",), 0) or 0
        positive = _fetch(result, ("positive_count",), 0) or 0
        summary = (
            f"{vuln_type or 'unknown'} statistical verification: "
            f"{rounds} rounds, {positive} positive, score={score}"
        )
    else:
        confidence = _coerce_confidence(_fetch(result, ("confidence", "confidence_score")))
        is_vulnerable = _fetch(result, ("is_vulnerable", "verified"))
        if is_vulnerable is False and confidence != "false_positive":
            confidence = "false_positive"
        detail = _fetch(result, ("evidence",))
        detail_text = detail if isinstance(detail, str) else ""
        summary = (
            f"{vuln_type or 'unknown'} verification via {method or 'unknown method'}: "
            f"confidence={confidence or 'unknown'}"
        )
        if detail_text.strip():
            summary = f"{summary}; {detail_text.strip()}"

    hint_kind = _fetch(result, ("kind",))
    if isinstance(hint_kind, str) and hint_kind in EVIDENCE_KINDS:
        kind = hint_kind
    else:
        kind = _infer_kind(
            method,
            statistical=is_statistical,
            response_code=response_code,
            response_time=response_time,
        )

    observed_at = _fetch(result, ("timestamp", "observed_at", "created_at")) or _now()

    return EvidenceItem(
        kind=kind,
        method=method,
        summary=summary,
        payload=payload,
        url=url,
        response_code=int(response_code),
        response_time=float(response_time),
        confidence=confidence,
        observed_at=str(observed_at),
        raw=_build_raw(result),
    )


def _item_from_mapping(
    entry: Dict[str, Any],
    *,
    method: str,
    url: str,
    fallback_confidence: str,
) -> EvidenceItem:
    """把 evidence 列表里的一个 dict 转成 EvidenceItem。"""
    item_method = entry.get("method") or entry.get("verification_method") or method
    item_method = item_method if isinstance(item_method, str) else str(item_method)
    item_url = entry.get("url") or url
    item_url = item_url if isinstance(item_url, str) else str(item_url)
    confidence = _coerce_confidence(entry.get("confidence")) or fallback_confidence
    summary = entry.get("summary") or entry.get("description") or entry.get("message") or ""
    if not isinstance(summary, str):
        summary = str(summary)
    payload = entry.get("payload", "")
    payload = payload if isinstance(payload, str) else str(payload)
    response_code = entry.get("response_code", 0)
    response_time = entry.get("response_time", 0.0)
    kind_hint = entry.get("kind")
    kind = (
        kind_hint
        if isinstance(kind_hint, str) and kind_hint in EVIDENCE_KINDS
        else _infer_kind(
            item_method,
            response_code=response_code if isinstance(response_code, int) else 0,
            response_time=response_time if isinstance(response_time, (int, float)) else 0.0,
        )
    )
    observed_at = entry.get("timestamp") or entry.get("observed_at") or ""
    if not isinstance(observed_at, str):
        observed_at = str(observed_at)
    return EvidenceItem(
        kind=kind,
        method=item_method,
        summary=summary,
        payload=payload,
        url=item_url,
        response_code=response_code if isinstance(response_code, int) else 0,
        response_time=float(response_time) if isinstance(response_time, (int, float)) else 0.0,
        confidence=confidence,
        observed_at=observed_at,
        raw=dict(entry),
    )


def _extract_evidence_items(finding: Dict[str, Any]) -> List[EvidenceItem]:
    """从 finding["evidence"] 抽取 EvidenceItem 列表（str/list/dict/其它都兼容）。"""
    raw = finding.get("evidence")
    if not _is_non_empty_evidence(raw):
        return []

    method = finding.get("verification_method") or finding.get("method") or ""
    method = method if isinstance(method, str) else str(method)
    url = finding.get("url") or ""
    url = url if isinstance(url, str) else str(url)
    confidence = _coerce_confidence(finding.get("confidence"))

    items: List[EvidenceItem] = []
    if isinstance(raw, str):
        items.append(
            EvidenceItem(
                kind=_infer_kind(method),
                method=method,
                summary=raw.strip(),
                url=url,
                confidence=confidence,
            )
        )
    elif isinstance(raw, dict):
        items.append(
            _item_from_mapping(raw, method=method, url=url, fallback_confidence=confidence)
        )
    elif isinstance(raw, (list, tuple, set)):
        for entry in raw:
            if isinstance(entry, dict):
                mapping_item = _item_from_mapping(
                    entry, method=method, url=url, fallback_confidence=confidence
                )
                items.append(mapping_item)
            elif isinstance(entry, str):
                if entry.strip():
                    items.append(
                        EvidenceItem(
                            kind=_infer_kind(method),
                            method=method,
                            summary=entry.strip(),
                            url=url,
                            confidence=confidence,
                        )
                    )
            elif entry is not None:
                items.append(
                    EvidenceItem(
                        kind="unknown",
                        method=method,
                        summary=str(entry),
                        url=url,
                        confidence=confidence,
                        raw={"value": entry},
                    )
                )
    else:
        items.append(
            EvidenceItem(
                kind="unknown",
                method=method,
                summary=str(raw),
                url=url,
                confidence=confidence,
                raw={"value": raw},
            )
        )
    return items


def _confidence_reading(raw: Any) -> Tuple[str, Optional[str]]:
    """返回 (归一化置信度, 不达标原因)。

    字符串 high/medium 达标；low 记为"低于阈值"；false_positive 标记为矛盾；
    数字按阈值映射；缺失或无法识别给出具体原因。
    """
    if raw is None:
        return "", "confidence missing"
    if isinstance(raw, bool):
        return "", "confidence missing"
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in ("high", "medium"):
            return normalized, None
        if normalized == "false_positive":
            return "false_positive", "verification reported contradiction"
        if normalized == "low":
            return "low", "confidence below threshold"
        return "", "confidence missing"
    if isinstance(raw, (int, float)):
        level = _numeric_to_level(float(raw))
        if level in ("high", "medium"):
            return level, None
        return level, "confidence below threshold"
    return "", "confidence missing"


def _has_provenance(finding: Dict[str, Any], items: List[EvidenceItem]) -> bool:
    """判断证据是否来自独立验证，而不是调用方自述。

    满足任一即可：
    - ``finding["verified_by"]`` 命中 ``PROVENANCE_SOURCES``（验证器主动声明来源）；
    - 至少一条结构化证据带非空 ``method``（``core.vuln_verifier`` 的
      ``VerificationResult`` 经 ``evidence_from_verification`` 转换后会带上它）。

    局限：门禁在进程内只能做保守判定，无法防住恶意伪造。它解决的是“探测器自述”
    与“验证器观测”混淆的问题，不是“谁能写 finding”的权限问题。
    """
    explicit = finding.get("verified_by")
    if isinstance(explicit, str) and explicit.strip().lower() in PROVENANCE_SOURCES:
        return True
    return any(item.method.strip() for item in items if isinstance(item.method, str))


def assess_finding(
    finding: Dict[str, Any], *, require_provenance: bool = True
) -> EvidenceAssessment:
    """判定一个 finding 的证据状态。判据严格如下：

    - contradicted: ``finding["verified"] is False``，或 confidence 是 "false_positive"
    - verified:     ``verified is True`` 且 confidence ∈ {"high","medium"} 且 evidence 非空
      **且**有独立验证来源（见 ``_has_provenance``）；``require_provenance=False``
      时退回只看前三个条件
    - 其它（包括没有 verified 字段、confidence 是数字但 < 0.7、或 confidence 缺失）: unverified
    - 数字 confidence：>= 0.7 视为 high，>= 0.4 视为 medium，否则 low
    - missing_checks 具体化，例如 "verified flag missing" / "no evidence attached" /
      "confidence below threshold" / "verification reported contradiction" /
      "no independent verification provenance"

    非 dict 输入退化成 unverified，不抛异常。
    """
    if not isinstance(finding, dict):
        return EvidenceAssessment(
            status="unverified",
            confidence="",
            evidence=[],
            missing_checks=["verified flag missing"],
            reason="finding payload is not a mapping",
        )

    verified = finding.get("verified", _MISSING)
    level, confidence_issue = _confidence_reading(finding.get("confidence"))
    items = _extract_evidence_items(finding)
    has_evidence = bool(items)

    if verified is False or level == "false_positive":
        return EvidenceAssessment(
            status="contradicted",
            confidence="false_positive",
            evidence=items,
            missing_checks=["verification reported contradiction"],
            reason=(
                "verification reported a contradiction "
                "(verified=False or confidence=false_positive)"
            ),
        )

    if verified is True and level in ("high", "medium") and has_evidence:
        if require_provenance and not _has_provenance(finding, items):
            return EvidenceAssessment(
                status="unverified",
                confidence=level,
                evidence=items,
                missing_checks=["no independent verification provenance"],
                reason=(
                    "caller-declared verification without an independent source: "
                    "verified_by is missing/unknown and no evidence item carries a "
                    "verification method"
                ),
            )
        return EvidenceAssessment(
            status="verified",
            confidence=level,
            evidence=items,
            missing_checks=[],
            reason=f"verified with {level} confidence and {len(items)} evidence item(s)",
        )

    missing_checks: List[str] = []
    if verified is not True and verified is not False:
        missing_checks.append("verified flag missing")
    if not has_evidence:
        missing_checks.append("no evidence attached")
    if confidence_issue is not None:
        missing_checks.append(confidence_issue)

    return EvidenceAssessment(
        status="unverified",
        confidence=level,
        evidence=items,
        missing_checks=missing_checks,
        reason="evidence gate not satisfied: " + "; ".join(missing_checks or ["unknown"]),
    )


def _severity_rank(value: Any) -> Optional[int]:
    """把严重级别映射成可比较的序号，无法识别返回 None。"""
    if not isinstance(value, str):
        return None
    return _SEVERITY_ORDER.get(value.strip().lower())


def enforce_evidence_gate(
    finding: Dict[str, Any],
    *,
    max_unverified_severity: str = "medium",
    require_provenance: bool = True,
) -> Tuple[Dict[str, Any], EvidenceAssessment]:
    """应用证据门禁，返回 (处理后的 finding 副本, assessment)。**不修改传入的字典**。

    - ``assessment.accepted()`` 为 True：原样返回副本，不改 severity/标题。
    - 否则：severity 高于 ``max_unverified_severity`` 时降级到该上限；
      在 title/type/name 前加 "[UNCONFIRMED] "（幂等）；写入
      ``verification_status`` 与 ``missing_checks``。
    - ``require_provenance=False`` 时退回只看自述字段（仅供兼容旧行为，不推荐）。
    - 任何奇怪输入（非 dict、字段类型不对）都退化成 unverified，不抛异常。
    """
    assessment = assess_finding(finding, require_provenance=require_provenance)
    if not isinstance(finding, dict):
        return {}, assessment

    processed = dict(finding)
    if assessment.accepted():
        return processed, assessment

    cap = _severity_rank(max_unverified_severity)
    cap_value = (
        max_unverified_severity.strip().lower() if isinstance(max_unverified_severity, str) else ""
    )
    rank = _severity_rank(processed.get("severity"))
    if rank is not None and cap is not None and rank > cap and cap_value in _SEVERITY_ORDER:
        processed["severity"] = cap_value

    # 只给展示用标题加前缀：type/name 会被下游用于分组与统计，加了前缀会弄脏分组键。
    # 优先 title；没有 title 时退到 name（type 始终不动）。
    for key in ("title", "name"):
        value = processed.get(key)
        if (
            isinstance(value, str)
            and value.strip()
            and not value.lstrip().startswith(UNCONFIRMED_PREFIX)
        ):
            processed[key] = UNCONFIRMED_PREFIX + value
            break

    processed["verification_status"] = assessment.status
    processed["missing_checks"] = list(assessment.missing_checks)
    return processed, assessment
