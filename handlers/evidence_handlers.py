"""
证据验证处理器

提供: verify_finding —— 对单个 finding 跑重放/统计/OOB 验证，把验证器输出
归一化成可复核证据，并给出证据门禁判定。

分工:
- 本模块负责"跑验证器"；
- ``core.evidence`` 负责"把验证结果判成证据/门禁结论"。

验证结论只有三态：``verified`` / ``contradicted`` / ``unverified``。OOB 验证器在没收到
回调时恒返回 ``is_vulnerable=False``，语义是"未确认"而非"已证伪"，因此只有验证器显式
给出 ``confidence="false_positive"`` 才判定否定。

风险边界: verify_finding 只重放验证请求，不执行利用；仍按中等风险工具
处理，并要求调用方在授权目标上使用。
"""

from __future__ import annotations

import asyncio
import time
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from core.evidence import assess_finding, evidence_from_verification
from core.result import ToolResult
from core.security import require_moderate_auth
from core.vuln_verifier import (
    BaseVerifier,
    OOBIntegratedVerifier,
    StatisticalVerifier,
    VulnerabilityVerifier,
)
from utils.validators import validate_url

from .error_handling import ErrorCategory, handle_errors
from .tooling import tool

# OOB 验证类型 -> OOBIntegratedVerifier 方法名。
_OOB_DISPATCH = {
    "xxe": "verify_xxe_oob",
    "ssrf": "verify_ssrf_oob",
    "rce": "verify_rce_oob",
}
# 语义上属于 OOB 场景、但验证器未提供对应方法的类型（显式记录，不静默跳过）。
_OOB_TYPES_WITHOUT_METHOD = ("lfi",)

# OOB 探测的请求超时：OOB 的判据是"回调是否到达"，与本次请求耗时无关，可以放宽。
_OOB_TIMEOUT = 15

# 统计学验证的采样次数与预期延迟。
#
# ``StatisticalVerifier`` 判定"显著延迟"的门槛是 ``expected_delay * 0.8``，默认
# expected_delay=5.0 时为 4.0s。单次请求超时必须 <= 该门槛：否则目标 hang 住或 WAF
# 丢弃连接时，请求会先"超时"再被记成一个巨大的耗时样本，被 ``statistical.py`` 算成
# 显著延迟并产出假 verified（正是 P2 要消除的误报）。这里让超时与判定门槛同量级。
_STAT_EXPECTED_DELAY = 5.0
_STAT_TIMEOUT = _STAT_EXPECTED_DELAY * 0.8
_STAT_SAMPLE_SIZE = 5

# 验证器明确判定"误报/否定"时使用的置信度；它区别于"未确认"。
_FALSE_POSITIVE = "false_positive"


def _normalize_vuln_type(finding: Dict[str, Any]) -> str:
    """从 finding 里取第一个可用的漏洞类型字段并归一化成小写。"""
    for key in ("vuln_type", "type", "title"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _match_oob_type(vuln_type: str) -> str:
    """返回 vuln_type 命中的 OOB 类型 token，未命中返回空串。"""
    for token in (*_OOB_DISPATCH, *_OOB_TYPES_WITHOUT_METHOD):
        if token in vuln_type:
            return token
    return ""


def _is_positive(result: Any) -> bool:
    """验证结果是否报告"存在漏洞"，兼容 VerificationResult/StatisticalVerification/dict。"""
    if isinstance(result, dict):
        for key in ("is_vulnerable", "verified", "is_confirmed"):
            if key in result:
                return bool(result[key])
        return False
    for attr in ("is_vulnerable", "is_confirmed"):
        value = getattr(result, attr, None)
        if value is not None:
            return bool(value)
    return False


def _result_confidence(result: Any) -> str:
    """取验证结果自述的 confidence（小写字符串），无法识别返回空串。

    只读原始结果对象/字典，不读 ``evidence_from_verification`` 归一化后的证据项：后者
    会把 ``is_vulnerable=False`` 一律改写成 ``false_positive``（见 ``core/evidence/gate.py``），
    那会把"没观测到"误判成"验证器判了否定"。
    """
    if isinstance(result, dict):
        value = result.get("confidence")
    else:
        value = getattr(result, "confidence", None)
    return value.strip().lower() if isinstance(value, str) else ""


def _classify(result: Any) -> Optional[bool]:
    """把单个验证结果判成三态：True=已确认 / False=明确否定 / None=未确认。

    ``OOBIntegratedVerifier`` 的四个 OOB 方法恒返回 ``is_vulnerable=False``（源码注释
    写明"需要回调确认"），它表达的是"没有收到回调"而不是"已证伪"；只有显式的
    ``confidence="false_positive"`` 才认定为否定。
    """
    if _result_confidence(result) == _FALSE_POSITIVE:
        return False
    if _is_positive(result):
        return True
    return None


def _classify_results(results: List[Any]) -> Optional[bool]:
    """合并多个验证结果：任一正向 → True；否则任一明确否定 → False；其余 → None。"""
    if not results:
        return None
    verdicts = [_classify(result) for result in results]
    if any(verdict is True for verdict in verdicts):
        return True
    if any(verdict is False for verdict in verdicts):
        return False
    return None


def _verification_status(verified: Optional[bool]) -> str:
    """把三态结论映射成 ``verified`` / ``contradicted`` / ``unverified``。"""
    if verified is True:
        return "verified"
    if verified is False:
        return "contradicted"
    return "unverified"


def _resolve_confidence(
    results: List[Any], evidence_items: List[Any], verified: Optional[bool]
) -> str:
    """挑选写进门禁的 ``confidence``。

    - 明确否定：``false_positive``（门禁据此判 contradicted）；
    - 有正向结果：用该结果对应证据项的置信度；
    - 未确认（含 OOB 未回调）：用验证器自述置信度，且**绝不**写 ``false_positive``——
      证据归一化会把 ``is_vulnerable=False`` 写成 false_positive，照抄进门禁会让未确认
      的 finding 被判成 contradicted。
    """
    if verified is False:
        return _FALSE_POSITIVE
    for result, item in zip(results, evidence_items):
        if _classify(result) is True:
            return item.confidence or "low"
    candidates = [_result_confidence(result) for result in results]
    candidates.extend(item.confidence or "" for item in evidence_items)
    return next((value for value in candidates if value and value != _FALSE_POSITIVE), "")


_transport: Optional[BaseVerifier] = None


def _get_transport() -> BaseVerifier:
    """懒加载的请求构造器。

    复用 ``BaseVerifier`` 的浏览器 UA、关闭证书校验的 SSL 上下文以及 URL/参数拼接
    （``_prepare_base_request``）；超时与异常处理由各适配器自己决定。
    """
    global _transport
    if _transport is None:
        _transport = BaseVerifier(timeout=_OOB_TIMEOUT)
    return _transport


def _oob_request(
    url: str,
    method: str = "GET",
    params: Any = None,
    data: Any = None,
    headers: Any = None,
) -> None:
    """OOB 验证器使用的探测请求函数；失败不抛出，回调确认不依赖本次响应。

    直接复用 ``BaseVerifier._request``：它带浏览器 UA、关闭证书校验，并把网络错误吞成
    返回值——对 OOB 而言请求本身失败属于预期路径，回调是否到达才是判据。
    """
    transport = _get_transport()
    method = str(method or "GET").upper()
    target_url, body, request_headers = transport._prepare_base_request(
        url=url, method=method, headers=headers, params=params, data=data
    )
    transport._request(target_url, method=method, data=body, headers=request_headers)


def _statistical_request_func(url: str, param: str, payload: str) -> Callable[[bool], float]:
    """构造统计学验证所需的请求计时函数: inject=True 时注入 payload。

    这里**没有**复用 ``BaseVerifier._request``，因为它把连接失败/超时吞成
    ``(None, 0, elapsed, 0)``：在时间盲注验证里，一次被目标 hang 掉或丢弃的请求会因此
    变成一个"慢响应"样本，被 ``statistical.py`` 算成显著延迟，产出假 verified（P2 要消除
    的误报）。所以这里显式让异常向上抛，由 ``StatisticalVerifier`` 丢弃该样本（样本数不足
    时它返回 ``is_confirmed=False``）。``core.http.client.HTTPClient`` 同样不适用：默认
    3 次重试 + 指数退避会污染计时样本。URL/参数拼接与 UA/SSL 仍复用 ``BaseVerifier``。
    """
    transport = _get_transport()

    def request(inject: bool) -> float:
        probe_url, _, request_headers = transport._prepare_base_request(
            url=url,
            method="GET",
            params={param: payload if inject else "1"} if param else None,
        )
        probe = urllib.request.Request(probe_url, method="GET")
        probe.add_header("User-Agent", transport.user_agent)
        for key, value in request_headers.items():
            probe.add_header(key, value)
        start = time.perf_counter()
        response = urllib.request.urlopen(probe, timeout=_STAT_TIMEOUT, context=transport.ssl_ctx)
        elapsed = time.perf_counter() - start
        response.close()
        return elapsed

    return request


def register_evidence_tools(mcp, counter, logger):
    """注册证据验证工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @require_moderate_auth
    @handle_errors(logger, category=ErrorCategory.DETECTOR)
    async def verify_finding(
        finding: Dict[str, Any],
        deep: bool = False,
        oob: bool = False,
    ) -> ToolResult:
        """验证单个 finding 的真实性并输出可复核证据

        只做重放/统计/带外验证，不执行利用。返回的 ``verified``、
        ``verification_confidence``、``evidence`` 来自验证器实际观测；
        ``assessment`` 是 ``core.evidence`` 的证据门禁判定。

        Args:
            finding: 漏洞检测结果，至少需要 ``url`` 与 ``vuln_type``/``type``；
                可选 ``param``/``payload``。
            deep: 追加统计学验证（需要 ``param`` 与 ``payload``）。
            oob: 对 xxe/ssrf/rce 使用带外回调验证（需要配置回调/DNS 服务）。

        Returns:
            ToolResult，data 字段: ``verified``（bool，等价于
            ``verification_status == "verified"``）/ ``verification_status``
            （"verified"/"unverified"/"contradicted" 三态，OOB 未回调属于 "unverified"）/
            ``verification_confidence`` / ``evidence`` / ``assessment``（证据门禁判定，
            可能比三态更严格）/ ``missing_checks``。
        """
        if not isinstance(finding, dict):
            return ToolResult.fail("finding 必须是对象", error_type="InvalidFinding")

        raw_url = finding.get("url")
        url = raw_url.strip() if isinstance(raw_url, str) else ""
        vuln_type = _normalize_vuln_type(finding)
        if not url:
            return ToolResult.fail("finding 缺少 url，无法验证", error_type="InvalidFinding")
        # 只允许带主机名的 http(s)：否则 url=file:///etc/passwd 之类会被下面的 urllib
        # 请求直接打开。校验逻辑复用 utils.validators.validate_url。
        if not validate_url(url):
            return ToolResult.fail(
                "finding 的 url 必须是不含路径穿越的 http/https 地址",
                error_type="InvalidFinding",
            )
        if not vuln_type:
            return ToolResult.fail(
                "finding 缺少 vuln_type/type，无法选择验证器",
                error_type="InvalidFinding",
            )

        raw_param = finding.get("param")
        param = raw_param.strip() if isinstance(raw_param, str) else ""

        missing_checks: List[str] = []
        results: List[Any] = []

        # 1. 重放验证: batch_verify 依据 finding["type"] 分派具体验证方法。
        verify_input = dict(finding)
        verify_input.setdefault("type", vuln_type)
        verify_input.setdefault("param", param)
        verifier = VulnerabilityVerifier(timeout=10)
        results.extend(await asyncio.to_thread(verifier.batch_verify, [verify_input]))
        if not results:
            missing_checks.append(f"no verifier matched vuln_type={vuln_type}")

        # 2. OOB 验证（可选）。
        if oob:
            oob_token = _match_oob_type(vuln_type)
            method_name = _OOB_DISPATCH.get(oob_token) if oob_token else None
            if method_name is None:
                if oob_token:
                    missing_checks.append(f"oob verification unavailable for {oob_token}")
                else:
                    missing_checks.append(f"oob verification unsupported for vuln_type={vuln_type}")
            else:
                oob_verifier = OOBIntegratedVerifier(timeout=_OOB_TIMEOUT)
                oob_result = await asyncio.to_thread(
                    getattr(oob_verifier, method_name), url, param, _oob_request
                )
                results.append(oob_result)
                if not _is_positive(oob_result):
                    missing_checks.append("oob callback not received")

        # 3. 统计学佐证（可选）。
        payload = finding.get("payload")
        if deep:
            if param and isinstance(payload, str) and payload:
                stat_verifier = StatisticalVerifier(
                    sample_size=_STAT_SAMPLE_SIZE, timeout=_STAT_TIMEOUT
                )
                stat_result = await asyncio.to_thread(
                    stat_verifier.verify_time_based,
                    url=url,
                    param=param,
                    payload=payload,
                    request_func=_statistical_request_func(url, param, payload),
                    expected_delay=_STAT_EXPECTED_DELAY,
                )
                results.append(stat_result)
                if not _is_positive(stat_result):
                    missing_checks.append("statistical verification not confirmed")
            else:
                missing_checks.append("deep verification requires 'param' and 'payload'")

        evidence_items = [evidence_from_verification(result) for result in results]
        evidence_payload = [item.to_dict() for item in evidence_items]

        # 三态结论：OOB 未收到回调 / 没有可用验证器只算“未确认”，不是“已证伪”。
        verified = _classify_results(results)
        verification_confidence = _resolve_confidence(results, evidence_items, verified)

        # 4. 证据门禁判定（不改写调用方的 finding）。
        # 没有任何验证结果时 verified=None：未做观测不能声称“被证伪”。
        gate_input = dict(finding)
        gate_input["verified"] = verified
        gate_input["confidence"] = verification_confidence
        gate_input["evidence"] = evidence_payload
        assessment = assess_finding(gate_input)
        for check in assessment.missing_checks:
            if check not in missing_checks:
                missing_checks.append(check)

        data = {
            "verified": verified is True,
            "verification_status": _verification_status(verified),
            "verification_confidence": verification_confidence,
            "evidence": evidence_payload,
            "assessment": assessment.to_dict(),
            "missing_checks": missing_checks,
        }
        return ToolResult.ok(
            data=data,
            vuln_type=vuln_type,
            url=url,
            deep=bool(deep),
            oob=bool(oob),
            assessment_status=assessment.status,
        )
