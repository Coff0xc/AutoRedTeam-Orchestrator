"""
自动化渗透编排工具处理器
包含: auto_pentest, pentest_resume, pentest_status, pentest_phase,
      exploit_vulnerability, exploit_by_cve, get_attack_paths
"""

from typing import Any, Dict, List
from .tooling import tool


def register_orchestration_tools(mcp, counter, logger):
    """注册自动化渗透编排工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    async def auto_pentest(
        target: str,
        quick_mode: bool = False,
        skip_exfiltrate: bool = True,
        skip_phases: List[str] = None,
        report_formats: List[str] = None
    ) -> Dict[str, Any]:
        """全自动渗透测试 - 执行完整的自动化渗透测试流程

        执行阶段: RECON -> VULN_SCAN -> POC_EXEC -> EXPLOIT -> PRIV_ESC -> LATERAL -> REPORT
        支持断点续传、状态持久化、智能决策

        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标URL或IP
            quick_mode: 是否快速模式 (跳过耗时的子域名和目录扫描)
            skip_exfiltrate: 是否跳过数据外泄阶段 (默认跳过，安全考虑)
            skip_phases: 要跳过的阶段列表 (例: ["privilege_escalation", "lateral_movement"])
            report_formats: 报告格式列表 (默认: ["html", "json"])

        Returns:
            完整渗透测试结果，包含各阶段数据和发现
        """
        try:
            from core.orchestrator import (
                AutoPentestOrchestrator,
                OrchestratorConfig
            )

            config = OrchestratorConfig(
                quick_mode=quick_mode,
                skip_exfiltrate=skip_exfiltrate,
                skip_phases=skip_phases or [],
                report_formats=report_formats or ['html', 'json']
            )

            orchestrator = AutoPentestOrchestrator(target, config)
            result = await orchestrator.run()
            success = result.get('status') == 'completed'

            return {
                'success': success,
                **result
            }
        except Exception as e:
            logger.exception(f"auto_pentest 失败: {e}")
            return {'success': False, 'error': str(e), 'target': target}

    @tool(mcp)
    async def pentest_resume(session_id: str) -> Dict[str, Any]:
        """恢复渗透测试 - 从检查点恢复之前中断的渗透测试

        支持断点续传，可从任意阶段继续执行

        警告: 仅限授权渗透测试使用！

        Args:
            session_id: 会话ID (32字符hex或UUID格式)

        Returns:
            渗透测试结果
        """
        try:
            from core.orchestrator import resume_pentest

            result = await resume_pentest(session_id)
            success = result.get('status') == 'completed'

            return {
                'success': success,
                **result
            }
        except ValueError as e:
            # session_id 格式错误或会话不存在
            return {'success': False, 'error': str(e), 'session_id': session_id}
        except Exception as e:
            logger.exception(f"pentest_resume 失败: {e}")
            return {'success': False, 'error': str(e), 'session_id': session_id}

    @tool(mcp)
    async def pentest_status(session_id: str) -> Dict[str, Any]:
        """查询渗透测试状态 - 获取渗透测试会话的当前状态

        Args:
            session_id: 会话ID

        Returns:
            会话状态、当前阶段、发现摘要
        """
        try:
            from core.orchestrator import AutoPentestOrchestrator

            orchestrator = AutoPentestOrchestrator.resume(session_id)
            state = orchestrator.get_state()
            findings = orchestrator.get_findings()
            attack_paths = orchestrator.get_attack_paths()

            return {
                'success': True,
                'session_id': session_id,
                'target': state.get('target'),
                'current_phase': state.get('current_phase'),
                'phase_status': state.get('phase_status'),
                'findings_count': len(findings),
                'high_value_findings': len([f for f in findings if f.get('severity') in ('critical', 'high')]),
                'suggested_attack_paths': attack_paths[:3]
            }
        except ValueError as e:
            return {'success': False, 'error': str(e), 'session_id': session_id}
        except Exception as e:
            logger.exception(f"pentest_status 失败: {e}")
            return {'success': False, 'error': str(e), 'session_id': session_id}

    @tool(mcp)
    async def pentest_phase(
        target: str,
        phase: str,
        session_id: str = None,
        config: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """执行单个渗透阶段 - 可以单独执行某一阶段

        可用阶段: recon, vuln_scan, poc_exec, exploit, privilege_escalation,
                  lateral_movement, exfiltrate, report

        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标URL或IP
            phase: 要执行的阶段
            session_id: 会话ID (可选，用于关联已有会话)
            config: 阶段配置

        Returns:
            阶段执行结果
        """
        try:
            from core.orchestrator import (
                AutoPentestOrchestrator,
                OrchestratorConfig,
                PentestPhase
            )

            if session_id:
                orchestrator = AutoPentestOrchestrator.resume(session_id)
            else:
                orchestrator = AutoPentestOrchestrator(target, OrchestratorConfig())

            phase_enum = PentestPhase(phase)
            result = await orchestrator.execute_phase(phase_enum, config)

            return {
                'success': result.success,
                'session_id': orchestrator.state.session_id,
                'phase': phase,
                'data': result.data,
                'findings_count': len(result.findings),
                'errors': result.errors,
                'duration': result.duration
            }
        except ValueError as e:
            return {'success': False, 'error': str(e), 'phase': phase}
        except Exception as e:
            logger.exception(f"pentest_phase 失败: {e}")
            return {'success': False, 'error': str(e), 'target': target, 'phase': phase}

    @tool(mcp)
    async def exploit_vulnerability(
        detection_result: Dict[str, Any],
        targets: Dict[str, Any] = None,
        use_feedback: bool = False,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """利用检测到的漏洞 - 根据漏洞检测结果自动执行利用

        支持漏洞类型: sqli, rce, ssti, xxe, path_traversal, ssrf, idor, xss, deserialize, file_upload

        警告: 仅限授权渗透测试使用！

        Args:
            detection_result: 漏洞检测结果 (包含 vulnerable, vuln_type, url, param, payload)
            targets: 利用目标配置 (可选，如 queries, commands, files)
            use_feedback: 是否启用反馈循环 (失败自动调整重试)
            max_retries: 最大重试次数 (仅在 use_feedback=True 时生效)

        Returns:
            利用结果
        """
        try:
            from core.exploit import ExploitEngine
            from dataclasses import dataclass

            # 将 dict 转换为类似对象以兼容 ExploitEngine
            @dataclass
            class DetectionResultWrapper:
                vulnerable: bool
                vuln_type: str
                url: str
                param: str = ''
                payload: str = ''
                evidence: str = ''
                extra: dict = None

            wrapped = DetectionResultWrapper(
                vulnerable=detection_result.get('vulnerable', False),
                vuln_type=detection_result.get('vuln_type', detection_result.get('type', 'unknown')),
                url=detection_result.get('url', ''),
                param=detection_result.get('param', ''),
                payload=detection_result.get('payload', ''),
                evidence=detection_result.get('evidence', ''),
                extra=detection_result.get('extra', {})
            )

            engine = ExploitEngine()

            if use_feedback:
                # 使用反馈循环引擎执行
                from core.feedback import FeedbackLoopEngine

                async def exploit_operation(context):
                    return await engine.async_exploit(wrapped, targets=targets)

                feedback_engine = FeedbackLoopEngine()
                feedback_result = await feedback_engine.execute_with_feedback(
                    exploit_operation,
                    wrapped,
                    max_retries=max_retries
                )

                if feedback_result.success:
                    result = feedback_result.result
                    return {
                        'success': result.success,
                        'status': result.status.value,
                        'exploit_type': result.exploit_type.value,
                        'vuln_type': result.vuln_type,
                        'url': result.url,
                        'evidence': result.evidence,
                        'payload_used': result.payload_used,
                        'data': result.data,
                        'shell': result.shell.to_dict() if result.shell else None,
                        'files': [f.to_dict() for f in result.files] if result.files else None,
                        'execution_time_ms': result.execution_time_ms,
                        'error': result.error,
                        'feedback': {
                            'attempts': feedback_result.attempts,
                            'adjustments_made': feedback_result.adjustments_made,
                            'final_strategy': feedback_result.final_strategy
                        }
                    }
                else:
                    return {
                        'success': False,
                        'error': feedback_result.error,
                        'feedback': {
                            'attempts': feedback_result.attempts,
                            'failure_reasons': feedback_result.failure_reasons,
                            'adjustments_tried': feedback_result.adjustments_tried
                        }
                    }
            else:
                # 直接执行
                result = await engine.async_exploit(wrapped, targets=targets)

                return {
                    'success': result.success,
                    'status': result.status.value,
                    'exploit_type': result.exploit_type.value,
                    'vuln_type': result.vuln_type,
                    'url': result.url,
                    'evidence': result.evidence,
                    'payload_used': result.payload_used,
                    'data': result.data,
                    'shell': result.shell.to_dict() if result.shell else None,
                    'files': [f.to_dict() for f in result.files] if result.files else None,
                    'execution_time_ms': result.execution_time_ms,
                    'error': result.error
                }
        except Exception as e:
            logger.exception(f"exploit_vulnerability 失败: {e}")
            return {'success': False, 'error': str(e)}

    @tool(mcp)
    async def exploit_by_cve(
        target: str,
        cve_id: str,
        variables: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """利用已知CVE漏洞 - 使用PoC模板利用指定CVE

        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标URL
            cve_id: CVE编号 (例: CVE-2021-44228)
            variables: PoC变量 (可选)

        Returns:
            利用结果
        """
        try:
            from core.exploit import ExploitEngine

            engine = ExploitEngine()
            result = engine.exploit_cve(target, cve_id, variables=variables)

            return {
                'success': result.success,
                'status': result.status.value,
                'vuln_type': result.vuln_type,
                'url': result.url,
                'evidence': result.evidence,
                'payload_used': result.payload_used,
                'data': result.data,
                'execution_time_ms': result.execution_time_ms,
                'metadata': result.metadata,
                'error': result.error
            }
        except Exception as e:
            logger.exception(f"exploit_by_cve 失败: {e}")
            return {'success': False, 'error': str(e), 'target': target, 'cve_id': cve_id}

    @tool(mcp)
    async def get_attack_paths(
        target: str,
        session_id: str = None,
        reconnaissance_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """获取攻击路径建议 - 基于侦察数据智能推荐攻击路径

        Args:
            target: 目标URL
            session_id: 会话ID (可选，获取会话关联的攻击路径)
            reconnaissance_data: 侦察数据 (可选)

        Returns:
            推荐的攻击路径列表
        """
        try:
            from core.orchestrator import AutoPentestOrchestrator, OrchestratorConfig

            if session_id:
                orchestrator = AutoPentestOrchestrator.resume(session_id)
            else:
                orchestrator = AutoPentestOrchestrator(target, OrchestratorConfig())
                if reconnaissance_data:
                    orchestrator.state.recon_data = reconnaissance_data

            attack_paths = orchestrator.get_attack_paths()

            return {
                'success': True,
                'target': target,
                'attack_paths': attack_paths,
                'count': len(attack_paths)
            }
        except Exception as e:
            logger.exception(f"get_attack_paths 失败: {e}")
            return {'success': False, 'error': str(e), 'target': target}

    @tool(mcp)
    async def exploit_orchestrate(
        detections: List[Dict[str, Any]],
        top_n: int = 3,
        verify_first: bool = True,
        parallel: bool = True
    ) -> Dict[str, Any]:
        """编排多漏洞利用 - 智能编排多个漏洞的利用流程

        功能:
        - 按严重程度/置信度对漏洞排序
        - 选择TOP N漏洞进行利用
        - 支持并行/顺序执行
        - 可选利用前验证

        警告: 仅限授权渗透测试使用！

        Args:
            detections: 漏洞检测结果列表 (每个包含 vulnerable, vuln_type, url, param, severity, confidence)
            top_n: 并行尝试数量 (默认3)
            verify_first: 利用前是否验证漏洞 (默认True)
            parallel: 是否并行执行 (默认True)

        Returns:
            编排利用结果，包含每个漏洞的利用状态
        """
        try:
            from core.exploit import ExploitOrchestrator, OrchestrationStrategy

            strategy = OrchestrationStrategy.PARALLEL if parallel else OrchestrationStrategy.SEQUENTIAL

            orchestrator = ExploitOrchestrator()
            result = await orchestrator.orchestrate(
                detections=detections,
                top_n=top_n,
                verify_first=verify_first,
                strategy=strategy
            )

            return {
                'success': result.success,
                'total_detections': result.total_detections,
                'exploited_count': result.exploited_count,
                'successful_count': result.successful_count,
                'results': [
                    {
                        'vuln_type': r.vuln_type,
                        'url': r.url,
                        'success': r.success,
                        'status': r.status.value if hasattr(r, 'status') else 'unknown',
                        'evidence': r.evidence,
                        'error': r.error
                    }
                    for r in result.results
                ],
                'execution_time_ms': result.execution_time_ms,
                'strategy_used': strategy.value
            }
        except Exception as e:
            logger.exception(f"exploit_orchestrate 失败: {e}")
            return {'success': False, 'error': str(e)}

    @tool(mcp)
    async def exploit_with_retry(
        detection_result: Dict[str, Any],
        max_retries: int = 3,
        targets: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """带重试的漏洞利用 - 失败时自动分析原因并调整策略重试

        功能:
        - 失败原因分析 (WAF拦截/超时/限速/Payload过滤等)
        - 策略自动调整 (编码绕过/延迟/代理切换等)
        - 指数退避重试

        警告: 仅限授权渗透测试使用！

        Args:
            detection_result: 漏洞检测结果
            max_retries: 最大重试次数 (默认3)
            targets: 利用目标配置

        Returns:
            利用结果，包含重试信息和调整策略
        """
        try:
            from core.exploit import exploit_with_retry as _exploit_with_retry

            result = await _exploit_with_retry(
                detection_result=detection_result,
                max_retries=max_retries,
                targets=targets
            )

            return {
                'success': result.success,
                'result': result.result.to_dict() if result.result else None,
                'attempts': result.attempts,
                'failure_reasons': result.failure_reasons,
                'adjustments_made': result.adjustments_made,
                'final_strategy': result.final_strategy,
                'total_time_ms': result.total_time_ms,
                'error': result.error
            }
        except Exception as e:
            logger.exception(f"exploit_with_retry 失败: {e}")
            return {'success': False, 'error': str(e)}

    @tool(mcp)
    async def verify_and_exploit(
        detection_result: Dict[str, Any],
        verification_method: str = 'auto',
        targets: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """验证并利用 - 先验证漏洞真实性，再执行利用

        验证方法:
        - auto: 自动选择最佳验证方法
        - oob: 带外验证 (DNS/HTTP回调)
        - statistical: 统计学验证 (多次请求比对)
        - timing: 时间盲注验证
        - error: 错误信息验证

        警告: 仅限授权渗透测试使用！

        Args:
            detection_result: 漏洞检测结果
            verification_method: 验证方法 (auto/oob/statistical/timing/error)
            targets: 利用目标配置

        Returns:
            验证和利用结果
        """
        try:
            from modules.vuln_verifier import VulnerabilityVerifier
            from core.exploit import ExploitEngine
            from dataclasses import dataclass

            @dataclass
            class DetectionResultWrapper:
                vulnerable: bool
                vuln_type: str
                url: str
                param: str = ''
                payload: str = ''
                evidence: str = ''
                extra: dict = None

            wrapped = DetectionResultWrapper(
                vulnerable=detection_result.get('vulnerable', False),
                vuln_type=detection_result.get('vuln_type', detection_result.get('type', 'unknown')),
                url=detection_result.get('url', ''),
                param=detection_result.get('param', ''),
                payload=detection_result.get('payload', ''),
                evidence=detection_result.get('evidence', ''),
                extra=detection_result.get('extra', {})
            )

            # 第一步：验证漏洞
            verifier = VulnerabilityVerifier()
            verification_result = await verifier.verify(
                detection_result=wrapped,
                method=verification_method
            )

            if not verification_result.get('verified', False):
                return {
                    'success': False,
                    'verified': False,
                    'verification_method': verification_method,
                    'verification_details': verification_result,
                    'error': '漏洞验证失败，可能是误报'
                }

            # 第二步：执行利用
            engine = ExploitEngine()
            exploit_result = await engine.async_exploit(wrapped, targets=targets)

            return {
                'success': exploit_result.success,
                'verified': True,
                'verification_method': verification_result.get('method_used', verification_method),
                'verification_confidence': verification_result.get('confidence', 0),
                'exploit_result': {
                    'status': exploit_result.status.value,
                    'vuln_type': exploit_result.vuln_type,
                    'url': exploit_result.url,
                    'evidence': exploit_result.evidence,
                    'payload_used': exploit_result.payload_used,
                    'data': exploit_result.data,
                    'shell': exploit_result.shell.to_dict() if exploit_result.shell else None,
                    'files': [f.to_dict() for f in exploit_result.files] if exploit_result.files else None,
                    'execution_time_ms': exploit_result.execution_time_ms,
                    'error': exploit_result.error
                }
            }
        except Exception as e:
            logger.exception(f"verify_and_exploit 失败: {e}")
            return {'success': False, 'error': str(e)}

    @tool(mcp)
    async def analyze_exploit_failure(
        failed_result: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """分析利用失败原因 - 深度分析漏洞利用失败的原因并给出建议

        分析维度:
        - WAF/防护检测
        - 网络/超时问题
        - Payload过滤情况
        - 目标环境限制
        - 误报可能性

        Args:
            failed_result: 失败的利用结果
            context: 额外上下文信息 (如目标技术栈、WAF类型等)

        Returns:
            失败原因分析和改进建议
        """
        try:
            from core.feedback import FailureAnalyzer, StrategyRegistry

            analyzer = FailureAnalyzer()
            analysis = analyzer.analyze(
                result=failed_result,
                context=context or {}
            )

            # 获取推荐的调整策略
            registry = StrategyRegistry()
            recommended_strategies = []

            for reason in analysis.failure_reasons:
                strategies = registry.get_strategies(reason)
                for strategy in strategies[:2]:  # 每种原因最多2个建议
                    recommended_strategies.append({
                        'reason': reason.value,
                        'strategy': strategy.name,
                        'description': strategy.description,
                        'parameters': strategy.parameters
                    })

            return {
                'success': True,
                'analysis': {
                    'primary_reason': analysis.primary_reason.value if analysis.primary_reason else 'unknown',
                    'all_reasons': [r.value for r in analysis.failure_reasons],
                    'confidence': analysis.confidence,
                    'waf_detected': analysis.waf_detected,
                    'waf_type': analysis.waf_type,
                    'rate_limited': analysis.rate_limited,
                    'payload_filtered': analysis.payload_filtered,
                    'is_false_positive': analysis.is_false_positive,
                    'error_details': analysis.error_details
                },
                'recommended_strategies': recommended_strategies,
                'suggestions': analysis.suggestions
            }
        except Exception as e:
            logger.exception(f"analyze_exploit_failure 失败: {e}")
            return {'success': False, 'error': str(e)}

    counter.add('orchestration', 11)
    logger.info("[Orchestration] 已注册 11 个自动化渗透编排工具")