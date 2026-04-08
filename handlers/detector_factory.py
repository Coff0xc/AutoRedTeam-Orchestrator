"""
检测器工具工厂

解决问题: detector_handlers.py 中 11 个检测器函数结构重复率 ~70%
通过工厂模式统一生成检测器工具，减少代码重复。

使用示例:
    from handlers.detector_factory import create_detector_tool, DetectorConfig

    # 定义检测器配置
    configs = [
        DetectorConfig("sqli", "SQLiDetector", "SQL注入检测"),
        DetectorConfig("xss", "XSSDetector", "XSS漏洞检测"),
    ]

    # 批量注册
    for config in configs:
        tool_func = create_detector_tool(config, mcp, logger)
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .error_handling import ErrorCategory, extract_url, handle_errors, validate_inputs
from .tooling import tool


@dataclass
class DetectorConfig:
    """检测器配置"""

    name: str  # 工具名称 (如 "sqli_scan")
    detector_class: str  # 检测器类名 (如 "SQLiDetector")
    description: str  # 工具描述
    vuln_type: str = ""  # 漏洞类型描述
    extra_params: Dict[str, Any] = field(default_factory=dict)  # 额外参数定义
    result_formatter: Optional[Callable] = None  # 自定义结果格式化


# 预定义检测器配置
DETECTOR_CONFIGS: List[DetectorConfig] = [
    DetectorConfig(
        name="sqli_scan",
        detector_class="SQLiDetector",
        description="SQL注入检测 - 检测SQL注入漏洞",
        vuln_type="支持: 基于错误、布尔盲注、时间盲注、联合注入",
    ),
    DetectorConfig(
        name="xss_scan",
        detector_class="XSSDetector",
        description="XSS漏洞检测 - 检测跨站脚本攻击漏洞",
        vuln_type="支持: 反射型XSS、存储型XSS、DOM型XSS",
    ),
    DetectorConfig(
        name="ssrf_scan",
        detector_class="SSRFDetector",
        description="SSRF漏洞检测 - 检测服务端请求伪造漏洞",
    ),
    DetectorConfig(
        name="rce_scan",
        detector_class="RCEDetector",
        description="命令注入检测 - 检测远程命令执行漏洞",
    ),
    DetectorConfig(
        name="path_traversal_scan",
        detector_class="PathTraversalDetector",
        description="路径遍历检测 - 检测目录遍历/LFI漏洞",
    ),
    DetectorConfig(
        name="ssti_scan",
        detector_class="SSTIDetector",
        description="模板注入检测 - 检测服务端模板注入漏洞",
        vuln_type="支持: Jinja2, Twig, Freemarker, Velocity等",
    ),
    DetectorConfig(
        name="xxe_scan",
        detector_class="XXEDetector",
        description="XXE漏洞检测 - 检测XML外部实体注入漏洞",
    ),
    DetectorConfig(
        name="idor_scan",
        detector_class="IDORDetector",
        description="IDOR漏洞检测 - 检测不安全的直接对象引用",
    ),
    DetectorConfig(
        name="cors_scan",
        detector_class="CORSDetector",
        description="CORS配置检测 - 检测跨域资源共享配置问题",
    ),
    DetectorConfig(
        name="security_headers_scan",
        detector_class="SecurityHeadersDetector",
        description="安全头检测 - 检测HTTP安全响应头配置",
    ),
    DetectorConfig(
        name="http_smuggling_scan",
        detector_class="HTTPSmugglingDetector",
        description="HTTP请求走私检测 - 检测CL.TE/TE.CL/TE.TE走私漏洞",
        vuln_type="支持: CL.TE、TE.CL、TE.TE 三种走私变体",
    ),
    DetectorConfig(
        name="cache_poisoning_scan",
        detector_class="CachePoisoningDetector",
        description="缓存投毒检测 - 检测Web缓存投毒漏洞",
        vuln_type="支持: Unkeyed Header、Unkeyed Parameter、Fat GET",
    ),
    DetectorConfig(
        name="prototype_pollution_scan",
        detector_class="PrototypePollutionDetector",
        description="原型链污染检测 - 检测JavaScript Prototype Pollution漏洞",
        vuln_type="支持: 服务端PP、客户端PP、参数合并PP",
    ),
    DetectorConfig(
        name="crlf_injection_scan",
        detector_class="CRLFInjectionDetector",
        description="CRLF注入检测 - 检测HTTP响应头注入/拆分漏洞",
        vuln_type="支持: 标准CRLF、Unicode变体、双重编码、Response Splitting",
    ),
    DetectorConfig(
        name="host_header_injection_scan",
        detector_class="HostHeaderInjectionDetector",
        description="Host头注入检测 - 检测Host Header Injection漏洞",
        vuln_type="支持: Host覆盖、X-Forwarded-Host、端口注入、URL覆盖",
    ),
    # ── 以下为 Phase 3 新增 (原 detector_handlers.py 中的 10 个检测器) ──
    DetectorConfig(
        name="ldap_scan",
        detector_class="LDAPiDetector",
        description="LDAP注入检测 - 检测LDAP注入漏洞",
    ),
    DetectorConfig(
        name="open_redirect_scan",
        detector_class="OpenRedirectDetector",
        description="开放重定向检测 - 检测URL重定向漏洞",
    ),
    DetectorConfig(
        name="info_disclosure_scan",
        detector_class="InfoDisclosureDetector",
        description="信息泄露检测 - 检测敏感信息泄露",
        vuln_type="检测: 错误信息泄露、目录列表、敏感文件暴露等",
    ),
    DetectorConfig(
        name="csrf_scan",
        detector_class="CSRFDetector",
        description="CSRF跨站请求伪造检测 - 检测CSRF防护缺失或配置问题",
    ),
    DetectorConfig(
        name="auth_bypass_scan",
        detector_class="AuthBypassDetector",
        description="认证绕过检测 - 检测身份认证绕过漏洞",
    ),
    DetectorConfig(
        name="weak_password_scan",
        detector_class="WeakPasswordDetector",
        description="弱密码检测 - 检测弱密码和默认凭据",
    ),
    DetectorConfig(
        name="session_scan",
        detector_class="SessionDetector",
        description="会话安全检测 - 检测会话管理漏洞",
        vuln_type="检测: 会话固定、会话劫持、Cookie安全属性缺失等",
    ),
    DetectorConfig(
        name="upload_scan",
        detector_class="FileUploadDetector",
        description="文件上传漏洞检测 - 检测文件上传安全问题",
        vuln_type="检测: 文件类型绕过、路径穿越、恶意文件上传等",
    ),
    DetectorConfig(
        name="lfi_scan",
        detector_class="LFIDetector",
        description="本地文件包含检测 - 检测LFI漏洞",
    ),
    DetectorConfig(
        name="deserialize_scan",
        detector_class="DeserializeDetector",
        description="反序列化漏洞检测 - 检测不安全的反序列化",
    ),
]


def _format_findings(results) -> List[Dict[str, Any]]:
    """默认结果格式化"""
    findings = []
    for r in results:
        if hasattr(r, "vulnerable") and not r.vulnerable:
            continue
        if hasattr(r, "to_dict"):
            findings.append(r.to_dict())
        else:
            findings.append(
                {
                    "param": getattr(r, "param", None),
                    "payload": getattr(r, "payload", None),
                    "evidence": (
                        r.evidence[:200] if hasattr(r, "evidence") and r.evidence else None
                    ),
                }
            )
    return findings


def create_detector_tool(
    config: DetectorConfig,
    mcp,
    logger,
) -> Callable:
    """创建检测器工具函数

    Args:
        config: 检测器配置
        mcp: FastMCP 实例
        logger: Logger 实例

    Returns:
        注册到 MCP 的工具函数
    """

    async def _detect(
        url: str, params: Optional[Dict[str, str]] = None, **kwargs
    ) -> Dict[str, Any]:
        # 动态导入检测器
        import core.detectors as detectors_module

        detector_cls = getattr(detectors_module, config.detector_class)
        detector = detector_cls()

        # 执行检测
        results = await detector.async_detect(url, params=params or {}, **kwargs)

        # 格式化结果
        formatter = config.result_formatter or _format_findings
        findings = formatter(results)

        return {
            "success": True,
            "vulnerable": len(findings) > 0,
            "url": url,
            "findings": findings,
        }

    # 设置函数元信息（在装饰器应用前）
    _detect.__name__ = config.name
    _detect.__qualname__ = config.name
    doc = f"{config.description}\n\n"
    if config.vuln_type:
        doc += f"{config.vuln_type}\n\n"
    doc += "Args:\n    url: 目标URL\n    params: 请求参数\n\nReturns:\n    检测结果"
    _detect.__doc__ = doc

    # 手动应用装饰器链 (内→外: handle_errors → validate_inputs → tool)
    wrapped = handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)(
        _detect
    )
    wrapped = validate_inputs(url="url")(wrapped)
    wrapped = tool(mcp, name=config.name)(wrapped)

    return wrapped


def _register_vuln_scan(mcp, logger):
    """注册综合漏洞扫描工具 (vuln_scan)

    此工具使用 CompositeDetector，不适合工厂模式，单独注册。
    """

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def vuln_scan(
        url: str,
        params: Optional[Dict[str, str]] = None,
        detectors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """综合漏洞扫描 - 检测多种Web漏洞

        支持: SQL注入、XSS、命令注入、SSRF、路径遍历、XXE等

        Args:
            url: 目标URL
            params: 请求参数 (例: {"id": "1", "name": "test"})
            detectors: 要使用的检测器 (默认: owasp_top10)

        Returns:
            发现的漏洞列表
        """
        from core.detectors import DetectorFactory, DetectorPresets

        if detectors:
            composite = DetectorFactory.create_composite(detectors)
        else:
            composite = DetectorPresets.owasp_top10()

        results = await composite.async_detect(url, params=params or {})

        vulnerabilities = [
            {
                "type": r.vuln_type,
                "severity": r.severity.value,
                "param": r.param,
                "payload": r.payload,
                "evidence": r.evidence[:200] if r.evidence else None,
                "remediation": r.remediation,
            }
            for r in results
            if r.vulnerable
        ]

        return {
            "success": True,
            "url": url,
            "vulnerabilities": vulnerabilities,
            "total_vulns": len(vulnerabilities),
            "detectors_used": detectors or ["owasp_top10"],
        }

    return vuln_scan


def register_detector_tools(mcp, counter, logger):
    """使用工厂模式注册所有检测器工具

    包含 1 个综合扫描工具 (vuln_scan) + N 个单检测器工具 (工厂生成)
    """
    # 综合扫描工具 (特殊逻辑，单独注册)
    _register_vuln_scan(mcp, logger)

    # 单检测器工具 (工厂批量注册)
    for config in DETECTOR_CONFIGS:
        create_detector_tool(config, mcp, logger)

    total = 1 + len(DETECTOR_CONFIGS)  # vuln_scan + factory tools
    counter.add("detector", total)
    logger.info("[Detector] 已注册 %d 个漏洞检测工具 (工厂模式)", total)
