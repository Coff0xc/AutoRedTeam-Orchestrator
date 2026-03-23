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

    @tool(mcp, name=config.name)
    @validate_inputs(url="url")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_url)
    async def detector_tool(url: str, params: Dict[str, str] = None, **kwargs) -> Dict[str, Any]:
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

    # 设置文档字符串
    doc = f"{config.description}\n\n"
    if config.vuln_type:
        doc += f"{config.vuln_type}\n\n"
    doc += "Args:\n    url: 目标URL\n    params: 请求参数\n\nReturns:\n    检测结果"
    detector_tool.__doc__ = doc

    return detector_tool


def register_detector_tools_v2(mcp, counter, logger):
    """使用工厂模式注册所有检测器工具（新版）

    相比原版减少约 200 行重复代码
    """
    for config in DETECTOR_CONFIGS:
        create_detector_tool(config, mcp, logger)

    counter.add("detector", len(DETECTOR_CONFIGS))
    logger.info("[Detector] 已注册 %d 个漏洞检测工具 (工厂模式)", len(DETECTOR_CONFIGS))
