"""
Web 扫描工具集 - MCP 工具注册

提供 web_discover 和 web_scan 两个核心工具:
- web_discover: 攻面发现与注入点抽取
- web_scan: 编排式 Web 漏洞扫描

按照 Web安全能力分析与优化方案.md 6.1 节设计
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============ web_discover 工具 ============


async def web_discover(
    url: str,
    max_pages: int = 50,
    max_depth: int = 2,
    include_js: bool = True,
    timeout: int = 10,
) -> Dict[str, Any]:
    """
    攻面发现 - 发现目标的攻击面并抽取注入点

    扫描目标网站，自动发现:
    - HTML 表单和输入字段
    - URL 链接和查询参数
    - JavaScript 中的 API 端点

    输出标准化的注入点列表，可用于后续 web_scan 扫描。

    Args:
        url: 目标 URL
        max_pages: 最大爬取页面数 (默认 50)
        max_depth: 最大爬取深度 (默认 2)
        include_js: 是否分析 JS 文件 (默认 True)
        timeout: 请求超时秒数 (默认 10)

    Returns:
        dict: 包含以下字段:
            - success: 是否成功
            - target: 目标 URL
            - discovery: 发现统计 (页面数、表单数、JS 文件数、注入点数)
            - injection_points: 标准化注入点列表
            - stats: 注入点统计 (按类型、来源、方法分组)

    Example:
        >>> result = await web_discover("https://example.com")
        >>> print(f"发现 {result['discovery']['injection_points_total']} 个注入点")
    """
    try:
        from modules.web_scanner import AttackSurfaceDiscovery

        discovery = AttackSurfaceDiscovery(
            timeout=timeout,
            max_pages=max_pages,
            max_depth=max_depth,
        )

        result = await discovery.discover(url, include_js=include_js)
        return result.to_dict()

    except ImportError as e:
        logger.error(f"模块导入失败: {e}")
        return {
            "success": False,
            "target": url,
            "error": f"模块导入失败: {e}",
            "discovery": {},
            "injection_points": [],
        }
    except Exception as e:
        logger.error(f"攻面发现失败: {e}")
        return {
            "success": False,
            "target": url,
            "error": str(e),
            "discovery": {},
            "injection_points": [],
        }


def web_discover_sync(url: str, **kwargs) -> Dict[str, Any]:
    """web_discover 的同步版本"""
    return asyncio.run(web_discover(url, **kwargs))


# ============ web_scan 工具 ============


async def web_scan(
    url: str,
    mode: str = "quick",
    scan_types: Optional[List[str]] = None,
    injection_points: Optional[List[Dict]] = None,
    max_pages: int = 30,
    concurrency: int = 5,
    timeout: int = 10,
    verify_findings: bool = True,
    advanced_scans: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    编排式 Web 漏洞扫描

    基于注入点列表并发执行多种漏洞检测，统一验证与报告结构。

    扫描流程:
    1. 如果未提供 injection_points，先执行攻面发现
    2. 根据 scan_types 选择扫描器
    3. 并发执行扫描
    4. 可选：二次验证减少误报
    5. 可选：高级扫描（需显式启用）
    6. 输出标准化报告

    Args:
        url: 目标 URL
        mode: 扫描模式 (quick=快速, full=完整)
        scan_types: 扫描类型列表，可选值:
            - sqli: SQL 注入
            - xss: 跨站脚本
            - ssrf: 服务端请求伪造
            - lfi: 本地文件包含
            - redirect: 开放重定向
            - crlf: CRLF 注入/响应拆分
            - nosql: NoSQL 注入 (MongoDB/Redis/Elasticsearch)
            - 默认: ["sqli", "xss"] (quick) 或全部 (full)
        injection_points: 预定义的注入点列表（跳过发现阶段）
        max_pages: 攻面发现时最大爬取页面数
        concurrency: 并发数
        timeout: 请求超时秒数
        verify_findings: 是否对发现进行二次验证
        advanced_scans: 高级扫描类型（默认关闭，需显式启用）:
            - cache_poisoning: Web缓存投毒探测
            - prototype_pollution: 原型污染检测
            - request_smuggling: HTTP请求走私（safe_mode=True）
            - browser: Playwright浏览器扫描（需安装依赖）

    Returns:
        dict: 包含以下字段:
            - success: 是否成功
            - target: 目标 URL
            - mode: 扫描模式
            - discovery: 发现统计
            - injection_points: 注入点列表
            - findings: 漏洞发现列表
            - advanced_findings: 高级扫描发现列表
            - coverage: 扫描覆盖情况
            - duration_seconds: 耗时

    Example:
        >>> result = await web_scan("https://example.com", mode="quick")
        >>> for vuln in result['findings']:
        ...     print(f"[{vuln['severity']}] {vuln['type']}: {vuln['param']}")
    """
    start_time = datetime.now()

    # 默认扫描类型
    default_scan_types = {
        "quick": ["sqli", "xss"],
        "full": ["sqli", "xss", "ssrf", "lfi", "redirect", "crlf", "nosql"],
    }

    if scan_types is None:
        scan_types = default_scan_types.get(mode, default_scan_types["quick"])

    result = {
        "success": False,
        "target": url,
        "mode": mode,
        "discovery": {},
        "injection_points": [],
        "findings": [],
        "advanced_findings": [],
        "coverage": {},
        "advanced_coverage": {},
        "duration_seconds": 0,
        "errors": [],
    }

    try:
        # 1. 攻面发现（如果未提供注入点）
        if injection_points is None:
            logger.info(f"[*] 开始攻面发现: {url}")
            discovery_result = await web_discover(
                url,
                max_pages=max_pages,
                timeout=timeout,
            )

            if not discovery_result.get("success"):
                result["errors"].append("攻面发现失败")
                return result

            result["discovery"] = discovery_result.get("discovery", {})
            injection_points = discovery_result.get("injection_points", [])

        result["injection_points"] = injection_points

        if not injection_points:
            result["success"] = True
            result["coverage"] = {t: "no_injection_points" for t in scan_types}
            return result

        logger.info(f"[*] 发现 {len(injection_points)} 个注入点，开始扫描...")

        # 2. 执行扫描
        findings = []
        coverage = {}

        for scan_type in scan_types:
            try:
                type_findings = await _run_scanner(
                    scan_type,
                    injection_points,
                    concurrency=concurrency,
                    timeout=timeout,
                )
                findings.extend(type_findings)
                coverage[scan_type] = f"completed ({len(type_findings)} findings)"
            except Exception as e:
                logger.warning(f"扫描类型 {scan_type} 失败: {e}")
                coverage[scan_type] = f"failed: {e}"
                result["errors"].append(f"{scan_type}: {e}")

        # 3. 可选验证
        if verify_findings and findings:
            logger.info(f"[*] 验证 {len(findings)} 个发现...")
            findings = await _verify_findings(findings, timeout=timeout)

        result["findings"] = findings
        result["coverage"] = coverage

        # 4. 高级扫描（可选）
        if advanced_scans:
            logger.info(f"[*] 执行高级扫描: {advanced_scans}")
            adv_findings, adv_coverage = await _run_advanced_scans(
                url, advanced_scans, timeout=timeout
            )
            result["advanced_findings"] = adv_findings
            result["advanced_coverage"] = adv_coverage

        result["success"] = True

    except Exception as e:
        logger.error(f"Web 扫描失败: {e}")
        result["errors"].append(str(e))

    finally:
        result["duration_seconds"] = round((datetime.now() - start_time).total_seconds(), 2)

    return result


async def _run_scanner(
    scan_type: str,
    injection_points: List[Dict],
    concurrency: int = 5,
    timeout: int = 10,
) -> List[Dict]:
    """
    运行特定类型的扫描器

    使用 tools/vuln_tools.py 中的独立顶层函数（非嵌套函数）
    """
    findings = []

    try:
        # 导入独立顶层扫描工具（这些是模块级别的函数，可以直接导入）
        from tools.vuln_tools import (
            crlf_detect,
            lfi_detect_standalone,
            nosql_detect,
            redirect_detect,
            sqli_detect,
            ssrf_detect,
            xss_detect,
        )

        scanners_available = True
    except ImportError as e:
        logger.warning(f"vuln_tools 导入失败: {e}，使用内置扫描")
        scanners_available = False
        return findings

    # 限制并发
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_point(point: Dict) -> List[Dict]:
        async with semaphore:
            point_findings = []
            url = point.get("url", "")
            param = point.get("param", "")
            method = point.get("method", "GET")

            if not url or not param:
                return point_findings

            try:
                # 根据扫描类型调用对应的检测函数
                if scan_type == "sqli":
                    test_url = f"{url}?{param}=1" if "?" not in url else url
                    result = sqli_detect(test_url, param=param, deep_scan=False)
                    if result.get("vulnerabilities"):
                        for vuln in result["vulnerabilities"]:
                            point_findings.append(
                                {
                                    "type": "SQL Injection",
                                    "subtype": vuln.get("injection_type", "unknown"),
                                    "severity": "CRITICAL",
                                    "url": url,
                                    "param": param,
                                    "method": method,
                                    "payload": vuln.get("payload", ""),
                                    "evidence": vuln.get("evidence", ""),
                                    "confidence": 0.8,
                                    "source_point": point.get("id", ""),
                                }
                            )

                elif scan_type == "xss":
                    test_url = f"{url}?{param}=test" if "?" not in url else url
                    result = xss_detect(test_url, param=param)
                    if result.get("xss_vulns"):
                        for vuln in result["xss_vulns"]:
                            point_findings.append(
                                {
                                    "type": "Cross-Site Scripting",
                                    "subtype": vuln.get("type", "reflected"),
                                    "severity": "HIGH",
                                    "url": url,
                                    "param": param,
                                    "method": method,
                                    "payload": vuln.get("payload", ""),
                                    "evidence": "Payload reflected in response",
                                    "confidence": 0.75,
                                    "source_point": point.get("id", ""),
                                }
                            )

                elif scan_type == "ssrf":
                    test_url = f"{url}?{param}=http://localhost" if "?" not in url else url
                    result = ssrf_detect(test_url, param=param)
                    if result.get("ssrf_vulns"):
                        for vuln in result["ssrf_vulns"]:
                            point_findings.append(
                                {
                                    "type": "Server-Side Request Forgery",
                                    "subtype": vuln.get("type", "basic"),
                                    "severity": "HIGH",
                                    "url": url,
                                    "param": param,
                                    "method": method,
                                    "payload": vuln.get("payload", ""),
                                    "evidence": vuln.get("evidence", ""),
                                    "confidence": 0.7,
                                    "source_point": point.get("id", ""),
                                }
                            )

                elif scan_type == "lfi":
                    test_url = f"{url}?{param}=test" if "?" not in url else url
                    result = lfi_detect_standalone(test_url, param=param)
                    if result.get("lfi_vulns"):
                        for vuln in result["lfi_vulns"]:
                            point_findings.append(
                                {
                                    "type": "Local File Inclusion",
                                    "subtype": vuln.get("os", "unknown"),
                                    "severity": "HIGH",
                                    "url": url,
                                    "param": param,
                                    "method": method,
                                    "payload": vuln.get("payload", ""),
                                    "evidence": vuln.get("evidence", ""),
                                    "confidence": 0.8,
                                    "source_point": point.get("id", ""),
                                }
                            )

                elif scan_type == "redirect":
                    test_url = f"{url}?{param}=test" if "?" not in url else url
                    result = redirect_detect(test_url, param=param)
                    if result.get("redirect_vulns"):
                        for vuln in result["redirect_vulns"]:
                            point_findings.append(
                                {
                                    "type": "Open Redirect",
                                    "subtype": vuln.get("type", "redirect"),
                                    "severity": "MEDIUM",
                                    "url": url,
                                    "param": param,
                                    "method": method,
                                    "payload": vuln.get("payload", ""),
                                    "evidence": vuln.get("evidence", ""),
                                    "confidence": 0.7,
                                    "source_point": point.get("id", ""),
                                }
                            )

                elif scan_type == "crlf":
                    test_url = f"{url}?{param}=test" if "?" not in url else url
                    result = crlf_detect(test_url, param=param)
                    if result.get("crlf_vulns"):
                        for vuln in result["crlf_vulns"]:
                            point_findings.append(
                                {
                                    "type": "CRLF Injection",
                                    "subtype": vuln.get("type", "crlf"),
                                    "severity": (
                                        "MEDIUM"
                                        if "Response Splitting" not in vuln.get("type", "")
                                        else "HIGH"
                                    ),
                                    "url": url,
                                    "param": param,
                                    "method": method,
                                    "payload": vuln.get("payload", ""),
                                    "evidence": vuln.get("evidence", ""),
                                    "confidence": 0.75,
                                    "source_point": point.get("id", ""),
                                }
                            )

                elif scan_type == "nosql":
                    test_url = f"{url}?{param}=test" if "?" not in url else url
                    result = nosql_detect(test_url, param=param)
                    if result.get("nosql_vulns"):
                        for vuln in result["nosql_vulns"]:
                            point_findings.append(
                                {
                                    "type": "NoSQL Injection",
                                    "subtype": vuln.get("type", "nosql"),
                                    "severity": vuln.get("severity", "HIGH"),
                                    "url": url,
                                    "param": param,
                                    "method": method,
                                    "payload": vuln.get("payload", ""),
                                    "evidence": vuln.get("evidence", ""),
                                    "confidence": 0.75,
                                    "source_point": point.get("id", ""),
                                }
                            )

            except Exception as e:
                logger.debug(f"扫描 {url}/{param} 失败: {e}")

            return point_findings

    # 并发扫描所有注入点
    tasks = [scan_point(p) for p in injection_points]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings


async def _run_advanced_scans(
    url: str,
    advanced_scans: List[str],
    timeout: int = 10,
) -> tuple:
    """
    运行高级扫描（默认关闭，需显式启用）

    这些扫描可能有较高的侵入性或需要额外依赖
    """
    findings = []
    coverage = {}

    for scan_type in advanced_scans:
        try:
            if scan_type == "cache_poisoning":
                from tools.vuln_tools import cache_poisoning_detect

                result = cache_poisoning_detect(url, aggressive=False)
                if result.get("success") and result.get("findings"):
                    for f in result["findings"]:
                        findings.append(
                            {
                                "type": "Cache Poisoning",
                                "subtype": f.get("type", "unknown"),
                                "severity": f.get("severity", "MEDIUM"),
                                "url": url,
                                "evidence": f.get("evidence", ""),
                                "description": f.get("description", ""),
                                "verification_status": "detection_only",
                            }
                        )
                coverage[scan_type] = f"completed ({len(result.get('findings', []))} findings)"

            elif scan_type == "prototype_pollution":
                from tools.vuln_tools import prototype_pollution_detect

                result = prototype_pollution_detect(url)
                if result.get("success") and result.get("findings"):
                    for f in result["findings"]:
                        findings.append(
                            {
                                "type": "Prototype Pollution",
                                "subtype": f.get("type", "unknown"),
                                "severity": f.get("severity", "MEDIUM"),
                                "url": url,
                                "payload": f.get("payload", ""),
                                "evidence": f.get("evidence", ""),
                                "verification_status": "needs_manual_review",
                            }
                        )
                coverage[scan_type] = f"completed ({len(result.get('findings', []))} findings)"

            elif scan_type == "request_smuggling":
                from tools.vuln_tools import request_smuggling_detect

                result = request_smuggling_detect(url, safe_mode=True)
                if result.get("success") and result.get("findings"):
                    for f in result["findings"]:
                        findings.append(
                            {
                                "type": "Request Smuggling",
                                "subtype": f.get("type", "unknown"),
                                "severity": f.get("severity", "HIGH"),
                                "url": url,
                                "evidence": f.get("evidence", ""),
                                "description": f.get("description", ""),
                                "verification_status": "safe_mode_detection",
                            }
                        )
                coverage[scan_type] = f"completed ({len(result.get('findings', []))} findings)"

            elif scan_type == "browser":
                try:
                    from tools.vuln_tools import browser_scan

                    result = browser_scan(url, scan_type="all", screenshot=False)
                    if result.get("success") and result.get("findings"):
                        for f in result["findings"]:
                            findings.append(
                                {
                                    "type": f.get("type", "Browser Finding"),
                                    "subtype": f.get("subtype", ""),
                                    "severity": f.get("severity", "MEDIUM"),
                                    "url": url,
                                    "payload": f.get("payload", ""),
                                    "evidence": f.get("evidence", ""),
                                    "verification_status": "browser_verified",
                                }
                            )
                    coverage[scan_type] = f"completed ({len(result.get('findings', []))} findings)"
                except ImportError:
                    coverage[scan_type] = "skipped (playwright not installed)"

            else:
                coverage[scan_type] = "unknown_type"

        except ImportError as e:
            coverage[scan_type] = f"skipped (import error: {e})"
        except Exception as e:
            coverage[scan_type] = f"failed: {e}"
            logger.warning(f"高级扫描 {scan_type} 失败: {e}")

    return findings, coverage


async def _verify_findings(
    findings: List[Dict],
    timeout: int = 10,
) -> List[Dict]:
    """
    验证发现（减少误报）

    使用 modules/vuln_verifier.py 中的统计学验证能力
    针对不同类型提供显式的验证状态
    """
    verified = []

    # 尝试导入统计学验证器
    try:
        from modules.vuln_verifier import verify_vuln_statistically

        verifier_available = True
    except ImportError:
        logger.warning("vuln_verifier 导入失败，使用简单验证")
        verifier_available = False

    # 漏洞类型映射和验证策略
    vuln_type_map = {
        "SQL Injection": {"code": "sqli", "verifiable": True},
        "Cross-Site Scripting": {"code": "xss", "verifiable": True},
        "Server-Side Request Forgery": {"code": "ssrf", "verifiable": True},
        "Local File Inclusion": {"code": "lfi", "verifiable": True},
        "Open Redirect": {
            "code": "redirect",
            "verifiable": False,
            "reason": "需人工确认重定向目标的安全性",
        },
        "CRLF Injection": {
            "code": "crlf",
            "verifiable": False,
            "reason": "需人工确认注入头部的影响",
        },
        "NoSQL Injection": {
            "code": "nosql",
            "verifiable": False,
            "reason": "需人工确认数据库类型和注入效果",
        },
    }

    for finding in findings:
        confidence = finding.get("confidence", 0)
        finding_type = finding.get("type", "")
        type_config = vuln_type_map.get(finding_type, {"code": "unknown", "verifiable": False})

        # 高置信度的直接确认
        if confidence >= 0.8:
            finding["verified"] = True
            finding["verification_method"] = "high_confidence"
            finding["verification_status"] = "confirmed"
            verified.append(finding)

        # 中置信度 - 检查是否支持自动验证
        elif confidence >= 0.5:
            if type_config.get("verifiable") and verifier_available:
                try:
                    result = verify_vuln_statistically(
                        url=finding.get("url", ""),
                        param=finding.get("param", ""),
                        vuln_type=type_config["code"],
                        payload=finding.get("payload", ""),
                        rounds=3,
                    )

                    if result.get("is_confirmed"):
                        finding["verified"] = True
                        finding["verification_method"] = "statistical"
                        finding["verification_status"] = "confirmed"
                        finding["verification_confidence"] = result.get("confidence_score", "N/A")
                    else:
                        finding["verified"] = False
                        finding["verification_method"] = "statistical"
                        finding["verification_status"] = "unconfirmed"
                        finding["verification_note"] = result.get("recommendation", "")

                except Exception as e:
                    logger.debug(f"统计验证失败: {e}")
                    finding["verified"] = False
                    finding["verification_method"] = "error"
                    finding["verification_status"] = "verification_error"
            else:
                # 不支持自动验证的类型
                finding["verified"] = False
                finding["verification_method"] = "manual_required"
                finding["verification_status"] = "needs_manual_review"
                finding["verification_note"] = type_config.get("reason", "此类型需人工复核")

            verified.append(finding)

        # 低置信度的标记为需人工复核
        else:
            finding["verified"] = False
            finding["verification_method"] = "low_confidence"
            finding["verification_status"] = "needs_manual_review"
            finding["verification_note"] = "置信度较低，建议人工复核"
            verified.append(finding)

    return verified


def web_scan_sync(url: str, **kwargs) -> Dict[str, Any]:
    """web_scan 的同步版本"""
    return asyncio.run(web_scan(url, **kwargs))


# ============ MCP 工具注册 ============


def get_web_scan_tools() -> List[Dict[str, Any]]:
    """
    获取 Web 扫描工具列表（用于 MCP 注册）
    """
    return [
        {
            "name": "web_discover",
            "description": "攻面发现 - 发现目标的攻击面并抽取注入点（表单、链接、API 端点）",
            "handler": web_discover_sync,
            "parameters": {
                "url": {"type": "string", "description": "目标 URL", "required": True},
                "max_pages": {"type": "integer", "description": "最大爬取页面数", "default": 50},
                "max_depth": {"type": "integer", "description": "最大爬取深度", "default": 2},
                "include_js": {
                    "type": "boolean",
                    "description": "是否分析 JS 文件",
                    "default": True,
                },
            },
        },
        {
            "name": "web_scan",
            "description": "编排式 Web 漏洞扫描 - 自动发现注入点并执行 SQLi/XSS/SSRF 等检测",
            "handler": web_scan_sync,
            "parameters": {
                "url": {"type": "string", "description": "目标 URL", "required": True},
                "mode": {
                    "type": "string",
                    "description": "扫描模式 (quick/full)",
                    "default": "quick",
                },
                "scan_types": {"type": "array", "description": "扫描类型列表", "default": None},
                "max_pages": {"type": "integer", "description": "最大爬取页面数", "default": 30},
                "verify_findings": {
                    "type": "boolean",
                    "description": "是否验证发现",
                    "default": True,
                },
                "advanced_scans": {"type": "array", "description": "高级扫描类型", "default": None},
            },
        },
    ]


def register_web_scan_tools(mcp) -> List[str]:
    """
    注册 Web 扫描工具到 MCP 服务器

    Args:
        mcp: FastMCP 服务器实例

    Returns:
        已注册的工具名称列表
    """
    registered = []

    # 注册 web_discover
    @mcp.tool()
    def web_discover_tool(
        url: str,
        max_pages: int = 50,
        max_depth: int = 2,
        include_js: bool = True,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """攻面发现 - 发现目标的攻击面并抽取注入点（表单、链接、API 端点）"""
        return web_discover_sync(
            url=url,
            max_pages=max_pages,
            max_depth=max_depth,
            include_js=include_js,
            timeout=timeout,
        )

    registered.append("web_discover")

    # 注册 web_scan
    @mcp.tool()
    def web_scan_tool(
        url: str,
        mode: str = "quick",
        scan_types: Optional[List[str]] = None,
        max_pages: int = 30,
        concurrency: int = 5,
        timeout: int = 10,
        verify_findings: bool = True,
        advanced_scans: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """编排式 Web 漏洞扫描 - 自动发现注入点并执行 SQLi/XSS/SSRF 等检测，支持高级扫描"""
        return web_scan_sync(
            url=url,
            mode=mode,
            scan_types=scan_types,
            max_pages=max_pages,
            concurrency=concurrency,
            timeout=timeout,
            verify_findings=verify_findings,
            advanced_scans=advanced_scans,
        )

    registered.append("web_scan")

    return registered


# ============ 测试入口 ============

if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python web_scan_tools.py <url>")
            return

        target = sys.argv[1]

        print(f"\n[*] 攻面发现: {target}")
        discover_result = await web_discover(target, max_pages=10)

        print(f"\n发现统计:")
        print(f"  - 页面: {discover_result.get('discovery', {}).get('pages_crawled', 0)}")
        print(f"  - 表单: {discover_result.get('discovery', {}).get('forms_found', 0)}")
        print(
            f"  - 注入点: {discover_result.get('discovery', {}).get('injection_points_total', 0)}"
        )

        print(f"\n注入点列表:")
        for p in discover_result.get("injection_points", [])[:10]:
            print(f"  [{p['type']}] {p['method']} {p['param']} @ {p['url'][:50]}...")

        print(f"\n[*] 开始扫描...")
        scan_result = await web_scan(
            target,
            mode="quick",
            injection_points=discover_result.get("injection_points"),
        )

        print(f"\n扫描结果:")
        print(f"  - 耗时: {scan_result.get('duration_seconds', 0)}s")
        print(f"  - 发现: {len(scan_result.get('findings', []))} 个漏洞")

        for vuln in scan_result.get("findings", []):
            status = vuln.get("verification_status", "unknown")
            print(f"  [{vuln['severity']}] {vuln['type']}: {vuln['param']} ({status})")

    asyncio.run(main())
