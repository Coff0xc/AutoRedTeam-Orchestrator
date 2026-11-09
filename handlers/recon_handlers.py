"""
侦察工具处理器
包含: recon_run, full_recon, port_scan, fingerprint, subdomain_enum,
      dir_scan, dns_lookup, tech_detect, waf_detect, passive_subdomain_enum
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.parse import urlparse

from .error_handling import (
    ErrorCategory,
    extract_domain,
    extract_target,
    extract_url,
    handle_errors,
    validate_inputs,
)
from .runtime_helpers import (
    blocked_handler_runtime_response,
    complete_handler_runtime_action,
    complete_handler_runtime_payload,
    gate_handler_runtime_action,
)
from .tooling import tool


def _gate_recon_runtime(tool_name: str, inputs: Dict[str, Any]) -> Dict[str, Any]:
    return gate_handler_runtime_action(
        tool_name,
        inputs=inputs,
        risk_level="moderate",
        source="recon_handler",
        network_policy="controlled",
    )


def _fail_recon_runtime(gate: Dict[str, Any], exc: Exception) -> None:
    complete_handler_runtime_action(
        gate,
        False,
        output={"success": False},
        error=str(exc),
    )


def _as_url(target: str) -> str:
    text = str(target).strip()
    if text.startswith(("http://", "https://")):
        return text
    return f"https://{text}"


def _as_host(target: str) -> str:
    text = str(target).strip()
    if text.startswith(("http://", "https://")):
        host = urlparse(text).hostname
        if not host:
            raise ValueError("invalid target URL: %s" % target)
        return host
    return text.split("/")[0]


def _normalize_recon_modules(
    modules: Optional[Union[str, Sequence[str]]],
) -> Optional[List[str]]:
    """Accept a list or a comma-separated string. None means full_recon."""
    if modules is None:
        return None
    if isinstance(modules, str):
        parts = [part.strip() for part in modules.replace(";", ",").split(",")]
        names = [part for part in parts if part]
    else:
        names = [str(item).strip() for item in modules if str(item).strip()]
    if not names:
        raise ValueError("modules is empty; omit it to run full_recon, or pass recon module names")
    return names


async def _exec_full_recon(target: str, quick_mode: bool) -> Dict[str, Any]:
    from core.recon import ReconConfig, StandardReconEngine

    config = ReconConfig(quick_mode=quick_mode)
    engine = StandardReconEngine(target, config)
    result = await engine.async_run()
    return {"success": True, "target": target, "data": result.to_dict()}


async def _exec_port_scan(target: str, ports: str, timeout: float) -> Dict[str, Any]:
    from core.recon import async_scan_ports

    results = await async_scan_ports(target, ports, timeout=timeout)
    open_ports = [
        {"port": r.port, "state": r.state, "service": r.service, "version": r.version}
        for r in results
        if r.state == "open"
    ]
    return {
        "success": True,
        "target": target,
        "open_ports": open_ports,
        "total_scanned": len(results),
        "total_open": len(open_ports),
    }


async def _exec_fingerprint(url: str) -> Dict[str, Any]:
    import asyncio

    from core.recon import identify_fingerprints

    results = await asyncio.to_thread(identify_fingerprints, url)
    return {
        "success": True,
        "url": url,
        "fingerprints": [
            {
                "name": f.name,
                "category": (f.category.value if hasattr(f.category, "value") else str(f.category)),
                "version": f.version,
                "confidence": f.confidence,
            }
            for f in results
        ],
        "count": len(results),
    }


async def _exec_subdomain_enum(
    domain: str, methods: Optional[List[str]], limit: int
) -> Dict[str, Any]:
    from core.recon import async_enumerate_subdomains

    results = await async_enumerate_subdomains(domain, methods=methods)
    subdomains = [
        {"subdomain": r.subdomain, "ip": r.ip, "source": r.source} for r in results[:limit]
    ]
    return {
        "success": True,
        "domain": domain,
        "subdomains": subdomains,
        "count": len(subdomains),
    }


async def _exec_dir_scan(
    url: str, wordlist: str, extensions: Optional[List[str]]
) -> Dict[str, Any]:
    from core.recon import async_scan_directories

    results = await async_scan_directories(
        url,
        wordlist=wordlist,
        extensions=extensions,
    )
    directories = [
        {
            "path": r.path,
            "status_code": r.status_code,
            "content_length": r.content_length,
            "redirect": r.redirect_url,
        }
        for r in results
        if r.status_code in [200, 301, 302, 403]
    ]
    return {
        "success": True,
        "url": url,
        "directories": directories,
        "count": len(directories),
    }


async def _exec_dns_lookup(domain: str, record_types: Optional[List[str]]) -> Dict[str, Any]:
    import asyncio

    from core.recon import get_dns_records

    results = await asyncio.to_thread(get_dns_records, domain, record_types=record_types)
    return {
        "success": True,
        "domain": domain,
        "records": results.to_dict() if hasattr(results, "to_dict") else results,
    }


async def _exec_tech_detect(url: str) -> Dict[str, Any]:
    import asyncio

    from core.recon import detect_technologies

    results = await asyncio.to_thread(detect_technologies, url)
    return {
        "success": True,
        "url": url,
        "technologies": [
            {
                "name": t.name,
                "category": t.category,
                "version": t.version,
                "confidence": t.confidence,
            }
            for t in results
        ],
    }


async def _exec_waf_detect(url: str) -> Dict[str, Any]:
    import asyncio

    from core.recon import detect_waf

    result = await asyncio.to_thread(detect_waf, url)
    return {
        "success": True,
        "url": url,
        "waf_detected": result.detected if hasattr(result, "detected") else bool(result),
        "waf_name": result.name if hasattr(result, "name") else None,
        "confidence": result.confidence if hasattr(result, "confidence") else None,
    }


async def _exec_passive_subdomain_enum(domain: str, timeout: int) -> Dict[str, Any]:
    from core.recon.passive_recon import PassiveRecon

    recon = PassiveRecon(timeout=timeout)
    by_source = await recon.discover_subdomains_with_sources(domain)
    all_subs = set()
    for subs in by_source.values():
        all_subs.update(subs)
    return {
        "success": True,
        "domain": domain,
        "subdomains": sorted(all_subs),
        "count": len(all_subs),
        "by_source": {k: {"subdomains": v, "count": len(v)} for k, v in by_source.items()},
    }


async def _dispatch_recon_module(
    name: str,
    target: str,
    *,
    ports: str,
    timeout: float,
    wordlist: str,
    extensions: Optional[List[str]],
    methods: Optional[List[str]],
    record_types: Optional[List[str]],
    limit: int,
    quick_mode: bool,
    source_timeout: int,
) -> Dict[str, Any]:
    if name == "full_recon":
        return await _exec_full_recon(target, quick_mode)
    if name == "port_scan":
        return await _exec_port_scan(_as_host(target), ports, timeout)
    if name == "fingerprint":
        return await _exec_fingerprint(_as_url(target))
    if name == "subdomain_enum":
        return await _exec_subdomain_enum(_as_host(target), methods, limit)
    if name == "dir_scan":
        return await _exec_dir_scan(_as_url(target), wordlist, extensions)
    if name == "dns_lookup":
        return await _exec_dns_lookup(_as_host(target), record_types)
    if name == "tech_detect":
        return await _exec_tech_detect(_as_url(target))
    if name == "waf_detect":
        return await _exec_waf_detect(_as_url(target))
    if name == "passive_subdomain_enum":
        return await _exec_passive_subdomain_enum(_as_host(target), source_timeout)
    raise ValueError("unknown recon module %r" % name)


def register_recon_tools(mcp, counter, logger):
    """注册侦察相关工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @validate_inputs(target="target")
    @handle_errors(logger, ErrorCategory.RECON, extract_target)
    async def recon_run(
        target: str,
        modules: Optional[Union[str, List[str]]] = None,
        ports: str = "1-1000",
        timeout: float = 2.0,
        wordlist: str = "common",
        extensions: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        record_types: Optional[List[str]] = None,
        limit: int = 100,
        quick_mode: bool = False,
        source_timeout: int = 10,
    ) -> Dict[str, Any]:
        """Run one or more reconnaissance modules against a target.

        Args:
            target: Target URL, host, or domain
            modules: Module names (port_scan, fingerprint) or aliases (port, waf).
                Omit to run full_recon.
            ports: Port range for port_scan
            timeout: Per-port timeout in seconds
            wordlist: Directory wordlist name
            extensions: Directory extensions
            methods: Subdomain enumeration methods
            record_types: DNS record types
            limit: Maximum subdomain rows
            quick_mode: Skip slow full_recon phases
            source_timeout: Per-source timeout for passive subdomain enum
        """
        from core.recon.names import canonical_recon_module

        selected = _normalize_recon_modules(modules)
        runtime_gate = _gate_recon_runtime(
            "recon_run",
            {
                "target": target,
                "modules": selected or ["full_recon"],
                "quick_mode": quick_mode,
            },
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            if selected is None:
                resolved = ["full_recon"]
            else:
                resolved = [canonical_recon_module(name) for name in selected]
            results = {}
            for name in resolved:
                results[name] = await _dispatch_recon_module(
                    name,
                    target,
                    ports=ports,
                    timeout=timeout,
                    wordlist=wordlist,
                    extensions=extensions,
                    methods=methods,
                    record_types=record_types,
                    limit=limit,
                    quick_mode=quick_mode,
                    source_timeout=source_timeout,
                )
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        payload = {
            "success": True,
            "target": target,
            "modules": resolved,
            "results": results,
        }
        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["target", "modules"],
        )

    @tool(mcp)
    @validate_inputs(target="target")
    @handle_errors(logger, ErrorCategory.RECON, extract_target)
    async def full_recon(target: str, quick_mode: bool = False) -> Dict[str, Any]:
        """完整侦察扫描 - 执行全面的目标信息收集

        包含: DNS解析、端口扫描、指纹识别、技术栈检测、WAF检测、子域名枚举、目录扫描

        Args:
            target: 目标URL或域名 (例: https://example.com)
            quick_mode: 是否快速模式 (跳过耗时的子域名和目录扫描)

        Returns:
            包含所有侦察结果的字典
        """
        runtime_gate = _gate_recon_runtime(
            "full_recon",
            {"target": target, "quick_mode": quick_mode},
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_full_recon(target, quick_mode)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(runtime_gate, payload, summary_keys=["target"])

    @tool(mcp)
    @validate_inputs(target="target", ports="port_range")
    @handle_errors(logger, ErrorCategory.RECON, extract_target)
    async def port_scan(target: str, ports: str = "1-1000", timeout: float = 2.0) -> Dict[str, Any]:
        """端口扫描 - 探测目标开放端口和服务

        Args:
            target: 目标IP或主机名
            ports: 端口范围 (例: "1-1000", "22,80,443,8080", "top100")
            timeout: 单端口超时时间(秒)

        Returns:
            开放端口列表和服务信息
        """
        runtime_gate = _gate_recon_runtime(
            "port_scan",
            {"target": target, "ports": ports, "timeout": timeout},
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_port_scan(target, ports, timeout)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["target", "total_scanned", "total_open"],
        )

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, ErrorCategory.RECON, extract_url)
    async def fingerprint(url: str) -> Dict[str, Any]:
        """Web指纹识别 - 识别目标Web应用的技术栈

        检测: 服务器、Web框架、CMS系统、JS库、CDN等

        Args:
            url: 目标URL

        Returns:
            指纹信息列表
        """
        runtime_gate = _gate_recon_runtime("fingerprint", {"url": url})
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_fingerprint(url)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["url", "count"],
        )

    @tool(mcp)
    @validate_inputs(domain="domain")
    @handle_errors(logger, ErrorCategory.RECON, extract_domain)
    async def subdomain_enum(
        domain: str, methods: Optional[List[str]] = None, limit: int = 100
    ) -> Dict[str, Any]:
        """子域名枚举 - 发现目标域名的子域名

        支持: DNS爆破、证书透明度、搜索引擎等多种方式

        Args:
            domain: 目标域名 (例: example.com)
            methods: 枚举方式列表 (默认全部)
            limit: 最大返回数量

        Returns:
            子域名列表
        """
        runtime_gate = _gate_recon_runtime(
            "subdomain_enum",
            {"domain": domain, "methods": methods or [], "limit": limit},
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_subdomain_enum(domain, methods, limit)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["domain", "count"],
        )

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, ErrorCategory.RECON, extract_url)
    async def dir_scan(
        url: str, wordlist: str = "common", extensions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """目录扫描 - 发现Web应用的隐藏路径

        Args:
            url: 目标URL
            wordlist: 字典名称 (common, large, api)
            extensions: 要测试的扩展名列表 (例: [".php", ".bak"])

        Returns:
            发现的路径列表
        """
        runtime_gate = _gate_recon_runtime(
            "dir_scan",
            {"url": url, "wordlist": wordlist, "extensions": extensions or []},
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_dir_scan(url, wordlist, extensions)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["url", "count"],
        )

    @tool(mcp)
    @validate_inputs(domain="domain")
    @handle_errors(logger, ErrorCategory.RECON, extract_domain)
    async def dns_lookup(domain: str, record_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """DNS查询 - 获取域名的DNS记录

        Args:
            domain: 目标域名
            record_types: 记录类型列表 (默认: A, AAAA, CNAME, MX, NS, TXT)

        Returns:
            DNS记录信息
        """
        runtime_gate = _gate_recon_runtime(
            "dns_lookup",
            {"domain": domain, "record_types": record_types or []},
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_dns_lookup(domain, record_types)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["domain"],
        )

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, ErrorCategory.RECON, extract_url)
    async def tech_detect(url: str) -> Dict[str, Any]:
        """技术栈检测 - 识别网站使用的技术

        Args:
            url: 目标URL

        Returns:
            检测到的技术列表
        """
        runtime_gate = _gate_recon_runtime("tech_detect", {"url": url})
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_tech_detect(url)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["url", "technologies"],
        )

    @tool(mcp)
    @validate_inputs(url="url")
    @handle_errors(logger, ErrorCategory.RECON, extract_url)
    async def waf_detect(url: str) -> Dict[str, Any]:
        """WAF检测 - 识别目标是否有Web应用防火墙

        Args:
            url: 目标URL

        Returns:
            WAF检测结果
        """
        runtime_gate = _gate_recon_runtime("waf_detect", {"url": url})
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_waf_detect(url)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["url", "waf_detected", "waf_name", "confidence"],
        )

    @tool(mcp)
    @validate_inputs(domain="domain")
    @handle_errors(logger, ErrorCategory.RECON, extract_domain)
    async def passive_subdomain_enum(domain: str, timeout: int = 10) -> Dict[str, Any]:
        """被动子域名枚举 - 通过公开API零流量发现子域名

        查询6个公开数据源: crt.sh、HackerTarget、ThreatCrowd、
        URLScan.io、AlienVault OTX、RapidDNS。无需主动扫描。

        Args:
            domain: 目标域名 (例: example.com)
            timeout: 每个数据源的超时时间(秒)

        Returns:
            子域名列表及各数据源的发现结果
        """
        runtime_gate = _gate_recon_runtime(
            "passive_subdomain_enum",
            {"domain": domain, "timeout": timeout},
        )
        if not runtime_gate["allowed"]:
            return blocked_handler_runtime_response(runtime_gate)

        try:
            payload = await _exec_passive_subdomain_enum(domain, timeout)
        except Exception as exc:
            _fail_recon_runtime(runtime_gate, exc)
            raise

        return complete_handler_runtime_payload(
            runtime_gate,
            payload,
            summary_keys=["domain", "count"],
        )

    counter.add("recon", 10)
    logger.info("[Recon] 已注册 10 个侦察工具 (含 recon_run 与被动侦察)")
