#!/usr/bin/env python3
"""
外部安全工具 MCP Handlers

提供与外部安全工具（nmap, nuclei, sqlmap, ffuf, masscan等）的增强集成。
支持自定义路径配置、工具链编排、结果结构化解析。

工具列表 (8个):
- ext_nmap_scan: Nmap 深度端口扫描与服务识别
- ext_nuclei_scan: Nuclei 漏洞模板扫描
- ext_sqlmap_scan: SQLMap SQL注入检测与利用
- ext_ffuf_fuzz: ffuf Web模糊测试
- ext_masscan_scan: Masscan 高速端口扫描
- ext_tool_chain: 工具链编排执行
- ext_tools_status: 查看外部工具状态
- ext_tools_reload: 重新加载工具配置
"""

from typing import Any, Dict, List, Literal, Optional, Tuple, get_args

from core.security import require_dangerous_auth

from .error_handling import (
    extract_target,
    extract_url,
    handle_external_tool_errors,
    validate_inputs,
)
from .runtime_helpers import (
    blocked_handler_runtime_response,
    complete_handler_runtime_payload,
    evidence_items,
    gate_handler_runtime_action,
)
from .tooling import tool

NmapPreset = Literal["quick", "full", "stealth", "version", "vuln"]
NucleiPreset = Literal["quick", "full", "cve"]
SqlmapPreset = Literal["detect", "exploit", "tamper"]
FfufMode = Literal["dir", "param", "vhost"]

NMAP_PRESETS: Tuple[str, ...] = get_args(NmapPreset)
NUCLEI_PRESETS: Tuple[str, ...] = get_args(NucleiPreset)
SQLMAP_PRESETS: Tuple[str, ...] = get_args(SqlmapPreset)
FFUF_MODES: Tuple[str, ...] = get_args(FfufMode)


def _invalid_choice(
    param: str, value: object, allowed: Tuple[str, ...]
) -> Optional[Dict[str, Any]]:
    if isinstance(value, str) and value in allowed:
        return None
    return {
        "success": False,
        "error": f"invalid {param}: {value!r}",
        "hint": f"allowed {param} values: {', '.join(allowed)}",
        "allowed": list(allowed),
    }


def _tool_unavailable(name: str) -> Dict[str, Any]:
    return {
        "success": False,
        "error": f"{name} is not installed or the path is unset",
        "hint": f"Set {name} in config/external_tools.yaml and retry.",
    }


def _confirm_required(action: str) -> Dict[str, Any]:
    return {
        "success": False,
        "action_required": action,
        "error": f"{action} requires confirmed=true",
        "hint": "Retry with confirmed=true after operator approval.",
    }


def _gate_external_runtime(
    tool_name: str,
    inputs: Dict[str, Any],
    risk_level: str = "high",
) -> Dict[str, Any]:
    return gate_handler_runtime_action(
        tool_name,
        inputs=inputs,
        risk_level=risk_level,
        source="external_tools_handler",
        requires_auth=True,
        human_approved=True,
        network_policy="controlled",
        artifact_policy="metadata-only",
        cleanup_policy="handler-owned",
    )


def register_external_tools(mcp, counter, logger):
    """注册外部工具 handlers

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_external_tool_errors(logger, "ext_nmap_scan", extract_target)
    async def ext_nmap_scan(
        target: str,
        ports: str = "1-1000",
        preset: NmapPreset = "quick",
    ) -> Dict[str, Any]:
        """Nmap port scan and service detection

        Use after a host is in scope when service versions or NSE scripts are needed.
        Use masscan for wide port discovery and nuclei for CVE templates.

        Args:
            target: IP or hostname in the authorized scope
            ports: "22,80,443", "1-1000", or "top100"
            preset: quick (-sT -T4), full (-sT -sV -sC -T4), stealth (-sS -T2, root),
                version (-sV -sC), vuln (-sV --script=vuln)

        Returns:
            success, hosts, ports, raw_output, plus the observation payload.
            Missing binary: success=false plus hint to config/external_tools.yaml.
            Invalid preset: success=false plus allowed list.
        """
        from core.tools import get_tool_manager, run_nmap

        bad = _invalid_choice("preset", preset, NMAP_PRESETS)
        if bad:
            return bad

        manager = get_tool_manager()
        if not manager.is_tool_available("nmap"):
            return _tool_unavailable("nmap")

        if ports == "top100":
            ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"

        gate = _gate_external_runtime(
            "ext_nmap_scan",
            {"target": target, "ports": ports, "preset": preset},
        )
        if not gate["allowed"]:
            return blocked_handler_runtime_response(gate)

        result = await run_nmap(target=target, ports=ports, preset=preset)

        parsed = result.get("parsed_data") or {}
        hosts = parsed.get("hosts") or []
        open_count = sum(
            1 for host in hosts for port in host.get("ports", []) if port.get("state") == "open"
        )
        result["evidence"] = evidence_items(
            "nmap", "external_tool", f"nmap 发现 {len(hosts)} 台主机、{open_count} 个开放端口"
        )
        result["verified"] = open_count > 0

        return complete_handler_runtime_payload(
            gate,
            result,
            summary_keys=("success", "hosts", "ports"),
        )

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_external_tool_errors(logger, "ext_nuclei_scan", extract_target)
    async def ext_nuclei_scan(
        target: str,
        preset: NucleiPreset = "quick",
        tags: Optional[List[str]] = None,
        severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Nuclei template vulnerability scan

        Use for CVE and misconfiguration templates on an in-scope URL.
        Use nmap for ports and services and sqlmap for injection on a parameterized URL.

        Args:
            target: Target URL
            preset: quick (critical/high), full (all severities), cve (CVE templates)
            tags: Template tags such as ["cve", "rce", "sqli"]
            severity: Comma-separated severities such as "critical,high,medium"

        Returns:
            success, findings, stats, plus the observation payload.
            Missing binary: success=false plus hint to config/external_tools.yaml.
            Invalid preset: success=false plus allowed list.
        """
        from core.tools import get_tool_manager, run_nuclei

        bad = _invalid_choice("preset", preset, NUCLEI_PRESETS)
        if bad:
            return bad

        manager = get_tool_manager()
        if not manager.is_tool_available("nuclei"):
            return _tool_unavailable("nuclei")

        args: List[str] = []
        if tags:
            args.extend(["-tags", ",".join(tags)])
        if severity:
            args.extend(["-severity", severity])

        gate = _gate_external_runtime(
            "ext_nuclei_scan",
            {"target": target, "preset": preset, "severity": severity, "tags": tags},
        )
        if not gate["allowed"]:
            return blocked_handler_runtime_response(gate)

        result = await run_nuclei(target=target, preset=preset, extra_args=args or None)

        parsed = result.get("parsed_data") or {}
        findings = parsed.get("findings") or []
        result["evidence"] = evidence_items(
            "nuclei", "external_tool", f"nuclei 命中 {len(findings)} 条模板"
        )
        result["verified"] = bool(findings)

        return complete_handler_runtime_payload(
            gate,
            result,
            summary_keys=("success", "findings", "stats"),
        )

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(url="url")
    @handle_external_tool_errors(logger, "ext_sqlmap_scan", extract_url)
    async def ext_sqlmap_scan(
        url: str,
        data: Optional[str] = None,
        preset: SqlmapPreset = "detect",
        tamper: Optional[List[str]] = None,
        confirmed: bool = False,
    ) -> Dict[str, Any]:
        """SQLMap SQL injection detect and exploit

        Use on an in-scope URL with parameters. Use nuclei for template CVEs.

        Args:
            url: Target URL with parameters, e.g. http://example.com/page?id=1
            data: Optional POST body
            preset: detect (--level=2 --risk=1), exploit (--level=5 --risk=3 --dump),
                tamper (WAF bypass scripts)
            tamper: Tamper script names such as ["space2comment", "randomcase"]
            confirmed: Required true for preset=exploit; otherwise action_required=confirm_exploit

        Returns:
            success, vulnerable, injection_type, dbms, data, plus the observation payload.
            Missing binary: success=false plus hint to config/external_tools.yaml.
            Invalid preset: success=false plus allowed list.
        """
        from core.tools import get_tool_manager, run_sqlmap

        bad = _invalid_choice("preset", preset, SQLMAP_PRESETS)
        if bad:
            return bad

        manager = get_tool_manager()
        if not manager.is_tool_available("sqlmap"):
            return _tool_unavailable("sqlmap")

        if preset == "exploit" and not confirmed:
            return _confirm_required("confirm_exploit")

        args: List[str] = []
        if data:
            args.extend(["--data", data])
        if tamper:
            args.extend(["--tamper", ",".join(tamper)])

        gate = _gate_external_runtime(
            "ext_sqlmap_scan",
            {"url": url, "preset": preset, "has_data": bool(data), "confirmed": confirmed},
            risk_level="critical" if preset == "exploit" else "high",
        )
        if not gate["allowed"]:
            return blocked_handler_runtime_response(gate)

        result = await run_sqlmap(url=url, preset=preset, extra_args=args or None)

        parsed = result.get("parsed_data") or {}
        vulnerable = bool(parsed.get("vulnerable"))
        result["evidence"] = evidence_items(
            "sqlmap", "external_tool", f"sqlmap 注入检测 {'命中' if vulnerable else '未命中'}"
        )
        result["verified"] = vulnerable

        return complete_handler_runtime_payload(
            gate,
            result,
            summary_keys=("success", "vulnerable", "dbms"),
        )

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(url="url")
    @handle_external_tool_errors(logger, "ext_ffuf_fuzz", extract_url)
    async def ext_ffuf_fuzz(
        url: str,
        wordlist: str = "common",
        mode: FfufMode = "dir",
        extensions: Optional[List[str]] = None,
        confirmed: bool = False,
    ) -> Dict[str, Any]:
        """ffuf web content discovery

        Use for directory, parameter, or vhost discovery on an in-scope URL.
        Use nmap for ports and nuclei for template hits.

        Args:
            url: Target URL; insert FUZZ or let dir/param mode append it
            wordlist: Named list common/large/api, or a local path
            mode: dir, param, or vhost
            extensions: File suffixes such as [".php", ".bak"]
            confirmed: Required true; otherwise action_required=confirm_fuzz

        Returns:
            success, results, stats, plus the observation payload.
            Missing binary: success=false plus hint to config/external_tools.yaml.
            Invalid mode: success=false plus allowed list.
        """
        from core.tools import get_tool_manager, run_ffuf

        bad = _invalid_choice("mode", mode, FFUF_MODES)
        if bad:
            return bad

        manager = get_tool_manager()
        if not manager.is_tool_available("ffuf"):
            return _tool_unavailable("ffuf")

        if not confirmed:
            return _confirm_required("confirm_fuzz")

        if "FUZZ" not in url:
            if mode == "dir":
                url = url.rstrip("/") + "/FUZZ"
            elif mode == "param":
                if "?" in url:
                    url = url + "&FUZZ=test"
                else:
                    url = url + "?FUZZ=test"

        args: List[str] = []
        if extensions:
            args.extend(["-e", ",".join(extensions)])

        gate = _gate_external_runtime(
            "ext_ffuf_fuzz",
            {"url": url, "wordlist": wordlist, "mode": mode, "confirmed": confirmed},
        )
        if not gate["allowed"]:
            return blocked_handler_runtime_response(gate)

        result = await run_ffuf(url=url, wordlist=wordlist, preset=mode, extra_args=args or None)

        parsed = result.get("parsed_data") or {}
        results_list = parsed.get("results") or []
        result["evidence"] = evidence_items(
            "ffuf", "external_tool", f"ffuf 发现 {len(results_list)} 条路径"
        )
        result["verified"] = bool(results_list)

        return complete_handler_runtime_payload(
            gate,
            result,
            summary_keys=("success", "results", "stats"),
        )

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_external_tool_errors(logger, "ext_masscan_scan", extract_target)
    async def ext_masscan_scan(
        target: str,
        ports: str = "1-10000",
        rate: int = 10000,
    ) -> Dict[str, Any]:
        """Masscan high-speed port scan

        Use for wide authorized ranges. Use nmap on the hosts that respond.

        Args:
            target: IP or CIDR, e.g. "192.168.1.0/24"
            ports: "1-65535" or "80,443,8080"
            rate: Packets per second, 1-10000000, default 10000

        Returns:
            success, hosts, ports, plus the observation payload.
            Missing binary: success=false plus hint to config/external_tools.yaml.
            Invalid rate: success=false.
        """
        from core.tools import get_tool_manager, run_masscan

        manager = get_tool_manager()
        if not manager.is_tool_available("masscan"):
            return _tool_unavailable("masscan")

        if rate <= 0 or rate > 10000000:
            return {"success": False, "error": "rate must be between 1 and 10000000"}

        args = ["--rate", str(rate)]

        gate = _gate_external_runtime(
            "ext_masscan_scan",
            {"target": target, "ports": ports, "rate": rate},
            risk_level="critical",
        )
        if not gate["allowed"]:
            return blocked_handler_runtime_response(gate)

        result = await run_masscan(target=target, ports=ports, extra_args=args)

        parsed = result.get("parsed_data") or {}
        hosts_dict = parsed.get("hosts") or {}
        open_count = sum(
            1
            for host in hosts_dict.values()
            for port in host.get("ports", [])
            if port.get("status") == "open"
        )
        result["evidence"] = evidence_items(
            "masscan", "external_tool", f"masscan 发现 {open_count} 个开放端口"
        )
        result["verified"] = open_count > 0

        return complete_handler_runtime_payload(
            gate,
            result,
            summary_keys=("success", "hosts", "ports"),
        )

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_external_tool_errors(logger, "ext_tool_chain", extract_target)
    async def ext_tool_chain(
        target: str, chain_name: str, config_override: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """工具链编排执行

        执行预定义的工具链，自动传递上下游数据。

        可用工具链:
        - full_recon: 完整侦察 (masscan快速发现 -> nmap详细识别)
        - vuln_scan: 漏洞扫描 (nuclei + sqlmap)
        - content_discovery: 内容发现 (ffuf目录扫描)

        Args:
            target: 目标URL或IP
            chain_name: 工具链名称
            config_override: 配置覆盖 (可选)

        Returns:
            工具链执行结果，包含各步骤的详细输出
        """
        from core.tools import get_tool_manager

        # 验证 chain_name
        valid_chains = ["full_recon", "vuln_scan", "content_discovery"]
        if not chain_name or chain_name not in valid_chains:
            return {
                "success": False,
                "error": f"无效的工具链名称: {chain_name}",
                "hint": f"可用的工具链: {', '.join(valid_chains)}",
            }

        gate = _gate_external_runtime(
            "ext_tool_chain",
            {"target": target, "chain_name": chain_name},
            risk_level="critical" if chain_name in {"full_recon", "vuln_scan"} else "high",
        )
        if not gate["allowed"]:
            return blocked_handler_runtime_response(gate)

        manager = get_tool_manager()
        results = await manager.run_chain(
            chain_name=chain_name, target=target, config_override=config_override
        )

        # run_chain 返回 List[ExternalToolResult]，而 complete_handler_runtime_payload
        # 第一行就是 payload.get("success")——列表没有 .get，会被 handle_external_tool_errors
        # 吞成恒失败。这里转成 dict，把每一步的 to_dict() 塞进 steps。
        steps = [r.to_dict() for r in results]
        payload = {
            "success": all(r.success for r in results),
            "chain_name": chain_name,
            "target": target,
            "steps": steps,
        }
        payload["evidence"] = [
            {
                "method": step.get("tool", "chain"),
                "kind": "external_tool",
                "summary": f"{step.get('tool')} 步骤 success={step.get('success')}",
            }
            for step in steps
        ]
        payload["verified"] = payload["success"]
        return complete_handler_runtime_payload(
            gate,
            payload,
            summary_keys=("success", "chain_name", "steps"),
        )

    counter.add("external_tools", 1)

    @tool(mcp)
    @handle_external_tool_errors(logger, "ext_tools_status")
    async def ext_tools_status() -> Dict[str, Any]:
        """查看外部工具状态

        检查所有配置的外部工具的可用性状态。

        Returns:
            工具状态列表，包含:
            - tools: 各工具的可用性、路径、版本信息
            - available_count: 可用工具数量
            - total_count: 配置的工具总数
        """
        from core.tools import get_tool_manager

        manager = get_tool_manager()
        status = manager.get_all_tools_status()

        available = sum(1 for t in status.values() if t.get("available"))

        return {
            "success": True,
            "tools": status,
            "available_count": available,
            "total_count": len(status),
            "config_path": "config/external_tools.yaml",
        }

    counter.add("external_tools", 1)

    @tool(mcp)
    @handle_external_tool_errors(logger, "ext_tools_reload")
    async def ext_tools_reload() -> Dict[str, Any]:
        """重新加载工具配置

        重新加载 config/external_tools.yaml 配置文件。
        用于配置文件修改后刷新工具状态。

        Returns:
            重新加载结果
        """
        # 重新创建管理器实例
        import core.tools.tool_manager as tm
        from core.tools import get_tool_manager

        tm._manager = None  # 清除缓存
        manager = get_tool_manager()

        status = manager.get_all_tools_status()
        available = sum(1 for t in status.values() if t.get("available"))

        return {
            "success": True,
            "message": "配置已重新加载",
            "available_tools": available,
            "total_tools": len(status),
        }

    counter.add("external_tools", 1)

    logger.info("[ExternalTools] 已注册 8 个外部工具")
