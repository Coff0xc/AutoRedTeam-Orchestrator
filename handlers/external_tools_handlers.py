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

from typing import Any, Dict, List, Optional

from core.security import require_dangerous_auth

from .error_handling import (
    extract_target,
    extract_url,
    handle_external_tool_errors,
    validate_inputs,
)
from .tooling import tool


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
        preset: str = "quick",
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Nmap深度端口扫描与服务识别

        使用外部Nmap工具进行专业级端口扫描，支持服务版本检测、NSE脚本扫描。
        相比内置端口扫描，提供更准确的服务识别和漏洞检测能力。

        Args:
            target: 目标IP或主机名
            ports: 端口范围 (例: "22,80,443" 或 "1-1000" 或 "top100")
            preset: 预设模式
                - quick: 快速扫描 (-sT -T4)
                - full: 完整扫描 (-sT -sV -sC -T4)
                - stealth: 隐蔽扫描 (-sS -T2) [需要root]
                - version: 版本检测 (-sV -sC)
                - vuln: 漏洞扫描 (-sV --script=vuln)
            extra_args: 额外的Nmap参数

        Returns:
            扫描结果，包含:
            - success: 是否成功
            - hosts: 主机列表
            - ports: 开放端口及服务信息
            - raw_output: 原始输出
        """
        from core.tools import get_tool_manager, run_nmap

        manager = get_tool_manager()

        # 检查工具是否可用
        if not manager.is_tool_available("nmap"):
            return {
                "success": False,
                "error": "Nmap未安装或路径未配置",
                "hint": "请检查 config/external_tools.yaml 中的 nmap 配置",
            }

        # 处理端口参数
        if ports == "top100":
            ports = (
                "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
            )

        result = await run_nmap(
            target=target, ports=ports, preset=preset, extra_args=extra_args
        )

        return result

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_external_tool_errors(logger, "ext_nuclei_scan", extract_target)
    async def ext_nuclei_scan(
        target: str,
        preset: str = "quick",
        tags: Optional[List[str]] = None,
        severity: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Nuclei漏洞模板扫描

        使用Nuclei进行基于模板的漏洞扫描，覆盖CVE、配置错误、敏感信息泄露等。
        支持7000+模板，自动更新。

        Args:
            target: 目标URL
            preset: 预设模式
                - quick: 快速扫描 (只扫描critical/high)
                - full: 完整扫描 (所有严重级别)
                - cve: CVE专项扫描
            tags: 模板标签过滤 (例: ["cve", "rce", "sqli"])
            severity: 严重级别过滤 (例: "critical,high,medium")
            extra_args: 额外的Nuclei参数

        Returns:
            扫描结果，包含:
            - success: 是否成功
            - findings: 发现的漏洞列表
            - stats: 扫描统计
        """
        from core.tools import get_tool_manager, run_nuclei

        manager = get_tool_manager()

        if not manager.is_tool_available("nuclei"):
            return {
                "success": False,
                "error": "Nuclei未安装或路径未配置",
                "hint": "请检查 config/external_tools.yaml 中的 nuclei 配置",
            }

        # 构建额外参数
        args = extra_args or []
        if tags:
            args.extend(["-tags", ",".join(tags)])
        if severity:
            args.extend(["-severity", severity])

        result = await run_nuclei(
            target=target, preset=preset, extra_args=args if args else None
        )

        return result

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(url="url")
    @handle_external_tool_errors(logger, "ext_sqlmap_scan", extract_url)
    async def ext_sqlmap_scan(
        url: str,
        data: Optional[str] = None,
        preset: str = "detect",
        tamper: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """SQLMap SQL注入检测与利用

        使用SQLMap进行专业级SQL注入检测，支持:
        - 6种注入技术 (布尔盲注、时间盲注、报错注入、联合查询、堆叠查询、带外)
        - 数据库指纹识别
        - WAF/IPS绕过 (tamper脚本)
        - 数据提取

        Args:
            url: 目标URL (带参数，如 http://example.com/page?id=1)
            data: POST数据 (可选)
            preset: 预设模式
                - detect: 检测模式 (--level=2 --risk=1)
                - exploit: 利用模式 (--level=5 --risk=3 --dump)
                - tamper: 绕过模式 (带tamper脚本)
            tamper: tamper脚本列表 (例: ["space2comment", "randomcase"])
            extra_args: 额外的SQLMap参数

        Returns:
            扫描结果，包含:
            - success: 是否成功
            - vulnerable: 是否存在注入
            - injection_type: 注入类型
            - dbms: 数据库类型
            - data: 提取的数据 (如有)
        """
        from core.tools import get_tool_manager, run_sqlmap

        manager = get_tool_manager()

        if not manager.is_tool_available("sqlmap"):
            return {
                "success": False,
                "error": "SQLMap未安装或路径未配置",
                "hint": "请检查 config/external_tools.yaml 中的 sqlmap 配置",
            }

        # 构建额外参数
        args = extra_args or []
        if data:
            args.extend(["--data", data])
        if tamper:
            args.extend(["--tamper", ",".join(tamper)])

        result = await run_sqlmap(url=url, preset=preset, extra_args=args if args else None)

        return result

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(url="url")
    @handle_external_tool_errors(logger, "ext_ffuf_fuzz", extract_url)
    async def ext_ffuf_fuzz(
        url: str,
        wordlist: str = "common",
        mode: str = "dir",
        extensions: Optional[List[str]] = None,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """ffuf Web模糊测试

        使用ffuf进行高速Web模糊测试，支持:
        - 目录/文件发现
        - 参数爆破
        - 虚拟主机枚举
        - 自定义字典

        Args:
            url: 目标URL (用FUZZ标记注入点，如 http://example.com/FUZZ)
            wordlist: 字典名称或路径
                - common: 通用目录字典
                - large: 大型字典
                - api: API端点字典
                - 或自定义路径
            mode: 模式
                - dir: 目录扫描
                - param: 参数爆破
                - vhost: 虚拟主机枚举
            extensions: 要测试的扩展名 (例: [".php", ".bak", ".old"])
            extra_args: 额外的ffuf参数

        Returns:
            扫描结果，包含:
            - success: 是否成功
            - results: 发现的路径列表
            - stats: 扫描统计
        """
        from core.tools import get_tool_manager, run_ffuf

        manager = get_tool_manager()

        if not manager.is_tool_available("ffuf"):
            return {
                "success": False,
                "error": "ffuf未安装或路径未配置",
                "hint": "请检查 config/external_tools.yaml 中的 ffuf 配置",
            }

        # 确保URL包含FUZZ标记
        if "FUZZ" not in url:
            if mode == "dir":
                url = url.rstrip("/") + "/FUZZ"
            elif mode == "param":
                if "?" in url:
                    url = url + "&FUZZ=test"
                else:
                    url = url + "?FUZZ=test"

        # 构建额外参数
        args = extra_args or []
        if extensions:
            args.extend(["-e", ",".join(extensions)])

        result = await run_ffuf(
            url=url, wordlist=wordlist, preset=mode, extra_args=args if args else None
        )

        return result

    counter.add("external_tools", 1)

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="target")
    @handle_external_tool_errors(logger, "ext_masscan_scan", extract_target)
    async def ext_masscan_scan(
        target: str,
        ports: str = "1-10000",
        rate: int = 10000,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Masscan高速端口扫描

        使用Masscan进行超高速端口扫描，适合大规模资产发现。
        扫描速度可达每秒数百万包。

        注意: 高速扫描可能触发IDS/IPS，建议在授权测试中使用。

        Args:
            target: 目标IP或CIDR (例: "192.168.1.0/24")
            ports: 端口范围 (例: "1-65535" 或 "80,443,8080")
            rate: 发包速率 (每秒包数，默认10000)
            extra_args: 额外的Masscan参数

        Returns:
            扫描结果，包含:
            - success: 是否成功
            - hosts: 发现的主机列表
            - ports: 开放端口列表
        """
        from core.tools import get_tool_manager, run_masscan

        manager = get_tool_manager()

        if not manager.is_tool_available("masscan"):
            return {
                "success": False,
                "error": "Masscan未安装或路径未配置",
                "hint": "请检查 config/external_tools.yaml 中的 masscan 配置",
            }

        # 速率验证
        if rate <= 0 or rate > 10000000:
            return {"success": False, "error": "rate 必须在 1-10000000 之间"}

        # 构建额外参数
        args = extra_args or []
        args.extend(["--rate", str(rate)])

        result = await run_masscan(target=target, ports=ports, extra_args=args)

        return result

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

        manager = get_tool_manager()
        result = await manager.run_chain(
            chain_name=chain_name, target=target, config_override=config_override
        )

        return result

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
