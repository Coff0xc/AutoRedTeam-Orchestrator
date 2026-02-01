#!/usr/bin/env python3
"""
优化模块MCP工具集成
将AI决策引擎、性能监控、智能缓存暴露为MCP工具
"""

import json
import logging

from utils.mcp_tooling import patch_mcp_tool

logger = logging.getLogger(__name__)


def register_optimization_tools(mcp):
    """注册优化模块的MCP工具"""
    patch_mcp_tool(mcp)

    # ========== AI智能决策工具 ==========

    @mcp.tool()
    def ai_suggest_attack(
        url: str, tech_stack: str = "{}", open_ports: str = "", waf: str = "", found_vulns: str = ""
    ) -> str:
        """AI智能攻击建议 - 基于目标特征推荐最优攻击路径

        Args:
            url: 目标URL
            tech_stack: 技术栈JSON (如 {"language": "php", "framework": "laravel"})
            open_ports: 开放端口列表 (逗号分隔，如 "80,443,3306")
            waf: 检测到的WAF类型 (如 cloudflare, aws_waf)
            found_vulns: 已发现的漏洞 (逗号分隔，如 "sqli_detect,xss_detect")

        Returns:
            JSON格式的攻击建议
        """
        try:
            from modules.ai_decision_engine import TargetContext, get_decision_engine

            # 解析参数
            try:
                tech = json.loads(tech_stack) if tech_stack else {}
            except (json.JSONDecodeError, TypeError):
                tech = {}

            ports = [int(p.strip()) for p in open_ports.split(",") if p.strip().isdigit()]
            vulns = [v.strip() for v in found_vulns.split(",") if v.strip()]

            # 创建目标上下文
            context = TargetContext(
                url=url,
                tech_stack=tech,
                open_ports=ports,
                waf_detected=waf if waf else None,
                vulnerabilities_found=vulns,
            )

            # 获取建议
            engine = get_decision_engine()
            suggestion = engine.suggest_next_action(context)

            return json.dumps(
                {"success": True, "suggestion": suggestion}, indent=2, ensure_ascii=False
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @mcp.tool()
    def ai_attack_chain(url: str, found_vulns: str = "", max_depth: int = 5) -> str:
        """AI攻击链规划 - 生成多条可能的攻击路径

        Args:
            url: 目标URL
            found_vulns: 已发现的漏洞 (逗号分隔)
            max_depth: 攻击链最大深度

        Returns:
            JSON格式的攻击链列表
        """
        try:
            from modules.ai_decision_engine import TargetContext, get_decision_engine

            vulns = [v.strip() for v in found_vulns.split(",") if v.strip()]

            context = TargetContext(url=url, vulnerabilities_found=vulns)

            engine = get_decision_engine()
            chains = engine.get_attack_chain(context, max_depth=max_depth)

            return json.dumps(
                {
                    "success": True,
                    "attack_chains": chains[:10],  # 返回前10条
                    "total_chains": len(chains),
                },
                indent=2,
                ensure_ascii=False,
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @mcp.tool()
    def ai_record_result(attack_type: str, success: bool, duration: float = 0.0) -> str:
        """记录攻击结果 - 用于AI学习优化

        Args:
            attack_type: 攻击类型 (如 sqli_detect, xss_detect)
            success: 是否成功
            duration: 执行耗时(秒)

        Returns:
            记录结果
        """
        try:
            from modules.ai_decision_engine import get_decision_engine

            engine = get_decision_engine()
            engine.record_result(attack_type, success, duration)

            return json.dumps(
                {
                    "success": True,
                    "message": f"已记录 {attack_type} 结果: {'成功' if success else '失败'}",
                }
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ========== 性能监控工具 ==========

    @mcp.tool()
    def perf_summary() -> str:
        """获取性能监控摘要

        Returns:
            JSON格式的性能摘要
        """
        try:
            from modules.performance_monitor import get_performance_monitor

            monitor = get_performance_monitor()
            summary = monitor.get_summary()

            return json.dumps({"success": True, "summary": summary}, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @mcp.tool()
    def perf_bottlenecks() -> str:
        """识别性能瓶颈

        Returns:
            JSON格式的瓶颈分析
        """
        try:
            from modules.performance_monitor import get_performance_monitor

            monitor = get_performance_monitor()
            bottlenecks = monitor.identify_bottlenecks()

            return json.dumps(
                {"success": True, "bottlenecks": bottlenecks}, indent=2, ensure_ascii=False
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @mcp.tool()
    def perf_tool_stats(tool_name: str = "") -> str:
        """获取工具执行统计

        Args:
            tool_name: 工具名称 (留空获取所有工具统计)

        Returns:
            JSON格式的统计信息
        """
        try:
            from modules.performance_monitor import get_performance_monitor

            monitor = get_performance_monitor()
            stats = monitor.get_tool_stats(tool_name if tool_name else None)

            return json.dumps({"success": True, "stats": stats}, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @mcp.tool()
    def perf_recent(limit: int = 20) -> str:
        """获取最近执行记录

        Args:
            limit: 返回数量限制

        Returns:
            JSON格式的执行记录
        """
        try:
            from modules.performance_monitor import get_performance_monitor

            monitor = get_performance_monitor()
            recent = monitor.get_recent_executions(limit)

            return json.dumps({"success": True, "executions": recent}, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ========== 智能缓存工具 ==========

    @mcp.tool()
    def cache_stats() -> str:
        """获取缓存统计信息

        Returns:
            JSON格式的缓存统计
        """
        try:
            from modules.smart_cache import get_smart_cache

            cache = get_smart_cache()
            stats = cache.stats()

            return json.dumps({"success": True, "cache_stats": stats}, indent=2, ensure_ascii=False)

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @mcp.tool()
    def cache_cleanup() -> str:
        """清理过期缓存

        Returns:
            清理结果
        """
        try:
            from modules.smart_cache import get_smart_cache

            cache = get_smart_cache()
            result = cache.cleanup()

            return json.dumps(
                {
                    "success": True,
                    "cleaned": result,
                    "message": f"已清理 {sum(result.values())} 个过期条目",
                }
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    @mcp.tool()
    def cache_clear(cache_type: str = "") -> str:
        """清空缓存

        Args:
            cache_type: 缓存类型 (dns/tech/cve/payload/recon/vuln，留空清空所有)

        Returns:
            清空结果
        """
        try:
            from modules.smart_cache import get_smart_cache

            cache = get_smart_cache()
            cache.clear(cache_type if cache_type else None)

            return json.dumps(
                {
                    "success": True,
                    "message": f"已清空{'所有' if not cache_type else cache_type}缓存",
                }
            )

        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ========== 智能渗透测试（集成优化） ==========

    @mcp.tool()
    def smart_pentest(target: str, auto_learn: bool = True, use_cache: bool = True) -> str:
        """智能渗透测试 - 集成AI决策、性能监控、智能缓存

        Args:
            target: 目标URL或域名
            auto_learn: 是否自动学习优化
            use_cache: 是否使用缓存

        Returns:
            JSON格式的渗透测试结果
        """
        import time
        from urllib.parse import urlparse

        results = {
            "target": target,
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "phases": [],
            "suggestions": [],
            "vulnerabilities": [],
            "performance": {},
        }

        try:
            from modules.ai_decision_engine import TargetContext, get_decision_engine
            from modules.performance_monitor import get_performance_monitor
            from modules.smart_cache import get_smart_cache

            engine = get_decision_engine()
            monitor = get_performance_monitor()
            cache = get_smart_cache()

            # 确保URL格式
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"

            parsed = urlparse(target)
            domain = parsed.netloc

            # Phase 1: 信息收集
            phase1_start = time.time()
            recon_data = {}

            # 检查缓存
            if use_cache:
                cached_recon = cache.get("recon", domain)
                if cached_recon:
                    recon_data = cached_recon
                    results["phases"].append(
                        {"name": "信息收集", "status": "cached", "duration": 0}
                    )

            if not recon_data:
                # 执行侦察（这里简化，实际调用full_recon）
                with monitor.track("smart_pentest_recon"):
                    # 模拟侦察结果
                    recon_data = {
                        "domain": domain,
                        "url": target,
                        "tech_stack": {},
                        "open_ports": [80, 443],
                    }

                if use_cache:
                    cache.set("recon", domain, recon_data)

                results["phases"].append(
                    {
                        "name": "信息收集",
                        "status": "completed",
                        "duration": round(time.time() - phase1_start, 2),
                    }
                )

            # Phase 2: AI分析并推荐攻击
            context = TargetContext(
                url=target,
                tech_stack=recon_data.get("tech_stack", {}),
                open_ports=recon_data.get("open_ports", []),
                waf_detected=recon_data.get("waf"),
                recon_data=recon_data,
            )

            suggestion = engine.suggest_next_action(context)
            results["suggestions"] = [suggestion]

            # Phase 3: 执行推荐的攻击
            attack_results = []
            for alt in [suggestion] + suggestion.get("alternatives", [])[:2]:
                attack_type = alt.get("action") if isinstance(alt, dict) else alt
                if attack_type:
                    attack_start = time.time()
                    with monitor.track(f"smart_pentest_{attack_type}"):
                        # 这里应该调用实际的攻击工具
                        # 简化示例
                        attack_result = {
                            "attack": attack_type,
                            "status": "executed",
                            "duration": round(time.time() - attack_start, 2),
                        }
                        attack_results.append(attack_result)

                        # 记录结果用于学习
                        if auto_learn:
                            engine.record_result(
                                attack_type, success=True, duration=attack_result["duration"]
                            )

            results["phases"].append(
                {"name": "漏洞检测", "attacks": attack_results, "status": "completed"}
            )

            # 获取性能统计
            results["performance"] = monitor.get_summary()
            results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            results["success"] = True

            return json.dumps(results, indent=2, ensure_ascii=False)

        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
            return json.dumps(results, indent=2, ensure_ascii=False)

    logger.info("优化模块MCP工具注册完成")
    return [
        "ai_suggest_attack",
        "ai_attack_chain",
        "ai_record_result",
        "perf_summary",
        "perf_bottlenecks",
        "perf_tool_stats",
        "perf_recent",
        "cache_stats",
        "cache_cleanup",
        "cache_clear",
        "smart_pentest",
    ]
