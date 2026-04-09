"""
并发扫描处理器
提供: parallel_scan (多URL并发漏洞扫描)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.security import require_dangerous_auth

from .error_handling import ErrorCategory, extract_target, handle_errors, validate_inputs
from .tooling import tool


def register_parallel_tools(mcp, counter, logger):
    """注册并发扫描工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @require_dangerous_auth
    @validate_inputs(target="urls")
    @handle_errors(logger, category=ErrorCategory.DETECTOR, context_extractor=extract_target)
    async def parallel_scan(
        urls: List[str],
        scan_types: List[str] = None,
        concurrency: int = 10,
        timeout_per_url: float = 30.0,
    ) -> Dict[str, Any]:
        """并发漏洞扫描 — 对多个URL并行执行指定类型的安全扫描

        Args:
            urls: 要扫描的URL列表
            scan_types: 扫描类型列表 (默认: ["sqli", "xss", "ssrf"])
            concurrency: 最大并发数 (默认: 10)
            timeout_per_url: 每个URL的超时时间(秒)
        """
        import asyncio
        import importlib

        from core.concurrency import AsyncPool

        scan_types = scan_types or ["sqli", "xss", "ssrf"]

        # 检测器映射
        detector_map = {
            "sqli": ("core.detectors.injection.sqli", "SQLiDetector"),
            "xss": ("core.detectors.injection.xss", "XSSDetector"),
            "ssrf": ("core.detectors.access.ssrf", "SSRFDetector"),
            "lfi": ("core.detectors.file.lfi", "LFIDetector"),
            "rce": ("core.detectors.injection.rce", "RCEDetector"),
            "ssti": ("core.detectors.injection.ssti", "SSTIDetector"),
        }

        async def scan_one(url: str, scan_type: str) -> Dict[str, Any]:
            """扫描单个URL的单个类型"""
            if scan_type not in detector_map:
                return {
                    "url": url,
                    "scan_type": scan_type,
                    "error": "未知扫描类型: %s" % scan_type,
                }
            module_path, class_name = detector_map[scan_type]
            try:
                mod = importlib.import_module(module_path)
                detector_cls = getattr(mod, class_name)
                detector = detector_cls()
                results = await asyncio.wait_for(
                    detector.async_detect(url, params={}),
                    timeout=timeout_per_url,
                )
                findings = [r.to_dict() for r in results if r.vulnerable]
                return {
                    "url": url,
                    "scan_type": scan_type,
                    "vulnerable": len(findings) > 0,
                    "findings": findings,
                }
            except asyncio.TimeoutError:
                return {"url": url, "scan_type": scan_type, "error": "超时"}
            except Exception as e:
                return {"url": url, "scan_type": scan_type, "error": str(e)}

        # 构建所有协程
        coros = [scan_one(url, st) for url in urls for st in scan_types]

        pool = AsyncPool(concurrency=concurrency)
        results = await pool.run(coros, return_exceptions=True)

        # 聚合结果
        all_results: List[Dict[str, Any]] = []
        errors: List[str] = []
        for r in results:
            if isinstance(r, Exception):
                errors.append(str(r))
            elif isinstance(r, dict):
                all_results.append(r)

        vulnerable_count = sum(1 for r in all_results if r.get("vulnerable"))

        return {
            "success": True,
            "total_scans": len(coros),
            "completed": len(all_results),
            "vulnerable_urls": vulnerable_count,
            "errors": len(errors),
            "results": all_results,
        }

    counter.add("orchestration", 1)
    logger.info("[Parallel] 已注册并发扫描工具")
