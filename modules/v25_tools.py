#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v2.5 新增MCP工具注册模块
包含: JS分析、CVE同步、PoC执行、隧道通信、分块传输
"""

import asyncio
import sys
import os
from typing import Dict, List, Optional
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

import logging
logger = logging.getLogger(__name__)


def register_v25_tools(mcp):
    """
    注册v2.5版本新增工具

    Args:
        mcp: FastMCP实例

    Returns:
        注册的工具列表
    """
    registered = []

    # ========== JS分析工具 ==========
    try:
        from modules.js_analyzer import JSAnalyzer

        @mcp.tool()
        def js_analyze(url: str, extract_type: str = "all") -> dict:
            """JavaScript分析 - 提取API端点、路由、敏感信息

            Args:
                url: 目标URL (JS文件或网页)
                extract_type: 提取类型 (api/routes/secrets/all)

            Returns:
                {
                    "api_endpoints": [...],
                    "routes": [...],
                    "secrets": {...}
                }
            """
            import asyncio

            async def _analyze():
                analyzer = JSAnalyzer()
                return await analyzer.analyze_url(url)

            try:
                # 在Windows上需要特殊处理事件循环
                try:
                    loop = asyncio.get_running_loop()
                    # 如果有运行中的循环，使用线程池
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        future = pool.submit(asyncio.run, _analyze())
                        result = future.result(timeout=60)
                except RuntimeError:
                    # 没有运行中的循环，直接使用 asyncio.run()
                    result = asyncio.run(_analyze())

                if extract_type == "api":
                    return {"api_endpoints": result.get("api_endpoints", [])}
                elif extract_type == "routes":
                    return {"routes": result.get("routes", [])}
                elif extract_type == "secrets":
                    return {"secrets": result.get("secrets", {})}
                else:
                    return result

            except Exception as e:
                return {"error": str(e), "success": False}

        @mcp.tool()
        def js_extract_apis(js_content: str) -> dict:
            """从JS代码中提取API端点

            Args:
                js_content: JavaScript代码内容

            Returns:
                {"api_endpoints": [...], "count": N}
            """
            try:
                endpoints = JSAnalyzer.extract_api_endpoints(js_content)
                return {
                    "api_endpoints": list(endpoints),
                    "count": len(endpoints),
                    "success": True
                }
            except Exception as e:
                return {"error": str(e), "success": False}

        @mcp.tool()
        def js_extract_secrets(js_content: str) -> dict:
            """从JS代码中提取敏感信息

            Args:
                js_content: JavaScript代码内容

            Returns:
                {"secrets": {...}, "count": N}
            """
            try:
                secrets = JSAnalyzer.extract_secrets(js_content)
                return {
                    "secrets": secrets,
                    "count": sum(len(v) for v in secrets.values()),
                    "success": True
                }
            except Exception as e:
                return {"error": str(e), "success": False}

        registered.extend(["js_analyze", "js_extract_apis", "js_extract_secrets"])
        logger.info("JS分析工具已注册")

    except ImportError as e:
        logger.warning(f"JS分析模块加载失败: {e}")

    # ========== CVE同步工具 ==========
    try:
        from core.cve import CVEUpdateManager

        # 全局CVE管理器实例
        _cve_manager = None

        def _get_cve_manager():
            global _cve_manager
            if _cve_manager is None:
                _cve_manager = CVEUpdateManager()
            return _cve_manager

        @mcp.tool()
        def cve_sync(days_back: int = 7, source: str = "all") -> dict:
            """同步CVE数据库 (NVD/Nuclei/Exploit-DB)

            Args:
                days_back: 同步最近N天的数据 (默认7天)
                source: 数据源 (nvd/nuclei/exploit_db/all)

            Returns:
                {
                    "status": "success",
                    "results": {"NVD": [new, updated], ...},
                    "stats": {...}
                }
            """
            manager = _get_cve_manager()

            async def _sync():
                if source == "nvd":
                    result = await manager.sync_nvd(days_back)
                    return {"NVD": result}
                elif source == "nuclei":
                    result = await manager.sync_nuclei_templates()
                    return {"Nuclei": result}
                elif source == "exploit_db":
                    result = await manager.sync_exploit_db()
                    return {"Exploit-DB": result}
                else:
                    return await manager.sync_all(days_back)

            try:
                results = asyncio.run(_sync())
                stats = manager.get_stats()
                return {
                    "status": "success",
                    "results": {k: list(v) if isinstance(v, tuple) else v for k, v in results.items()},
                    "stats": stats
                }
            except Exception as e:
                return {"status": "error", "error": str(e)}

        @mcp.tool()
        def cve_search_advanced(
            keyword: str = "",
            severity: str = "",
            min_cvss: float = 0.0,
            poc_only: bool = False,
            limit: int = 50
        ) -> dict:
            """高级CVE搜索 - 多条件过滤

            Args:
                keyword: 关键词 (CVE ID或描述)
                severity: 严重性 (CRITICAL/HIGH/MEDIUM/LOW)
                min_cvss: 最低CVSS分数
                poc_only: 仅显示有PoC的CVE
                limit: 最多返回数量

            Returns:
                {"total": N, "cves": [...]}
            """
            manager = _get_cve_manager()

            try:
                results = manager.search(
                    keyword=keyword,
                    severity=severity.upper() if severity else None,
                    min_cvss=min_cvss,
                    poc_only=poc_only
                )

                return {
                    "status": "success",
                    "total": len(results),
                    "cves": [cve.to_dict() for cve in results[:limit]]
                }
            except Exception as e:
                return {"status": "error", "error": str(e)}

        @mcp.tool()
        def cve_stats() -> dict:
            """获取CVE数据库统计信息

            Returns:
                {
                    "total_cves": N,
                    "poc_available": N,
                    "by_severity": {...},
                    "by_source": {...}
                }
            """
            manager = _get_cve_manager()

            try:
                stats = manager.get_stats()
                return {"status": "success", **stats}
            except Exception as e:
                return {"status": "error", "error": str(e)}

        registered.extend(["cve_sync", "cve_search_advanced", "cve_stats"])
        logger.info("CVE同步工具已注册")

    except ImportError as e:
        logger.warning(f"CVE模块加载失败: {e}")

    # ========== PoC执行工具 ==========
    try:
        from core.cve import PoCEngine, load_poc, execute_poc

        @mcp.tool()
        def poc_execute(target: str, poc_id: str = "", poc_file: str = "") -> dict:
            """执行PoC验证漏洞

            Args:
                target: 目标URL
                poc_id: PoC ID (如 CVE-2021-44228)
                poc_file: PoC文件路径 (与poc_id二选一)

            Returns:
                {
                    "vulnerable": bool,
                    "details": {...}
                }
            """
            try:
                if poc_file:
                    poc = load_poc(poc_file)
                elif poc_id:
                    # 从内置模板查找
                    templates_dir = Path(__file__).parent.parent / "templates" / "builtin"
                    poc_files = list(templates_dir.glob(f"*{poc_id.lower()}*.yaml"))
                    if not poc_files:
                        return {"error": f"PoC not found: {poc_id}", "success": False}
                    poc = load_poc(str(poc_files[0]))
                else:
                    return {"error": "需要指定 poc_id 或 poc_file", "success": False}

                result = execute_poc(poc, target)

                return {
                    "success": True,
                    "vulnerable": result.vulnerable,
                    "poc_id": result.poc_id,
                    "target": result.target,
                    "matched_at": result.matched_at,
                    "extracted_data": result.extracted_data,
                    "timestamp": result.timestamp
                }

            except Exception as e:
                return {"error": str(e), "success": False}

        @mcp.tool()
        def poc_list() -> dict:
            """列出可用的PoC模板

            Returns:
                {"templates": [...], "count": N}
            """
            try:
                templates_dir = Path(__file__).parent.parent / "templates" / "builtin"
                templates = []

                for yaml_file in templates_dir.glob("*.yaml"):
                    templates.append({
                        "file": yaml_file.name,
                        "id": yaml_file.stem.upper().replace("-", "_")
                    })

                return {
                    "success": True,
                    "templates": templates,
                    "count": len(templates)
                }

            except Exception as e:
                return {"error": str(e), "success": False}

        registered.extend(["poc_execute", "poc_list"])
        logger.info("PoC执行工具已注册")

    except ImportError as e:
        logger.warning(f"PoC模块加载失败: {e}")

    # ========== WebSocket隧道工具 ==========
    try:
        # 优先使用新架构
        from core.c2 import WebSocketTunnel, C2Config, CryptoAlgorithm

        @mcp.tool()
        def tunnel_websocket_create(
            server_url: str,
            encryption: str = "xor",
            disguise: str = "chat"
        ) -> dict:
            """创建WebSocket隧道配置

            Args:
                server_url: WebSocket服务器URL (wss://...)
                encryption: 加密方式 (none/xor/aes)
                disguise: 伪装类型 (chat/notifications/metrics)

            Returns:
                {"tunnel_id": "...", "config": {...}}
            """
            try:
                # 映射加密类型
                encryption_map = {
                    "none": "none",
                    "xor": "xor",
                    "aes": "aes256_gcm"
                }
                enc_algo = encryption_map.get(encryption.lower(), "xor")

                # 解析 URL
                from urllib.parse import urlparse
                parsed = urlparse(server_url)
                protocol = 'wss' if parsed.scheme == 'wss' else 'ws'
                server = parsed.hostname or 'localhost'
                port = parsed.port or (443 if protocol == 'wss' else 80)

                config = C2Config(
                    server=server,
                    port=port,
                    protocol=protocol,
                    encryption=enc_algo,
                )

                return {
                    "success": True,
                    "config": {
                        "url": server_url,
                        "server": server,
                        "port": port,
                        "protocol": protocol,
                        "encryption": enc_algo,
                    }
                }

            except Exception as e:
                return {"error": str(e), "success": False}

        registered.append("tunnel_websocket_create")
        logger.info("WebSocket隧道工具已注册")

    except ImportError as e:
        logger.warning(f"WebSocket隧道模块加载失败: {e}")

    # ========== 分块传输工具 ==========
    try:
        # 使用新架构的编码器
        from core.c2 import C2Encoder, ChunkEncoder

        @mcp.tool()
        def chunked_split(
            data: str,
            chunk_size: int = 1024,
            compress: bool = True
        ) -> dict:
            """分块传输 - 数据分割

            Args:
                data: 要分割的数据
                chunk_size: 块大小 (字节)
                compress: 是否压缩

            Returns:
                {"chunks": [...], "total": N, "checksum": "..."}
            """
            try:
                encoder = C2Encoder()
                data_bytes = data.encode('utf-8')

                # 使用编码器的压缩功能
                result = encoder.encode(data_bytes, encoding='base64', compress=compress)
                encoded_data = result.data if isinstance(result.data, str) else result.data.decode()

                # 分块
                chunk_encoder = ChunkEncoder(chunk_size=chunk_size)
                chunks = chunk_encoder.encode_chunks(data_bytes, encoding='base64')

                return {
                    "success": True,
                    "chunks_count": len(chunks),
                    "total_size": len(data),
                    "chunk_size": chunk_size,
                    "compressed": compress
                }

            except Exception as e:
                return {"error": str(e), "success": False}

        registered.append("chunked_split")
        logger.info("分块传输工具已注册")

    except ImportError as e:
        logger.warning(f"分块传输模块加载失败: {e}")

    return registered


# 独立测试
if __name__ == "__main__":
    print("v2.5 工具模块测试")
    print("=" * 50)

    # 测试导入
    print("\n1. 测试JS分析模块:")
    try:
        from modules.js_analyzer import JSAnalyzer
        print("   [OK] JSAnalyzer 导入成功")
    except Exception as e:
        print(f"   [FAIL] {e}")

    print("\n2. 测试CVE模块:")
    try:
        from core.cve import CVEUpdateManager
        print("   [OK] CVEUpdateManager 导入成功")
    except Exception as e:
        print(f"   [FAIL] {e}")

    print("\n3. 测试PoC模块:")
    try:
        from core.cve import PoCEngine, load_poc
        print("   [OK] PoCEngine 导入成功")
    except Exception as e:
        print(f"   [FAIL] {e}")

    print("\n4. 测试WebSocket隧道:")
    try:
        from core.c2 import WebSocketTunnel
        print("   [OK] WebSocketTunnel 导入成功")
    except Exception as e:
        print(f"   [FAIL] {e}")

    print("\n5. 测试分块传输:")
    try:
        from core.c2 import ChunkEncoder
        print("   [OK] ChunkEncoder 导入成功")
    except Exception as e:
        print(f"   [FAIL] {e}")

    print("\n" + "=" * 50)
    print("测试完成!")
