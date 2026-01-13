#!/usr/bin/env python3
"""
MCP Stdio Server - Windows/Linux 跨平台版本
支持 Claude Code / Cursor / Windsurf / Kiro 直接调用

架构重构后的精简入口文件:
- 核心工具模块已拆分到 tools/ 目录
- 高级模块保留在 modules/ 目录
- ToolRegistry 统一管理所有工具元数据
"""

import sys
import os

# 确保项目根目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

# 创建 MCP 服务器实例
mcp = FastMCP("AutoRedTeam")

# ========== 初始化 ToolRegistry (可选，用于工具元数据管理) ==========
try:
    from core.tool_registry import get_bridge, ToolCategory
    bridge = get_bridge(mcp)
    print("[INFO] ToolRegistry 已初始化", file=sys.stderr)
except ImportError:
    bridge = None
    print("[WARN] ToolRegistry 未加载 (不影响 MCP 功能)", file=sys.stderr)


# ========== 注册核心工具模块 ==========
# 从 tools/ 目录加载所有核心工具
try:
    from tools import register_all_tools
    core_tools = register_all_tools(mcp)
    print(f"[INFO] 核心工具模块已注册: {len(core_tools)} 个工具", file=sys.stderr)

    # 同步已注册的工具到 ToolRegistry (修复 registry_stats 空转问题)
    if bridge and core_tools:
        try:
            from core.tool_registry import ToolCategory, FunctionTool
            # 为每个工具名创建简单的元数据并注册到 Registry
            for tool_name in core_tools:
                # 创建一个占位工具对象用于统计
                try:
                    tool = FunctionTool(
                        name=tool_name,
                        description=f"MCP工具: {tool_name}",
                        category=ToolCategory.RECON,  # 默认类别
                        func=lambda: None  # 占位函数
                    )
                    bridge.registry.register(tool)
                except Exception:
                    pass  # 忽略重复注册等错误
            print(f"[INFO] 已同步 {len(core_tools)} 个工具到 ToolRegistry", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] ToolRegistry 同步失败: {e}", file=sys.stderr)
except ImportError as e:
    print(f"[ERROR] 核心工具模块加载失败: {e}", file=sys.stderr)
    print("[HINT] 请确保 tools/ 目录存在且包含所有必需模块", file=sys.stderr)
except Exception as e:
    print(f"[ERROR] 核心工具模块注册失败: {e}", file=sys.stderr)


# ========== 注册优化模块工具 ==========
try:
    from modules.optimization_tools import register_optimization_tools
    registered_tools = register_optimization_tools(mcp)
    print(f"[INFO] 优化模块工具已注册: {registered_tools}", file=sys.stderr)
except ImportError as e:
    print(f"[WARN] 优化模块加载失败 (可选): {e}", file=sys.stderr)
except Exception as e:
    print(f"[WARN] 优化模块注册失败: {e}", file=sys.stderr)


# ========== 注册Red Team高级工具 ==========
try:
    from modules.redteam_tools import register_redteam_tools
    redteam_tools = register_redteam_tools(mcp)
    print(f"[INFO] Red Team工具已注册: {redteam_tools}", file=sys.stderr)
except ImportError as e:
    print(f"[WARN] Red Team模块加载失败 (可选): {e}", file=sys.stderr)
except Exception as e:
    print(f"[WARN] Red Team模块注册失败: {e}", file=sys.stderr)


# ========== 注册v2.5新增工具 ==========
try:
    from modules.v25_tools import register_v25_tools
    v25_tools = register_v25_tools(mcp)
    print(f"[INFO] v2.5新增工具已注册: {v25_tools}", file=sys.stderr)
except ImportError as e:
    print(f"[WARN] v2.5模块加载失败 (可选): {e}", file=sys.stderr)
except Exception as e:
    print(f"[WARN] v2.5模块注册失败: {e}", file=sys.stderr)


# ========== 注册增强检测器工具 (JWT/CORS/SecurityHeaders) ==========
try:
    from modules.enhanced_detector_tools import register_enhanced_detector_tools
    enhanced_tools = register_enhanced_detector_tools(mcp)
    print(f"[INFO] 增强检测器工具已注册: {enhanced_tools}", file=sys.stderr)
except ImportError as e:
    print(f"[WARN] 增强检测器模块加载失败 (可选): {e}", file=sys.stderr)
except Exception as e:
    print(f"[WARN] 增强检测器模块注册失败: {e}", file=sys.stderr)


# ========== 注册API安全工具 (GraphQL/WebSocket) ==========
try:
    from modules.api_security_tools import register_api_security_tools
    api_security_tools = register_api_security_tools(mcp)
    print(f"[INFO] API安全工具已注册: {api_security_tools}", file=sys.stderr)
except ImportError as e:
    print(f"[WARN] API安全模块加载失败 (可选): {e}", file=sys.stderr)
except Exception as e:
    print(f"[WARN] API安全模块注册失败: {e}", file=sys.stderr)


# ========== 注册供应链安全工具 (SBOM/依赖扫描/CI-CD) ==========
try:
    from modules.supply_chain_tools import register_supply_chain_tools
    supply_chain_tools = register_supply_chain_tools(mcp)
    print(f"[INFO] 供应链安全工具已注册: {supply_chain_tools}", file=sys.stderr)
except ImportError as e:
    print(f"[WARN] 供应链安全模块加载失败 (可选): {e}", file=sys.stderr)
except Exception as e:
    print(f"[WARN] 供应链安全模块注册失败: {e}", file=sys.stderr)


# ========== 注册云安全工具 (K8s/gRPC) ==========
try:
    from modules.cloud_security_tools import register_cloud_security_tools
    cloud_security_tools = register_cloud_security_tools(mcp)
    print(f"[INFO] 云安全工具已注册: {cloud_security_tools}", file=sys.stderr)
except ImportError as e:
    print(f"[WARN] 云安全模块加载失败 (可选): {e}", file=sys.stderr)
except Exception as e:
    print(f"[WARN] 云安全模块注册失败: {e}", file=sys.stderr)


# ========== 注册 ToolRegistry 管理工具 ==========
@mcp.tool()
def registry_stats() -> dict:
    """获取 ToolRegistry 统计信息 - 查看工具分类和数量

    Returns:
        工具注册表统计信息，包括总数、按类别分布、MCP注册数
    """
    if bridge:
        return {"success": True, **bridge.export_stats()}
    return {"success": False, "error": "ToolRegistry 未初始化"}


@mcp.tool()
def registry_search(keyword: str) -> dict:
    """搜索工具 - 按名称或描述搜索注册的工具

    Args:
        keyword: 搜索关键词

    Returns:
        匹配的工具列表
    """
    if bridge:
        results = bridge.registry.search_tools(keyword)
        return {"success": True, "count": len(results), "tools": results}
    return {"success": False, "error": "ToolRegistry 未初始化"}


if __name__ == "__main__":
    # 启动时输出统计
    if bridge:
        stats = bridge.export_stats()
        print(f"[INFO] ToolRegistry: {stats['total_tools']} 个工具已索引", file=sys.stderr)
    mcp.run()
