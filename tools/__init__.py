"""
AutoRedTeam-Orchestrator 工具模块

统一注册接口，将所有工具模块整合到一起。

注意: tools/ 属于 legacy 注册入口，推荐使用 mcp_stdio_server.py + handlers/

使用方式:
    from tools import register_all_tools
    registered = register_all_tools(mcp)
    print(f"已注册 {len(registered)} 个工具")
"""

from typing import List

from utils.mcp_tooling import patch_mcp_tool
from utils.decorators import deprecated


@deprecated(version="3.0.0", replacement="mcp_stdio_server.py + handlers")
def register_all_tools(mcp) -> List[str]:
    """统一注册所有工具到MCP服务器

    Args:
        mcp: FastMCP 服务器实例

    Returns:
        已注册的工具名称列表
    """
    patch_mcp_tool(mcp)
    all_tools = []

    # 1. 配置管理工具
    try:
        from .config_tools import register_config_tools
        tools = register_config_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] 配置工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] 配置工具注册失败: {e}")

    # 2. 信息收集工具
    try:
        from .recon_tools import register_recon_tools
        tools = register_recon_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] 侦察工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] 侦察工具注册失败: {e}")

    # 3. Payload生成工具
    try:
        from .payload_tools import register_payload_tools
        tools = register_payload_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] Payload工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] Payload工具注册失败: {e}")

    # 4. 漏洞检测工具
    try:
        from .vuln_tools import register_vuln_tools
        tools = register_vuln_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] 漏洞检测工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] 漏洞检测工具注册失败: {e}")

    # 5. 会话管理工具
    try:
        from .session_tools import register_session_tools
        tools = register_session_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] 会话工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] 会话工具注册失败: {e}")

    # 6. 任务队列工具
    try:
        from .task_tools import register_task_tools
        tools = register_task_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] 任务工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] 任务工具注册失败: {e}")

    # 7. CVE情报工具
    try:
        from .cve_tools import register_cve_tools
        tools = register_cve_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] CVE工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] CVE工具注册失败: {e}")

    # 8. AI决策工具
    try:
        from .ai_tools import register_ai_tools
        tools = register_ai_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] AI工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] AI工具注册失败: {e}")

    # 9. 渗透测试工具
    try:
        from .pentest_tools import register_pentest_tools
        tools = register_pentest_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] 渗透测试工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] 渗透测试工具注册失败: {e}")

    # 10. 外部工具集成 (nmap, nuclei, sqlmap等)
    try:
        from .external_tools import register_external_tools
        tools = register_external_tools(mcp)
        all_tools.extend(tools)
        print(f"[+] 外部工具已注册: {len(tools)} 个")
    except ImportError as e:
        print(f"[-] 外部工具注册失败: {e}")

    # 11. 流水线工具 (指纹→POC→弱口令→攻击链联动)
    try:
        from .pipeline_tools import register_pipeline_tools
        tools = register_pipeline_tools(mcp)
        all_tools.extend(tools if tools else [])
        print(f"[+] 流水线工具已注册")
    except ImportError as e:
        print(f"[-] 流水线工具注册失败: {e}")

    # 12. Web 扫描工具 (攻面发现 + 编排式扫描)
    try:
        from .web_scan_tools import register_web_scan_tools
        tools = register_web_scan_tools(mcp)
        all_tools.extend(tools if tools else [])
        print(f"[+] Web扫描工具已注册: {len(tools) if tools else 0} 个")
    except ImportError as e:
        print(f"[-] Web扫描工具注册失败: {e}")

    print(f"\n[*] 工具注册完成，共 {len(all_tools)} 个工具")
    return all_tools


def register_tools_silent(mcp) -> List[str]:
    """静默注册所有工具（无打印输出）

    Args:
        mcp: FastMCP 服务器实例

    Returns:
        已注册的工具名称列表
    """
    patch_mcp_tool(mcp)
    all_tools = []

    registrars = [
        ('config_tools', 'register_config_tools'),
        ('recon_tools', 'register_recon_tools'),
        ('payload_tools', 'register_payload_tools'),
        ('vuln_tools', 'register_vuln_tools'),
        ('session_tools', 'register_session_tools'),
        ('task_tools', 'register_task_tools'),
        ('cve_tools', 'register_cve_tools'),
        ('ai_tools', 'register_ai_tools'),
        ('pentest_tools', 'register_pentest_tools'),
        ('external_tools', 'register_external_tools'),
    ]

    for module_name, func_name in registrars:
        try:
            module = __import__(f'tools.{module_name}', fromlist=[func_name])
            register_func = getattr(module, func_name)
            tools = register_func(mcp)
            all_tools.extend(tools)
        except (ImportError, AttributeError):
            pass

    return all_tools


# 导出模块化检测器 (新架构)
try:
    from .detectors import (
        # 基类
        BaseDetector, Vulnerability,
        # 检测器类
        SQLiDetector, XSSDetector, RCEDetector,
        SSRFDetector, CSRFDetector, CORSDetector,
        LFIDetector, FileUploadDetector,
        AuthBypassDetector, WeakPasswordDetector,
        # 工具函数
        get_detector, list_detectors,
        DETECTOR_REGISTRY,
    )
    HAS_DETECTORS = True
except ImportError:
    HAS_DETECTORS = False


# 导出公共接口
__all__ = [
    'register_all_tools',
    'register_tools_silent',
    # 检测器 (新架构)
    'BaseDetector',
    'Vulnerability',
    'SQLiDetector',
    'XSSDetector',
    'RCEDetector',
    'SSRFDetector',
    'CSRFDetector',
    'CORSDetector',
    'LFIDetector',
    'FileUploadDetector',
    'AuthBypassDetector',
    'WeakPasswordDetector',
    'get_detector',
    'list_detectors',
    'DETECTOR_REGISTRY',
]
