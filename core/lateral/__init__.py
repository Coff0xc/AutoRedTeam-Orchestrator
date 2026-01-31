#!/usr/bin/env python3
"""
横向移动模块 - Lateral Movement Module
提供 SMB/SSH/WMI/WinRM/PsExec 等横向移动能力
用于内网渗透测试场景

用于授权安全测试，仅限合法渗透测试使用

Usage:
    from core.lateral import (
        SMBLateral, SSHLateral, WMILateral, WinRMLateral, PsExecLateral,
        Credentials, LateralConfig, AuthMethod,
        smb_exec, ssh_exec, wmi_exec, winrm_exec, psexec,
        create_lateral, auto_lateral, detect_os
    )

    # 创建凭证
    creds = Credentials(
        username='administrator',
        password='password123',
        domain='WORKGROUP'
    )

    # 方式1: 使用上下文管理器
    with SMBLateral('192.168.1.100', creds) as smb:
        result = smb.execute('whoami')
        print(result.output)

    # 方式2: 使用便捷函数
    result = smb_exec('192.168.1.100', 'admin', 'password', command='whoami')

    # 方式3: 自动选择方法
    lateral = auto_lateral('192.168.1.100', creds)
    if lateral:
        result = lateral.execute('whoami')
        lateral.disconnect()

    # Pass-the-Hash
    creds = Credentials(
        username='administrator',
        ntlm_hash='aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
    )
    result = pass_the_hash('192.168.1.100', 'admin', 'aad3b435:8846f7ea...')
"""

import logging

# 基类和数据结构
from .base import (  # 基类; 枚举; 数据类; 异常; 工具函数
    AuthenticationError,
    AuthMethod,
    BaseLateralModule,
    ConnectionError,
    Credentials,
    ExecutionError,
    ExecutionMethod,
    ExecutionResult,
    FileTransferResult,
    LateralConfig,
    LateralModuleError,
    LateralStatus,
    TransferError,
    ensure_credentials,
)

# PsExec 模块
from .psexec import (
    PsExecLateral,
    psexec,
    psexec_upload_exec,
)

# SMB 模块
from .smb import (
    SMBFile,
    SMBLateral,
    SMBShare,
    pass_the_hash,
    smb_connect,
    smb_download,
    smb_exec,
    smb_upload,
)

# SSH 模块
from .ssh import (
    SSHLateral,
    TunnelConfig,
    TunnelInfo,
    ssh_download,
    ssh_exec,
    ssh_tunnel,
    ssh_upload,
)

# 工具函数
from .utils import (  # 端口检测; 操作系统检测; 横向移动; 批量操作; 辅助函数; 常量
    COMMON_PORTS,
    OSType,
    PortStatus,
    auto_lateral,
    batch_execute,
    check_port,
    create_lateral,
    detect_os,
    format_result,
    get_available_methods,
    get_local_platform,
    is_valid_ip,
    parse_target_list,
    resolve_hostname,
    scan_ports,
    spray_credentials,
)

# WinRM 模块
from .winrm import (
    WinRMLateral,
    winrm_exec,
    winrm_ps,
)

# WMI 模块
from .wmi import (
    WMILateral,
    WMIQueryResult,
    WQLQueries,
    wmi_exec,
    wmi_query,
    wmi_recon,
)

logger = logging.getLogger(__name__)

# 版本信息
__version__ = "2.0.0"
__author__ = "AutoRedTeam"
__description__ = "Lateral Movement Module for Penetration Testing"

# 导出列表
__all__ = [
    # 版本
    "__version__",
    "__author__",
    "__description__",
    # 基类
    "BaseLateralModule",
    # 枚举
    "LateralStatus",
    "AuthMethod",
    "ExecutionMethod",
    "PortStatus",
    "OSType",
    # 数据类
    "Credentials",
    "ExecutionResult",
    "FileTransferResult",
    "LateralConfig",
    "SMBShare",
    "SMBFile",
    "TunnelConfig",
    "TunnelInfo",
    "WMIQueryResult",
    # 异常
    "LateralModuleError",
    "ConnectionError",
    "AuthenticationError",
    "ExecutionError",
    "TransferError",
    # 模块类
    "SMBLateral",
    "SSHLateral",
    "WMILateral",
    "WinRMLateral",
    "PsExecLateral",
    # SMB 函数
    "smb_connect",
    "smb_exec",
    "smb_upload",
    "smb_download",
    "pass_the_hash",
    # SSH 函数
    "ssh_exec",
    "ssh_tunnel",
    "ssh_upload",
    "ssh_download",
    # WMI 函数
    "wmi_exec",
    "wmi_query",
    "wmi_recon",
    "WQLQueries",
    # WinRM 函数
    "winrm_exec",
    "winrm_ps",
    # PsExec 函数
    "psexec",
    "psexec_upload_exec",
    # 工具函数
    "check_port",
    "scan_ports",
    "detect_os",
    "get_local_platform",
    "get_available_methods",
    "create_lateral",
    "auto_lateral",
    "batch_execute",
    "spray_credentials",
    "ensure_credentials",
    "is_valid_ip",
    "resolve_hostname",
    "parse_target_list",
    "format_result",
    # 常量
    "COMMON_PORTS",
]


def get_module_info() -> dict:
    """获取模块信息"""
    from .smb import HAS_IMPACKET
    from .ssh import HAS_PARAMIKO
    from .winrm import HAS_KERBEROS, HAS_NTLM, HAS_WINRM

    return {
        "version": __version__,
        "modules": {
            "smb": {
                "available": True,
                "impacket": HAS_IMPACKET,
            },
            "ssh": {
                "available": True,
                "paramiko": HAS_PARAMIKO,
            },
            "wmi": {
                "available": HAS_IMPACKET,
                "impacket": HAS_IMPACKET,
            },
            "winrm": {
                "available": HAS_WINRM,
                "pywinrm": HAS_WINRM,
                "ntlm": HAS_NTLM,
                "kerberos": HAS_KERBEROS,
            },
            "psexec": {
                "available": HAS_IMPACKET,
                "impacket": HAS_IMPACKET,
            },
        },
        "auth_methods": [m.value for m in AuthMethod],
    }


if __name__ == "__main__":
    # 配置测试用日志
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    logger.info("=" * 60)
    logger.info("AutoRedTeam Lateral Movement Module")
    logger.info("=" * 60)

    info = get_module_info()

    logger.info(f"\n版本: {info['version']}")
    logger.info("模块状态:")

    for module, status in info["modules"].items():
        available = "可用" if status["available"] else "不可用"
        deps = ", ".join(
            f"{k}={'已安装' if v else '未安装'}" for k, v in status.items() if k != "available"
        )
        logger.info(f"  {module}: {available} ({deps})")

    logger.info(f"\n认证方式: {', '.join(info['auth_methods'])}")

    logger.info("使用示例:")
    logger.info("  from core.lateral import SMBLateral, Credentials, smb_exec")
    logger.info("  result = smb_exec('192.168.1.100', 'admin', 'password', command='whoami')")
