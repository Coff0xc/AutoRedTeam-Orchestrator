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

# 基类和数据结构
from .base import (
    # 基类
    BaseLateralModule,

    # 枚举
    LateralStatus,
    AuthMethod,
    ExecutionMethod,

    # 数据类
    Credentials,
    ExecutionResult,
    FileTransferResult,
    LateralConfig,

    # 异常
    LateralModuleError,
    ConnectionError,
    AuthenticationError,
    ExecutionError,
    TransferError,

    # 工具函数
    ensure_credentials,
)

# SMB 模块
from .smb import (
    SMBLateral,
    SMBShare,
    SMBFile,
    smb_connect,
    smb_exec,
    smb_upload,
    smb_download,
    pass_the_hash,
)

# SSH 模块
from .ssh import (
    SSHLateral,
    TunnelConfig,
    TunnelInfo,
    ssh_exec,
    ssh_tunnel,
    ssh_upload,
    ssh_download,
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

# WinRM 模块
from .winrm import (
    WinRMLateral,
    winrm_exec,
    winrm_ps,
)

# PsExec 模块
from .psexec import (
    PsExecLateral,
    psexec,
    psexec_upload_exec,
)

# 工具函数
from .utils import (
    # 端口检测
    check_port,
    scan_ports,
    PortStatus,

    # 操作系统检测
    detect_os,
    OSType,
    get_local_platform,

    # 横向移动
    get_available_methods,
    create_lateral,
    auto_lateral,

    # 批量操作
    batch_execute,
    spray_credentials,

    # 辅助函数
    is_valid_ip,
    resolve_hostname,
    parse_target_list,
    format_result,

    # 常量
    COMMON_PORTS,
)

# 版本信息
__version__ = '2.0.0'
__author__ = 'AutoRedTeam'
__description__ = 'Lateral Movement Module for Penetration Testing'

# 导出列表
__all__ = [
    # 版本
    '__version__',
    '__author__',
    '__description__',

    # 基类
    'BaseLateralModule',

    # 枚举
    'LateralStatus',
    'AuthMethod',
    'ExecutionMethod',
    'PortStatus',
    'OSType',

    # 数据类
    'Credentials',
    'ExecutionResult',
    'FileTransferResult',
    'LateralConfig',
    'SMBShare',
    'SMBFile',
    'TunnelConfig',
    'TunnelInfo',
    'WMIQueryResult',

    # 异常
    'LateralModuleError',
    'ConnectionError',
    'AuthenticationError',
    'ExecutionError',
    'TransferError',

    # 模块类
    'SMBLateral',
    'SSHLateral',
    'WMILateral',
    'WinRMLateral',
    'PsExecLateral',

    # SMB 函数
    'smb_connect',
    'smb_exec',
    'smb_upload',
    'smb_download',
    'pass_the_hash',

    # SSH 函数
    'ssh_exec',
    'ssh_tunnel',
    'ssh_upload',
    'ssh_download',

    # WMI 函数
    'wmi_exec',
    'wmi_query',
    'wmi_recon',
    'WQLQueries',

    # WinRM 函数
    'winrm_exec',
    'winrm_ps',

    # PsExec 函数
    'psexec',
    'psexec_upload_exec',

    # 工具函数
    'check_port',
    'scan_ports',
    'detect_os',
    'get_local_platform',
    'get_available_methods',
    'create_lateral',
    'auto_lateral',
    'batch_execute',
    'spray_credentials',
    'ensure_credentials',
    'is_valid_ip',
    'resolve_hostname',
    'parse_target_list',
    'format_result',

    # 常量
    'COMMON_PORTS',
]


def get_module_info() -> dict:
    """获取模块信息"""
    from .smb import HAS_IMPACKET
    from .ssh import HAS_PARAMIKO
    from .winrm import HAS_WINRM, HAS_NTLM, HAS_KERBEROS

    return {
        'version': __version__,
        'modules': {
            'smb': {
                'available': True,
                'impacket': HAS_IMPACKET,
            },
            'ssh': {
                'available': True,
                'paramiko': HAS_PARAMIKO,
            },
            'wmi': {
                'available': HAS_IMPACKET,
                'impacket': HAS_IMPACKET,
            },
            'winrm': {
                'available': HAS_WINRM,
                'pywinrm': HAS_WINRM,
                'ntlm': HAS_NTLM,
                'kerberos': HAS_KERBEROS,
            },
            'psexec': {
                'available': HAS_IMPACKET,
                'impacket': HAS_IMPACKET,
            },
        },
        'auth_methods': [m.value for m in AuthMethod],
    }


if __name__ == '__main__':
    print("=" * 60)
    print("AutoRedTeam Lateral Movement Module")
    print("=" * 60)

    info = get_module_info()

    print(f"\n版本: {info['version']}")
    print("\n模块状态:")

    for module, status in info['modules'].items():
        available = "可用" if status['available'] else "不可用"
        deps = ', '.join(f"{k}={'已安装' if v else '未安装'}"
                         for k, v in status.items() if k != 'available')
        print(f"  {module}: {available} ({deps})")

    print(f"\n认证方式: {', '.join(info['auth_methods'])}")

    print("\n使用示例:")
    print("  from core.lateral import SMBLateral, Credentials, smb_exec")
    print("  result = smb_exec('192.168.1.100', 'admin', 'password', command='whoami')")
