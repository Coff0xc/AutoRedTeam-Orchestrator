#!/usr/bin/env python3
"""
横向移动模块 - Lateral Movement Module
提供 SMB/SSH/WMI/RDP 等横向移动能力
用于内网渗透场景
"""

from .smb_lateral import (
    SMBLateral,
    SMBConnection,
    pass_the_hash,
    smb_exec,
    smb_upload,
    smb_download,
)
from .ssh_lateral import (
    SSHLateral,
    SSHConnection,
    ssh_exec,
    ssh_tunnel,
    ssh_upload,
)
from .wmi_lateral import (
    WMILateral,
    wmi_exec,
    wmi_query,
)

__all__ = [
    # SMB
    'SMBLateral',
    'SMBConnection',
    'pass_the_hash',
    'smb_exec',
    'smb_upload',
    'smb_download',
    # SSH
    'SSHLateral',
    'SSHConnection',
    'ssh_exec',
    'ssh_tunnel',
    'ssh_upload',
    # WMI
    'WMILateral',
    'wmi_exec',
    'wmi_query',
]
