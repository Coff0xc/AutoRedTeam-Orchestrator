# -*- coding: utf-8 -*-
"""
Active Directory 渗透模块 (AD Penetration Module)
ATT&CK Tactics: TA0006 (Credential Access), TA0007 (Discovery)

提供完整的AD渗透能力:
- AD枚举 (用户/组/计算机/SPN/GPO/信任)
- Kerberos攻击 (AS-REP Roasting/Kerberoasting/密码喷洒)
"""

from .ad_enum import (
    ADEnumerator,
    ADObject,
    ADObjectType,
    EnumResult,
    SimpleLDAPClient,
    ad_enumerate
)

from .kerberos_attack import (
    KerberosAttacker,
    KerberosClient,
    KerberosTicket,
    ASREPHash,
    AttackResult,
    KerberosEncType,
    KerberosErrorCode,
    kerberos_attack
)

__all__ = [
    # AD Enumeration
    'ADEnumerator',
    'ADObject',
    'ADObjectType',
    'EnumResult',
    'SimpleLDAPClient',
    'ad_enumerate',
    # Kerberos Attack
    'KerberosAttacker',
    'KerberosClient',
    'KerberosTicket',
    'ASREPHash',
    'AttackResult',
    'KerberosEncType',
    'KerberosErrorCode',
    'kerberos_attack',
]
