# -*- coding: utf-8 -*-
"""
Active Directory 渗透模块 (AD Penetration Module)
ATT&CK Tactics: TA0006 (Credential Access), TA0007 (Discovery)

提供完整的AD渗透能力:
- AD枚举 (用户/组/计算机/SPN/GPO/信任)
- Kerberos攻击 (AS-REP Roasting/Kerberoasting/密码喷洒)
- 高级Kerberos攻击 (Golden/Silver Ticket, Pass-the-Ticket)
"""

from .ad_enum import (
    ADEnumerator,
    ADObject,
    ADObjectType,
    EnumResult,
    SimpleLDAPClient,
    ad_enumerate,
)
from .kerberos_attack import (
    ASREPHash,
    AttackResult,
    KerberosAttacker,
    KerberosClient,
    KerberosEncType,
    KerberosErrorCode,
    KerberosTicket,
    kerberos_attack,
)
from .kerberos_attacks import (
    ASREPInfo,
)
from .kerberos_attacks import AttackResult as ImpacketAttackResult
from .kerberos_attacks import (
    KerberosAttacks,
    TicketInfo,
    kerberos_attacks,
)

__all__ = [
    # AD Enumeration
    "ADEnumerator",
    "ADObject",
    "ADObjectType",
    "EnumResult",
    "SimpleLDAPClient",
    "ad_enumerate",
    # Kerberos Attack (Pure Python)
    "KerberosAttacker",
    "KerberosClient",
    "KerberosTicket",
    "ASREPHash",
    "AttackResult",
    "KerberosEncType",
    "KerberosErrorCode",
    "kerberos_attack",
    # Kerberos Attacks (impacket-based)
    "KerberosAttacks",
    "TicketInfo",
    "ASREPInfo",
    "ImpacketAttackResult",
    "kerberos_attacks",
]
