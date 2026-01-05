# -*- coding: utf-8 -*-
"""
凭证收集模块 (Credential Access Module)
ATT&CK Tactic: TA0006 - Credential Access

提供多种凭证收集技术:
- 凭证提取 (浏览器/WiFi/注册表/Shadow)
- 敏感信息搜索 (密码/API密钥/私钥)
"""

from .credential_dumper import (
    CredentialDumper,
    CredentialType,
    Credential,
    DumpResult,
    dump_credentials
)

from .password_finder import (
    PasswordFinder,
    SecretType,
    SecretFinding,
    find_secrets
)

__all__ = [
    # Credential Dumper
    'CredentialDumper',
    'CredentialType',
    'Credential',
    'DumpResult',
    'dump_credentials',
    # Password Finder
    'PasswordFinder',
    'SecretType',
    'SecretFinding',
    'find_secrets',
]
