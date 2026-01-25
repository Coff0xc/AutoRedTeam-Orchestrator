#!/usr/bin/env python3
"""
Evasion 模块 - 混淆与免杀
提供 Payload 混淆、代码变形、Shellcode 加载器
仅用于授权渗透测试
"""

from .payload_obfuscator import (
    # 核心类
    PayloadObfuscator,
    VariableObfuscator,
    CodeTransformer,
    ShellcodeObfuscator,
    PowerShellObfuscator,
    # 编码器
    XOREncoder,
    AESEncoder,
    Base64Encoder,
    Base32Encoder,
    HexEncoder,
    ROT13Encoder,
    UnicodeEncoder,
    # 枚举和配置
    EncodingType,
    ObfuscationType,
    ObfuscationConfig,
    ObfuscationResult,
    # 便捷函数
    obfuscate_payload,
    obfuscate_python_code,
    generate_shellcode_loader,
)

# WAF绕过引擎
from .waf_bypass_engine import (
    WAFBypassEngine,
    WAFDetector,
    PayloadMutator,
    ChunkedEncoder,
    HeaderManipulator,
    PathNormalizer,
    WAFType,
    BypassTechnique,
    WAFFingerprint,
    BypassResult,
    normalize_waf_type,
    bypass_waf,
    detect_waf,
)

__all__ = [
    # 核心类
    'PayloadObfuscator',
    'VariableObfuscator',
    'CodeTransformer',
    'ShellcodeObfuscator',
    'PowerShellObfuscator',
    # 编码器
    'XOREncoder',
    'AESEncoder',
    'Base64Encoder',
    'Base32Encoder',
    'HexEncoder',
    'ROT13Encoder',
    'UnicodeEncoder',
    # 枚举和配置
    'EncodingType',
    'ObfuscationType',
    'ObfuscationConfig',
    'ObfuscationResult',
    # 便捷函数
    'obfuscate_payload',
    'obfuscate_python_code',
    'generate_shellcode_loader',
    # WAF绕过
    'WAFBypassEngine',
    'WAFDetector',
    'PayloadMutator',
    'ChunkedEncoder',
    'HeaderManipulator',
    'PathNormalizer',
    'WAFType',
    'BypassTechnique',
    'WAFFingerprint',
    'BypassResult',
    'normalize_waf_type',
    'bypass_waf',
    'detect_waf',
]
