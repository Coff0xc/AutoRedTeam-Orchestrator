#!/usr/bin/env python3
"""
漏洞检测工具模块 - 兼容层

此文件已重构为模块化架构，实际实现已迁移到 tools/vuln/ 子模块：
- tools/vuln/injection.py: SQL注入、XSS、命令注入、SSTI、NoSQL注入
- tools/vuln/access.py: SSRF、LFI、开放重定向、IDOR、CRLF
- tools/vuln/auth.py: 认证绕过、弱密码、JWT漏洞
- tools/vuln/web_security.py: CSRF、CORS、安全头、缓存投毒
- tools/vuln/serialization.py: XXE、反序列化漏洞
- tools/vuln/advanced.py: 请求走私、原型污染、浏览器扫描、WAF检测等
- tools/vuln/utils.py: 通用工具函数

向后兼容：
- register_vuln_tools(mcp) 仍然可用，会注册所有漏洞检测工具
- 所有检测函数可通过此模块直接导入

迁移说明:
- 新代码应直接从 tools.vuln 导入
- 旧代码继续工作，无需修改
"""
import logging
import warnings

# 从新的模块化结构导入
from .vuln import (
    # 主注册函数
    register_vuln_tools,
    # 注入类
    sqli_detect,
    xss_detect,
    ssti_detect,
    nosql_detect,
    cmd_inject_detect,
    # 访问控制类
    ssrf_detect,
    lfi_detect,
    redirect_detect,
    idor_detect,
    crlf_detect,
    # 认证类
    auth_bypass_detect,
    weak_password_detect,
    jwt_vuln_detect,
    # Web安全类
    csrf_detect,
    cors_deep_check,
    security_headers_check,
    cache_poisoning_detect,
    # 序列化类
    xxe_detect,
    deserialize_detect,
    # 高级检测
    request_smuggling_detect,
    prototype_pollution_detect,
    browser_scan,
    waf_detect,
    access_control_test,
    logic_vuln_check,
    file_upload_detect,
    # 工具函数
    vuln_check,
)

# 可选：导入旧的检测器类（用于渐进式迁移）
try:
    from .detectors import (
        SQLiDetector, XSSDetector, RCEDetector,
        SSRFDetector, CSRFDetector, CORSDetector,
        LFIDetector, FileUploadDetector,
        AuthBypassDetector, WeakPasswordDetector,
        get_detector, list_detectors
    )
    HAS_DETECTORS = True
except ImportError:
    HAS_DETECTORS = False

logger = logging.getLogger(__name__)

# 发出弃用警告（仅在直接导入此模块时）
def _emit_deprecation_warning():
    """发出弃用警告，建议使用新的模块化结构"""
    warnings.warn(
        "tools.vuln_tools 已重构为模块化架构。"
        "建议直接从 tools.vuln 导入: from tools.vuln import sqli_detect",
        DeprecationWarning,
        stacklevel=3
    )

# 导出所有公开符号
__all__ = [
    # 主注册函数
    "register_vuln_tools",
    # 注入类
    "sqli_detect",
    "xss_detect",
    "ssti_detect",
    "nosql_detect",
    "cmd_inject_detect",
    # 访问控制类
    "ssrf_detect",
    "lfi_detect",
    "redirect_detect",
    "idor_detect",
    "crlf_detect",
    # 认证类
    "auth_bypass_detect",
    "weak_password_detect",
    "jwt_vuln_detect",
    # Web安全类
    "csrf_detect",
    "cors_deep_check",
    "security_headers_check",
    "cache_poisoning_detect",
    # 序列化类
    "xxe_detect",
    "deserialize_detect",
    # 高级检测
    "request_smuggling_detect",
    "prototype_pollution_detect",
    "browser_scan",
    "waf_detect",
    "access_control_test",
    "logic_vuln_check",
    "file_upload_detect",
    # 工具函数
    "vuln_check",
]

# 如果有检测器类，也导出
if HAS_DETECTORS:
    __all__.extend([
        "SQLiDetector", "XSSDetector", "RCEDetector",
        "SSRFDetector", "CSRFDetector", "CORSDetector",
        "LFIDetector", "FileUploadDetector",
        "AuthBypassDetector", "WeakPasswordDetector",
        "get_detector", "list_detectors",
    ])

logger.debug("vuln_tools 兼容层已加载，实际实现在 tools.vuln 子模块")
