#!/usr/bin/env python3
"""
漏洞检测工具模块 - 重构后的模块化结构

从 vuln_tools.py (3722行) 拆分为多个子模块:
- injection.py: SQL注入、XSS、命令注入、SSTI、NoSQL注入
- access.py: SSRF、LFI/RFI、开放重定向、IDOR、CRLF注入
- auth.py: 认证绕过、弱密码检测、JWT漏洞
- web_security.py: CSRF、CORS、安全头、缓存投毒
- serialization.py: XXE、反序列化漏洞
- advanced.py: 请求走私、原型污染、浏览器扫描
- utils.py: 通用工具函数
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp import FastMCP

logger = logging.getLogger(__name__)

# 延迟导入各子模块的注册函数
def register_vuln_tools(mcp: "FastMCP") -> None:
    """注册所有漏洞检测工具到 MCP 服务器"""
    from .injection import register_injection_tools
    from .access import register_access_tools
    from .auth import register_auth_tools
    from .web_security import register_web_security_tools
    from .serialization import register_serialization_tools
    from .advanced import register_advanced_tools
    
    register_injection_tools(mcp)
    register_access_tools(mcp)
    register_auth_tools(mcp)
    register_web_security_tools(mcp)
    register_serialization_tools(mcp)
    register_advanced_tools(mcp)
    
    logger.info("已注册所有漏洞检测工具")


# 导出独立函数供外部调用
from .injection import (
    sqli_detect,
    xss_detect,
    ssti_detect,
    nosql_detect,
    cmd_inject_detect,
)
from .access import (
    ssrf_detect,
    lfi_detect,
    redirect_detect,
    idor_detect,
    crlf_detect,
)
from .auth import (
    auth_bypass_detect,
    weak_password_detect,
    jwt_vuln_detect,
)
from .web_security import (
    csrf_detect,
    cors_deep_check,
    security_headers_check,
    cache_poisoning_detect,
)
from .serialization import (
    xxe_detect,
    deserialize_detect,
)
from .advanced import (
    request_smuggling_detect,
    prototype_pollution_detect,
    browser_scan,
    waf_detect,
    access_control_test,
    logic_vuln_check,
    file_upload_detect,
)

# 兼容层 - 保持旧 API
from .utils import vuln_check

__all__ = [
    "register_vuln_tools",
    # Injection
    "sqli_detect",
    "xss_detect", 
    "ssti_detect",
    "nosql_detect",
    "cmd_inject_detect",
    # Access
    "ssrf_detect",
    "lfi_detect",
    "redirect_detect",
    "idor_detect",
    "crlf_detect",
    # Auth
    "auth_bypass_detect",
    "weak_password_detect",
    "jwt_vuln_detect",
    # Web Security
    "csrf_detect",
    "cors_deep_check",
    "security_headers_check",
    "cache_poisoning_detect",
    # Serialization
    "xxe_detect",
    "deserialize_detect",
    # Advanced
    "request_smuggling_detect",
    "prototype_pollution_detect",
    "browser_scan",
    "waf_detect",
    "access_control_test",
    "logic_vuln_check",
    "file_upload_detect",
    # Utils
    "vuln_check",
]