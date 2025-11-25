"""
Web Scanner - 智能Web漏洞扫描器
支持主动探测和被动分析
"""

import asyncio
import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class WebFinding:
    vuln_type: str
    severity: str
    url: str
    param: str
    payload: str
    evidence: str
    confidence: float


class WebScanner:
    """智能Web漏洞扫描器"""
    
    # 敏感路径字典
    SENSITIVE_PATHS = [
        # 配置和备份
        "/.env", "/.git/config", "/.svn/entries", "/config.php.bak",
        "/web.config", "/wp-config.php", "/config/database.yml",
        "/backup.sql", "/backup.zip", "/dump.sql", "/db.sql",
        
        # 管理后台
        "/admin", "/administrator", "/admin.php", "/manager",
        "/wp-admin", "/phpmyadmin", "/adminer.php",
        
        # API和调试
        "/swagger.json", "/api-docs", "/swagger-ui.html", "/graphql",
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/debug", "/trace", "/console", "/phpinfo.php",
        
        # 信息泄露
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/crossdomain.xml", "/server-status", "/server-info",
    ]
    
    # SQL注入检测Payload
    SQLI_PAYLOADS = [
        ("'", r"(sql|syntax|mysql|postgresql|oracle|sqlite|ORA-\d+)"),
        ("' OR '1'='1", r"(sql|syntax|error)"),
        ("1' AND '1'='1", r""),
        ("' UNION SELECT NULL--", r"(column|select|union)"),
        ("1; SELECT SLEEP(3)--", r""),
    ]
    
    # XSS检测Payload
    XSS_PAYLOADS = [
        ("<script>alert(1)</script>", r"<script>alert\(1\)</script>"),
        ('"><img src=x onerror=alert(1)>', r'<img[^>]*onerror'),
        ("javascript:alert(1)", r"javascript:alert"),
        ("{{7*7}}", r"49"),  # SSTI检测
    ]
    
    # LFI检测Payload
    LFI_PAYLOADS = [
        ("../../../../etc/passwd", r"root:.*:0:0"),
        ("....//....//etc/passwd", r"root:.*:0:0"),
        ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", r"localhost"),
        ("php://filter/convert.base64-encode/resource=index.php", r"^[A-Za-z0-9+/=]{50,}"),
    ]
    
    def __init__(self, http_engine=None):
        self.engine = http_engine
        self.findings: List[WebFinding] = []
    
    async def scan_sensitive_paths(self, base_url: str) -> List[Dict]:
        """扫描敏感路径"""
        results = []
        
        for path in self.SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            try:
                resp = await self.engine.get(url) if self.engine else {"status": 0}
                
                if resp.get("status") == 200:
                    body = resp.get("body", "")
                    
                    # 检查是否为真实敏感内容
                    if self._is_real_content(path, body):
                        results.append({
                            "type": "sensitive_path",
                            "url": url,
                            "status": 200,
                            "severity": self._get_path_severity(path)
                        })
                        logger.info(f"[+] Found: {url}")
                        
            except Exception as e:
                logger.debug(f"Error scanning {url}: {e}")
        
        return results
    
    def _is_real_content(self, path: str, body: str) -> bool:
        """判断是否为真实敏感内容（非404自定义页面）"""
        # 检查是否为常见404页面
        fp_patterns = [
            r"404.*not found", r"page.*not.*exist",
            r"cannot be found", r"does not exist"
        ]
        
        for pattern in fp_patterns:
            if re.search(pattern, body, re.I):
                return False
        
        # 特定路径的内容验证
        if ".env" in path and "=" in body:
            return True
        if ".git" in path and ("[core]" in body or "repositoryformatversion" in body):
            return True
        if "swagger" in path and ("swagger" in body.lower() or "openapi" in body.lower()):
            return True
        if "actuator" in path and "status" in body.lower():
            return True
        
        return len(body) > 100  # 基本内容检查
    
    def _get_path_severity(self, path: str) -> str:
        """根据路径评估严重性"""
        critical_paths = [".env", ".git", "backup", "dump", "config"]
        high_paths = ["admin", "actuator", "phpinfo", "swagger"]
        
        for p in critical_paths:
            if p in path:
                return "critical"
        for p in high_paths:
            if p in path:
                return "high"
        return "medium"
    
    async def scan_sqli(self, url: str, params: Dict[str, str]) -> List[WebFinding]:
        """SQL注入扫描"""
        findings = []
        
        for param_name, original_value in params.items():
            for payload, pattern in self.SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = original_value + payload
                
                test_url = self._build_url(url, test_params)
                
                try:
                    resp = await self.engine.get(test_url) if self.engine else {"body": ""}
                    body = resp.get("body", "")
                    
                    if pattern and re.search(pattern, body, re.I):
                        finding = WebFinding(
                            vuln_type="SQL Injection",
                            severity="critical",
                            url=url,
                            param=param_name,
                            payload=payload,
                            evidence=body[:200],
                            confidence=0.85
                        )
                        findings.append(finding)
                        self.findings.append(finding)
                        logger.info(f"[!] SQLi found: {param_name} @ {url}")
                        break  # 找到一个就停止该参数测试
                        
                except Exception as e:
                    logger.debug(f"SQLi test error: {e}")
        
        return findings
    
    async def scan_xss(self, url: str, params: Dict[str, str]) -> List[WebFinding]:
        """XSS扫描"""
        findings = []
        
        for param_name, original_value in params.items():
            for payload, pattern in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = self._build_url(url, test_params)
                
                try:
                    resp = await self.engine.get(test_url) if self.engine else {"body": ""}
                    body = resp.get("body", "")
                    
                    if re.search(pattern, body):
                        severity = "high" if "script" in payload else "medium"
                        finding = WebFinding(
                            vuln_type="XSS" if "{{" not in payload else "SSTI",
                            severity=severity,
                            url=url,
                            param=param_name,
                            payload=payload,
                            evidence=body[:200],
                            confidence=0.80
                        )
                        findings.append(finding)
                        self.findings.append(finding)
                        break
                        
                except Exception as e:
                    logger.debug(f"XSS test error: {e}")
        
        return findings
    
    async def scan_lfi(self, url: str, params: Dict[str, str]) -> List[WebFinding]:
        """LFI扫描"""
        findings = []
        
        # 识别可能的文件参数
        file_params = ["file", "path", "page", "template", "include", "doc", "folder"]
        target_params = {k: v for k, v in params.items() 
                        if any(fp in k.lower() for fp in file_params)}
        
        if not target_params:
            target_params = params  # 如果没有明显文件参数，测试所有参数
        
        for param_name in target_params:
            for payload, pattern in self.LFI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload
                
                test_url = self._build_url(url, test_params)
                
                try:
                    resp = await self.engine.get(test_url) if self.engine else {"body": ""}
                    body = resp.get("body", "")
                    
                    if re.search(pattern, body):
                        finding = WebFinding(
                            vuln_type="Local File Inclusion",
                            severity="critical",
                            url=url,
                            param=param_name,
                            payload=payload,
                            evidence=body[:300],
                            confidence=0.90
                        )
                        findings.append(finding)
                        self.findings.append(finding)
                        break
                        
                except Exception as e:
                    logger.debug(f"LFI test error: {e}")
        
        return findings
    
    async def full_scan(self, url: str) -> Dict[str, Any]:
        """完整Web扫描"""
        results = {
            "target": url,
            "sensitive_paths": [],
            "vulnerabilities": []
        }
        
        # 1. 敏感路径扫描
        logger.info(f"[*] Scanning sensitive paths: {url}")
        results["sensitive_paths"] = await self.scan_sensitive_paths(url)
        
        # 2. 解析URL参数
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        
        if params:
            logger.info(f"[*] Testing {len(params)} parameters")
            
            # 3. 漏洞扫描
            sqli_findings = await self.scan_sqli(url, params)
            xss_findings = await self.scan_xss(url, params)
            lfi_findings = await self.scan_lfi(url, params)
            
            results["vulnerabilities"] = [
                {"type": f.vuln_type, "severity": f.severity, "param": f.param, 
                 "payload": f.payload, "confidence": f.confidence}
                for f in sqli_findings + xss_findings + lfi_findings
            ]
        
        return results
    
    def _build_url(self, base_url: str, params: Dict) -> str:
        """构建带参数的URL"""
        parsed = urlparse(base_url)
        query = urlencode(params)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
    
    def get_findings(self) -> List[WebFinding]:
        return self.findings
    
    def get_critical_findings(self) -> List[WebFinding]:
        return [f for f in self.findings if f.severity == "critical"]
