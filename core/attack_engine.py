"""
Attack Engine - 攻击执行引擎
协调各类攻击模块的统一接口
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """攻击结果"""
    attack_type: str
    target: str
    success: bool
    severity: str = "info"
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AttackEngine:
    """
    统一攻击执行引擎
    整合所有攻击模块，提供统一的攻击接口
    """
    
    def __init__(self, http_client=None, config: Dict = None):
        self.http_client = http_client
        self.config = config or {}
        self.results: List[AttackResult] = []
        
        # 攻击模块
        self.modules = {}
        self._load_modules()
    
    def _load_modules(self):
        """加载攻击模块"""
        try:
            from core.web_scanner import WebScanner
            self.modules["web"] = WebScanner(self.http_client)
        except ImportError:
            pass
        
        try:
            from modules.attack.service_scanner import ServiceScanner
            self.modules["service"] = ServiceScanner()
        except ImportError:
            pass
    
    async def run_sqli_scan(self, url: str, params: Dict) -> List[AttackResult]:
        """SQL注入扫描"""
        from core.payloads.sqli import ALL_SQLI, SQLI_ERROR
        
        results = []
        
        for payload, pattern in SQLI_ERROR:
            test_url = self._inject_payload(url, params, payload)
            
            try:
                resp = await self.http_client.get(test_url)
                body = resp.get("body", "")
                
                import re
                if re.search(pattern, body, re.I):
                    result = AttackResult(
                        attack_type="sqli",
                        target=url,
                        success=True,
                        severity="critical",
                        payload=payload,
                        evidence=body[:200],
                        confidence=0.9
                    )
                    results.append(result)
                    self.results.append(result)
                    logger.info(f"[!] SQLi found: {url}")
                    break
                    
            except Exception as e:
                logger.debug(f"SQLi test error: {e}")
        
        return results
    
    async def run_xss_scan(self, url: str, params: Dict) -> List[AttackResult]:
        """XSS扫描"""
        from core.payloads.xss import XSS_BASIC
        
        results = []
        
        for payload in XSS_BASIC[:10]:  # 使用前10个payload
            test_url = self._inject_payload(url, params, payload)
            
            try:
                resp = await self.http_client.get(test_url)
                body = resp.get("body", "")
                
                # 检查payload是否反射
                if payload in body or payload.replace('"', '&quot;') in body:
                    result = AttackResult(
                        attack_type="xss",
                        target=url,
                        success=True,
                        severity="high",
                        payload=payload,
                        evidence=body[:200],
                        confidence=0.85
                    )
                    results.append(result)
                    self.results.append(result)
                    break
                    
            except Exception as e:
                logger.debug(f"XSS test error: {e}")
        
        return results
    
    async def run_lfi_scan(self, url: str, params: Dict) -> List[AttackResult]:
        """LFI扫描"""
        from core.payloads.lfi import LFI_BASIC, LFI_LINUX
        
        results = []
        test_payloads = LFI_BASIC + LFI_LINUX[:5]
        
        for payload in test_payloads:
            test_url = self._inject_payload(url, params, payload)
            
            try:
                resp = await self.http_client.get(test_url)
                body = resp.get("body", "")
                
                import re
                if re.search(r"root:.*:0:0", body):
                    result = AttackResult(
                        attack_type="lfi",
                        target=url,
                        success=True,
                        severity="critical",
                        payload=payload,
                        evidence=body[:300],
                        confidence=0.95
                    )
                    results.append(result)
                    self.results.append(result)
                    break
                    
            except Exception as e:
                logger.debug(f"LFI test error: {e}")
        
        return results
    
    async def run_ssrf_scan(self, url: str, params: Dict) -> List[AttackResult]:
        """SSRF扫描"""
        from core.payloads.ssrf import SSRF_BASIC, CLOUD_METADATA
        
        results = []
        
        for payload in CLOUD_METADATA[:5]:
            test_url = self._inject_payload(url, params, payload)
            
            try:
                resp = await self.http_client.get(test_url)
                body = resp.get("body", "")
                
                import re
                if re.search(r"(ami-id|instance-id|access_token)", body, re.I):
                    result = AttackResult(
                        attack_type="ssrf",
                        target=url,
                        success=True,
                        severity="critical",
                        payload=payload,
                        evidence=body[:300],
                        confidence=0.9
                    )
                    results.append(result)
                    self.results.append(result)
                    break
                    
            except Exception as e:
                logger.debug(f"SSRF test error: {e}")
        
        return results
    
    async def run_service_scan(self, host: str, ports: List[int] = None) -> List[AttackResult]:
        """服务漏洞扫描"""
        if "service" not in self.modules:
            return []
        
        scanner = self.modules["service"]
        ports = ports or {6379: "redis", 27017: "mongodb", 9200: "elasticsearch"}
        
        findings = await scanner.scan_all(host, ports)
        
        results = []
        for finding in findings:
            result = AttackResult(
                attack_type=f"service_{finding.service}",
                target=f"{host}:{finding.port}",
                success=True,
                severity=finding.severity,
                payload="",
                evidence=finding.details,
                confidence=0.9
            )
            results.append(result)
            self.results.append(result)
        
        return results
    
    async def run_full_scan(self, target: str, options: Dict = None) -> Dict:
        """运行完整扫描"""
        options = options or {}
        all_results = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": [],
            "summary": {}
        }
        
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        
        if params:
            # Web漏洞扫描
            if options.get("sqli", True):
                sqli_results = await self.run_sqli_scan(target, params)
                all_results["vulnerabilities"].extend([r.__dict__ for r in sqli_results])
            
            if options.get("xss", True):
                xss_results = await self.run_xss_scan(target, params)
                all_results["vulnerabilities"].extend([r.__dict__ for r in xss_results])
            
            if options.get("lfi", True):
                lfi_results = await self.run_lfi_scan(target, params)
                all_results["vulnerabilities"].extend([r.__dict__ for r in lfi_results])
            
            if options.get("ssrf", True):
                ssrf_results = await self.run_ssrf_scan(target, params)
                all_results["vulnerabilities"].extend([r.__dict__ for r in ssrf_results])
        
        # 统计
        all_results["summary"] = {
            "total": len(all_results["vulnerabilities"]),
            "critical": len([v for v in all_results["vulnerabilities"] if v["severity"] == "critical"]),
            "high": len([v for v in all_results["vulnerabilities"] if v["severity"] == "high"]),
        }
        
        return all_results
    
    def _inject_payload(self, url: str, params: Dict, payload: str) -> str:
        """注入payload到URL参数"""
        from urllib.parse import urlencode, urlparse
        
        if not params:
            return url
        
        # 注入到第一个参数
        first_param = list(params.keys())[0]
        test_params = params.copy()
        test_params[first_param] = params[first_param] + payload
        
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
    
    def get_results(self) -> List[AttackResult]:
        return self.results
    
    def get_critical_results(self) -> List[AttackResult]:
        return [r for r in self.results if r.severity == "critical"]
