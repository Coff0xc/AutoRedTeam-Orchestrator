"""
AI Decision Enhancement - AI决策增强模块
增强的威胁分析和智能决策能力
"""

import re
import logging
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class ThreatIndicator:
    """威胁指标"""
    name: str
    pattern: str
    level: ThreatLevel
    description: str
    remediation: str


class ThreatAnalyzer:
    """威胁分析器 - 分析响应中的安全问题"""
    
    # 敏感信息泄露模式
    SENSITIVE_PATTERNS = [
        ThreatIndicator("AWS Key", r"AKIA[0-9A-Z]{16}", ThreatLevel.CRITICAL,
                       "AWS Access Key泄露", "立即轮换密钥"),
        ThreatIndicator("Private Key", r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", 
                       ThreatLevel.CRITICAL, "私钥泄露", "立即轮换密钥"),
        ThreatIndicator("JWT Token", r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
                       ThreatLevel.HIGH, "JWT Token泄露", "检查Token权限范围"),
        ThreatIndicator("Password in URL", r"[?&](password|passwd|pwd)=([^&\s]+)",
                       ThreatLevel.HIGH, "URL中明文密码", "移除敏感参数"),
        ThreatIndicator("API Key", r"(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})",
                       ThreatLevel.HIGH, "API密钥泄露", "轮换API密钥"),
        ThreatIndicator("Database Connection", r"(mysql|postgresql|mongodb)://[^@]+@[^\s]+",
                       ThreatLevel.CRITICAL, "数据库连接串泄露", "立即更改凭据"),
        ThreatIndicator("Internal IP", r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
                       ThreatLevel.MEDIUM, "内网IP泄露", "检查是否需要暴露"),
        ThreatIndicator("Email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                       ThreatLevel.LOW, "邮箱地址", "信息收集用途"),
        ThreatIndicator("Phone Number", r"\b1[3-9]\d{9}\b",
                       ThreatLevel.LOW, "手机号码", "可能用于社工"),
    ]
    
    # 安全Header检查
    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("HSTS未配置", ThreatLevel.MEDIUM),
        "X-Content-Type-Options": ("X-Content-Type-Options缺失", ThreatLevel.LOW),
        "X-Frame-Options": ("点击劫持防护缺失", ThreatLevel.MEDIUM),
        "Content-Security-Policy": ("CSP未配置", ThreatLevel.MEDIUM),
        "X-XSS-Protection": ("XSS防护Header缺失", ThreatLevel.LOW),
    }
    
    # 危险响应特征
    DANGEROUS_PATTERNS = [
        (r"(?i)(sql\s*syntax|mysql_fetch|pg_query|ORA-\d{5})", ThreatLevel.CRITICAL, "SQL错误信息泄露"),
        (r"(?i)(stack\s*trace|traceback|exception\s*in\s*thread)", ThreatLevel.HIGH, "堆栈跟踪泄露"),
        (r"(?i)(debug\s*mode|DEBUG\s*=\s*True)", ThreatLevel.HIGH, "调试模式开启"),
        (r"(?i)(phpinfo\(\)|<title>phpinfo\(\))", ThreatLevel.MEDIUM, "phpinfo页面暴露"),
        (r"(?i)(server\s*error|internal\s*error).*?(path|file|directory)", ThreatLevel.MEDIUM, "路径信息泄露"),
        (r"root:.*?:0:0", ThreatLevel.CRITICAL, "/etc/passwd内容泄露"),
    ]
    
    def __init__(self):
        self.findings = []
    
    def analyze_response(self, url: str, status: int, headers: Dict, body: str) -> List[Dict]:
        """分析HTTP响应"""
        findings = []
        
        # 检查敏感信息
        for indicator in self.SENSITIVE_PATTERNS:
            matches = re.findall(indicator.pattern, body, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "sensitive_data",
                    "name": indicator.name,
                    "level": indicator.level.name,
                    "url": url,
                    "matches": len(matches) if len(matches) < 10 else "10+",
                    "description": indicator.description,
                    "remediation": indicator.remediation
                })
        
        # 检查安全Header
        for header, (desc, level) in self.SECURITY_HEADERS.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                findings.append({
                    "type": "missing_header",
                    "name": header,
                    "level": level.name,
                    "url": url,
                    "description": desc
                })
        
        # 检查危险响应
        for pattern, level, desc in self.DANGEROUS_PATTERNS:
            if re.search(pattern, body):
                findings.append({
                    "type": "dangerous_response",
                    "level": level.name,
                    "url": url,
                    "description": desc
                })
        
        # 检查Server Header信息泄露
        if "Server" in headers:
            server = headers["Server"]
            if re.search(r"[\d.]+", server):
                findings.append({
                    "type": "version_disclosure",
                    "level": ThreatLevel.LOW.name,
                    "url": url,
                    "description": f"服务器版本泄露: {server}"
                })
        
        self.findings.extend(findings)
        return findings
    
    def get_critical_findings(self) -> List[Dict]:
        return [f for f in self.findings if f.get("level") == "CRITICAL"]


class AttackSurfaceAnalyzer:
    """攻击面分析器"""
    
    # 参数名风险评估
    HIGH_RISK_PARAMS = {
        "cmd", "exec", "command", "execute", "ping", "query", "code",
        "reg", "do", "func", "arg", "option", "load", "process", "step",
        "read", "feature", "exe", "module", "payload", "run", "daemon"
    }
    
    SQLI_RISK_PARAMS = {
        "id", "user", "username", "name", "pass", "password", "email",
        "select", "report", "role", "update", "query", "order", "sort",
        "where", "search", "params", "process", "row", "view", "table",
        "from", "sel", "results", "sleep", "fetch", "order", "keyword"
    }
    
    FILE_RISK_PARAMS = {
        "file", "document", "folder", "root", "path", "pg", "style",
        "pdf", "template", "php_path", "doc", "page", "name", "cat",
        "dir", "action", "board", "date", "detail", "download", "prefix",
        "include", "inc", "locate", "show", "site", "type", "view", "content"
    }
    
    SSRF_RISK_PARAMS = {
        "url", "uri", "src", "source", "link", "href", "path", "dest",
        "redirect", "uri", "next", "data", "reference", "site", "html",
        "domain", "callback", "return", "page", "feed", "host", "port",
        "to", "out", "view", "dir", "show", "navigation", "open"
    }
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """分析URL的攻击面"""
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        risks = []
        
        for param in params.keys():
            param_lower = param.lower()
            
            if param_lower in self.HIGH_RISK_PARAMS:
                risks.append({"param": param, "risk": "RCE", "level": "critical"})
            elif param_lower in self.SQLI_RISK_PARAMS:
                risks.append({"param": param, "risk": "SQLi", "level": "high"})
            elif param_lower in self.FILE_RISK_PARAMS:
                risks.append({"param": param, "risk": "LFI/Path Traversal", "level": "high"})
            elif param_lower in self.SSRF_RISK_PARAMS:
                risks.append({"param": param, "risk": "SSRF", "level": "high"})
        
        return {
            "url": url,
            "params_count": len(params),
            "risks": risks,
            "attack_vectors": self._suggest_vectors(risks)
        }
    
    def _suggest_vectors(self, risks: List[Dict]) -> List[str]:
        """根据风险建议攻击向量"""
        vectors = []
        risk_types = {r["risk"] for r in risks}
        
        if "RCE" in risk_types:
            vectors.append("command_injection")
            vectors.append("code_injection")
        if "SQLi" in risk_types:
            vectors.append("sql_injection")
            vectors.append("blind_sqli")
        if "LFI/Path Traversal" in risk_types:
            vectors.append("lfi")
            vectors.append("path_traversal")
        if "SSRF" in risk_types:
            vectors.append("ssrf")
            vectors.append("open_redirect")
        
        return vectors


class SmartDecisionEngine:
    """智能决策引擎 - 根据上下文做出最优决策"""
    
    def __init__(self):
        self.threat_analyzer = ThreatAnalyzer()
        self.surface_analyzer = AttackSurfaceAnalyzer()
        self.context = {}
        self.learning_data = []
    
    def evaluate_target(self, target_info: Dict) -> Dict[str, Any]:
        """评估目标并给出扫描建议"""
        hostname = target_info.get("hostname", "")
        ports = target_info.get("ports", [])
        services = target_info.get("services", {})
        
        score = 50  # 基础分数
        recommendations = []
        
        # 根据子域名特征加分
        high_value_keywords = ['dev', 'test', 'staging', 'admin', 'api', 'internal']
        for kw in high_value_keywords:
            if kw in hostname.lower():
                score += 15
                recommendations.append(f"高价值目标: 包含关键词'{kw}'")
        
        # 根据开放端口加分
        critical_ports = {22: 10, 3389: 15, 3306: 20, 6379: 25, 27017: 20, 9200: 20}
        for port in ports:
            if port in critical_ports:
                score += critical_ports[port]
                recommendations.append(f"敏感端口开放: {port}")
        
        # Web服务加分
        web_ports = [80, 443, 8080, 8443, 8000, 3000]
        if any(p in ports for p in web_ports):
            score += 10
            recommendations.append("Web服务可用，建议深度Web扫描")
        
        return {
            "target": hostname,
            "priority_score": min(score, 100),
            "recommendations": recommendations,
            "suggested_scan_type": self._suggest_scan_type(score, ports, services)
        }
    
    def _suggest_scan_type(self, score: int, ports: List, services: Dict) -> str:
        if score >= 80:
            return "aggressive"  # 全面扫描
        elif score >= 60:
            return "standard"    # 标准扫描
        else:
            return "light"       # 轻量扫描
    
    def should_continue_attack(self, current_findings: List, resources_used: Dict) -> Tuple[bool, str]:
        """决定是否继续攻击"""
        critical_count = len([f for f in current_findings if f.get("severity") == "critical"])
        high_count = len([f for f in current_findings if f.get("severity") == "high"])
        
        # 发现严重漏洞，继续深入
        if critical_count > 0:
            return True, "发现严重漏洞，建议继续深入探测"
        
        # 资源消耗过大
        if resources_used.get("time_minutes", 0) > 30:
            return False, "扫描时间过长，建议暂停"
        
        if resources_used.get("requests", 0) > 10000:
            return False, "请求数过多，可能触发防护"
        
        # 有高危发现，适度继续
        if high_count > 2:
            return True, "多个高危发现，继续验证"
        
        return True, "继续常规扫描"
