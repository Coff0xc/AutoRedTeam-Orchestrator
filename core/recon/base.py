#!/usr/bin/env python3
"""
BaseReconEngine - 侦察引擎抽象基类

定义统一的侦察引擎接口，所有侦察引擎都应继承此类。

架构说明：
- BaseReconEngine: 抽象基类，定义标准接口
- StandardReconEngine: 标准侦察引擎，整合基础功能
- IntelligentReconEngine: 智能侦察引擎，AI驱动的深度扫描
"""

import ssl
import socket
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


class ReconPhase(Enum):
    """侦察阶段枚举"""
    INIT = "init"                      # 初始化
    BASIC_INFO = "basic_info"          # 基础信息收集
    PORT_SCAN = "port_scan"            # 端口扫描
    SUBDOMAIN = "subdomain"            # 子域名枚举
    FINGERPRINT = "fingerprint"        # Web指纹识别
    DIRECTORY = "directory"            # 目录扫描
    JS_ANALYSIS = "js_analysis"        # JS文件分析
    SENSITIVE = "sensitive"            # 敏感文件探测
    VULN_SCAN = "vuln_scan"            # 漏洞检测
    WAF_DETECT = "waf_detect"          # WAF检测
    REPORT = "report"                  # 报告生成
    COMPLETE = "complete"              # 完成


class Severity(Enum):
    """漏洞严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """发现结果数据类"""
    type: str                          # 发现类型
    severity: Severity                 # 严重级别
    title: str                         # 标题
    description: str                   # 描述
    evidence: str = ""                 # 证据
    recommendation: str = ""           # 修复建议
    confidence: float = 0.8            # 置信度 (0-1)
    cve_id: Optional[str] = None       # CVE编号
    url: Optional[str] = None          # 相关URL
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class Asset:
    """资产信息数据类"""
    url: str                           # 目标URL
    ip: str = ""                       # IP地址
    ports: List[int] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    technologies: Dict[str, str] = field(default_factory=dict)
    cms: Optional[str] = None          # CMS类型
    waf: Optional[str] = None          # WAF类型
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    sensitive_files: List[str] = field(default_factory=list)


@dataclass
class ReconResult:
    """侦察结果数据类"""
    target: str
    start_time: str
    end_time: str = ""
    status: str = "running"
    current_phase: ReconPhase = ReconPhase.INIT
    asset: Optional[Asset] = None
    findings: List[Finding] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "current_phase": self.current_phase.value,
            "asset": self._asset_to_dict() if self.asset else None,
            "findings": [self._finding_to_dict(f) for f in self.findings],
            "summary": self._generate_summary()
        }

    def _asset_to_dict(self) -> Dict[str, Any]:
        """资产转字典"""
        if not self.asset:
            return {}
        return {
            "url": self.asset.url,
            "ip": self.asset.ip,
            "ports": self.asset.ports,
            "subdomains": self.asset.subdomains,
            "technologies": self.asset.technologies,
            "cms": self.asset.cms,
            "waf": self.asset.waf,
            "js_files": self.asset.js_files[:10],  # 限制数量
            "api_endpoints": self.asset.api_endpoints[:20],
            "sensitive_files": self.asset.sensitive_files
        }

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """发现转字典"""
        return {
            "type": finding.type,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "evidence": finding.evidence[:500] if finding.evidence else "",  # 限制长度
            "recommendation": finding.recommendation,
            "confidence": finding.confidence,
            "cve_id": finding.cve_id,
            "url": finding.url
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """生成摘要"""
        severity_count = {s.value: 0 for s in Severity}
        for f in self.findings:
            severity_count[f.severity.value] += 1

        return {
            "total_findings": len(self.findings),
            "by_severity": severity_count,
            "ports_found": len(self.asset.ports) if self.asset else 0,
            "subdomains_found": len(self.asset.subdomains) if self.asset else 0,
            "technologies": list(self.asset.technologies.keys()) if self.asset else []
        }


class BaseReconEngine(ABC):
    """侦察引擎抽象基类"""

    # 通用配置
    DEFAULT_TIMEOUT = 10
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def __init__(self, target: str, verify_ssl: bool = True, timeout: int = None):
        """初始化侦察引擎

        Args:
            target: 目标URL或域名
            verify_ssl: 是否验证SSL证书 (默认True)
            timeout: 请求超时时间 (秒)
        """
        self.target = self._normalize_target(target)
        self.verify_ssl = verify_ssl
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.ssl_context = self._create_ssl_context()

        # 初始化结果
        self.result = ReconResult(
            target=self.target,
            start_time=datetime.now().isoformat(),
            asset=Asset(url=self.target)
        )

        # 进度回调
        self._progress_callback = None

    def _normalize_target(self, target: str) -> str:
        """规范化目标URL"""
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        return target.rstrip('/')

    def _create_ssl_context(self) -> ssl.SSLContext:
        """创建SSL上下文"""
        if self.verify_ssl:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def set_progress_callback(self, callback):
        """设置进度回调函数

        Args:
            callback: 回调函数，签名为 callback(phase: ReconPhase, progress: int, message: str)
        """
        self._progress_callback = callback

    def _report_progress(self, phase: ReconPhase, progress: int, message: str = ""):
        """报告进度"""
        self.result.current_phase = phase
        if self._progress_callback:
            self._progress_callback(phase, progress, message)

    def _add_finding(self, finding: Finding):
        """添加发现结果"""
        self.result.findings.append(finding)

    # ========== 通用辅助方法 ==========

    def _resolve_ip(self, hostname: str) -> str:
        """解析IP地址"""
        try:
            parsed = urlparse(hostname if '://' in hostname else f"https://{hostname}")
            host = parsed.hostname or hostname
            return socket.gethostbyname(host)
        except socket.gaierror:
            return ""

    def _make_request(self, url: str, method: str = "GET",
                      headers: Dict[str, str] = None,
                      data: bytes = None) -> Dict[str, Any]:
        """发送HTTP请求

        Args:
            url: 请求URL
            method: HTTP方法
            headers: 请求头
            data: POST数据

        Returns:
            包含 status, headers, body, error 的字典
        """
        req_headers = {"User-Agent": self.DEFAULT_USER_AGENT}
        if headers:
            req_headers.update(headers)

        try:
            req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                body = resp.read().decode('utf-8', errors='replace')
                return {
                    "success": True,
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body[:50000],  # 限制大小
                    "url": resp.url
                }
        except urllib.error.HTTPError as e:
            return {
                "success": False,
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": "",
                "error": str(e)
            }
        except Exception as e:
            return {
                "success": False,
                "status": 0,
                "headers": {},
                "body": "",
                "error": str(e)
            }

    def _check_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """检查端口是否开放"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    # ========== 抽象方法 (子类必须实现) ==========

    @abstractmethod
    def run(self) -> ReconResult:
        """执行侦察扫描

        Returns:
            ReconResult 侦察结果
        """
        pass

    @abstractmethod
    def get_phases(self) -> List[ReconPhase]:
        """获取此引擎支持的扫描阶段

        Returns:
            ReconPhase 列表
        """
        pass

    # ========== 可选方法 (子类可以覆盖) ==========

    def stop(self):
        """停止扫描"""
        self.result.status = "stopped"
        self.result.end_time = datetime.now().isoformat()

    def get_result(self) -> ReconResult:
        """获取当前结果"""
        return self.result

    def export_json(self) -> str:
        """导出JSON格式结果"""
        import json
        return json.dumps(self.result.to_dict(), ensure_ascii=False, indent=2)
