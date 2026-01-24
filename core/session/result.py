#!/usr/bin/env python3
"""
result.py - 扫描结果定义模块

定义漏洞信息和扫描结果的数据结构。
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import json


class Severity(Enum):
    """
    严重程度枚举

    遵循 CVSS v3.0 标准的严重性等级划分
    """
    CRITICAL = 'critical'   # 严重 (CVSS 9.0-10.0)
    HIGH = 'high'           # 高危 (CVSS 7.0-8.9)
    MEDIUM = 'medium'       # 中危 (CVSS 4.0-6.9)
    LOW = 'low'             # 低危 (CVSS 0.1-3.9)
    INFO = 'info'           # 信息 (CVSS 0.0)

    @property
    def score_range(self) -> tuple:
        """获取对应的CVSS分数范围"""
        ranges = {
            'critical': (9.0, 10.0),
            'high': (7.0, 8.9),
            'medium': (4.0, 6.9),
            'low': (0.1, 3.9),
            'info': (0.0, 0.0),
        }
        return ranges.get(self.value, (0.0, 0.0))

    @property
    def priority(self) -> int:
        """获取优先级（数值越小优先级越高）"""
        priorities = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5,
        }
        return priorities.get(self.value, 5)


class VulnType(Enum):
    """
    漏洞类型枚举

    覆盖 OWASP Top 10 及常见漏洞类型
    """
    # 注入类
    SQLI = 'sqli'                       # SQL注入
    XSS = 'xss'                         # 跨站脚本
    XXE = 'xxe'                         # XML外部实体注入
    SSTI = 'ssti'                       # 模板注入
    CMD_INJECTION = 'cmd_injection'     # 命令注入
    LDAP_INJECTION = 'ldap_injection'   # LDAP注入
    XPATH_INJECTION = 'xpath_injection' # XPath注入

    # 服务端请求类
    SSRF = 'ssrf'                       # 服务端请求伪造
    LFI = 'lfi'                         # 本地文件包含
    RFI = 'rfi'                         # 远程文件包含
    PATH_TRAVERSAL = 'path_traversal'   # 目录穿越

    # 认证授权类
    AUTH_BYPASS = 'auth_bypass'         # 认证绕过
    WEAK_PASSWORD = 'weak_password'     # 弱密码
    IDOR = 'idor'                       # 不安全的直接对象引用
    BROKEN_ACCESS = 'broken_access'     # 失效的访问控制
    SESSION_FIXATION = 'session_fixation'  # 会话固定

    # 跨站请求类
    CSRF = 'csrf'                       # 跨站请求伪造
    CORS = 'cors'                       # CORS配置错误
    CLICKJACKING = 'clickjacking'       # 点击劫持

    # 代码执行类
    RCE = 'rce'                         # 远程代码执行
    DESERIALIZATION = 'deserialization' # 不安全的反序列化
    FILE_UPLOAD = 'file_upload'         # 任意文件上传

    # 信息泄露类
    INFO_DISCLOSURE = 'info_disclosure' # 信息泄露
    SENSITIVE_DATA = 'sensitive_data'   # 敏感数据暴露
    SOURCE_CODE_LEAK = 'source_code_leak'  # 源代码泄露

    # 配置类
    MISCONFIG = 'misconfig'             # 安全配置错误
    DEFAULT_CREDS = 'default_creds'     # 默认凭证
    DEBUG_ENABLED = 'debug_enabled'     # 调试功能开启

    # API安全
    JWT_VULN = 'jwt_vuln'               # JWT漏洞
    API_ABUSE = 'api_abuse'             # API滥用
    RATE_LIMIT = 'rate_limit'           # 缺乏速率限制

    # 其他
    OPEN_REDIRECT = 'open_redirect'     # 开放重定向
    DOS = 'dos'                         # 拒绝服务
    PROTOTYPE_POLLUTION = 'prototype_pollution'  # 原型链污染
    OTHER = 'other'                     # 其他漏洞

    @property
    def category(self) -> str:
        """获取漏洞分类"""
        categories = {
            'sqli': 'injection',
            'xss': 'injection',
            'xxe': 'injection',
            'ssti': 'injection',
            'cmd_injection': 'injection',
            'ldap_injection': 'injection',
            'xpath_injection': 'injection',
            'ssrf': 'server_side_request',
            'lfi': 'server_side_request',
            'rfi': 'server_side_request',
            'path_traversal': 'server_side_request',
            'auth_bypass': 'authentication',
            'weak_password': 'authentication',
            'idor': 'authorization',
            'broken_access': 'authorization',
            'session_fixation': 'authentication',
            'csrf': 'cross_site',
            'cors': 'cross_site',
            'clickjacking': 'cross_site',
            'rce': 'code_execution',
            'deserialization': 'code_execution',
            'file_upload': 'code_execution',
            'info_disclosure': 'information',
            'sensitive_data': 'information',
            'source_code_leak': 'information',
            'misconfig': 'configuration',
            'default_creds': 'configuration',
            'debug_enabled': 'configuration',
            'jwt_vuln': 'api_security',
            'api_abuse': 'api_security',
            'rate_limit': 'api_security',
            'open_redirect': 'other',
            'dos': 'other',
            'prototype_pollution': 'other',
            'other': 'other',
        }
        return categories.get(self.value, 'other')


@dataclass
class Vulnerability:
    """
    漏洞信息数据类

    存储检测到的漏洞的完整信息。

    Attributes:
        type: 漏洞类型
        severity: 严重程度
        title: 漏洞标题
        url: 漏洞URL
        param: 漏洞参数
        payload: 使用的payload
        evidence: 漏洞证据
        verified: 是否已验证
        confidence: 置信度 (0-1)
        detected_at: 检测时间
        detector: 检测器名称
        cve_id: CVE编号
        remediation: 修复建议
        references: 参考链接
    """
    type: VulnType                          # 漏洞类型
    severity: Severity                       # 严重程度
    title: str                               # 漏洞标题
    url: str                                 # 漏洞URL

    # 详情
    param: Optional[str] = None              # 漏洞参数
    payload: Optional[str] = None            # 使用的payload
    evidence: Optional[str] = None           # 证据
    request: Optional[str] = None            # 原始请求
    response: Optional[str] = None           # 原始响应

    # 验证信息
    verified: bool = False                   # 是否验证
    confidence: float = 0.0                  # 置信度 0-1

    # 元数据
    detected_at: datetime = field(default_factory=datetime.now)
    detector: Optional[str] = None           # 检测器名称
    cve_id: Optional[str] = None             # CVE编号
    cwe_id: Optional[str] = None             # CWE编号
    cvss_score: Optional[float] = None       # CVSS分数

    # 修复建议
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    # 扩展字段
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理"""
        # 确保列表字段不为None
        if self.references is None:
            self.references = []
        if self.metadata is None:
            self.metadata = {}

        # 验证置信度范围
        if not 0 <= self.confidence <= 1:
            self.confidence = max(0, min(1, self.confidence))

    def mark_verified(self, verified: bool = True, confidence: float = None) -> None:
        """
        标记验证状态

        Args:
            verified: 是否已验证
            confidence: 置信度
        """
        self.verified = verified
        if confidence is not None:
            self.confidence = max(0, min(1, confidence))

    def add_reference(self, ref: str) -> None:
        """
        添加参考链接

        Args:
            ref: 参考链接URL
        """
        if ref and ref not in self.references:
            self.references.append(ref)

    def set_evidence(self, evidence: str, request: str = None, response: str = None) -> None:
        """
        设置漏洞证据

        Args:
            evidence: 证据描述
            request: 原始HTTP请求
            response: 原始HTTP响应
        """
        self.evidence = evidence
        if request:
            self.request = request
        if response:
            self.response = response

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典

        Returns:
            Dict[str, Any]: 字典表示
        """
        return {
            'type': self.type.value,
            'severity': self.severity.value,
            'title': self.title,
            'url': self.url,
            'param': self.param,
            'payload': self.payload,
            'evidence': self.evidence,
            'request': self.request,
            'response': self.response,
            'verified': self.verified,
            'confidence': self.confidence,
            'detected_at': self.detected_at.isoformat(),
            'detector': self.detector,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'cvss_score': self.cvss_score,
            'remediation': self.remediation,
            'references': self.references,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """
        从字典创建漏洞对象

        Args:
            data: 字典数据

        Returns:
            Vulnerability: 漏洞对象
        """
        return cls(
            type=VulnType(data['type']),
            severity=Severity(data['severity']),
            title=data['title'],
            url=data['url'],
            param=data.get('param'),
            payload=data.get('payload'),
            evidence=data.get('evidence'),
            request=data.get('request'),
            response=data.get('response'),
            verified=data.get('verified', False),
            confidence=data.get('confidence', 0.0),
            detected_at=datetime.fromisoformat(data['detected_at']) if data.get('detected_at') else datetime.now(),
            detector=data.get('detector'),
            cve_id=data.get('cve_id'),
            cwe_id=data.get('cwe_id'),
            cvss_score=data.get('cvss_score'),
            remediation=data.get('remediation'),
            references=data.get('references', []),
            metadata=data.get('metadata', {}),
        )

    def __str__(self) -> str:
        """字符串表示"""
        return f"[{self.severity.value.upper()}] {self.title} @ {self.url}"

    def __repr__(self) -> str:
        """详细表示"""
        return (
            f"Vulnerability(type={self.type.value!r}, severity={self.severity.value!r}, "
            f"title={self.title!r}, verified={self.verified})"
        )


@dataclass
class ScanResult:
    """
    扫描结果数据类

    汇总一次扫描的所有结果。

    Attributes:
        session_id: 会话ID
        target: 目标
        status: 扫描状态
        started_at: 开始时间
        ended_at: 结束时间
        duration: 持续时间（秒）
        vulnerabilities: 漏洞列表
        fingerprints: 指纹信息
        total_requests: 总请求数
        total_vulns: 漏洞总数
        critical_count: 严重漏洞数
        high_count: 高危漏洞数
        medium_count: 中危漏洞数
        low_count: 低危漏洞数
        info_count: 信息级别数
    """
    session_id: str                          # 会话ID
    target: str                              # 目标
    status: str                              # 扫描状态

    # 时间
    started_at: datetime                     # 开始时间
    ended_at: Optional[datetime] = None      # 结束时间
    duration: Optional[float] = None         # 持续时间（秒）

    # 结果
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    fingerprints: Dict[str, Any] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)

    # 统计
    total_requests: int = 0
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    errors_count: int = 0

    # 元数据
    scan_config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理"""
        # 确保列表和字典字段不为None
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.fingerprints is None:
            self.fingerprints = {}
        if self.technologies is None:
            self.technologies = []
        if self.ports is None:
            self.ports = []
        if self.subdomains is None:
            self.subdomains = []
        if self.scan_config is None:
            self.scan_config = {}
        if self.metadata is None:
            self.metadata = {}

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """
        添加漏洞

        Args:
            vuln: 漏洞对象
        """
        self.vulnerabilities.append(vuln)
        self.total_vulns += 1

        # 更新统计
        if vuln.severity == Severity.CRITICAL:
            self.critical_count += 1
        elif vuln.severity == Severity.HIGH:
            self.high_count += 1
        elif vuln.severity == Severity.MEDIUM:
            self.medium_count += 1
        elif vuln.severity == Severity.LOW:
            self.low_count += 1
        else:
            self.info_count += 1

    def calculate_stats(self) -> None:
        """
        计算统计信息

        重新计算所有统计数据
        """
        self.total_vulns = len(self.vulnerabilities)
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.info_count = 0

        for vuln in self.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                self.critical_count += 1
            elif vuln.severity == Severity.HIGH:
                self.high_count += 1
            elif vuln.severity == Severity.MEDIUM:
                self.medium_count += 1
            elif vuln.severity == Severity.LOW:
                self.low_count += 1
            else:
                self.info_count += 1

        # 计算持续时间
        if self.ended_at and self.started_at:
            self.duration = (self.ended_at - self.started_at).total_seconds()

    def complete(self) -> None:
        """
        完成扫描

        设置结束时间并计算统计
        """
        self.ended_at = datetime.now()
        self.status = 'completed'
        self.calculate_stats()

    def fail(self, error: str = None) -> None:
        """
        标记扫描失败

        Args:
            error: 错误信息
        """
        self.ended_at = datetime.now()
        self.status = 'failed'
        if error:
            self.metadata['error'] = error
        self.calculate_stats()

    def get_vulns_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """
        按严重程度获取漏洞

        Args:
            severity: 严重程度

        Returns:
            List[Vulnerability]: 漏洞列表
        """
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_vulns_by_type(self, vuln_type: VulnType) -> List[Vulnerability]:
        """
        按类型获取漏洞

        Args:
            vuln_type: 漏洞类型

        Returns:
            List[Vulnerability]: 漏洞列表
        """
        return [v for v in self.vulnerabilities if v.type == vuln_type]

    def get_verified_vulns(self) -> List[Vulnerability]:
        """
        获取已验证的漏洞

        Returns:
            List[Vulnerability]: 已验证漏洞列表
        """
        return [v for v in self.vulnerabilities if v.verified]

    def get_summary(self) -> Dict[str, Any]:
        """
        获取结果摘要

        Returns:
            Dict[str, Any]: 摘要字典
        """
        self.calculate_stats()

        return {
            'session_id': self.session_id,
            'target': self.target,
            'status': self.status,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'duration': self.duration,
            'total_vulns': self.total_vulns,
            'by_severity': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'info': self.info_count,
            },
            'total_requests': self.total_requests,
            'errors_count': self.errors_count,
            'technologies_count': len(self.technologies),
            'subdomains_count': len(self.subdomains),
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典

        Returns:
            Dict[str, Any]: 完整字典表示
        """
        self.calculate_stats()

        return {
            'session_id': self.session_id,
            'target': self.target,
            'status': self.status,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'duration': self.duration,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'fingerprints': self.fingerprints,
            'technologies': self.technologies,
            'ports': self.ports,
            'subdomains': self.subdomains,
            'stats': {
                'total_requests': self.total_requests,
                'total_vulns': self.total_vulns,
                'critical_count': self.critical_count,
                'high_count': self.high_count,
                'medium_count': self.medium_count,
                'low_count': self.low_count,
                'info_count': self.info_count,
                'errors_count': self.errors_count,
            },
            'scan_config': self.scan_config,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanResult':
        """
        从字典创建结果对象

        Args:
            data: 字典数据

        Returns:
            ScanResult: 结果对象
        """
        # 解析漏洞列表
        vulns = []
        for v_data in data.get('vulnerabilities', []):
            vulns.append(Vulnerability.from_dict(v_data))

        # 解析统计数据
        stats = data.get('stats', {})

        result = cls(
            session_id=data['session_id'],
            target=data['target'],
            status=data['status'],
            started_at=datetime.fromisoformat(data['started_at']),
            ended_at=datetime.fromisoformat(data['ended_at']) if data.get('ended_at') else None,
            duration=data.get('duration'),
            vulnerabilities=vulns,
            fingerprints=data.get('fingerprints', {}),
            technologies=data.get('technologies', []),
            ports=data.get('ports', []),
            subdomains=data.get('subdomains', []),
            total_requests=stats.get('total_requests', 0),
            total_vulns=stats.get('total_vulns', 0),
            critical_count=stats.get('critical_count', 0),
            high_count=stats.get('high_count', 0),
            medium_count=stats.get('medium_count', 0),
            low_count=stats.get('low_count', 0),
            info_count=stats.get('info_count', 0),
            errors_count=stats.get('errors_count', 0),
            scan_config=data.get('scan_config', {}),
            metadata=data.get('metadata', {}),
        )

        return result

    def to_json(self, indent: int = 2) -> str:
        """
        导出为JSON字符串

        Args:
            indent: 缩进空格数

        Returns:
            str: JSON字符串
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def __str__(self) -> str:
        """字符串表示"""
        return (
            f"ScanResult(target={self.target}, status={self.status}, "
            f"vulns={self.total_vulns}, duration={self.duration}s)"
        )

    def __repr__(self) -> str:
        """详细表示"""
        return (
            f"ScanResult(session_id={self.session_id!r}, target={self.target!r}, "
            f"status={self.status!r}, total_vulns={self.total_vulns})"
        )
