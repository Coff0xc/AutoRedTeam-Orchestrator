"""
检测结果数据类

定义漏洞检测结果的数据结构
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class Severity(Enum):
    """严重程度枚举"""
    CRITICAL = 'critical'  # 严重 - 可直接获取系统权限或敏感数据
    HIGH = 'high'          # 高危 - 可能导致重大安全风险
    MEDIUM = 'medium'      # 中危 - 存在一定安全风险
    LOW = 'low'            # 低危 - 轻微安全问题
    INFO = 'info'          # 信息 - 安全建议或信息泄露

    @property
    def score(self) -> float:
        """获取CVSS风格的分数"""
        scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'info': 1.0
        }
        return scores.get(self.value, 0.0)

    @classmethod
    def from_score(cls, score: float) -> 'Severity':
        """从分数获取严重程度"""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score >= 1.0:
            return cls.LOW
        else:
            return cls.INFO


class DetectorType(Enum):
    """检测器类型枚举"""
    INJECTION = 'injection'  # 注入类漏洞
    ACCESS = 'access'        # 访问控制漏洞
    AUTH = 'auth'            # 认证漏洞
    MISC = 'misc'            # 其他漏洞

    @property
    def description(self) -> str:
        """获取类型描述"""
        descriptions = {
            'injection': '注入类漏洞 (SQL注入、XSS、命令注入等)',
            'access': '访问控制漏洞 (IDOR、路径遍历、SSRF等)',
            'auth': '认证漏洞 (弱密码、认证绕过、会话劫持等)',
            'misc': '其他漏洞 (CORS、CSRF、安全头缺失等)'
        }
        return descriptions.get(self.value, '未知类型')


@dataclass
class RequestInfo:
    """请求信息"""
    method: str = 'GET'
    url: str = ''
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)


@dataclass
class ResponseInfo:
    """响应信息"""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ''
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)


@dataclass
class DetectionResult:
    """检测结果数据类

    存储单个漏洞检测的完整信息，包括漏洞详情、证据、修复建议等
    """

    # 基本信息
    vulnerable: bool                     # 是否存在漏洞
    vuln_type: str                       # 漏洞类型 (sqli, xss, rce等)
    severity: Severity                   # 严重程度
    url: str                             # 目标URL

    # 详细信息
    param: Optional[str] = None          # 受影响参数
    payload: Optional[str] = None        # 触发漏洞的payload
    evidence: Optional[str] = None       # 漏洞证据（响应片段等）

    # 验证信息
    verified: bool = False               # 是否经过验证
    confidence: float = 0.0              # 置信度 (0.0 - 1.0)

    # 检测器信息
    detector: str = ''                   # 检测器名称
    detector_version: str = '1.0.0'      # 检测器版本

    # 请求/响应信息
    request: Optional[RequestInfo] = None   # 请求详情
    response: Optional[ResponseInfo] = None # 响应详情

    # 修复建议
    remediation: Optional[str] = None    # 修复建议
    references: List[str] = field(default_factory=list)  # 参考链接

    # 元数据
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    extra: Dict[str, Any] = field(default_factory=dict)  # 额外信息

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = {
            'vulnerable': self.vulnerable,
            'vuln_type': self.vuln_type,
            'severity': self.severity.value if isinstance(self.severity, Severity) else self.severity,
            'url': self.url,
            'param': self.param,
            'payload': self.payload,
            'evidence': self.evidence,
            'verified': self.verified,
            'confidence': self.confidence,
            'detector': self.detector,
            'detector_version': self.detector_version,
            'remediation': self.remediation,
            'references': self.references,
            'timestamp': self.timestamp,
            'extra': self.extra
        }

        if self.request:
            result['request'] = self.request.to_dict() if hasattr(self.request, 'to_dict') else self.request
        if self.response:
            result['response'] = self.response.to_dict() if hasattr(self.response, 'to_dict') else self.response

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DetectionResult':
        """从字典创建实例"""
        # 处理severity
        severity = data.get('severity', 'medium')
        if isinstance(severity, str):
            severity = Severity(severity)

        # 处理request
        request = data.get('request')
        if isinstance(request, dict):
            request = RequestInfo(**request)

        # 处理response
        response = data.get('response')
        if isinstance(response, dict):
            response = ResponseInfo(**response)

        return cls(
            vulnerable=data.get('vulnerable', False),
            vuln_type=data.get('vuln_type', ''),
            severity=severity,
            url=data.get('url', ''),
            param=data.get('param'),
            payload=data.get('payload'),
            evidence=data.get('evidence'),
            verified=data.get('verified', False),
            confidence=data.get('confidence', 0.0),
            detector=data.get('detector', ''),
            detector_version=data.get('detector_version', '1.0.0'),
            request=request,
            response=response,
            remediation=data.get('remediation'),
            references=data.get('references', []),
            timestamp=data.get('timestamp', datetime.now().isoformat()),
            extra=data.get('extra', {})
        )

    def __str__(self) -> str:
        """字符串表示"""
        status = "VULNERABLE" if self.vulnerable else "SAFE"
        return f"[{self.severity.value.upper()}] {self.vuln_type}: {status} - {self.url}"

    def __repr__(self) -> str:
        """详细表示"""
        return (
            f"DetectionResult(vuln_type={self.vuln_type!r}, "
            f"vulnerable={self.vulnerable}, severity={self.severity.value}, "
            f"url={self.url!r}, param={self.param!r})"
        )


@dataclass
class DetectionSummary:
    """检测结果汇总"""

    total_scans: int = 0                 # 总扫描数
    vulnerable_count: int = 0            # 漏洞数量
    safe_count: int = 0                  # 安全数量

    # 按严重程度统计
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # 按类型统计
    by_type: Dict[str, int] = field(default_factory=dict)

    # 检测时间
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0

    # 结果列表
    results: List[DetectionResult] = field(default_factory=list)

    def add_result(self, result: DetectionResult) -> None:
        """添加检测结果"""
        self.results.append(result)
        self.total_scans += 1

        if result.vulnerable:
            self.vulnerable_count += 1

            # 按严重程度统计
            severity = result.severity
            if severity == Severity.CRITICAL:
                self.critical_count += 1
            elif severity == Severity.HIGH:
                self.high_count += 1
            elif severity == Severity.MEDIUM:
                self.medium_count += 1
            elif severity == Severity.LOW:
                self.low_count += 1
            else:
                self.info_count += 1

            # 按类型统计
            vuln_type = result.vuln_type
            self.by_type[vuln_type] = self.by_type.get(vuln_type, 0) + 1
        else:
            self.safe_count += 1

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'total_scans': self.total_scans,
            'vulnerable_count': self.vulnerable_count,
            'safe_count': self.safe_count,
            'severity_counts': {
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
                'info': self.info_count
            },
            'by_type': self.by_type,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration_seconds': self.duration_seconds,
            'results': [r.to_dict() for r in self.results]
        }

    @property
    def vulnerability_rate(self) -> float:
        """漏洞发现率"""
        if self.total_scans == 0:
            return 0.0
        return self.vulnerable_count / self.total_scans

    @property
    def risk_score(self) -> float:
        """风险评分 (0-100)"""
        if self.vulnerable_count == 0:
            return 0.0

        # 加权计算
        weighted_sum = (
            self.critical_count * 10 +
            self.high_count * 7 +
            self.medium_count * 4 +
            self.low_count * 2 +
            self.info_count * 1
        )

        max_possible = self.vulnerable_count * 10
        return min(100, (weighted_sum / max_possible) * 100)
