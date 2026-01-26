"""
失败原因分析器 - 分析利用失败的原因并提供诊断

支持的分析:
- HTTP响应分析 (状态码、响应头、响应体)
- 异常类型分析 (超时、连接错误等)
- WAF特征检测
- 限速特征检测
- 误报检测
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .strategies import FailureReason


@dataclass
class FailureAnalysis:
    """失败分析结果"""
    reason: FailureReason                    # 失败原因
    confidence: float                        # 置信度 (0.0-1.0)
    description: str                         # 描述
    evidence: List[str] = field(default_factory=list)   # 证据
    suggestions: List[str] = field(default_factory=list)  # 建议
    raw_data: Dict[str, Any] = field(default_factory=dict)  # 原始数据
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'reason': self.reason.name,
            'confidence': self.confidence,
            'description': self.description,
            'evidence': self.evidence,
            'suggestions': self.suggestions,
            'timestamp': self.timestamp,
        }


class FailureAnalyzer:
    """失败原因分析器"""

    # WAF特征模式
    WAF_PATTERNS: Dict[str, List[str]] = {
        'cloudflare': [
            r'cloudflare',
            r'cf-ray',
            r'cf-cache-status',
            r'attention required',
            r'checking your browser',
        ],
        'akamai': [
            r'akamai',
            r'akamaighost',
            r'ak_bmsc',
            r'reference #\d+\.\d+\.\d+',
        ],
        'imperva': [
            r'incapsula',
            r'visid_incap',
            r'incap_ses',
            r'request unsuccessful',
        ],
        'fortinet': [
            r'fortigate',
            r'fortiweb',
            r'.fgd_icon',
        ],
        'f5_bigip': [
            r'bigip',
            r'ts[a-z0-9]{8,}=',
            r'f5-ltm',
        ],
        'modsecurity': [
            r'mod_security',
            r'modsecurity',
            r'owasp.*crs',
            r'not acceptable',
        ],
        'aws_waf': [
            r'awswaf',
            r'x-amzn-requestid',
            r'request blocked',
        ],
        'generic': [
            r'access denied',
            r'request blocked',
            r'forbidden',
            r'not allowed',
            r'security violation',
            r'attack detected',
            r'blocked by',
            r'malicious request',
        ]
    }

    # 限速响应特征
    RATE_LIMIT_PATTERNS: List[str] = [
        r'rate limit',
        r'too many requests',
        r'retry-after',
        r'x-ratelimit',
        r'x-rate-limit',
        r'quota exceeded',
        r'throttl',
        r'slow down',
    ]

    # 验证码特征
    CAPTCHA_PATTERNS: List[str] = [
        r'captcha',
        r'recaptcha',
        r'hcaptcha',
        r'g-recaptcha',
        r'verify.*human',
        r'robot.*check',
        r'challenge',
    ]

    # 认证要求特征
    AUTH_PATTERNS: List[str] = [
        r'unauthorized',
        r'login.*required',
        r'authentication.*required',
        r'www-authenticate',
        r'please.*log.*in',
        r'session.*expired',
    ]

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """预编译正则表达式"""
        self._waf_compiled: Dict[str, List[re.Pattern]] = {}
        for waf_name, patterns in self.WAF_PATTERNS.items():
            self._waf_compiled[waf_name] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        self._rate_limit_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.RATE_LIMIT_PATTERNS
        ]
        self._captcha_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.CAPTCHA_PATTERNS
        ]
        self._auth_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.AUTH_PATTERNS
        ]

    def analyze(
        self,
        error: Optional[Exception] = None,
        response: Optional[Any] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> FailureAnalysis:
        """
        分析失败原因

        Args:
            error: 捕获的异常
            response: HTTP响应对象 (requests.Response 或类似)
            context: 额外上下文信息

        Returns:
            FailureAnalysis 分析结果
        """
        context = context or {}

        # 1. 先分析异常
        if error:
            analysis = self._analyze_exception(error, context)
            if analysis.confidence > 0.7:
                return analysis

        # 2. 分析HTTP响应
        if response:
            analysis = self._analyze_response(response, context)
            if analysis.confidence > 0.7:
                return analysis

        # 3. 如果无法确定，返回未知原因
        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.3,
            description='无法确定失败原因',
            evidence=['未能匹配已知的失败模式'],
            suggestions=['检查目标可达性', '验证请求参数', '查看详细日志'],
            raw_data={'error': str(error) if error else None}
        )

    def _analyze_exception(
        self,
        error: Exception,
        context: Dict[str, Any]
    ) -> FailureAnalysis:
        """分析异常类型"""
        error_type = type(error).__name__
        error_msg = str(error).lower()

        # 超时异常
        if 'timeout' in error_type.lower() or 'timeout' in error_msg:
            return FailureAnalysis(
                reason=FailureReason.TIMEOUT,
                confidence=0.95,
                description='请求超时',
                evidence=[f'异常类型: {error_type}', f'错误信息: {str(error)[:200]}'],
                suggestions=['增加超时时间', '检查网络连接', '降低并发数'],
                raw_data={'exception_type': error_type, 'message': str(error)}
            )

        # 连接错误
        if any(kw in error_msg for kw in ['connection', 'connect', 'refused', 'reset']):
            return FailureAnalysis(
                reason=FailureReason.CONNECTION_ERROR,
                confidence=0.9,
                description='连接错误',
                evidence=[f'异常类型: {error_type}', f'错误信息: {str(error)[:200]}'],
                suggestions=['检查目标服务器状态', '验证端口是否开放', '检查防火墙设置'],
                raw_data={'exception_type': error_type, 'message': str(error)}
            )

        # DNS解析错误
        if any(kw in error_msg for kw in ['dns', 'resolve', 'getaddrinfo', 'name or service']):
            return FailureAnalysis(
                reason=FailureReason.DNS_ERROR,
                confidence=0.95,
                description='DNS解析失败',
                evidence=[f'异常类型: {error_type}', f'错误信息: {str(error)[:200]}'],
                suggestions=['检查域名是否正确', '验证DNS服务器', '尝试使用IP地址'],
                raw_data={'exception_type': error_type, 'message': str(error)}
            )

        # SSL/TLS错误
        if any(kw in error_msg for kw in ['ssl', 'certificate', 'tls', 'handshake']):
            return FailureAnalysis(
                reason=FailureReason.CONNECTION_ERROR,
                confidence=0.85,
                description='SSL/TLS错误',
                evidence=[f'异常类型: {error_type}', f'错误信息: {str(error)[:200]}'],
                suggestions=['禁用SSL验证', '更新CA证书', '检查TLS版本兼容性'],
                raw_data={'exception_type': error_type, 'message': str(error)}
            )

        # 默认返回未知
        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.3,
            description=f'异常: {error_type}',
            evidence=[f'错误信息: {str(error)[:200]}'],
            suggestions=['查看完整堆栈跟踪'],
            raw_data={'exception_type': error_type, 'message': str(error)}
        )

    def _analyze_response(
        self,
        response: Any,
        context: Dict[str, Any]
    ) -> FailureAnalysis:
        """分析HTTP响应"""
        status_code = getattr(response, 'status_code', 0)
        headers = {}
        body = ''

        # 提取响应信息
        try:
            headers = dict(getattr(response, 'headers', {}))
            body = getattr(response, 'text', '') or ''
            if callable(body):
                body = body()
        except (AttributeError, TypeError):
            pass

        # 合并用于搜索的文本
        search_text = (
            ' '.join(f'{k}: {v}' for k, v in headers.items()) +
            ' ' + body[:5000]  # 限制搜索长度
        ).lower()

        # 1. 检查状态码
        status_analysis = self._analyze_status_code(status_code, headers)
        if status_analysis and status_analysis.confidence > 0.7:
            return status_analysis

        # 2. 检测WAF
        waf_analysis = self._detect_waf(search_text, headers, status_code)
        if waf_analysis.confidence > 0.7:
            return waf_analysis

        # 3. 检测限速
        rate_analysis = self._detect_rate_limit(search_text, headers, status_code)
        if rate_analysis.confidence > 0.7:
            return rate_analysis

        # 4. 检测验证码
        captcha_analysis = self._detect_captcha(search_text)
        if captcha_analysis.confidence > 0.7:
            return captcha_analysis

        # 5. 检测认证要求
        auth_analysis = self._detect_auth_required(search_text, status_code)
        if auth_analysis.confidence > 0.7:
            return auth_analysis

        # 6. 检测Payload过滤
        if context.get('payload'):
            filter_analysis = self._detect_payload_filtered(body, context.get('payload', ''))
            if filter_analysis.confidence > 0.7:
                return filter_analysis

        # 返回基于状态码的默认分析
        return self._default_analysis_by_status(status_code, headers, body)

    def _analyze_status_code(
        self,
        status_code: int,
        headers: Dict[str, str]
    ) -> Optional[FailureAnalysis]:
        """根据状态码初步分析"""
        if status_code == 429:
            retry_after = headers.get('retry-after', headers.get('Retry-After', ''))
            return FailureAnalysis(
                reason=FailureReason.RATE_LIMITED,
                confidence=0.95,
                description='请求被限速 (429 Too Many Requests)',
                evidence=[f'状态码: {status_code}', f'Retry-After: {retry_after}'],
                suggestions=['等待后重试', '降低请求频率', '切换代理IP'],
                raw_data={'status_code': status_code, 'retry_after': retry_after}
            )

        if status_code == 403:
            return FailureAnalysis(
                reason=FailureReason.WAF_BLOCKED,
                confidence=0.6,  # 需要进一步确认
                description='请求被禁止 (403 Forbidden)',
                evidence=[f'状态码: {status_code}'],
                suggestions=['可能是WAF拦截', '尝试编码绕过', '检查请求参数'],
                raw_data={'status_code': status_code}
            )

        if status_code == 401:
            return FailureAnalysis(
                reason=FailureReason.AUTH_REQUIRED,
                confidence=0.9,
                description='需要认证 (401 Unauthorized)',
                evidence=[f'状态码: {status_code}'],
                suggestions=['提供有效凭据', '检查认证方式'],
                raw_data={'status_code': status_code}
            )

        if status_code == 404:
            return FailureAnalysis(
                reason=FailureReason.NOT_FOUND,
                confidence=0.9,
                description='资源不存在 (404 Not Found)',
                evidence=[f'状态码: {status_code}'],
                suggestions=['验证URL路径', '检查资源是否存在'],
                raw_data={'status_code': status_code}
            )

        if 500 <= status_code < 600:
            return FailureAnalysis(
                reason=FailureReason.SERVER_ERROR,
                confidence=0.85,
                description=f'服务器错误 ({status_code})',
                evidence=[f'状态码: {status_code}'],
                suggestions=['服务端可能存在问题', '尝试不同的Payload', '稍后重试'],
                raw_data={'status_code': status_code}
            )

        return None

    def _detect_waf(
        self,
        search_text: str,
        headers: Dict[str, str],
        status_code: int
    ) -> FailureAnalysis:
        """检测WAF"""
        detected_wafs = []
        evidence = []

        for waf_name, patterns in self._waf_compiled.items():
            for pattern in patterns:
                if pattern.search(search_text):
                    if waf_name not in detected_wafs:
                        detected_wafs.append(waf_name)
                        evidence.append(f'匹配WAF特征: {waf_name} (pattern: {pattern.pattern})')
                    break

        if detected_wafs:
            # 计算置信度
            confidence = min(0.95, 0.7 + 0.1 * len(detected_wafs))
            if status_code in [403, 406, 501]:
                confidence = min(0.98, confidence + 0.1)

            return FailureAnalysis(
                reason=FailureReason.WAF_BLOCKED,
                confidence=confidence,
                description=f'检测到WAF拦截: {", ".join(detected_wafs)}',
                evidence=evidence,
                suggestions=[
                    '尝试编码绕过 (URL双重编码、Unicode)',
                    '使用大小写混合',
                    '添加注释符',
                    '分块传输',
                    '切换HTTP方法',
                ],
                raw_data={'detected_wafs': detected_wafs, 'status_code': status_code}
            )

        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.1,
            description='未检测到WAF特征',
            evidence=[],
            suggestions=[]
        )

    def _detect_rate_limit(
        self,
        search_text: str,
        headers: Dict[str, str],
        status_code: int
    ) -> FailureAnalysis:
        """检测限速"""
        evidence = []

        # 检查响应内容
        for pattern in self._rate_limit_compiled:
            if pattern.search(search_text):
                evidence.append(f'匹配限速特征: {pattern.pattern}')

        # 检查特定响应头
        rate_headers = ['x-ratelimit-remaining', 'x-rate-limit-remaining',
                        'retry-after', 'x-ratelimit-limit']
        for header in rate_headers:
            for key in headers:
                if header in key.lower():
                    evidence.append(f'限速响应头: {key}={headers[key]}')

        if evidence or status_code == 429:
            confidence = 0.5 + 0.15 * len(evidence)
            if status_code == 429:
                confidence = max(confidence, 0.95)

            return FailureAnalysis(
                reason=FailureReason.RATE_LIMITED,
                confidence=min(0.98, confidence),
                description='请求被限速',
                evidence=evidence,
                suggestions=[
                    '使用指数退避策略',
                    '降低请求频率',
                    '切换代理IP',
                    '等待限速重置',
                ],
                raw_data={'status_code': status_code, 'evidence_count': len(evidence)}
            )

        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.1,
            description='未检测到限速特征',
            evidence=[],
            suggestions=[]
        )

    def _detect_captcha(self, search_text: str) -> FailureAnalysis:
        """检测验证码"""
        evidence = []

        for pattern in self._captcha_compiled:
            if pattern.search(search_text):
                evidence.append(f'匹配验证码特征: {pattern.pattern}')

        if evidence:
            return FailureAnalysis(
                reason=FailureReason.CAPTCHA_REQUIRED,
                confidence=min(0.95, 0.6 + 0.15 * len(evidence)),
                description='需要验证码',
                evidence=evidence,
                suggestions=[
                    '手动完成验证码',
                    '使用验证码识别服务',
                    '切换IP避免触发',
                    '降低请求频率',
                ],
                raw_data={'evidence_count': len(evidence)}
            )

        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.1,
            description='未检测到验证码',
            evidence=[],
            suggestions=[]
        )

    def _detect_auth_required(
        self,
        search_text: str,
        status_code: int
    ) -> FailureAnalysis:
        """检测认证要求"""
        evidence = []

        for pattern in self._auth_compiled:
            if pattern.search(search_text):
                evidence.append(f'匹配认证特征: {pattern.pattern}')

        if evidence or status_code == 401:
            confidence = 0.5 + 0.15 * len(evidence)
            if status_code == 401:
                confidence = max(confidence, 0.9)

            return FailureAnalysis(
                reason=FailureReason.AUTH_REQUIRED,
                confidence=min(0.95, confidence),
                description='需要认证',
                evidence=evidence,
                suggestions=[
                    '提供有效的认证凭据',
                    '检查Session/Cookie有效性',
                    '尝试绕过认证',
                ],
                raw_data={'status_code': status_code}
            )

        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.1,
            description='未检测到认证要求',
            evidence=[],
            suggestions=[]
        )

    def _detect_payload_filtered(
        self,
        response_body: str,
        payload: str
    ) -> FailureAnalysis:
        """检测Payload是否被过滤"""
        # 检查Payload关键字符是否被过滤
        filtered_chars = []
        dangerous_chars = ['<', '>', '"', "'", '`', '(', ')', '{', '}', '|', '&', ';']

        for char in dangerous_chars:
            if char in payload and char not in response_body:
                filtered_chars.append(char)

        # 检查SQL关键字是否被过滤
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'exec']
        filtered_keywords = []
        payload_lower = payload.lower()
        response_lower = response_body.lower()

        for kw in sql_keywords:
            if kw in payload_lower and kw not in response_lower:
                filtered_keywords.append(kw)

        if filtered_chars or filtered_keywords:
            evidence = []
            if filtered_chars:
                evidence.append(f'被过滤的字符: {filtered_chars}')
            if filtered_keywords:
                evidence.append(f'被过滤的关键字: {filtered_keywords}')

            return FailureAnalysis(
                reason=FailureReason.PAYLOAD_FILTERED,
                confidence=min(0.85, 0.5 + 0.1 * (len(filtered_chars) + len(filtered_keywords))),
                description='Payload被过滤',
                evidence=evidence,
                suggestions=[
                    '使用编码绕过 (URL编码、Unicode、十六进制)',
                    '使用大小写混合',
                    '使用等效替换 (如 OR -> ||)',
                    '添加注释符混淆',
                ],
                raw_data={
                    'filtered_chars': filtered_chars,
                    'filtered_keywords': filtered_keywords
                }
            )

        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.1,
            description='未检测到Payload过滤',
            evidence=[],
            suggestions=[]
        )

    def _default_analysis_by_status(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str
    ) -> FailureAnalysis:
        """基于状态码的默认分析"""
        if 200 <= status_code < 300:
            return FailureAnalysis(
                reason=FailureReason.FALSE_POSITIVE,
                confidence=0.6,
                description='请求成功但利用失败，可能是误报',
                evidence=[f'状态码: {status_code}'],
                suggestions=[
                    '验证漏洞是否真实存在',
                    '使用统计学方法确认',
                    '尝试OOB带外验证',
                ],
                raw_data={'status_code': status_code}
            )

        return FailureAnalysis(
            reason=FailureReason.UNKNOWN,
            confidence=0.3,
            description=f'请求失败 (状态码: {status_code})',
            evidence=[f'状态码: {status_code}'],
            suggestions=['检查请求参数', '查看详细响应'],
            raw_data={'status_code': status_code, 'body_length': len(body)}
        )


# 全局分析器实例
_analyzer = FailureAnalyzer()


def analyze_failure(
    error: Optional[Exception] = None,
    response: Optional[Any] = None,
    context: Optional[Dict[str, Any]] = None
) -> FailureAnalysis:
    """分析失败原因 (便捷函数)"""
    return _analyzer.analyze(error, response, context)
