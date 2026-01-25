#!/usr/bin/env python3
"""
误报过滤引擎 - False Positive Filter Engine
功能: 动态内容规范化、SPA检测增强、WAF拦截识别、响应一致性验证
减少漏洞扫描误报，提高检出精度
"""

import re
import hashlib
import statistics
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter, defaultdict
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


class FilterReason(Enum):
    """过滤原因"""
    SPA_FALLBACK = "spa_fallback"
    WAF_BLOCKED = "waf_blocked"
    DYNAMIC_CONTENT = "dynamic_content"
    RANDOM_RESPONSE = "random_response"
    RATE_LIMITED = "rate_limited"
    CAPTCHA = "captcha"
    ERROR_PAGE = "error_page"
    CDN_CACHE = "cdn_cache"
    LOAD_BALANCER = "load_balancer"
    NOT_FILTERED = "not_filtered"


@dataclass
class FilterResult:
    """过滤结果"""
    is_false_positive: bool
    reason: FilterReason
    confidence: float
    evidence: str = ""
    normalized_content: str = ""
    suggestions: List[str] = field(default_factory=list)


@dataclass
class ResponseBaseline:
    """响应基线"""
    status_code: int
    content_length: int
    content_hash: str
    response_time: float
    headers: Dict[str, str]
    normalized_length: int = 0
    structure: str = ""
    dynamic_patterns: List[str] = field(default_factory=list)
    is_spa: bool = False
    spa_framework: Optional[str] = None


class DynamicContentNormalizer:
    """动态内容规范化器"""
    
    # 动态内容正则模式
    DYNAMIC_PATTERNS: List[Tuple[str, str]] = [
        # 时间戳
        (r'\b\d{10,13}\b', '[TIMESTAMP]'),
        (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '[DATETIME]'),
        (r'\d{2}/\d{2}/\d{4}', '[DATE]'),
        
        # Session/Token
        (r'[a-f0-9]{32}', '[MD5_HASH]'),
        (r'[a-f0-9]{40}', '[SHA1_HASH]'),
        (r'[a-f0-9]{64}', '[SHA256_HASH]'),
        (r'[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[JWT]'),
        (r'[a-zA-Z0-9]{24,40}', '[SESSION_ID]'),
        
        # CSRF Token
        (r'csrf[_-]?token["\']?\s*[:=]\s*["\'][^"\']+["\']', '[CSRF_TOKEN]'),
        (r'authenticity_token["\']?\s*[:=]\s*["\'][^"\']+["\']', '[AUTH_TOKEN]'),
        (r'_token["\']?\s*[:=]\s*["\'][^"\']+["\']', '[TOKEN]'),
        
        # Nonce
        (r'nonce["\']?\s*[:=]\s*["\'][^"\']+["\']', '[NONCE]'),
        (r'nonce-[a-zA-Z0-9+/=]+', '[CSP_NONCE]'),
        
        # UUID
        (r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '[UUID]'),
        
        # 随机数
        (r'rand["\']?\s*[:=]\s*["\']?\d+', '[RANDOM]'),
        (r'_r=\d+', '[CACHE_BUSTER]'),
        (r'\?v=\d+', '[VERSION_PARAM]'),
        
        # 追踪ID
        (r'trace[_-]?id["\']?\s*[:=]\s*["\'][^"\']+["\']', '[TRACE_ID]'),
        (r'request[_-]?id["\']?\s*[:=]\s*["\'][^"\']+["\']', '[REQUEST_ID]'),
        (r'x-request-id:\s*[^\s]+', '[X_REQUEST_ID]'),
        
        # 广告/追踪像素
        (r'<img[^>]+pixel[^>]*>', '[TRACKING_PIXEL]'),
        (r'<img[^>]+analytics[^>]*>', '[ANALYTICS_PIXEL]'),
        
        # 动态脚本版本
        (r'\.js\?v=\d+', '.js?v=[VERSION]'),
        (r'\.css\?v=\d+', '.css?v=[VERSION]'),
    ]
    
    def __init__(self, custom_patterns: List[Tuple[str, str]] = None):
        self.patterns = self.DYNAMIC_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        
        # 编译正则表达式
        self._compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self.patterns
        ]
    
    def normalize(self, content: str) -> str:
        """规范化动态内容"""
        normalized = content
        for regex, replacement in self._compiled_patterns:
            normalized = regex.sub(replacement, normalized)
        return normalized
    
    def extract_static_structure(self, content: str) -> str:
        """提取静态结构（移除所有文本内容，保留HTML结构）"""
        # 移除脚本内容
        content = re.sub(r'<script[^>]*>.*?</script>', '<script></script>', content, flags=re.DOTALL | re.IGNORECASE)
        # 移除样式内容
        content = re.sub(r'<style[^>]*>.*?</style>', '<style></style>', content, flags=re.DOTALL | re.IGNORECASE)
        # 移除HTML注释
        content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
        # 移除标签内文本，保留结构
        content = re.sub(r'>([^<]+)<', '><', content)
        # 规范化空白
        content = re.sub(r'\s+', ' ', content)
        return content.strip()
    
    def get_content_fingerprint(self, content: str) -> str:
        """获取内容指纹（忽略动态部分）"""
        normalized = self.normalize(content)
        structure = self.extract_static_structure(normalized)
        return hashlib.md5(structure.encode()).hexdigest()


class SPADetector:
    """SPA应用检测器 - 增强版"""
    
    # SPA框架特征
    SPA_FRAMEWORKS: Dict[str, Dict[str, Any]] = {
        "react": {
            "markers": [
                '<div id="root">', 'data-reactroot', '__REACT_DEVTOOLS',
                '_reactRootContainer', 'react-app', '__NEXT_DATA__',
                'data-react-helmet', 'react-dom'
            ],
            "scripts": ['react', 'react-dom', 'react-router'],
            "meta": ['next-head-count'],
        },
        "vue": {
            "markers": [
                '<div id="app">', 'data-v-', '__VUE__', 'v-cloak',
                'vue-router', 'data-vue-meta', '__NUXT__'
            ],
            "scripts": ['vue', 'vuex', 'vue-router'],
            "meta": ['nuxt'],
        },
        "angular": {
            "markers": [
                'ng-version', '_ngcontent', 'ng-star-inserted',
                '<app-root>', 'ngIf', 'ngFor', '*ngIf', '*ngFor'
            ],
            "scripts": ['angular', 'zone.js', 'rxjs'],
            "meta": [],
        },
        "svelte": {
            "markers": ['svelte', '__SVELTE__', 'data-svelte'],
            "scripts": ['svelte'],
            "meta": [],
        },
        "nextjs": {
            "markers": [
                '__NEXT_DATA__', '_next/static', 'next/router',
                '__next', 'next-route-loader'
            ],
            "scripts": ['next', '_next'],
            "meta": ['next-head-count'],
        },
        "nuxtjs": {
            "markers": ['__NUXT__', '_nuxt', 'nuxt-link'],
            "scripts": ['nuxt', '_nuxt'],
            "meta": [],
        },
        "gatsby": {
            "markers": ['___gatsby', 'gatsby-focus-wrapper'],
            "scripts": ['gatsby'],
            "meta": ['generator.*gatsby'],
        },
    }
    
    # SPA通用特征
    GENERIC_SPA_MARKERS = [
        # 空白容器
        '<div id="root"></div>',
        '<div id="app"></div>',
        '<app-root></app-root>',
        # 客户端路由
        'history.pushState',
        'window.history',
        # 状态管理
        '__INITIAL_STATE__',
        '__PRELOADED_STATE__',
        # SPA路由
        'single-page-app',
        'client-side-rendering',
    ]
    
    def detect(self, body: str, headers: Dict[str, str] = None) -> Tuple[bool, Optional[str]]:
        """检测是否为SPA应用及框架类型"""
        headers = headers or {}
        body_lower = body.lower()
        
        # 检测特定框架
        for framework, features in self.SPA_FRAMEWORKS.items():
            score = 0
            max_score = len(features['markers']) + len(features['scripts']) + len(features.get('meta', []))
            
            # 检查标记
            for marker in features['markers']:
                if marker.lower() in body_lower:
                    score += 1
            
            # 检查脚本引用
            for script in features['scripts']:
                if re.search(rf'<script[^>]*{script}[^>]*>', body, re.IGNORECASE):
                    score += 1
                if re.search(rf'src=["\'][^"\']*{script}[^"\']*["\']', body, re.IGNORECASE):
                    score += 1
            
            # 检查meta标签
            for meta in features.get('meta', []):
                if re.search(rf'<meta[^>]*{meta}[^>]*>', body, re.IGNORECASE):
                    score += 1
            
            # 置信度阈值
            if max_score > 0 and score / max_score >= 0.3:
                return True, framework
        
        # 检测通用SPA特征
        spa_score = sum(1 for marker in self.GENERIC_SPA_MARKERS if marker.lower() in body_lower)
        if spa_score >= 2:
            return True, "generic"
        
        return False, None
    
    def is_spa_fallback(self, response1: str, response2: str, 
                        similarity_threshold: float = 0.95) -> bool:
        """检查两个响应是否为SPA fallback（相同HTML模板）"""
        # 提取静态结构
        normalizer = DynamicContentNormalizer()
        struct1 = normalizer.extract_static_structure(response1)
        struct2 = normalizer.extract_static_structure(response2)
        
        # 计算相似度
        similarity = SequenceMatcher(None, struct1, struct2).ratio()
        return similarity >= similarity_threshold

    def is_spa_fallback_structure(
        self,
        struct1: str,
        struct2: str,
        similarity_threshold: float = 0.95
    ) -> bool:
        """使用静态结构直接比较SPA fallback"""
        if not struct1 or not struct2:
            return False
        if len(struct1) < 30 or len(struct2) < 30:
            return False
        similarity = SequenceMatcher(None, struct1, struct2).ratio()
        return similarity >= similarity_threshold


class WAFBlockDetector:
    """WAF拦截检测器"""
    
    # WAF拦截特征
    WAF_BLOCK_PATTERNS: Dict[str, List[str]] = {
        "cloudflare": [
            "attention required", "cloudflare ray id", "checking your browser",
            "please wait while we verify", "ddos protection by cloudflare"
        ],
        "aws_waf": [
            "request blocked", "waf block", "access denied by aws"
        ],
        "modsecurity": [
            "mod_security", "not acceptable", "request rejected",
            "detected as suspicious", "blocked by mod_security"
        ],
        "imperva": [
            "incapsula incident", "powered by incapsula", "access denied"
        ],
        "akamai": [
            "reference #", "access denied", "akamai ghost"
        ],
        "generic": [
            "blocked", "forbidden", "access denied", "request blocked",
            "security violation", "suspicious request", "threat detected",
            "web application firewall", "attack detected"
        ],
    }
    
    # 拦截状态码
    BLOCK_STATUS_CODES = [403, 406, 429, 503]
    
    def is_blocked(self, status_code: int, body: str, 
                   headers: Dict[str, str] = None) -> Tuple[bool, Optional[str]]:
        """检测请求是否被WAF拦截"""
        headers = headers or {}
        body_lower = body.lower()
        
        # 检查状态码
        if status_code not in self.BLOCK_STATUS_CODES:
            return False, None
        
        # 检查WAF特定特征
        for waf_name, patterns in self.WAF_BLOCK_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in body_lower:
                    return True, waf_name
        
        # 检查通用拦截响应（短响应+403/503）
        if status_code in [403, 503] and len(body) < 5000:
            # 检查是否包含拦截关键词
            block_keywords = ['block', 'denied', 'forbidden', 'security', 'firewall']
            if any(kw in body_lower for kw in block_keywords):
                return True, "generic"
        
        return False, None


class RateLimitDetector:
    """速率限制检测器"""
    
    RATE_LIMIT_INDICATORS = [
        "rate limit", "too many requests", "slow down",
        "throttled", "quota exceeded", "try again later",
        "requests per minute", "requests per second",
        "exceeded the rate limit"
    ]
    
    RATE_LIMIT_HEADERS = [
        "x-ratelimit-limit", "x-ratelimit-remaining",
        "x-rate-limit-limit", "retry-after",
        "x-ratelimit-reset"
    ]
    
    def is_rate_limited(self, status_code: int, body: str,
                        headers: Dict[str, str] = None) -> bool:
        """检测是否被速率限制"""
        headers = headers or {}
        
        # 检查429状态码
        if status_code == 429:
            return True
        
        # 检查速率限制响应头
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header in self.RATE_LIMIT_HEADERS:
            if header in headers_lower:
                # 检查是否已耗尽配额
                if 'remaining' in header and headers_lower[header] == '0':
                    return True
        
        # 检查响应体
        body_lower = body.lower()
        return any(ind in body_lower for ind in self.RATE_LIMIT_INDICATORS)


class CaptchaDetector:
    """验证码检测器"""
    
    CAPTCHA_INDICATORS = [
        # reCAPTCHA
        "g-recaptcha", "grecaptcha", "recaptcha/api",
        "www.google.com/recaptcha",
        # hCaptcha
        "h-captcha", "hcaptcha.com", "hcaptcha",
        # 通用
        "captcha", "verify you are human", "prove you're not a robot",
        "human verification", "security check",
        # 图形验证码
        "captcha.php", "captcha.png", "captcha.jpg",
        "验证码", "输入验证码",
    ]
    
    def has_captcha(self, body: str) -> bool:
        """检测页面是否包含验证码"""
        body_lower = body.lower()
        return any(ind in body_lower for ind in self.CAPTCHA_INDICATORS)


class FalsePositiveFilter:
    """
    误报过滤器 - 主类
    
    Usage:
        filter = FalsePositiveFilter()
        
        # 建立基线
        baseline = filter.establish_baseline(url, request_func)
        
        # 检查是否为误报
        result = filter.check(response, baseline)
        if result.is_false_positive:
            print(f"误报原因: {result.reason}")
    """
    
    def __init__(self):
        self.normalizer = DynamicContentNormalizer()
        self.spa_detector = SPADetector()
        self.waf_detector = WAFBlockDetector()
        self.rate_limit_detector = RateLimitDetector()
        self.captcha_detector = CaptchaDetector()
        
        # 缓存基线
        self._baselines: Dict[str, ResponseBaseline] = {}
    
    def establish_baseline(self, url: str, 
                          request_func,
                          num_requests: int = 3) -> ResponseBaseline:
        """
        建立响应基线
        
        Args:
            url: 目标URL
            request_func: 请求函数，签名 (url) -> (body, status, time, headers)
            num_requests: 基线请求数
        """
        responses = []
        
        for _ in range(num_requests):
            body, status, resp_time, headers = request_func(url)
            responses.append({
                'body': body,
                'status': status,
                'time': resp_time,
                'headers': headers or {},
            })
        
        # 计算基线值
        avg_time = statistics.mean([r['time'] for r in responses])
        
        # 找出动态模式
        dynamic_patterns = self._find_dynamic_patterns(
            [r['body'] for r in responses]
        )
        
        # 检测SPA
        is_spa, spa_framework = self.spa_detector.detect(
            responses[0]['body'],
            responses[0]['headers']
        )
        
        # 计算规范化内容的哈希
        normalized = self.normalizer.normalize(responses[0]['body'])
        content_hash = hashlib.md5(normalized.encode()).hexdigest()
        structure = self.normalizer.extract_static_structure(normalized)

        baseline = ResponseBaseline(
            status_code=responses[0]['status'],
            content_length=len(responses[0]['body']),
            content_hash=content_hash,
            response_time=avg_time,
            headers=responses[0]['headers'],
            normalized_length=len(normalized),
            structure=structure,
            dynamic_patterns=dynamic_patterns,
            is_spa=is_spa,
            spa_framework=spa_framework,
        )
        
        # 缓存
        self._baselines[url] = baseline
        
        return baseline
    
    def _find_dynamic_patterns(self, bodies: List[str]) -> List[str]:
        """从多个响应中找出动态变化的模式"""
        if len(bodies) < 2:
            return []
        
        dynamic = []
        
        # 简化：找出在不同响应中变化的行
        lines_sets = [set(body.split('\n')) for body in bodies]
        
        # 找出所有行的交集（静态内容）
        if lines_sets:
            static_lines = lines_sets[0]
            for lines in lines_sets[1:]:
                static_lines &= lines
            
            # 非交集的行可能是动态的
            for i, lines in enumerate(lines_sets):
                dynamic_lines = lines - static_lines
                for line in dynamic_lines:
                    # 提取可能的动态模式
                    if len(line) < 200:  # 忽略太长的行
                        dynamic.append(line[:50])  # 只保留前50字符作为模式
        
        return list(set(dynamic))[:20]  # 最多20个模式
    
    def check(self, body: str, status_code: int, response_time: float,
              headers: Dict[str, str] = None,
              baseline: ResponseBaseline = None,
              url: str = None) -> FilterResult:
        """
        检查响应是否为误报
        
        Args:
            body: 响应体
            status_code: 状态码
            response_time: 响应时间
            headers: 响应头
            baseline: 基线（可选）
            url: URL（用于获取缓存的基线）
        
        Returns:
            FilterResult
        """
        headers = headers or {}
        
        # 获取基线
        if baseline is None and url:
            baseline = self._baselines.get(url)
        
        # 1. 检查WAF拦截
        is_blocked, waf_name = self.waf_detector.is_blocked(status_code, body, headers)
        if is_blocked:
            return FilterResult(
                is_false_positive=True,
                reason=FilterReason.WAF_BLOCKED,
                confidence=0.9,
                evidence=f"WAF blocked: {waf_name}",
                suggestions=["使用WAF绕过技术", "降低请求频率", "更换IP"]
            )
        
        # 2. 检查速率限制
        if self.rate_limit_detector.is_rate_limited(status_code, body, headers):
            return FilterResult(
                is_false_positive=True,
                reason=FilterReason.RATE_LIMITED,
                confidence=0.95,
                evidence="Rate limited",
                suggestions=["降低请求频率", "添加延迟", "分布式扫描"]
            )
        
        # 3. 检查验证码
        if self.captcha_detector.has_captcha(body):
            return FilterResult(
                is_false_positive=True,
                reason=FilterReason.CAPTCHA,
                confidence=0.9,
                evidence="CAPTCHA detected",
                suggestions=["手动处理验证码", "使用验证码识别服务"]
            )
        
        # 4. 检查SPA fallback（需要基线）
        if baseline and baseline.is_spa and baseline.structure:
            # 规范化当前响应
            normalized = self.normalizer.normalize(body)
            current_structure = self.normalizer.extract_static_structure(normalized)

            # 比较静态结构
            if self.spa_detector.is_spa_fallback_structure(current_structure, baseline.structure):
                return FilterResult(
                    is_false_positive=True,
                    reason=FilterReason.SPA_FALLBACK,
                    confidence=0.85,
                    evidence=f"SPA fallback detected ({baseline.spa_framework})",
                    suggestions=["使用无头浏览器", "等待JS渲染", "检查客户端路由"]
                )
        
        # 5. 检查动态内容导致的误差
        normalized_content = self.normalizer.normalize(body)

        if baseline:
            # 比较规范化后的内容
            baseline_normalized_len = baseline.normalized_length or baseline.content_length
            current_normalized_len = len(normalized_content)
            
            # 如果规范化后长度差异很小但原始差异大，可能是动态内容
            original_diff = abs(len(body) - baseline.content_length)
            normalized_diff = abs(current_normalized_len - baseline_normalized_len)
            
            if original_diff > 100 and normalized_diff < 50:
                return FilterResult(
                    is_false_positive=True,
                    reason=FilterReason.DYNAMIC_CONTENT,
                    confidence=0.7,
                    evidence="Dynamic content variation",
                    normalized_content=normalized_content,
                    suggestions=["使用规范化内容比较", "忽略动态字段"]
                )
        
        # 6. 检查CDN缓存异常
        cache_headers = ['x-cache', 'cf-cache-status', 'x-varnish', 'age']
        has_cache = any(h.lower() in [k.lower() for k in headers.keys()] for h in cache_headers)
        if has_cache and baseline:
            # CDN缓存可能导致响应不一致
            age = headers.get('age', headers.get('Age', '0'))
            try:
                if int(age) > 3600:  # 缓存超过1小时
                    return FilterResult(
                        is_false_positive=False,  # 不一定是误报，但需要注意
                        reason=FilterReason.CDN_CACHE,
                        confidence=0.5,
                        evidence=f"CDN cached response (age: {age}s)",
                        suggestions=["添加缓存破坏参数", "直接请求源站"]
                    )
            except (ValueError, TypeError):
                pass
        
        # 7. 检查通用错误页面
        error_indicators = [
            "404 not found", "500 internal server error",
            "page not found", "something went wrong",
            "error occurred", "service unavailable"
        ]
        body_lower = body.lower()
        if status_code >= 400 and any(ind in body_lower for ind in error_indicators):
            # 检查是否是通用错误页
            if len(body) < 10000:  # 错误页通常较短
                return FilterResult(
                    is_false_positive=True,
                    reason=FilterReason.ERROR_PAGE,
                    confidence=0.75,
                    evidence=f"Generic error page (status: {status_code})",
                    suggestions=["验证参数有效性", "检查URL路径"]
                )
        
        # 未检测到误报
        return FilterResult(
            is_false_positive=False,
            reason=FilterReason.NOT_FILTERED,
            confidence=0.0,
            normalized_content=normalized_content,
        )
    
    def check_response_consistency(self, responses: List[Tuple[str, int, float]],
                                   threshold: float = 0.8) -> Tuple[bool, float]:
        """
        检查多次响应的一致性
        
        Args:
            responses: [(body, status, time), ...]
            threshold: 一致性阈值
        
        Returns:
            (is_consistent, consistency_score)
        """
        if len(responses) < 2:
            return True, 1.0
        
        # 规范化所有响应
        normalized = [self.normalizer.normalize(r[0]) for r in responses]
        
        # 计算两两相似度
        similarities = []
        for i in range(len(normalized)):
            for j in range(i + 1, len(normalized)):
                sim = SequenceMatcher(None, normalized[i], normalized[j]).ratio()
                similarities.append(sim)
        
        avg_similarity = statistics.mean(similarities) if similarities else 1.0
        return avg_similarity >= threshold, avg_similarity
    
    def filter_time_based_false_positive(self, 
                                         response_times: List[float],
                                         expected_delay: float,
                                         tolerance: float = 0.3) -> Tuple[bool, str]:
        """
        过滤时间盲注误报
        
        Args:
            response_times: 响应时间列表
            expected_delay: 预期延迟
            tolerance: 容差比例
        
        Returns:
            (is_false_positive, reason)
        """
        if len(response_times) < 3:
            return False, "insufficient_data"
        
        # 计算统计量
        mean_time = statistics.mean(response_times)
        std_dev = statistics.stdev(response_times) if len(response_times) > 1 else 0
        
        # 检查标准差是否过大（网络不稳定）
        if std_dev > mean_time * 0.5:
            return True, "high_variance"
        
        # 检查是否所有响应都延迟（可能是网络问题）
        all_delayed = all(t > expected_delay * 0.8 for t in response_times)
        if all_delayed:
            return True, "all_responses_delayed"
        
        # 检查延迟是否与预期匹配
        delayed_count = sum(1 for t in response_times if t >= expected_delay * (1 - tolerance))
        non_delayed_count = len(response_times) - delayed_count
        
        # 如果延迟和非延迟响应数量相近，可能是随机波动
        if 0.3 <= delayed_count / len(response_times) <= 0.7:
            return True, "inconsistent_delay"
        
        return False, "valid"


# 便捷函数
def is_false_positive(body: str, status_code: int, 
                      headers: Dict[str, str] = None) -> Tuple[bool, str]:
    """快速检查是否为误报"""
    filter_engine = FalsePositiveFilter()
    result = filter_engine.check(body, status_code, 0, headers)
    return result.is_false_positive, result.reason.value


def normalize_response(body: str) -> str:
    """规范化响应内容"""
    normalizer = DynamicContentNormalizer()
    return normalizer.normalize(body)
