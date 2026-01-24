#!/usr/bin/env python3
"""
安全头评分系统
功能: 基于OWASP指南的加权评分、等级评定、详细建议
作者: AutoRedTeam
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# 统一 HTTP 客户端工厂
try:
    from core.http import get_sync_client
    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


class SecurityLevel(Enum):
    """安全等级"""
    EXCELLENT = "A+"
    VERY_GOOD = "A"
    GOOD = "B"
    FAIR = "C"
    POOR = "D"
    CRITICAL = "F"


@dataclass
class HeaderAnalysis:
    """单个安全头分析结果"""
    name: str
    present: bool
    value: str
    score: int
    max_score: int
    correct: bool
    issues: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class SecurityHeadersReport:
    """安全头评分报告"""
    url: str
    total_score: int
    max_score: int
    grade: str
    grade_description: str
    headers_analyzed: List[HeaderAnalysis]
    missing_headers: List[str]
    recommendations: List[str]
    raw_headers: Dict[str, str]


class SecurityHeadersScorer:
    """安全头评分器"""

    # 安全头权重配置 (满分100)
    HEADER_CONFIG = {
        "Strict-Transport-Security": {
            "weight": 15,
            "required": True,
            "description": "HSTS - 强制HTTPS",
            "checks": [
                ("max-age", r"max-age=(\d+)", lambda v: int(v) >= 31536000, "max-age应至少为1年(31536000秒)"),
                ("includeSubDomains", r"includeSubDomains", lambda v: True, "建议包含includeSubDomains"),
                ("preload", r"preload", lambda v: True, "建议添加preload"),
            ],
            "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        "Content-Security-Policy": {
            "weight": 20,
            "required": True,
            "description": "CSP - 内容安全策略",
            "checks": [
                ("default-src", r"default-src\s+([^;]+)", lambda v: "'self'" in v or "'none'" in v, "default-src应设置为'self'或'none'"),
                ("script-src", r"script-src\s+([^;]+)", lambda v: "'unsafe-inline'" not in v, "script-src不应包含'unsafe-inline'"),
                ("object-src", r"object-src\s+([^;]+)", lambda v: "'none'" in v, "object-src应设置为'none'"),
            ],
            "recommendation": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
        },
        "X-Content-Type-Options": {
            "weight": 10,
            "required": True,
            "description": "防止MIME类型嗅探",
            "checks": [
                ("nosniff", r"nosniff", lambda v: True, "值必须为nosniff"),
            ],
            "recommendation": "X-Content-Type-Options: nosniff"
        },
        "X-Frame-Options": {
            "weight": 10,
            "required": True,
            "description": "防止点击劫持",
            "checks": [
                ("value", r"(DENY|SAMEORIGIN)", lambda v: v in ["DENY", "SAMEORIGIN"], "值应为DENY或SAMEORIGIN"),
            ],
            "recommendation": "X-Frame-Options: DENY"
        },
        "X-XSS-Protection": {
            "weight": 5,
            "required": False,
            "description": "XSS过滤器 (已弃用但仍建议)",
            "checks": [
                ("enabled", r"1", lambda v: True, "应启用XSS过滤"),
                ("mode", r"mode=block", lambda v: True, "建议设置mode=block"),
            ],
            "recommendation": "X-XSS-Protection: 1; mode=block"
        },
        "Referrer-Policy": {
            "weight": 8,
            "required": True,
            "description": "控制Referrer信息",
            "checks": [
                ("policy", r"(strict-origin-when-cross-origin|no-referrer|same-origin)",
                 lambda v: v in ["strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"],
                 "应设置安全的Referrer策略"),
            ],
            "recommendation": "Referrer-Policy: strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "weight": 10,
            "required": False,
            "description": "权限策略 (原Feature-Policy)",
            "checks": [
                ("geolocation", r"geolocation=\(\)", lambda v: True, "建议禁用geolocation"),
                ("camera", r"camera=\(\)", lambda v: True, "建议禁用camera"),
                ("microphone", r"microphone=\(\)", lambda v: True, "建议禁用microphone"),
            ],
            "recommendation": "Permissions-Policy: geolocation=(), camera=(), microphone=()"
        },
        "Cross-Origin-Opener-Policy": {
            "weight": 7,
            "required": False,
            "description": "COOP - 跨源开启者策略",
            "checks": [
                ("policy", r"(same-origin|same-origin-allow-popups)",
                 lambda v: v in ["same-origin", "same-origin-allow-popups"],
                 "建议设置same-origin"),
            ],
            "recommendation": "Cross-Origin-Opener-Policy: same-origin"
        },
        "Cross-Origin-Resource-Policy": {
            "weight": 5,
            "required": False,
            "description": "CORP - 跨源资源策略",
            "checks": [
                ("policy", r"(same-origin|same-site|cross-origin)",
                 lambda v: v in ["same-origin", "same-site"],
                 "建议设置same-origin或same-site"),
            ],
            "recommendation": "Cross-Origin-Resource-Policy: same-origin"
        },
        "Cross-Origin-Embedder-Policy": {
            "weight": 5,
            "required": False,
            "description": "COEP - 跨源嵌入策略",
            "checks": [
                ("policy", r"(require-corp|credentialless)",
                 lambda v: v in ["require-corp", "credentialless"],
                 "建议设置require-corp"),
            ],
            "recommendation": "Cross-Origin-Embedder-Policy: require-corp"
        },
        "Cache-Control": {
            "weight": 5,
            "required": False,
            "description": "缓存控制",
            "checks": [
                ("no-store", r"no-store", lambda v: True, "敏感页面应设置no-store"),
                ("private", r"private", lambda v: True, "敏感页面应设置private"),
            ],
            "recommendation": "Cache-Control: no-store, private"
        },
    }

    # 危险头检测
    DANGEROUS_HEADERS = {
        "Server": "泄露服务器版本信息",
        "X-Powered-By": "泄露技术栈信息",
        "X-AspNet-Version": "泄露ASP.NET版本",
        "X-AspNetMvc-Version": "泄露ASP.NET MVC版本",
    }

    # 等级划分
    GRADE_THRESHOLDS = [
        (95, SecurityLevel.EXCELLENT, "优秀 - 安全配置完善"),
        (85, SecurityLevel.VERY_GOOD, "很好 - 满足大多数安全要求"),
        (70, SecurityLevel.GOOD, "良好 - 基本安全配置到位"),
        (55, SecurityLevel.FAIR, "一般 - 存在改进空间"),
        (40, SecurityLevel.POOR, "较差 - 多个安全头缺失"),
        (0, SecurityLevel.CRITICAL, "危险 - 严重缺乏安全保护"),
    ]

    def __init__(self, timeout: float = 10.0, proxy: Optional[str] = None):
        """
        初始化评分器

        Args:
            timeout: 请求超时时间
            proxy: 代理地址
        """
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        # 优先使用统一 HTTP 客户端工厂
        if HAS_HTTP_FACTORY:
            self._session = get_sync_client(proxy=proxy, force_new=True)
        else:
            self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def _fetch_headers(self, url: str) -> Tuple[bool, Dict[str, str], str]:
        """
        获取目标URL的响应头

        Returns:
            (成功, 响应头字典, 错误信息)
        """
        try:
            resp = self._session.get(
                url,
                timeout=self.timeout,
                proxies=self.proxies,
                allow_redirects=True
            )
            # 转换为小写键的字典 (便于查找)
            headers = {k: v for k, v in resp.headers.items()}
            return True, headers, ""
        except requests.RequestException as e:
            return False, {}, str(e)

    def _find_header(self, headers: Dict[str, str], name: str) -> Tuple[bool, str]:
        """
        查找响应头 (不区分大小写)

        Returns:
            (是否存在, 值)
        """
        name_lower = name.lower()
        for key, value in headers.items():
            if key.lower() == name_lower:
                return True, value
        return False, ""

    def _analyze_header(self, name: str, value: str, config: Dict) -> HeaderAnalysis:
        """分析单个安全头"""
        analysis = HeaderAnalysis(
            name=name,
            present=bool(value),
            value=value,
            score=0,
            max_score=config["weight"],
            correct=False,
            issues=[],
            recommendation=config.get("recommendation", "")
        )

        if not value:
            analysis.issues.append(f"缺少{name}头")
            return analysis

        # 执行检查
        checks_passed = 0
        total_checks = len(config.get("checks", []))

        for check_name, pattern, validator, issue_msg in config.get("checks", []):
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                matched_value = match.group(1) if match.lastindex else match.group(0)
                if validator(matched_value):
                    checks_passed += 1
                else:
                    analysis.issues.append(issue_msg)
            else:
                analysis.issues.append(issue_msg)

        # 计算分数
        if total_checks > 0:
            score_ratio = checks_passed / total_checks
            analysis.score = int(config["weight"] * score_ratio)
            analysis.correct = checks_passed == total_checks
        else:
            # 只检查存在性
            analysis.score = config["weight"]
            analysis.correct = True

        return analysis

    def analyze(self, url: str = "", headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        分析安全头配置

        Args:
            url: 目标URL (如提供则自动获取响应头)
            headers: 直接提供的响应头字典

        Returns:
            分析结果字典
        """
        result = {
            "success": False,
            "url": url,
            "score": 0,
            "max_score": 100,
            "percentage": 0,
            "grade": "F",
            "grade_description": "",
            "headers": [],
            "missing_headers": [],
            "dangerous_headers": [],
            "recommendations": [],
            "raw_headers": {}
        }

        # 获取响应头
        if headers:
            raw_headers = headers
        elif url:
            success, raw_headers, error = self._fetch_headers(url)
            if not success:
                result["error"] = error
                return result
        else:
            result["error"] = "需要提供url或headers参数"
            return result

        result["success"] = True
        result["raw_headers"] = raw_headers

        total_score = 0
        max_score = 0

        # 分析每个安全头
        for header_name, config in self.HEADER_CONFIG.items():
            present, value = self._find_header(raw_headers, header_name)
            analysis = self._analyze_header(header_name, value, config)

            result["headers"].append({
                "name": analysis.name,
                "present": analysis.present,
                "value": analysis.value,
                "score": analysis.score,
                "max_score": analysis.max_score,
                "correct": analysis.correct,
                "issues": analysis.issues,
                "recommendation": analysis.recommendation
            })

            total_score += analysis.score
            max_score += config["weight"]

            if not present:
                result["missing_headers"].append(header_name)
                if config.get("required"):
                    result["recommendations"].append(f"添加 {analysis.recommendation}")

        # 检查危险头
        for header_name, description in self.DANGEROUS_HEADERS.items():
            present, value = self._find_header(raw_headers, header_name)
            if present:
                result["dangerous_headers"].append({
                    "name": header_name,
                    "value": value,
                    "risk": description
                })
                result["recommendations"].append(f"移除或隐藏 {header_name} 头: {description}")

        # 计算总分和等级
        result["score"] = total_score
        result["max_score"] = max_score
        result["percentage"] = round((total_score / max_score) * 100, 1) if max_score > 0 else 0

        # 确定等级
        for threshold, level, description in self.GRADE_THRESHOLDS:
            if result["percentage"] >= threshold:
                result["grade"] = level.value
                result["grade_description"] = description
                break

        return result

    def get_grade(self, score: int, max_score: int = 100) -> Tuple[str, str]:
        """
        获取评级

        Args:
            score: 得分
            max_score: 满分

        Returns:
            (等级, 描述)
        """
        percentage = (score / max_score) * 100 if max_score > 0 else 0

        for threshold, level, description in self.GRADE_THRESHOLDS:
            if percentage >= threshold:
                return level.value, description

        return "F", "危险"

    def compare(self, url1: str, url2: str) -> Dict[str, Any]:
        """
        比较两个URL的安全头配置

        Returns:
            比较结果
        """
        result1 = self.analyze(url1)
        result2 = self.analyze(url2)

        comparison = {
            "url1": {
                "url": url1,
                "score": result1.get("score", 0),
                "grade": result1.get("grade", "F")
            },
            "url2": {
                "url": url2,
                "score": result2.get("score", 0),
                "grade": result2.get("grade", "F")
            },
            "differences": []
        }

        # 比较每个头
        headers1 = {h["name"]: h for h in result1.get("headers", [])}
        headers2 = {h["name"]: h for h in result2.get("headers", [])}

        for name in self.HEADER_CONFIG.keys():
            h1 = headers1.get(name, {})
            h2 = headers2.get(name, {})

            if h1.get("present") != h2.get("present") or h1.get("value") != h2.get("value"):
                comparison["differences"].append({
                    "header": name,
                    "url1": {"present": h1.get("present", False), "value": h1.get("value", "")},
                    "url2": {"present": h2.get("present", False), "value": h2.get("value", "")}
                })

        return comparison

    def generate_report(self, url: str) -> str:
        """
        生成文本格式的评分报告

        Args:
            url: 目标URL

        Returns:
            格式化的报告文本
        """
        result = self.analyze(url)

        if not result.get("success"):
            return f"分析失败: {result.get('error', '未知错误')}"

        lines = [
            "=" * 60,
            "安全头评分报告",
            "=" * 60,
            f"URL: {url}",
            f"评分: {result['score']}/{result['max_score']} ({result['percentage']}%)",
            f"等级: {result['grade']} - {result['grade_description']}",
            "",
            "-" * 60,
            "详细分析:",
            "-" * 60,
        ]

        for header in result["headers"]:
            status = "✓" if header["present"] else "✗"
            score_str = f"{header['score']}/{header['max_score']}"
            lines.append(f"{status} {header['name']}: {score_str}")
            if header["value"]:
                lines.append(f"   值: {header['value'][:50]}...")
            if header["issues"]:
                for issue in header["issues"]:
                    lines.append(f"   ⚠ {issue}")

        if result["dangerous_headers"]:
            lines.extend(["", "-" * 60, "危险头:", "-" * 60])
            for dh in result["dangerous_headers"]:
                lines.append(f"⚠ {dh['name']}: {dh['value']}")
                lines.append(f"  风险: {dh['risk']}")

        if result["recommendations"]:
            lines.extend(["", "-" * 60, "建议:", "-" * 60])
            for i, rec in enumerate(result["recommendations"], 1):
                lines.append(f"{i}. {rec}")

        lines.append("=" * 60)

        return "\n".join(lines)


# 便捷函数
def quick_header_scan(url: str) -> Dict[str, Any]:
    """快速安全头扫描"""
    scorer = SecurityHeadersScorer()
    return scorer.analyze(url)


def get_header_grade(url: str) -> Tuple[str, int]:
    """获取安全头评级"""
    scorer = SecurityHeadersScorer()
    result = scorer.analyze(url)
    return result.get("grade", "F"), result.get("score", 0)


if __name__ == "__main__":
    # 测试示例
    test_url = "https://example.com"

    scorer = SecurityHeadersScorer()

    # 分析
    result = scorer.analyze(test_url)
    print(f"Score: {result.get('score')}/{result.get('max_score')}")
    print(f"Grade: {result.get('grade')}")

    # 生成报告
    # report = scorer.generate_report(test_url)
    # print(report)
