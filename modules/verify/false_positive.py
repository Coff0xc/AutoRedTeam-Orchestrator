"""
False Positive Filter - 误报过滤模块
AI驱动的漏洞验证和误报剔除
"""

import re
import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class VerificationResult(Enum):
    CONFIRMED = "confirmed"       # 确认漏洞
    LIKELY = "likely"            # 可能存在
    UNCERTAIN = "uncertain"      # 不确定
    FALSE_POSITIVE = "false_positive"  # 误报


@dataclass
class VerifiedFinding:
    original_id: str
    name: str
    target: str
    result: VerificationResult
    confidence: float  # 0.0 - 1.0
    reasoning: str
    evidence: Dict = None


class FalsePositiveFilter:
    """
    误报过滤器
    使用规则引擎和AI分析来验证漏洞
    """
    
    # 常见误报模式
    FP_PATTERNS = {
        "404_page": [
            r"404\s*not\s*found",
            r"page\s*(not|does not)\s*exist",
            r"resource\s*not\s*found",
        ],
        "error_page": [
            r"internal\s*server\s*error",
            r"something\s*went\s*wrong",
            r"an\s*error\s*occurred",
        ],
        "waf_block": [
            r"access\s*denied",
            r"forbidden",
            r"blocked\s*by\s*firewall",
            r"request\s*blocked",
        ],
        "static_content": [
            r"<!DOCTYPE\s+html>.*?(error|404|not found)",
            r"<html>.*?static.*?page",
        ],
        "cdn_response": [
            r"cloudflare",
            r"akamai",
            r"fastly",
            r"cdn\s*error",
        ]
    }
    
    # 漏洞确认指标
    CONFIRMATION_INDICATORS = {
        "sqli": {
            "positive": [
                r"sql\s*syntax",
                r"mysql.*?error",
                r"postgresql.*?error",
                r"ora-\d+",
                r"sqlite.*?error",
                r"unclosed\s*quotation",
                r"syntax\s*error.*?query",
            ],
            "negative": [
                r"404.*?not\s*found",
                r"no\s*results",
            ]
        },
        "xss": {
            "positive": [
                r"<script[^>]*>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
            ],
            "negative": [
                r"&lt;script",  # 转义的标签
                r"content-security-policy",
            ]
        },
        "rce": {
            "positive": [
                r"root:.*?:0:0",  # /etc/passwd
                r"uid=\d+.*?gid=\d+",  # id command
                r"windows.*?directory",
            ],
            "negative": []
        },
        "lfi": {
            "positive": [
                r"root:.*?:/bin",
                r"\[boot\s*loader\]",  # windows boot.ini
                r"for\s*16-bit\s*app",
            ],
            "negative": []
        },
        "ssrf": {
            "positive": [
                r"127\.0\.0\.1",
                r"localhost",
                r"internal",
            ],
            "negative": []
        },
        "unauth": {
            "positive": [
                r"200\s*ok",
                r"welcome",
                r"dashboard",
                r"admin",
            ],
            "negative": [
                r"401",
                r"403",
                r"login",
                r"authenticate",
            ]
        }
    }
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.verified_findings: List[VerifiedFinding] = []
    
    def verify(self, finding_id: str, name: str, target: str, 
               evidence: str, vuln_type: str = None) -> VerifiedFinding:
        """
        验证单个漏洞发现
        
        Args:
            finding_id: 漏洞ID
            name: 漏洞名称
            target: 目标
            evidence: 证据(响应内容等)
            vuln_type: 漏洞类型
        """
        evidence_lower = evidence.lower() if evidence else ""
        
        # 检查是否为明显误报
        fp_score, fp_reason = self._check_false_positive(evidence_lower)
        
        if fp_score > 0.7:
            result = VerifiedFinding(
                original_id=finding_id,
                name=name,
                target=target,
                result=VerificationResult.FALSE_POSITIVE,
                confidence=fp_score,
                reasoning=fp_reason
            )
            self.verified_findings.append(result)
            return result
        
        # 根据漏洞类型进行特定验证
        vuln_type = self._detect_vuln_type(name) if not vuln_type else vuln_type
        confirm_score, confirm_reason = self._check_confirmation(evidence_lower, vuln_type)
        
        # 综合判断
        if confirm_score > 0.8:
            result_type = VerificationResult.CONFIRMED
            confidence = confirm_score
            reasoning = confirm_reason
        elif confirm_score > 0.5:
            result_type = VerificationResult.LIKELY
            confidence = confirm_score
            reasoning = confirm_reason
        elif fp_score > 0.3:
            result_type = VerificationResult.FALSE_POSITIVE
            confidence = 1 - confirm_score
            reasoning = fp_reason
        else:
            result_type = VerificationResult.UNCERTAIN
            confidence = 0.5
            reasoning = "Unable to determine, manual verification recommended"
        
        result = VerifiedFinding(
            original_id=finding_id,
            name=name,
            target=target,
            result=result_type,
            confidence=confidence,
            reasoning=reasoning,
            evidence={"raw_length": len(evidence) if evidence else 0}
        )
        
        self.verified_findings.append(result)
        logger.info(f"Verified {finding_id}: {result_type.value} (conf: {confidence:.2f})")
        
        return result

    def _check_false_positive(self, evidence: str) -> Tuple[float, str]:
        """检查误报指标"""
        max_score = 0.0
        matched_pattern = ""
        
        for category, patterns in self.FP_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, evidence, re.IGNORECASE | re.DOTALL):
                    score = 0.8 if category in ["404_page", "waf_block"] else 0.6
                    if score > max_score:
                        max_score = score
                        matched_pattern = f"{category}: {pattern}"
        
        return max_score, f"Matched FP pattern: {matched_pattern}" if matched_pattern else ""

    def _check_confirmation(self, evidence: str, vuln_type: str) -> Tuple[float, str]:
        """检查漏洞确认指标"""
        if vuln_type not in self.CONFIRMATION_INDICATORS:
            return 0.5, "No specific indicators for this vulnerability type"
        
        indicators = self.CONFIRMATION_INDICATORS[vuln_type]
        positive_matches = 0
        negative_matches = 0
        matched_indicators = []
        
        for pattern in indicators.get("positive", []):
            if re.search(pattern, evidence, re.IGNORECASE):
                positive_matches += 1
                matched_indicators.append(f"+{pattern}")
        
        for pattern in indicators.get("negative", []):
            if re.search(pattern, evidence, re.IGNORECASE):
                negative_matches += 1
                matched_indicators.append(f"-{pattern}")
        
        if positive_matches > 0 and negative_matches == 0:
            score = min(0.5 + (positive_matches * 0.15), 0.95)
        elif positive_matches > negative_matches:
            score = 0.5 + ((positive_matches - negative_matches) * 0.1)
        elif negative_matches > 0:
            score = max(0.3 - (negative_matches * 0.1), 0.1)
        else:
            score = 0.5
        
        reasoning = f"Indicators: {', '.join(matched_indicators)}" if matched_indicators else "No indicators matched"
        return score, reasoning

    def _detect_vuln_type(self, name: str) -> str:
        """从漏洞名称推断类型"""
        name_lower = name.lower()
        
        type_keywords = {
            "sqli": ["sql", "injection", "sqli"],
            "xss": ["xss", "cross-site", "scripting"],
            "rce": ["rce", "command", "exec", "remote code"],
            "lfi": ["lfi", "local file", "path traversal", "directory traversal"],
            "ssrf": ["ssrf", "server-side request"],
            "unauth": ["unauth", "unauthorized", "bypass", "disclosure"],
        }
        
        for vuln_type, keywords in type_keywords.items():
            if any(kw in name_lower for kw in keywords):
                return vuln_type
        
        return "unknown"

    def batch_verify(self, findings: List[Dict]) -> List[VerifiedFinding]:
        """批量验证漏洞"""
        results = []
        
        for finding in findings:
            result = self.verify(
                finding_id=finding.get("id", "unknown"),
                name=finding.get("name", "Unknown"),
                target=finding.get("target", ""),
                evidence=finding.get("evidence", ""),
                vuln_type=finding.get("type")
            )
            results.append(result)
        
        return results

    def get_confirmed_findings(self) -> List[VerifiedFinding]:
        """获取已确认的漏洞"""
        return [f for f in self.verified_findings 
                if f.result in [VerificationResult.CONFIRMED, VerificationResult.LIKELY]]

    def get_statistics(self) -> Dict[str, int]:
        """获取验证统计"""
        stats = {r.value: 0 for r in VerificationResult}
        for finding in self.verified_findings:
            stats[finding.result.value] += 1
        return stats

    def generate_report(self) -> Dict:
        """生成验证报告"""
        stats = self.get_statistics()
        confirmed = self.get_confirmed_findings()
        
        return {
            "summary": {
                "total_verified": len(self.verified_findings),
                "confirmed": stats[VerificationResult.CONFIRMED.value],
                "likely": stats[VerificationResult.LIKELY.value],
                "uncertain": stats[VerificationResult.UNCERTAIN.value],
                "false_positives": stats[VerificationResult.FALSE_POSITIVE.value],
                "fp_rate": stats[VerificationResult.FALSE_POSITIVE.value] / len(self.verified_findings) 
                          if self.verified_findings else 0
            },
            "confirmed_findings": [
                {
                    "id": f.original_id,
                    "name": f.name,
                    "target": f.target,
                    "confidence": f.confidence,
                    "reasoning": f.reasoning
                }
                for f in confirmed
            ]
        }
