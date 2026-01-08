#!/usr/bin/env python3
"""
StandardReconEngine - 标准侦察引擎

整合 auto_recon.py 和 full_recon_engine.py 的功能，提供完整的10阶段侦察。

使用方式：
    engine = StandardReconEngine("https://example.com")
    result = engine.run()
    print(result.to_dict())
"""

import re
import json
import socket
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import (
    BaseReconEngine, ReconPhase, ReconResult, Asset, Finding, Severity
)


# 常用字典
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

COMMON_DIRS = [
    "admin", "login", "wp-admin", "phpmyadmin", "backup", ".git", ".env",
    "api", "v1", "v2", "config", "upload", "uploads", "files", "static",
    "console", "dashboard", "manager", "swagger", "graphql", "actuator"
]

SENSITIVE_FILES = [
    ".git/config", ".git/HEAD", ".env", ".env.local", "web.config",
    "wp-config.php", "config.php", "robots.txt", "sitemap.xml",
    "phpinfo.php", "backup.sql", "dump.sql", ".DS_Store",
    "actuator/env", "actuator/health", "swagger.json", "swagger-ui.html",
    "main.js.map", "app.js.map", "bundle.js.map"
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "test", "staging", "admin",
    "portal", "vpn", "m", "mobile", "static", "cdn", "img", "assets",
    "git", "jenkins", "ci", "db", "mysql", "redis", "auth", "sso"
]

# 技术栈指纹
TECH_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "Spring": ["JSESSIONID", "spring", "actuator"],
    "Express": ["X-Powered-By: Express"],
    "Nginx": ["nginx"],
    "Apache": ["Apache", "mod_"],
    "React": ["react", "_next", "__NEXT_DATA__"],
    "Vue": ["vue", "__vue__"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
}


class StandardReconEngine(BaseReconEngine):
    """标准侦察引擎 - 10阶段完整侦察"""

    def __init__(self, target: str, verify_ssl: bool = True, timeout: int = 10,
                 max_threads: int = 10, quick_mode: bool = False):
        """初始化标准侦察引擎

        Args:
            target: 目标URL或域名
            verify_ssl: 是否验证SSL证书
            timeout: 请求超时时间
            max_threads: 最大并发线程数
            quick_mode: 快速模式 (跳过耗时扫描)
        """
        super().__init__(target, verify_ssl, timeout)
        self.max_threads = max_threads
        self.quick_mode = quick_mode

        # 解析目标信息
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        self.hostname = parsed.hostname or ""
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    def get_phases(self) -> List[ReconPhase]:
        """获取支持的扫描阶段"""
        return [
            ReconPhase.BASIC_INFO,
            ReconPhase.PORT_SCAN,
            ReconPhase.SUBDOMAIN,
            ReconPhase.FINGERPRINT,
            ReconPhase.DIRECTORY,
            ReconPhase.JS_ANALYSIS,
            ReconPhase.SENSITIVE,
            ReconPhase.VULN_SCAN,
            ReconPhase.WAF_DETECT,
            ReconPhase.REPORT
        ]

    def run(self) -> ReconResult:
        """执行完整侦察"""
        try:
            # 1/10 基础信息
            self._report_progress(ReconPhase.BASIC_INFO, 10, "收集基础信息")
            self._basic_info()

            # 2/10 端口扫描
            self._report_progress(ReconPhase.PORT_SCAN, 20, "扫描常用端口")
            self._port_scan()

            # 3/10 子域名 (快速模式跳过)
            if not self.quick_mode:
                self._report_progress(ReconPhase.SUBDOMAIN, 30, "枚举子域名")
                self._subdomain_enum()

            # 4/10 Web指纹
            self._report_progress(ReconPhase.FINGERPRINT, 40, "识别技术栈")
            self._web_fingerprint()

            # 5/10 目录扫描
            self._report_progress(ReconPhase.DIRECTORY, 50, "扫描目录")
            self._directory_scan()

            # 6/10 JS分析 (快速模式跳过)
            if not self.quick_mode:
                self._report_progress(ReconPhase.JS_ANALYSIS, 60, "分析JS文件")
                self._js_analysis()

            # 7/10 敏感文件
            self._report_progress(ReconPhase.SENSITIVE, 70, "探测敏感文件")
            self._sensitive_files()

            # 8/10 漏洞检测
            self._report_progress(ReconPhase.VULN_SCAN, 80, "检测漏洞")
            self._vulnerability_scan()

            # 9/10 WAF检测
            self._report_progress(ReconPhase.WAF_DETECT, 90, "检测WAF")
            self._waf_detection()

            # 10/10 生成报告
            self._report_progress(ReconPhase.REPORT, 100, "生成报告")
            self._finalize()

            self.result.status = "completed"
        except Exception as e:
            self.result.status = "error"
            self._add_finding(Finding(
                type="error",
                severity=Severity.INFO,
                title="扫描错误",
                description=str(e)
            ))
        finally:
            self.result.end_time = datetime.now().isoformat()

        return self.result

    # ========== 阶段1: 基础信息 ==========
    def _basic_info(self):
        """收集基础信息"""
        # 解析IP
        ip = self._resolve_ip(self.hostname)
        if ip:
            self.result.asset.ip = ip
            self._add_finding(Finding(
                type="info",
                severity=Severity.INFO,
                title="IP地址",
                description=f"目标解析到 {ip}"
            ))

        # HTTP探测
        resp = self._make_request(self.target)
        if resp.get("success"):
            self.result.raw_data["http_response"] = {
                "status": resp["status"],
                "headers": resp["headers"]
            }
            # 提取Server头
            server = resp["headers"].get("Server", "")
            if server:
                self.result.asset.technologies["server"] = server

    # ========== 阶段2: 端口扫描 ==========
    def _port_scan(self):
        """扫描常用端口"""
        if not self.result.asset.ip:
            return

        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, self.result.asset.ip, port): port
                       for port in COMMON_PORTS}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass

        self.result.asset.ports = sorted(open_ports)
        if open_ports:
            self._add_finding(Finding(
                type="port",
                severity=Severity.INFO,
                title="开放端口",
                description=f"发现 {len(open_ports)} 个开放端口: {open_ports}"
            ))

    # ========== 阶段3: 子域名枚举 ==========
    def _subdomain_enum(self):
        """枚举子域名"""
        # 提取主域名
        parts = self.hostname.split('.')
        if len(parts) >= 2:
            domain = '.'.join(parts[-2:])
        else:
            return

        found = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}
            for sub in COMMON_SUBDOMAINS:
                subdomain = f"{sub}.{domain}"
                futures[executor.submit(self._resolve_ip, subdomain)] = subdomain

            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    ip = future.result()
                    if ip:
                        found.append(subdomain)
                except Exception:
                    pass

        self.result.asset.subdomains = found
        if found:
            self._add_finding(Finding(
                type="subdomain",
                severity=Severity.INFO,
                title="子域名发现",
                description=f"发现 {len(found)} 个子域名",
                evidence=", ".join(found[:10])
            ))

    # ========== 阶段4: Web指纹识别 ==========
    def _web_fingerprint(self):
        """识别Web技术栈"""
        resp = self._make_request(self.target)
        if not resp.get("success"):
            return

        body = resp.get("body", "")
        headers_str = str(resp.get("headers", {}))
        combined = body + headers_str

        detected = {}
        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined.lower():
                    detected[tech] = sig
                    break

        self.result.asset.technologies.update(detected)
        if detected:
            self._add_finding(Finding(
                type="technology",
                severity=Severity.INFO,
                title="技术栈识别",
                description=f"检测到: {', '.join(detected.keys())}"
            ))

        # 识别CMS
        cms_patterns = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["Drupal", "sites/default"],
            "Joomla": ["Joomla", "/administrator/"],
            "ThinkPHP": ["ThinkPHP", "thinkphp"],
            "Spring Boot": ["Whitelabel Error", "actuator"],
        }
        for cms, patterns in cms_patterns.items():
            if any(p.lower() in combined.lower() for p in patterns):
                self.result.asset.cms = cms
                break

    # ========== 阶段5: 目录扫描 ==========
    def _directory_scan(self):
        """扫描目录"""
        found = []

        def check_dir(path):
            url = f"{self.base_url}/{path}"
            resp = self._make_request(url, method="HEAD")
            if resp.get("status") in [200, 301, 302, 403]:
                return (path, resp.get("status"))
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(check_dir, d): d for d in COMMON_DIRS}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found.append(result)
                except Exception:
                    pass

        if found:
            self._add_finding(Finding(
                type="directory",
                severity=Severity.LOW,
                title="目录发现",
                description=f"发现 {len(found)} 个目录",
                evidence=str(found[:10])
            ))

    # ========== 阶段6: JS文件分析 ==========
    def _js_analysis(self):
        """分析JS文件"""
        resp = self._make_request(self.target)
        if not resp.get("success"):
            return

        body = resp.get("body", "")

        # 提取JS文件
        js_pattern = r'src=["\']([^"\']*\.js[^"\']*)["\']'
        js_files = list(set(re.findall(js_pattern, body)))[:20]
        self.result.asset.js_files = js_files

        # 提取API端点
        api_pattern = r'["\']/(api|v1|v2|graphql)[^"\']*["\']'
        apis = list(set(re.findall(api_pattern, body)))[:20]
        self.result.asset.api_endpoints = [f"/{a}" for a in apis]

        # 检查敏感信息
        sensitive_patterns = [
            (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', "API Key"),
            (r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Secret"),
            (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']', "Password"),
        ]
        for pattern, name in sensitive_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                self._add_finding(Finding(
                    type="sensitive_info",
                    severity=Severity.HIGH,
                    title=f"JS中发现{name}",
                    description=f"在前端代码中发现可能的{name}",
                    evidence=matches[0][:50] + "..." if len(matches[0]) > 50 else matches[0],
                    recommendation="检查是否为硬编码的敏感凭证"
                ))

    # ========== 阶段7: 敏感文件探测 ==========
    def _sensitive_files(self):
        """探测敏感文件"""
        found = []

        def check_file(path):
            url = f"{self.base_url}/{path}"
            resp = self._make_request(url)
            if resp.get("status") == 200 and len(resp.get("body", "")) > 10:
                # 排除404页面伪装
                body = resp.get("body", "")
                if "404" not in body[:200] and "not found" not in body.lower()[:200]:
                    return (path, len(body))
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(check_file, f): f for f in SENSITIVE_FILES}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found.append(result)
                except Exception:
                    pass

        self.result.asset.sensitive_files = [f[0] for f in found]

        for path, size in found:
            severity = Severity.HIGH if any(x in path for x in [".env", "config", ".git", "backup"]) else Severity.MEDIUM
            self._add_finding(Finding(
                type="sensitive_file",
                severity=severity,
                title=f"敏感文件: {path}",
                description=f"发现敏感文件 (大小: {size} bytes)",
                url=f"{self.base_url}/{path}",
                recommendation="确认文件是否应该对外公开，建议限制访问"
            ))

    # ========== 阶段8: 漏洞检测 ==========
    def _vulnerability_scan(self):
        """基础漏洞检测"""
        # 检测常见安全头缺失
        resp = self._make_request(self.target)
        if resp.get("success"):
            headers = resp.get("headers", {})
            security_headers = [
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY/SAMEORIGIN"),
                ("X-XSS-Protection", "1"),
                ("Content-Security-Policy", "CSP"),
                ("Strict-Transport-Security", "HSTS"),
            ]
            missing = []
            for header, desc in security_headers:
                if header not in headers:
                    missing.append(f"{header} ({desc})")

            if missing:
                self._add_finding(Finding(
                    type="security_header",
                    severity=Severity.LOW,
                    title="缺失安全头",
                    description=f"缺少 {len(missing)} 个安全响应头",
                    evidence=", ".join(missing[:3]),
                    recommendation="配置缺失的安全响应头以增强安全性"
                ))

        # 简单SQLi检测
        test_url = f"{self.target}?id=1'"
        sqli_resp = self._make_request(test_url)
        if sqli_resp.get("success"):
            body = sqli_resp.get("body", "").lower()
            sqli_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "oracle", "syntax error"]
            if any(err in body for err in sqli_errors):
                self._add_finding(Finding(
                    type="sqli",
                    severity=Severity.CRITICAL,
                    title="潜在SQL注入",
                    description="检测到SQL错误信息泄露，可能存在SQL注入",
                    url=test_url,
                    recommendation="使用参数化查询，避免直接拼接SQL"
                ))

    # ========== 阶段9: WAF检测 ==========
    def _waf_detection(self):
        """检测WAF"""
        waf_payload = "<script>alert(1)</script>"
        test_url = f"{self.target}?test={waf_payload}"
        resp = self._make_request(test_url)

        waf_signatures = {
            "Cloudflare": ["cloudflare", "__cf_bm", "cf-ray"],
            "AWS WAF": ["awswaf", "x-amzn-requestid"],
            "Akamai": ["akamai", "ak_bmsc"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "阿里云WAF": ["aliyun", "ali-cdn"],
            "腾讯云WAF": ["tencent", "qcloud"],
        }

        headers_str = str(resp.get("headers", {})).lower()
        body = resp.get("body", "").lower()
        combined = headers_str + body

        for waf, sigs in waf_signatures.items():
            if any(sig in combined for sig in sigs):
                self.result.asset.waf = waf
                self._add_finding(Finding(
                    type="waf",
                    severity=Severity.INFO,
                    title="WAF检测",
                    description=f"检测到 {waf}",
                    recommendation="存在WAF可能影响漏洞扫描结果"
                ))
                break

        # 检查是否被拦截
        if resp.get("status") in [403, 406, 429, 503]:
            if not self.result.asset.waf:
                self.result.asset.waf = "Unknown WAF"
                self._add_finding(Finding(
                    type="waf",
                    severity=Severity.INFO,
                    title="可能存在WAF",
                    description=f"请求被拦截 (状态码: {resp.get('status')})"
                ))

    # ========== 阶段10: 完成 ==========
    def _finalize(self):
        """生成最终报告"""
        self.result.current_phase = ReconPhase.COMPLETE

        # 生成风险摘要
        critical = sum(1 for f in self.result.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.result.findings if f.severity == Severity.HIGH)

        if critical > 0:
            risk_level = "严重"
        elif high > 0:
            risk_level = "高危"
        elif len(self.result.findings) > 5:
            risk_level = "中危"
        else:
            risk_level = "低危"

        self.result.raw_data["risk_level"] = risk_level
        self.result.raw_data["scan_duration"] = self._calculate_duration()

    def _calculate_duration(self) -> str:
        """计算扫描耗时"""
        try:
            start = datetime.fromisoformat(self.result.start_time)
            end = datetime.now()
            duration = (end - start).total_seconds()
            return f"{duration:.1f}s"
        except Exception:
            return "N/A"
