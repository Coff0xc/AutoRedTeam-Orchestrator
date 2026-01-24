#!/usr/bin/env python3
"""
AutoRedTeam-Orchestrator MCP Server
AI驱动的自动化渗透测试框架 - MCP协议服务端

版本: 3.0.0
作者: AutoRedTeam Team
许可: 仅限授权安全测试使用

功能:
    - 130+ 纯Python安全工具
    - 覆盖 OWASP Top 10、API安全、供应链安全、云原生安全
    - 支持 Claude Code / Cursor / Windsurf / Kiro 等AI编辑器
"""

from __future__ import annotations

import sys
import os
import asyncio
import logging
import traceback
from typing import Any, Dict, List, Optional, Union

# 确保项目根目录在路径中
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from mcp.server.fastmcp import FastMCP


# ==================== 日志配置 ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("AutoRedTeam")


# ==================== MCP服务器实例 ====================

mcp = FastMCP(
    "AutoRedTeam",
    version="3.0.0",
    description="AI驱动的自动化渗透测试框架 - 130+ 安全工具"
)


# ==================== 工具计数器 ====================

class ToolCounter:
    """工具注册计数器"""

    def __init__(self):
        self.counts = {
            'recon': 0,
            'detector': 0,
            'cve': 0,
            'redteam': 0,
            'api_security': 0,
            'cloud_security': 0,
            'supply_chain': 0,
            'session': 0,
            'report': 0,
            'ai': 0,
            'misc': 0,
        }
        self.total = 0

    def add(self, category: str, count: int = 1):
        if category in self.counts:
            self.counts[category] += count
        else:
            self.counts['misc'] += count
        self.total += count

    def summary(self) -> str:
        parts = [f"{k}={v}" for k, v in self.counts.items() if v > 0]
        return f"总计 {self.total} 个工具 ({', '.join(parts)})"


_counter = ToolCounter()


# ==================== 侦察工具 ====================

def _register_recon_tools():
    """注册侦察相关工具"""

    @mcp.tool()
    async def full_recon(target: str, quick_mode: bool = False) -> Dict[str, Any]:
        """完整侦察扫描 - 执行全面的目标信息收集

        包含: DNS解析、端口扫描、指纹识别、技术栈检测、WAF检测、子域名枚举、目录扫描

        Args:
            target: 目标URL或域名 (例: https://example.com)
            quick_mode: 是否快速模式 (跳过耗时的子域名和目录扫描)

        Returns:
            包含所有侦察结果的字典
        """
        try:
            from core.recon import StandardReconEngine, ReconConfig

            config = ReconConfig(quick_mode=quick_mode)
            engine = StandardReconEngine(target, config)
            result = engine.run()

            return {
                'success': True,
                'target': target,
                'data': result.to_dict()
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def port_scan(target: str, ports: str = "1-1000", timeout: float = 2.0) -> Dict[str, Any]:
        """端口扫描 - 探测目标开放端口和服务

        Args:
            target: 目标IP或主机名
            ports: 端口范围 (例: "1-1000", "22,80,443,8080", "top100")
            timeout: 单端口超时时间(秒)

        Returns:
            开放端口列表和服务信息
        """
        try:
            from core.recon import PortScanner, async_scan_ports

            results = await async_scan_ports(target, ports, timeout=timeout)

            open_ports = [
                {
                    'port': r.port,
                    'state': r.state,
                    'service': r.service,
                    'version': r.version
                }
                for r in results if r.state == 'open'
            ]

            return {
                'success': True,
                'target': target,
                'open_ports': open_ports,
                'total_scanned': len(results),
                'total_open': len(open_ports)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def fingerprint(url: str) -> Dict[str, Any]:
        """Web指纹识别 - 识别目标Web应用的技术栈

        检测: 服务器、Web框架、CMS系统、JS库、CDN等

        Args:
            url: 目标URL

        Returns:
            指纹信息列表
        """
        try:
            from core.recon import FingerprintEngine, identify_fingerprints

            results = identify_fingerprints(url)

            return {
                'success': True,
                'url': url,
                'fingerprints': [
                    {
                        'name': f.name,
                        'category': f.category.value if hasattr(f.category, 'value') else str(f.category),
                        'version': f.version,
                        'confidence': f.confidence
                    }
                    for f in results
                ],
                'count': len(results)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def subdomain_enum(domain: str, methods: List[str] = None, limit: int = 100) -> Dict[str, Any]:
        """子域名枚举 - 发现目标域名的子域名

        支持: DNS爆破、证书透明度、搜索引擎等多种方式

        Args:
            domain: 目标域名 (例: example.com)
            methods: 枚举方式列表 (默认全部)
            limit: 最大返回数量

        Returns:
            子域名列表
        """
        try:
            from core.recon import SubdomainEnumerator, async_enumerate_subdomains

            results = await async_enumerate_subdomains(domain, methods=methods)

            subdomains = [
                {
                    'subdomain': r.subdomain,
                    'ip': r.ip,
                    'source': r.source
                }
                for r in results[:limit]
            ]

            return {
                'success': True,
                'domain': domain,
                'subdomains': subdomains,
                'count': len(subdomains)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'domain': domain}

    @mcp.tool()
    async def dir_scan(url: str, wordlist: str = "common", extensions: List[str] = None) -> Dict[str, Any]:
        """目录扫描 - 发现Web应用的隐藏路径

        Args:
            url: 目标URL
            wordlist: 字典名称 (common, large, api)
            extensions: 要测试的扩展名列表 (例: [".php", ".bak"])

        Returns:
            发现的路径列表
        """
        try:
            from core.recon import DirectoryScanner, async_scan_directories

            results = await async_scan_directories(url, wordlist=wordlist, extensions=extensions)

            directories = [
                {
                    'path': r.path,
                    'status_code': r.status_code,
                    'content_length': r.content_length,
                    'redirect': r.redirect_url
                }
                for r in results if r.status_code in [200, 301, 302, 403]
            ]

            return {
                'success': True,
                'url': url,
                'directories': directories,
                'count': len(directories)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def dns_lookup(domain: str, record_types: List[str] = None) -> Dict[str, Any]:
        """DNS查询 - 获取域名的DNS记录

        Args:
            domain: 目标域名
            record_types: 记录类型列表 (默认: A, AAAA, CNAME, MX, NS, TXT)

        Returns:
            DNS记录信息
        """
        try:
            from core.recon import DNSResolver, get_dns_records

            results = get_dns_records(domain, record_types=record_types)

            return {
                'success': True,
                'domain': domain,
                'records': results.to_dict() if hasattr(results, 'to_dict') else results
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'domain': domain}

    @mcp.tool()
    async def tech_detect(url: str) -> Dict[str, Any]:
        """技术栈检测 - 识别网站使用的技术

        Args:
            url: 目标URL

        Returns:
            检测到的技术列表
        """
        try:
            from core.recon import TechDetector, detect_technologies

            results = detect_technologies(url)

            return {
                'success': True,
                'url': url,
                'technologies': [
                    {
                        'name': t.name,
                        'category': t.category,
                        'version': t.version,
                        'confidence': t.confidence
                    }
                    for t in results
                ]
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def waf_detect(url: str) -> Dict[str, Any]:
        """WAF检测 - 识别目标是否有Web应用防火墙

        Args:
            url: 目标URL

        Returns:
            WAF检测结果
        """
        try:
            from core.recon import WAFDetector, detect_waf

            result = detect_waf(url)

            return {
                'success': True,
                'url': url,
                'waf_detected': result.detected if hasattr(result, 'detected') else bool(result),
                'waf_name': result.name if hasattr(result, 'name') else None,
                'confidence': result.confidence if hasattr(result, 'confidence') else None
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    _counter.add('recon', 8)
    logger.info("[Recon] 已注册 8 个侦察工具")


# ==================== 漏洞检测工具 ====================

def _register_detector_tools():
    """注册漏洞检测工具"""

    @mcp.tool()
    async def vuln_scan(
        url: str,
        params: Dict[str, str] = None,
        detectors: List[str] = None
    ) -> Dict[str, Any]:
        """综合漏洞扫描 - 检测多种Web漏洞

        支持: SQL注入、XSS、命令注入、SSRF、路径遍历、XXE等

        Args:
            url: 目标URL
            params: 请求参数 (例: {"id": "1", "name": "test"})
            detectors: 要使用的检测器 (默认: sqli, xss, rce, ssrf, path_traversal)

        Returns:
            发现的漏洞列表
        """
        try:
            from core.detectors import DetectorFactory, DetectorPresets

            if detectors:
                composite = DetectorFactory.create_composite(detectors)
            else:
                composite = DetectorPresets.owasp_top10()

            results = await composite.async_detect(url, params=params or {})

            vulnerabilities = [
                {
                    'type': r.vuln_type,
                    'severity': r.severity.value,
                    'param': r.param,
                    'payload': r.payload,
                    'evidence': r.evidence[:200] if r.evidence else None,
                    'remediation': r.remediation
                }
                for r in results if r.vulnerable
            ]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulnerabilities,
                'total_vulns': len(vulnerabilities),
                'detectors_used': detectors or ['owasp_top10']
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def sqli_scan(url: str, params: Dict[str, str] = None, method: str = "GET") -> Dict[str, Any]:
        """SQL注入检测 - 检测SQL注入漏洞

        支持: 基于错误、布尔盲注、时间盲注、联合注入

        Args:
            url: 目标URL
            params: 请求参数
            method: HTTP方法 (GET/POST)

        Returns:
            SQL注入检测结果
        """
        try:
            from core.detectors import SQLiDetector

            detector = SQLiDetector()
            results = await detector.async_detect(url, params=params or {}, method=method)

            findings = [
                {
                    'param': r.param,
                    'payload': r.payload,
                    'type': r.injection_type if hasattr(r, 'injection_type') else 'unknown',
                    'evidence': r.evidence[:200] if r.evidence else None
                }
                for r in results if r.vulnerable
            ]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def xss_scan(url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """XSS漏洞检测 - 检测跨站脚本攻击漏洞

        支持: 反射型XSS、存储型XSS、DOM型XSS

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            XSS检测结果
        """
        try:
            from core.detectors import XSSDetector

            detector = XSSDetector()
            results = await detector.async_detect(url, params=params or {})

            findings = [
                {
                    'param': r.param,
                    'payload': r.payload,
                    'context': r.context if hasattr(r, 'context') else None,
                    'evidence': r.evidence[:200] if r.evidence else None
                }
                for r in results if r.vulnerable
            ]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def ssrf_scan(url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """SSRF漏洞检测 - 检测服务端请求伪造漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            SSRF检测结果
        """
        try:
            from core.detectors import SSRFDetector

            detector = SSRFDetector()
            results = await detector.async_detect(url, params=params or {})

            findings = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def rce_scan(url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """命令注入检测 - 检测远程命令执行漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            RCE检测结果
        """
        try:
            from core.detectors import RCEDetector

            detector = RCEDetector()
            results = await detector.async_detect(url, params=params or {})

            findings = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def path_traversal_scan(url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """路径遍历检测 - 检测目录遍历/LFI漏洞

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            路径遍历检测结果
        """
        try:
            from core.detectors import PathTraversalDetector

            detector = PathTraversalDetector()
            results = await detector.async_detect(url, params=params or {})

            findings = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def ssti_scan(url: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """模板注入检测 - 检测服务端模板注入漏洞

        支持: Jinja2, Twig, Freemarker, Velocity等模板引擎

        Args:
            url: 目标URL
            params: 请求参数

        Returns:
            SSTI检测结果
        """
        try:
            from core.detectors import SSTIDetector

            detector = SSTIDetector()
            results = await detector.async_detect(url, params=params or {})

            findings = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def xxe_scan(url: str, content_type: str = "application/xml") -> Dict[str, Any]:
        """XXE漏洞检测 - 检测XML外部实体注入漏洞

        Args:
            url: 目标URL (接受XML输入的端点)
            content_type: Content-Type头

        Returns:
            XXE检测结果
        """
        try:
            from core.detectors import XXEDetector

            detector = XXEDetector()
            results = await detector.async_detect(url, content_type=content_type)

            findings = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def idor_scan(url: str, id_param: str = "id", test_ids: List[str] = None) -> Dict[str, Any]:
        """IDOR漏洞检测 - 检测不安全的直接对象引用

        Args:
            url: 目标URL
            id_param: ID参数名
            test_ids: 要测试的ID列表

        Returns:
            IDOR检测结果
        """
        try:
            from core.detectors import IDORDetector

            detector = IDORDetector()
            results = await detector.async_detect(url, id_param=id_param, test_ids=test_ids)

            findings = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def cors_scan(url: str) -> Dict[str, Any]:
        """CORS配置检测 - 检测跨域资源共享配置问题

        检测: 通配符源、凭据泄露、Origin反射等

        Args:
            url: 目标URL

        Returns:
            CORS检测结果
        """
        try:
            from core.detectors import CORSDetector

            detector = CORSDetector()
            results = await detector.async_detect(url)

            findings = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'vulnerable': len(findings) > 0,
                'url': url,
                'findings': findings
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def security_headers_scan(url: str) -> Dict[str, Any]:
        """安全头检测 - 检测HTTP安全响应头配置

        检测: CSP, X-Frame-Options, X-XSS-Protection, HSTS等

        Args:
            url: 目标URL

        Returns:
            安全头检测结果
        """
        try:
            from core.detectors import SecurityHeadersDetector

            detector = SecurityHeadersDetector()
            results = await detector.async_detect(url)

            return {
                'success': True,
                'url': url,
                'findings': [r.to_dict() for r in results]
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    _counter.add('detector', 12)
    logger.info("[Detector] 已注册 12 个漏洞检测工具")


# ==================== CVE工具 ====================

def _register_cve_tools():
    """注册CVE相关工具"""

    @mcp.tool()
    async def cve_search(
        keyword: str,
        severity: str = None,
        has_poc: bool = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """搜索CVE漏洞 - 在本地CVE数据库中搜索

        Args:
            keyword: 搜索关键词 (CVE ID或描述关键词)
            severity: 严重程度过滤 (CRITICAL, HIGH, MEDIUM, LOW)
            has_poc: 是否只返回有PoC的CVE
            limit: 最大返回数量

        Returns:
            CVE列表
        """
        try:
            from core.cve.update_manager import CVEUpdateManager

            manager = CVEUpdateManager()
            results = manager.search(
                keyword=keyword,
                severity=severity,
                poc_only=has_poc or False
            )

            cves = [
                {
                    'cve_id': r.cve_id,
                    'description': r.description[:200],
                    'severity': r.severity,
                    'cvss': r.cvss,
                    'poc_available': r.poc_available,
                    'poc_path': r.poc_path
                }
                for r in results[:limit]
            ]

            return {
                'success': True,
                'keyword': keyword,
                'cves': cves,
                'count': len(cves)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def cve_sync(days: int = 7, sources: List[str] = None) -> Dict[str, Any]:
        """同步CVE数据 - 从多个数据源同步最新CVE

        数据源: NVD (官方), Nuclei Templates, Exploit-DB

        Args:
            days: 同步最近多少天的数据
            sources: 指定数据源 (默认全部)

        Returns:
            同步结果
        """
        try:
            from core.cve.update_manager import CVEUpdateManager

            manager = CVEUpdateManager()
            results = await manager.sync_all(days_back=days)

            return {
                'success': True,
                'days': days,
                'results': {
                    source: {'new': new, 'updated': updated}
                    for source, (new, updated) in results.items()
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def cve_stats() -> Dict[str, Any]:
        """CVE数据库统计 - 获取本地CVE数据库统计信息

        Returns:
            统计信息
        """
        try:
            from core.cve.update_manager import CVEUpdateManager

            manager = CVEUpdateManager()
            stats = manager.get_stats()

            return {
                'success': True,
                'stats': stats
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def poc_execute(target: str, template_id: str, variables: Dict[str, str] = None) -> Dict[str, Any]:
        """执行PoC验证 - 使用PoC模板验证目标漏洞

        Args:
            target: 目标URL
            template_id: PoC模板ID
            variables: 自定义变量

        Returns:
            执行结果
        """
        try:
            from core.cve.poc_engine import get_poc_engine

            engine = get_poc_engine()
            template = engine.get_template(template_id)

            if not template:
                return {
                    'success': False,
                    'error': f'模板不存在: {template_id}',
                    'available_templates': engine.list_templates()[:10]
                }

            result = engine.execute(target, template, variables)

            return {
                'success': result.success,
                'vulnerable': result.vulnerable,
                'template_id': template_id,
                'target': target,
                'evidence': result.evidence,
                'extracted': result.extracted,
                'execution_time_ms': result.execution_time_ms
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def poc_list(keyword: str = None, limit: int = 50) -> Dict[str, Any]:
        """列出PoC模板 - 查看已加载的PoC模板

        Args:
            keyword: 过滤关键词
            limit: 最大返回数量

        Returns:
            PoC模板列表
        """
        try:
            from core.cve.poc_engine import get_poc_engine

            engine = get_poc_engine()
            templates = engine.list_templates()

            if keyword:
                templates = [t for t in templates if keyword.lower() in t.lower()]

            return {
                'success': True,
                'templates': templates[:limit],
                'count': len(templates[:limit])
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    _counter.add('cve', 5)
    logger.info("[CVE] 已注册 5 个CVE工具")


# ==================== API安全工具 ====================

def _register_api_security_tools():
    """注册API安全工具"""

    @mcp.tool()
    async def jwt_scan(token: str, target: str = None) -> Dict[str, Any]:
        """JWT安全扫描 - 检测JWT令牌的安全问题

        检测: None算法、弱密钥、算法混淆、KID注入等

        Args:
            token: JWT令牌
            target: 目标URL (用于验证)

        Returns:
            JWT安全问题
        """
        try:
            from modules.api_security import JWTTester, quick_jwt_test, decode_jwt

            # 先解码查看基本信息
            decoded = decode_jwt(token)

            # 执行安全测试
            if target:
                tester = JWTTester(target, token)
                results = tester.test()

                vulns = [r.to_dict() for r in results if r.vulnerable]
            else:
                vulns = quick_jwt_test(token)

            return {
                'success': True,
                'decoded': decoded,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def cors_deep_scan(url: str) -> Dict[str, Any]:
        """CORS深度扫描 - 全面检测CORS配置问题

        检测: Origin反射、子域名绕过、Null Origin、预检请求等

        Args:
            url: 目标URL

        Returns:
            CORS安全问题
        """
        try:
            from modules.api_security import CORSTester

            tester = CORSTester(url)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def graphql_scan(url: str) -> Dict[str, Any]:
        """GraphQL安全扫描 - 检测GraphQL API安全问题

        检测: 内省查询、批量查询DoS、深层嵌套、字段建议、别名滥用

        Args:
            url: GraphQL端点URL

        Returns:
            GraphQL安全问题
        """
        try:
            from modules.api_security import GraphQLTester

            tester = GraphQLTester(url)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def websocket_scan(url: str) -> Dict[str, Any]:
        """WebSocket安全扫描 - 检测WebSocket安全问题

        检测: Origin绕过、CSWSH、认证绕过、压缩攻击

        Args:
            url: WebSocket URL (ws:// 或 wss://)

        Returns:
            WebSocket安全问题
        """
        try:
            from modules.api_security import WebSocketTester

            tester = WebSocketTester(url)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def oauth_scan(url: str, client_id: str = None) -> Dict[str, Any]:
        """OAuth安全扫描 - 检测OAuth 2.0实现问题

        检测: 开放重定向、CSRF、令牌泄露、PKCE缺失

        Args:
            url: OAuth端点URL
            client_id: 客户端ID (可选)

        Returns:
            OAuth安全问题
        """
        try:
            from modules.api_security import OAuthTester

            tester = OAuthTester(url, client_id=client_id)
            results = tester.test()

            vulns = [r.to_dict() for r in results if r.vulnerable]

            return {
                'success': True,
                'url': url,
                'vulnerabilities': vulns,
                'total_issues': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def security_headers_score(url: str) -> Dict[str, Any]:
        """安全头评分 - 评估网站的安全头配置

        评分标准: CSP, HSTS, X-Frame-Options等

        Args:
            url: 目标URL

        Returns:
            安全头评分和建议
        """
        try:
            from modules.api_security import SecurityHeadersTester

            tester = SecurityHeadersTester(url)
            results = tester.test()
            summary = tester.get_summary()

            return {
                'success': True,
                'url': url,
                'score': summary.score if hasattr(summary, 'score') else 0,
                'grade': summary.grade if hasattr(summary, 'grade') else 'N/A',
                'headers': summary.to_dict() if hasattr(summary, 'to_dict') else {},
                'recommendations': [r.to_dict() for r in results]
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    @mcp.tool()
    async def full_api_scan(target: str, jwt_token: str = None) -> Dict[str, Any]:
        """完整API安全扫描 - 执行全面的API安全测试

        包含: JWT、CORS、安全头、GraphQL(如适用)

        Args:
            target: 目标URL
            jwt_token: JWT令牌 (可选)

        Returns:
            综合API安全报告
        """
        try:
            from modules.api_security import full_api_scan as _full_api_scan

            result = _full_api_scan(target, jwt_token=jwt_token)

            return {
                'success': True,
                'target': target,
                **result
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    _counter.add('api_security', 7)
    logger.info("[API Security] 已注册 7 个API安全工具")


# ==================== 云安全工具 ====================

def _register_cloud_security_tools():
    """注册云安全工具"""

    @mcp.tool()
    async def k8s_scan(manifest_path: str = None, namespace: str = "default") -> Dict[str, Any]:
        """Kubernetes安全扫描 - 检测K8s配置安全问题

        检测: 特权容器、HostPath挂载、RBAC问题、网络策略、Secrets暴露

        Args:
            manifest_path: K8s清单文件路径 (可选)
            namespace: 命名空间

        Returns:
            安全发现
        """
        try:
            from modules.cloud_security import KubernetesTester, scan_k8s_manifest

            if manifest_path:
                findings = scan_k8s_manifest(manifest_path)
            else:
                tester = KubernetesTester(config={'namespace': namespace})
                findings = tester.scan()

            return {
                'success': True,
                'findings': [f.to_dict() for f in findings],
                'critical': len([f for f in findings if f.severity.value == 'critical']),
                'high': len([f for f in findings if f.severity.value == 'high']),
                'total': len(findings)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def grpc_scan(target: str) -> Dict[str, Any]:
        """gRPC安全扫描 - 检测gRPC服务安全问题

        检测: 反射服务、TLS配置、认证问题

        Args:
            target: gRPC服务地址 (host:port)

        Returns:
            安全发现
        """
        try:
            from modules.cloud_security import GRPCTester, scan_grpc

            result = scan_grpc(target)

            return {
                'success': True,
                'target': target,
                'findings': result if isinstance(result, list) else [result]
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def aws_scan(region: str = "us-east-1", services: List[str] = None) -> Dict[str, Any]:
        """AWS安全扫描 - 检测AWS配置安全问题

        需要: 配置AWS凭证 (环境变量或~/.aws/credentials)

        Args:
            region: AWS区域
            services: 要检查的服务列表

        Returns:
            安全发现
        """
        try:
            from modules.cloud_security import AWSTester, scan_aws

            result = scan_aws(region=region, services=services)

            return {
                'success': True,
                'region': region,
                'findings': result if isinstance(result, list) else [result]
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'region': region}

    _counter.add('cloud_security', 3)
    logger.info("[Cloud Security] 已注册 3 个云安全工具")


# ==================== 供应链安全工具 ====================

def _register_supply_chain_tools():
    """注册供应链安全工具"""

    @mcp.tool()
    async def sbom_generate(project_path: str, output_format: str = "cyclonedx") -> Dict[str, Any]:
        """生成SBOM - 生成软件物料清单

        支持格式: CycloneDX, SPDX

        Args:
            project_path: 项目路径
            output_format: 输出格式 (cyclonedx, spdx)

        Returns:
            SBOM数据
        """
        try:
            from modules.supply_chain.sbom_generator import SBOMGenerator

            generator = SBOMGenerator()
            sbom = generator.generate(project_path, format=output_format)

            return {
                'success': True,
                'project': project_path,
                'format': output_format,
                'sbom': sbom if isinstance(sbom, dict) else sbom.to_dict()
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'project': project_path}

    @mcp.tool()
    async def dependency_audit(project_path: str) -> Dict[str, Any]:
        """依赖审计 - 检查项目依赖的已知漏洞

        支持: npm, pip, maven, go.mod

        Args:
            project_path: 项目路径

        Returns:
            依赖漏洞报告
        """
        try:
            from modules.supply_chain.dependency_scanner import DependencyScanner

            scanner = DependencyScanner()
            results = scanner.scan(project_path)

            return {
                'success': True,
                'project': project_path,
                'vulnerabilities': results if isinstance(results, list) else [results],
                'total': len(results) if isinstance(results, list) else 1
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'project': project_path}

    @mcp.tool()
    async def cicd_scan(config_path: str) -> Dict[str, Any]:
        """CI/CD配置扫描 - 检测CI/CD配置安全问题

        支持: GitHub Actions, GitLab CI, Jenkins

        Args:
            config_path: CI/CD配置文件路径

        Returns:
            安全发现
        """
        try:
            from modules.supply_chain.cicd_security import CICDScanner

            scanner = CICDScanner()
            findings = scanner.scan(config_path)

            return {
                'success': True,
                'config': config_path,
                'findings': findings if isinstance(findings, list) else [findings],
                'total': len(findings) if isinstance(findings, list) else 1
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'config': config_path}

    _counter.add('supply_chain', 3)
    logger.info("[Supply Chain] 已注册 3 个供应链安全工具")


# ==================== 红队工具 ====================

def _register_redteam_tools():
    """注册红队相关工具"""

    @mcp.tool()
    async def lateral_smb(
        target: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        command: str = "whoami"
    ) -> Dict[str, Any]:
        """SMB横向移动 - 通过SMB执行远程命令

        支持: 密码认证、Pass-the-Hash
        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP
            username: 用户名
            password: 密码 (与ntlm_hash二选一)
            ntlm_hash: NTLM Hash (格式: LM:NT)
            command: 要执行的命令

        Returns:
            执行结果
        """
        try:
            from core.lateral.smb_lateral import smb_exec

            result = smb_exec(
                target=target,
                username=username,
                password=password or "",
                ntlm_hash=ntlm_hash or "",
                command=command
            )

            return result
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def c2_beacon_start(
        server: str,
        port: int = 443,
        protocol: str = "https",
        interval: float = 60.0
    ) -> Dict[str, Any]:
        """启动C2 Beacon - 创建到C2服务器的Beacon连接

        警告: 仅限授权渗透测试使用！

        Args:
            server: C2服务器地址
            port: 端口
            protocol: 协议 (http, https)
            interval: 心跳间隔(秒)

        Returns:
            Beacon状态
        """
        try:
            from core.c2.beacon import create_beacon

            beacon = create_beacon(
                server=server,
                port=port,
                protocol=protocol,
                interval=interval
            )

            if beacon.connect():
                beacon.start()
                return {
                    'success': True,
                    'beacon_id': beacon.beacon_id,
                    'status': beacon.status.value,
                    'server': server
                }

            return {'success': False, 'error': 'Connection failed'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def payload_obfuscate(payload: str, technique: str = "xor") -> Dict[str, Any]:
        """Payload混淆 - 对payload进行混淆处理

        支持技术: xor, base64, aes, custom
        警告: 仅限授权渗透测试使用！

        Args:
            payload: 原始payload
            technique: 混淆技术

        Returns:
            混淆后的payload
        """
        try:
            from core.evasion.payload_obfuscator import obfuscate_payload

            result = obfuscate_payload(payload, technique=technique)

            return {
                'success': True,
                'original_length': len(payload),
                'obfuscated_length': len(result),
                'technique': technique,
                'obfuscated': result
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def credential_find(path: str = None, patterns: List[str] = None) -> Dict[str, Any]:
        """凭证发现 - 在文件中搜索敏感凭证

        搜索: API密钥、密码、令牌、私钥等
        警告: 仅限授权渗透测试使用！

        Args:
            path: 搜索路径
            patterns: 自定义搜索模式

        Returns:
            发现的凭证
        """
        try:
            from core.credential.password_finder import find_credentials

            results = find_credentials(path=path, patterns=patterns)

            return {
                'success': True,
                'path': path,
                'findings': results if isinstance(results, list) else [results],
                'total': len(results) if isinstance(results, list) else 1
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    _counter.add('redteam', 4)
    logger.info("[RedTeam] 已注册 4 个红队工具")


# ==================== 会话管理工具 ====================

def _register_session_tools():
    """注册会话管理工具"""

    @mcp.tool()
    async def session_create(target: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """创建扫描会话 - 创建新的渗透测试会话

        Args:
            target: 目标URL或IP
            config: 会话配置

        Returns:
            会话信息
        """
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            context = manager.create_session(target, config)

            return {
                'success': True,
                'session_id': context.session_id,
                'target': target,
                'status': context.status.value,
                'created_at': context.started_at.isoformat()
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def session_status(session_id: str) -> Dict[str, Any]:
        """查询会话状态 - 获取会话的当前状态

        Args:
            session_id: 会话ID

        Returns:
            会话状态
        """
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            context = manager.get_session(session_id)

            if not context:
                return {'success': False, 'error': f'会话不存在: {session_id}'}

            return {
                'success': True,
                'session_id': session_id,
                'target': context.target.url,
                'status': context.status.value,
                'phase': context.phase.value,
                'vulns_found': len(context.vulnerabilities)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def session_list(status: str = None, limit: int = 20) -> Dict[str, Any]:
        """列出会话 - 获取会话列表

        Args:
            status: 按状态过滤 (active, completed, failed)
            limit: 最大返回数量

        Returns:
            会话列表
        """
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            sessions = manager.list_sessions(status=status, limit=limit)

            return {
                'success': True,
                'sessions': [
                    {
                        'session_id': s.session_id,
                        'target': s.target.url,
                        'status': s.status.value,
                        'phase': s.phase.value
                    }
                    for s in sessions
                ],
                'count': len(sessions)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def session_complete(session_id: str) -> Dict[str, Any]:
        """完成会话 - 结束会话并生成报告

        Args:
            session_id: 会话ID

        Returns:
            扫描结果摘要
        """
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            result = manager.complete_session(session_id)

            if not result:
                return {'success': False, 'error': f'会话不存在: {session_id}'}

            return {
                'success': True,
                'session_id': session_id,
                'total_vulns': result.total_vulns,
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': result.medium_count,
                'low': result.low_count,
                'duration': result.duration
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    _counter.add('session', 4)
    logger.info("[Session] 已注册 4 个会话管理工具")


# ==================== 报告工具 ====================

def _register_report_tools():
    """注册报告生成工具"""

    @mcp.tool()
    async def generate_report(
        session_id: str,
        format: str = "json",
        output_path: str = None
    ) -> Dict[str, Any]:
        """生成渗透测试报告 - 生成详细的安全评估报告

        Args:
            session_id: 会话ID
            format: 报告格式 (json, html, markdown, pdf)
            output_path: 输出路径 (可选)

        Returns:
            报告内容或路径
        """
        try:
            from core.session import get_session_manager
            from utils.report_generator import ReportGenerator

            manager = get_session_manager()
            result = manager.get_result(session_id)

            if not result:
                return {'success': False, 'error': f'会话结果不存在: {session_id}'}

            generator = ReportGenerator()

            if format == 'json':
                report = result.to_dict()
            elif format == 'html':
                report = generator.to_html(result)
            elif format == 'markdown':
                report = generator.to_markdown(result)
            else:
                report = result.to_dict()

            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    if isinstance(report, dict):
                        import json
                        json.dump(report, f, indent=2, ensure_ascii=False)
                    else:
                        f.write(report)

                return {
                    'success': True,
                    'session_id': session_id,
                    'format': format,
                    'output_path': output_path
                }

            return {
                'success': True,
                'session_id': session_id,
                'format': format,
                'report': report
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @mcp.tool()
    async def export_findings(
        session_id: str,
        severity: str = None,
        format: str = "json"
    ) -> Dict[str, Any]:
        """导出漏洞发现 - 导出会话中发现的漏洞

        Args:
            session_id: 会话ID
            severity: 按严重程度过滤 (critical, high, medium, low)
            format: 输出格式

        Returns:
            漏洞列表
        """
        try:
            from core.session import get_session_manager

            manager = get_session_manager()
            context = manager.get_session(session_id)

            if not context:
                return {'success': False, 'error': f'会话不存在: {session_id}'}

            vulns = context.vulnerabilities

            if severity:
                vulns = [v for v in vulns if v.severity.value.lower() == severity.lower()]

            return {
                'success': True,
                'session_id': session_id,
                'vulnerabilities': [v.to_dict() for v in vulns],
                'count': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    _counter.add('report', 2)
    logger.info("[Report] 已注册 2 个报告工具")


# ==================== AI辅助工具 ====================

def _register_ai_tools():
    """注册AI辅助工具"""

    @mcp.tool()
    async def smart_analyze(target: str, context: str = None) -> Dict[str, Any]:
        """智能分析 - AI辅助分析目标并推荐测试策略

        Args:
            target: 目标URL
            context: 额外上下文信息

        Returns:
            分析结果和建议
        """
        try:
            from core.ai_engine import AIAnalyzer

            analyzer = AIAnalyzer()
            result = analyzer.analyze(target, context)

            return {
                'success': True,
                'target': target,
                'analysis': result
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def attack_chain_plan(
        target: str,
        reconnaissance_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """攻击链规划 - 基于侦察数据规划攻击链

        Args:
            target: 目标URL
            reconnaissance_data: 侦察数据 (可选)

        Returns:
            推荐的攻击链
        """
        try:
            from core.attack_chain import AttackChainPlanner

            planner = AttackChainPlanner()
            chain = planner.plan(target, recon_data=reconnaissance_data)

            return {
                'success': True,
                'target': target,
                'attack_chain': chain
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @mcp.tool()
    async def smart_payload(
        vuln_type: str,
        context: Dict[str, Any] = None,
        waf_detected: bool = False
    ) -> Dict[str, Any]:
        """智能Payload生成 - 根据上下文生成优化的payload

        Args:
            vuln_type: 漏洞类型 (sqli, xss, rce, ssrf, etc.)
            context: 上下文信息 (WAF类型、过滤规则等)
            waf_detected: 是否检测到WAF

        Returns:
            推荐的payloads
        """
        try:
            from modules.smart_payload_engine import SmartPayloadEngine

            engine = SmartPayloadEngine()
            payloads = engine.generate(
                vuln_type=vuln_type,
                context=context,
                waf_bypass=waf_detected
            )

            return {
                'success': True,
                'vuln_type': vuln_type,
                'payloads': payloads,
                'count': len(payloads)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    _counter.add('ai', 3)
    logger.info("[AI] 已注册 3 个AI辅助工具")


# ==================== 工具管理 ====================

def _register_misc_tools():
    """注册杂项工具"""

    @mcp.tool()
    async def registry_stats() -> Dict[str, Any]:
        """工具统计 - 获取已注册工具的统计信息

        Returns:
            工具统计
        """
        return {
            'success': True,
            'total': _counter.total,
            'by_category': _counter.counts,
            'version': '3.0.0'
        }

    @mcp.tool()
    async def health_check() -> Dict[str, Any]:
        """健康检查 - 检查MCP服务器状态

        Returns:
            服务器状态
        """
        import platform

        return {
            'success': True,
            'status': 'healthy',
            'version': '3.0.0',
            'python_version': platform.python_version(),
            'platform': platform.system(),
            'tools_registered': _counter.total
        }

    @mcp.tool()
    async def js_analyze(url: str) -> Dict[str, Any]:
        """JS代码分析 - 分析JavaScript代码中的敏感信息

        提取: API端点、密钥、令牌、内部路径

        Args:
            url: 目标URL或JS文件URL

        Returns:
            分析结果
        """
        try:
            from modules.js_analyzer import JSAnalyzer

            analyzer = JSAnalyzer()
            results = analyzer.analyze(url)

            return {
                'success': True,
                'url': url,
                'findings': results
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}

    _counter.add('misc', 3)
    logger.info("[Misc] 已注册 3 个杂项工具")


# ==================== 工具注册入口 ====================

def register_all_tools():
    """注册所有工具到MCP"""

    logger.info("=" * 60)
    logger.info("AutoRedTeam MCP Server v3.0.0 - 工具注册")
    logger.info("=" * 60)

    try:
        # 1. 侦察工具
        _register_recon_tools()
    except Exception as e:
        logger.warning(f"侦察工具注册失败: {e}")

    try:
        # 2. 漏洞检测工具
        _register_detector_tools()
    except Exception as e:
        logger.warning(f"漏洞检测工具注册失败: {e}")

    try:
        # 3. CVE工具
        _register_cve_tools()
    except Exception as e:
        logger.warning(f"CVE工具注册失败: {e}")

    try:
        # 4. API安全工具
        _register_api_security_tools()
    except Exception as e:
        logger.warning(f"API安全工具注册失败: {e}")

    try:
        # 5. 云安全工具
        _register_cloud_security_tools()
    except Exception as e:
        logger.warning(f"云安全工具注册失败: {e}")

    try:
        # 6. 供应链安全工具
        _register_supply_chain_tools()
    except Exception as e:
        logger.warning(f"供应链安全工具注册失败: {e}")

    try:
        # 7. 红队工具
        _register_redteam_tools()
    except Exception as e:
        logger.warning(f"红队工具注册失败: {e}")

    try:
        # 8. 会话管理工具
        _register_session_tools()
    except Exception as e:
        logger.warning(f"会话管理工具注册失败: {e}")

    try:
        # 9. 报告工具
        _register_report_tools()
    except Exception as e:
        logger.warning(f"报告工具注册失败: {e}")

    try:
        # 10. AI辅助工具
        _register_ai_tools()
    except Exception as e:
        logger.warning(f"AI辅助工具注册失败: {e}")

    try:
        # 11. 杂项工具
        _register_misc_tools()
    except Exception as e:
        logger.warning(f"杂项工具注册失败: {e}")

    logger.info("=" * 60)
    logger.info(f"工具注册完成: {_counter.summary()}")
    logger.info("=" * 60)


# ==================== 主入口 ====================

def main():
    """主入口函数"""

    # 注册所有工具
    register_all_tools()

    # 启动MCP服务器
    logger.info("AutoRedTeam MCP Server v3.0.0 启动中...")
    logger.info("支持: Claude Code / Cursor / Windsurf / Kiro")
    logger.info("-" * 60)

    # 根据命令行参数决定传输方式
    if len(sys.argv) > 1 and sys.argv[1] == '--stdio':
        mcp.run(transport='stdio')
    else:
        mcp.run()


if __name__ == "__main__":
    main()
