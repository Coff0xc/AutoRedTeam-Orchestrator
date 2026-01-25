#!/usr/bin/env python3
"""
engine.py - 标准侦察引擎

整合所有侦察模块，提供完整的10阶段侦察流程。

使用方式:
    from core.recon.engine import StandardReconEngine

    engine = StandardReconEngine("https://example.com")
    result = engine.run()
    print(result.to_dict())

    # 异步执行
    result = await engine.async_run()
"""

import re
import ssl
import time
import asyncio
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from urllib.parse import urlparse

from .phases import (
    ReconPhase,
    PhaseResult,
    PhaseStatus,
    PhaseManager,
    DEFAULT_PHASE_ORDER,
    QUICK_PHASE_ORDER,
)
from .base import (
    BaseReconEngine,
    ReconConfig,
    ReconResult,
    Finding,
    Severity,
)
from .dns_resolver import DNSResolver
from .port_scanner import PortScanner
from .fingerprint import FingerprintEngine
from .tech_detect import TechDetector
from .waf_detect import WAFDetector
from .subdomain import SubdomainEnumerator
from .directory import DirectoryScanner


logger = logging.getLogger(__name__)


# 敏感文件列表
SENSITIVE_FILES = [
    ".git/config", ".git/HEAD", ".env", ".env.local",
    "web.config", "wp-config.php", "config.php",
    "robots.txt", "sitemap.xml", "phpinfo.php",
    "backup.sql", "dump.sql", ".DS_Store",
    "actuator/env", "actuator/health", "swagger.json",
    "main.js.map", "app.js.map", "bundle.js.map",
]


class StandardReconEngine(BaseReconEngine):
    """标准侦察引擎 - 10阶段完整侦察

    执行完整的侦察流程，包括:
    1. 初始化 (INIT)
    2. DNS解析 (DNS)
    3. 端口扫描 (PORT_SCAN)
    4. 指纹识别 (FINGERPRINT)
    5. 技术栈识别 (TECH_DETECT)
    6. WAF检测 (WAF_DETECT)
    7. 子域名枚举 (SUBDOMAIN)
    8. 目录扫描 (DIRECTORY)
    9. 敏感信息 (SENSITIVE)
    10. 完成 (COMPLETE)

    Attributes:
        target: 目标URL
        config: 侦察配置
    """

    def __init__(
        self,
        target: str,
        config: Optional[ReconConfig] = None
    ):
        """初始化标准侦察引擎

        Args:
            target: 目标URL或域名
            config: 侦察配置
        """
        super().__init__(target, config)

        # 阶段处理器映射
        self._phase_handlers: Dict[ReconPhase, Callable[[], PhaseResult]] = {
            ReconPhase.INIT: self._phase_init,
            ReconPhase.DNS: self._phase_dns,
            ReconPhase.PORT_SCAN: self._phase_port_scan,
            ReconPhase.FINGERPRINT: self._phase_fingerprint,
            ReconPhase.TECH_DETECT: self._phase_tech_detect,
            ReconPhase.WAF_DETECT: self._phase_waf_detect,
            ReconPhase.SUBDOMAIN: self._phase_subdomain,
            ReconPhase.DIRECTORY: self._phase_directory,
            ReconPhase.SENSITIVE: self._phase_sensitive,
            ReconPhase.COMPLETE: self._phase_complete,
        }

        # 根据配置设置阶段管理器
        if self.config.quick_mode:
            self._phase_manager.use_quick_mode()

        # 禁用配置中关闭的阶段
        if not self.config.enable_port_scan:
            self._phase_manager.disable_phase(ReconPhase.PORT_SCAN)
        if not self.config.enable_subdomain:
            self._phase_manager.disable_phase(ReconPhase.SUBDOMAIN)
        if not self.config.enable_directory:
            self._phase_manager.disable_phase(ReconPhase.DIRECTORY)
        if not self.config.enable_waf_detect:
            self._phase_manager.disable_phase(ReconPhase.WAF_DETECT)
        if not self.config.enable_fingerprint:
            self._phase_manager.disable_phase(ReconPhase.FINGERPRINT)
        if not self.config.enable_tech_detect:
            self._phase_manager.disable_phase(ReconPhase.TECH_DETECT)
        if not self.config.enable_sensitive:
            self._phase_manager.disable_phase(ReconPhase.SENSITIVE)

    def run(self) -> ReconResult:
        """运行完整侦察流程

        Returns:
            ReconResult 侦察结果
        """
        start_time = time.time()
        phase_order = self._phase_manager.get_phase_order()
        total_phases = len(phase_order)

        self._logger.info(f"Starting recon for {self.target} with {total_phases} phases")

        for idx, phase in enumerate(phase_order):
            if self.is_stopped():
                self._logger.info("Recon stopped by user")
                break

            self._current_phase = phase
            progress = int((idx / total_phases) * 100)
            self._report_progress(phase, progress, f"Running {phase.display_name}")

            try:
                # 获取阶段处理器
                handler = self._phase_handlers.get(phase)
                if handler:
                    phase_start = time.time()
                    phase_result = handler()
                    phase_result.duration = time.time() - phase_start
                    self._add_phase_result(phase_result)

                    # 关键阶段失败则中止
                    if not phase_result.success and phase.is_critical:
                        self._logger.error(f"Critical phase {phase.name} failed, aborting")
                        break
                else:
                    # 没有处理器，跳过
                    self._add_phase_result(
                        PhaseResult.create_skipped(phase, "No handler")
                    )

            except Exception as e:
                self._logger.error(f"Phase {phase.name} error: {e}")
                self._add_phase_result(
                    PhaseResult.create_failure(phase, [str(e)])
                )
                self._add_error(f"{phase.name}: {str(e)}")

                if phase.is_critical:
                    break

        # 完成
        self.result.duration = time.time() - start_time
        self.result.end_time = datetime.now().isoformat()
        self.result.success = len(self.result.errors) == 0

        self._report_progress(ReconPhase.COMPLETE, 100, "Recon completed")
        self._logger.info(
            f"Recon completed for {self.target} in {self.result.duration:.2f}s, "
            f"found {len(self.result.findings)} findings"
        )

        return self.result

    async def async_run(self) -> ReconResult:
        """异步运行侦察流程

        Returns:
            ReconResult 侦察结果
        """
        # 目前使用线程池执行同步代码
        # 未来可以优化为完全异步
        return await asyncio.to_thread(self.run)

    # ========== 阶段1: 初始化 ==========
    def _phase_init(self) -> PhaseResult:
        """初始化阶段

        解析目标URL，提取主机名、端口等信息。
        """
        data = {}
        errors = []

        try:
            parsed = urlparse(self.target)
            data["hostname"] = parsed.hostname
            data["scheme"] = parsed.scheme
            data["port"] = parsed.port
            data["path"] = parsed.path

            self._logger.info(f"Target parsed: {data}")

            return PhaseResult.create_success(ReconPhase.INIT, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.INIT, errors)

    # ========== 阶段2: DNS解析 ==========
    def _phase_dns(self) -> PhaseResult:
        """DNS解析阶段

        获取目标的IP地址和DNS记录。
        """
        data = {}
        errors = []

        try:
            resolver = DNSResolver(timeout=self.config.timeout)
            dns_result = resolver.get_all_records(self.hostname)

            # 保存IP地址
            self.result.ip_addresses = dns_result.ip_addresses
            data["ip_addresses"] = dns_result.ip_addresses
            data["ipv6_addresses"] = dns_result.ipv6_addresses
            data["nameservers"] = dns_result.nameservers
            data["mail_servers"] = [
                {"priority": p, "server": s}
                for p, s in dns_result.mail_servers
            ]
            data["txt_records"] = dns_result.txt_records

            if dns_result.ip_addresses:
                self._add_finding(Finding(
                    type="dns",
                    severity=Severity.INFO,
                    title="IP地址解析",
                    description=f"目标解析到 {len(dns_result.ip_addresses)} 个IP地址",
                    evidence=", ".join(dns_result.ip_addresses[:5]),
                ))

            return PhaseResult.create_success(ReconPhase.DNS, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.DNS, errors)

    # ========== 阶段3: 端口扫描 ==========
    def _phase_port_scan(self) -> PhaseResult:
        """端口扫描阶段

        扫描目标的开放端口。
        """
        data = {}
        errors = []

        if not self.result.ip_addresses:
            return PhaseResult.create_skipped(ReconPhase.PORT_SCAN, "No IP addresses")

        try:
            scanner = PortScanner(
                timeout=self.config.port_timeout,
                max_threads=self.config.port_concurrency
            )

            ip = self.result.ip_addresses[0]

            # 扫描Top端口
            ports = scanner.scan_top_ports(ip, top=self.config.top_ports)

            # 保存结果
            self.result.open_ports = [p.to_dict() for p in ports]
            data["open_ports"] = self.result.open_ports
            data["scanned_ip"] = ip

            if ports:
                port_list = [p.port for p in ports]
                self._add_finding(Finding(
                    type="port",
                    severity=Severity.INFO,
                    title="开放端口",
                    description=f"发现 {len(ports)} 个开放端口",
                    evidence=", ".join(str(p) for p in port_list[:10]),
                ))

                # 检测危险端口
                dangerous_ports = {22: "SSH", 23: "Telnet", 3389: "RDP",
                                   445: "SMB", 6379: "Redis", 27017: "MongoDB"}
                for port in ports:
                    if port.port in dangerous_ports:
                        self._add_finding(Finding(
                            type="port",
                            severity=Severity.MEDIUM,
                            title=f"敏感服务端口开放: {dangerous_ports[port.port]}",
                            description=f"端口 {port.port} ({port.service or dangerous_ports[port.port]}) 开放",
                            recommendation="确认该服务是否需要对外开放，建议进行访问控制",
                        ))

            return PhaseResult.create_success(ReconPhase.PORT_SCAN, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.PORT_SCAN, errors)

    # ========== 阶段4: 指纹识别 ==========
    def _phase_fingerprint(self) -> PhaseResult:
        """指纹识别阶段

        识别Web服务器、框架、CMS等。
        """
        data = {}
        errors = []

        try:
            engine = FingerprintEngine(
                timeout=self.config.timeout,
                verify_ssl=self.config.verify_ssl
            )

            fingerprints = engine.identify(self.target)

            # 保存结果
            self.result.fingerprints = {
                fp.category: {"name": fp.name, "version": fp.version, "confidence": fp.confidence}
                for fp in fingerprints
            }
            data["fingerprints"] = [fp.to_dict() for fp in fingerprints]

            if fingerprints:
                self._add_finding(Finding(
                    type="fingerprint",
                    severity=Severity.INFO,
                    title="指纹识别",
                    description=f"识别到 {len(fingerprints)} 个指纹",
                    evidence=", ".join(str(fp) for fp in fingerprints[:5]),
                ))

            return PhaseResult.create_success(ReconPhase.FINGERPRINT, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.FINGERPRINT, errors)

    # ========== 阶段5: 技术栈识别 ==========
    def _phase_tech_detect(self) -> PhaseResult:
        """技术栈识别阶段

        基于Wappalyzer规则识别技术栈。
        """
        data = {}
        errors = []

        try:
            detector = TechDetector(
                timeout=self.config.timeout,
                verify_ssl=self.config.verify_ssl
            )

            technologies = detector.detect(self.target)

            # 保存结果
            self.result.technologies = [t.name for t in technologies]
            data["technologies"] = [t.to_dict() for t in technologies]

            if technologies:
                self._add_finding(Finding(
                    type="technology",
                    severity=Severity.INFO,
                    title="技术栈识别",
                    description=f"识别到 {len(technologies)} 种技术",
                    evidence=", ".join(self.result.technologies[:10]),
                ))

            return PhaseResult.create_success(ReconPhase.TECH_DETECT, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.TECH_DETECT, errors)

    # ========== 阶段6: WAF检测 ==========
    def _phase_waf_detect(self) -> PhaseResult:
        """WAF检测阶段

        检测是否存在WAF/防火墙。
        """
        data = {}
        errors = []

        try:
            detector = WAFDetector(
                timeout=self.config.timeout,
                verify_ssl=self.config.verify_ssl,
                aggressive=not self.config.stealth_mode
            )

            waf = detector.detect(self.target)

            if waf:
                self.result.waf_detected = waf.name
                data["waf"] = waf.to_dict()

                self._add_finding(Finding(
                    type="waf",
                    severity=Severity.INFO,
                    title=f"检测到WAF: {waf.name}",
                    description=f"目标受 {waf.vendor or waf.name} 保护",
                    evidence=", ".join(waf.evidence[:3]),
                    recommendation="; ".join(waf.bypass_hints[:2]) if waf.bypass_hints else "",
                ))
            else:
                data["waf"] = None

            return PhaseResult.create_success(ReconPhase.WAF_DETECT, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.WAF_DETECT, errors)

    # ========== 阶段7: 子域名枚举 ==========
    def _phase_subdomain(self) -> PhaseResult:
        """子域名枚举阶段

        通过字典暴破发现子域名。
        """
        data = {}
        errors = []

        try:
            enumerator = SubdomainEnumerator(
                timeout=self.config.subdomain_timeout,
                threads=self.config.max_threads,
                wordlist=self.config.subdomain_wordlist,
                max_subdomains=self.config.max_subdomains
            )

            # 提取根域名
            parts = self.hostname.split(".")
            if len(parts) >= 2:
                domain = ".".join(parts[-2:])
            else:
                domain = self.hostname

            subdomains = enumerator.enumerate(domain)

            # 保存结果
            self.result.subdomains = [s.subdomain for s in subdomains]
            data["subdomains"] = [s.to_dict() for s in subdomains]
            data["domain"] = domain

            if subdomains:
                self._add_finding(Finding(
                    type="subdomain",
                    severity=Severity.INFO,
                    title="子域名发现",
                    description=f"发现 {len(subdomains)} 个子域名",
                    evidence=", ".join(self.result.subdomains[:10]),
                ))

            return PhaseResult.create_success(ReconPhase.SUBDOMAIN, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.SUBDOMAIN, errors)

    # ========== 阶段8: 目录扫描 ==========
    def _phase_directory(self) -> PhaseResult:
        """目录扫描阶段

        扫描Web目录和文件。
        """
        data = {}
        errors = []

        try:
            scanner = DirectoryScanner(
                timeout=self.config.directory_timeout,
                threads=self.config.max_threads,
                verify_ssl=self.config.verify_ssl,
                extensions=self.config.extensions,
                wordlist=self.config.wordlist,
                max_results=self.config.max_directories
            )

            directories = scanner.scan(self.target)

            # 保存结果
            self.result.directories = [d.path for d in directories]
            data["directories"] = [d.to_dict() for d in directories]

            if directories:
                self._add_finding(Finding(
                    type="directory",
                    severity=Severity.LOW,
                    title="目录发现",
                    description=f"发现 {len(directories)} 个目录/文件",
                    evidence=", ".join(self.result.directories[:10]),
                ))

            return PhaseResult.create_success(ReconPhase.DIRECTORY, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.DIRECTORY, errors)

    # ========== 阶段9: 敏感信息 ==========
    def _phase_sensitive(self) -> PhaseResult:
        """敏感信息阶段

        扫描敏感文件和配置泄露。
        """
        data = {}
        errors = []

        try:
            found_files = []

            for file_path in SENSITIVE_FILES:
                url = f"{self.base_url}/{file_path}"
                result = self._check_sensitive_file(url, file_path)
                if result:
                    found_files.append(result)

            # 保存结果
            self.result.sensitive_files = [f["path"] for f in found_files]
            data["sensitive_files"] = found_files

            # 添加发现
            for file_info in found_files:
                severity = Severity.HIGH if any(
                    x in file_info["path"] for x in [".env", "config", ".git", "backup"]
                ) else Severity.MEDIUM

                self._add_finding(Finding(
                    type="sensitive_file",
                    severity=severity,
                    title=f"敏感文件: {file_info['path']}",
                    description=f"发现敏感文件 (大小: {file_info.get('size', 'N/A')} bytes)",
                    url=file_info["url"],
                    recommendation="确认文件是否应该对外公开，建议限制访问",
                ))

            return PhaseResult.create_success(ReconPhase.SENSITIVE, data)

        except Exception as e:
            errors.append(str(e))
            return PhaseResult.create_failure(ReconPhase.SENSITIVE, errors)

    def _check_sensitive_file(self, url: str, path: str) -> Optional[Dict[str, Any]]:
        """检查敏感文件是否存在

        Args:
            url: 完整URL
            path: 文件路径

        Returns:
            文件信息字典
        """
        try:
            # 创建SSL上下文
            if self.config.verify_ssl:
                ssl_context = ssl.create_default_context()
            else:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            headers = {"User-Agent": self.config.user_agent}
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(
                req,
                timeout=self.config.timeout,
                context=ssl_context
            ) as resp:
                if resp.status == 200:
                    body = resp.read(2000).decode("utf-8", errors="replace")
                    # 排除404伪装页面
                    if "404" not in body[:200] and "not found" not in body.lower()[:200]:
                        return {
                            "path": path,
                            "url": url,
                            "status": resp.status,
                            "size": len(body),
                        }

        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return None

    # ========== 阶段10: 完成 ==========
    def _phase_complete(self) -> PhaseResult:
        """完成阶段

        汇总结果，生成报告摘要。
        """
        data = {}

        # 统计发现
        severity_count = {s.value: 0 for s in Severity}
        for f in self.result.findings:
            severity_count[f.severity.value] += 1

        # 计算风险等级
        if severity_count["critical"] > 0:
            risk_level = "critical"
        elif severity_count["high"] > 0:
            risk_level = "high"
        elif severity_count["medium"] > 0:
            risk_level = "medium"
        elif severity_count["low"] > 0:
            risk_level = "low"
        else:
            risk_level = "info"

        data["risk_level"] = risk_level
        data["total_findings"] = len(self.result.findings)
        data["by_severity"] = severity_count
        data["open_ports_count"] = len(self.result.open_ports)
        data["subdomains_count"] = len(self.result.subdomains)
        data["directories_count"] = len(self.result.directories)
        data["technologies"] = self.result.technologies

        self.result.metadata["risk_level"] = risk_level
        self.result.metadata["summary"] = data

        return PhaseResult.create_success(ReconPhase.COMPLETE, data)


# 工厂函数
def create_recon_engine(
    target: str,
    config: Optional[ReconConfig] = None,
    quick_mode: bool = False
) -> StandardReconEngine:
    """创建侦察引擎实例

    Args:
        target: 目标URL
        config: 配置对象
        quick_mode: 是否使用快速模式

    Returns:
        StandardReconEngine 实例
    """
    if config is None:
        config = ReconConfig(quick_mode=quick_mode)
    elif quick_mode:
        config.quick_mode = True

    return StandardReconEngine(target, config)


# 导出
__all__ = [
    "StandardReconEngine",
    "create_recon_engine",
]
