"""扫描接口 — 封装 core.recon + core.detectors

提供统一的扫描与侦察 API，包括:
- 完整10阶段侦察
- 端口扫描
- 指纹识别
- WAF 检测
- 子域名枚举
- 漏洞检测

Usage:
    scanner = Scanner("http://target.com")
    results = await scanner.full_recon()
    vulns = await scanner.detect_vulns(categories=["sqli", "xss"])
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Scanner:
    """统一扫描接口

    封装 core.recon.engine.StandardReconEngine 和 core.detectors
    提供简洁的异步 API。

    Args:
        target: 目标 URL 或 IP
        config: 可选配置字典，支持以下键:
            - recon: dict — 传递给 ReconConfig 的参数
            - detectors: dict — 传递给检测器的配置
            - quick_mode: bool — 是否使用快速模式
    """

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self._validate_target(target)
        self.target = target
        self._config = config or {}

    @staticmethod
    def _validate_target(target: str) -> None:
        """验证目标格式（URL / IP / 域名）

        优先使用 utils.validators 中的验证函数；
        如果导入失败，则回退到基础正则校验。

        Raises:
            ValueError: 目标格式无效
        """
        if not target or not isinstance(target, str):
            raise ValueError("目标不能为空")
        target = target.strip()
        try:
            from utils.validators import validate_url, validate_ip, validate_domain

            if target.startswith(("http://", "https://")):
                if validate_url(target):
                    return
                raise ValueError(
                    "无效的 URL 格式: %s（需要 http/https 协议和有效的主机名）" % target
                )

            if validate_ip(target):
                return
            if validate_domain(target):
                return

            raise ValueError(
                "无效的目标格式: %s（支持 URL / IP / 域名）" % target
            )

        except ImportError:
            # validators 模块不可用时使用基础正则校验
            import re as _re

            _url_re = _re.compile(
                r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(:\d{1,5})?(/.*)?$"
            )
            _ip_re = _re.compile(
                r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
            )
            _domain_re = _re.compile(
                r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                r"[a-zA-Z]{2,}$"
            )

            if _url_re.match(target):
                return
            if _ip_re.match(target):
                return
            if _domain_re.match(target):
                return

            raise ValueError(
                "无效的目标格式: %s（支持 URL / IP / 域名）" % target
            )

    async def full_recon(self) -> Dict[str, Any]:
        """执行完整10阶段侦察

        包括: DNS解析 → 端口扫描 → 指纹识别 → 技术栈检测 →
        WAF检测 → 子域名枚举 → 目录扫描 → 敏感信息检测

        Returns:
            ReconResult.to_dict() — 完整侦察结果
        """
        try:
            from core.recon.base import ReconConfig
            from core.recon.engine import StandardReconEngine

            recon_kwargs = self._config.get("recon", {})
            if self._config.get("quick_mode"):
                recon_kwargs.setdefault("quick_mode", True)

            config = ReconConfig(**recon_kwargs)
            engine = StandardReconEngine(target=self.target, config=config)
            result = await engine.async_run()
            return result.to_dict()
        except Exception as e:
            logger.error("full_recon 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def port_scan(
        self, ports: str = "1-1000", top: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """端口扫描

        Args:
            ports: 端口范围字符串，如 "1-1000" 或 "22,80,443"
            top: 扫描 Top N 常用端口，设置时忽略 ports 参数

        Returns:
            端口信息列表 [{"port": 80, "state": "open", "service": "http", ...}]
        """
        try:
            from core.recon.port_scanner import PortScanner

            scanner = PortScanner(
                timeout=self._config.get("timeout", 3),
                max_threads=self._config.get("max_threads", 100),
            )

            if top:
                # 需要从 target 解析出 IP
                ip = self._resolve_ip()
                results = scanner.scan_top_ports(ip, top=top)
            else:
                ip = self._resolve_ip()
                results = scanner.scan(ip, ports=ports)

            return [p.to_dict() for p in results]
        except Exception as e:
            logger.error("port_scan 失败: %s", e)
            return [{"success": False, "error": str(e)}]

    async def detect_vulns(
        self,
        categories: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """漏洞检测

        使用 DetectorFactory 创建检测器并扫描目标。

        Args:
            categories: 检测类别名称列表，如 ["sqli", "xss", "ssrf"]
                       None 时使用所有已注册检测器
            config: 检测器配置

        Returns:
            检测结果列表
        """
        try:
            from core.detectors.factory import DetectorFactory

            detector_config = config or self._config.get("detectors", {})

            if categories:
                # 按名称创建指定检测器
                detectors = []
                available = DetectorFactory.list_detectors()
                for cat in categories:
                    if cat in available:
                        detectors.append(DetectorFactory.create(cat, detector_config))
                    else:
                        logger.warning("检测器 '%s' 不存在，跳过。可用: %s", cat, available)
            else:
                detectors = DetectorFactory.create_all(detector_config)

            results = []

            async def _run_detector(detector):
                """执行单个检测器"""
                try:
                    if hasattr(detector, "async_detect"):
                        result = await detector.async_detect(self.target)
                    else:
                        result = detector.detect(self.target)
                    if result:
                        items = result if isinstance(result, list) else [result]
                        return [
                            item.to_dict() if hasattr(item, "to_dict") else item
                            for item in items
                        ]
                except Exception as e:
                    logger.warning("检测器 %s 执行失败: %s", getattr(detector, "name", "?"), e)
                return []

            # 并发执行所有检测器 (限流避免目标过载)
            from utils.async_utils import gather_with_limit

            coros = [_run_detector(d) for d in detectors]
            all_results = await gather_with_limit(coros, limit=10, return_exceptions=False)
            for batch in all_results:
                if isinstance(batch, list):
                    results.extend(batch)

            return results
        except Exception as e:
            logger.error("detect_vulns 失败: %s", e)
            return [{"success": False, "error": str(e)}]

    async def fingerprint(self) -> Dict[str, Any]:
        """技术栈指纹识别

        Returns:
            指纹识别结果 {"fingerprints": [...]}
        """
        try:
            from core.recon.fingerprint import FingerprintEngine

            engine = FingerprintEngine(
                timeout=self._config.get("timeout", 10),
                verify_ssl=self._config.get("verify_ssl", False),
            )
            fingerprints = engine.identify(self.target)
            return {
                "success": True,
                "fingerprints": [fp.to_dict() for fp in fingerprints],
            }
        except Exception as e:
            logger.error("fingerprint 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def waf_detect(self) -> Dict[str, Any]:
        """WAF 检测

        Returns:
            WAF 检测结果 {"detected": bool, "waf": {...} | None}
        """
        try:
            from core.recon.waf_detect import WAFDetector

            detector = WAFDetector(
                timeout=self._config.get("timeout", 10),
                verify_ssl=self._config.get("verify_ssl", False),
            )
            waf = detector.detect(self.target)
            if waf:
                return {"success": True, "detected": True, "waf": waf.to_dict()}
            return {"success": True, "detected": False, "waf": None}
        except Exception as e:
            logger.error("waf_detect 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def subdomain_enum(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """子域名枚举

        Args:
            domain: 根域名，默认从 target 自动提取

        Returns:
            子域名信息列表
        """
        try:
            from core.recon.subdomain import SubdomainEnumerator

            if domain is None:
                from urllib.parse import urlparse

                parsed = urlparse(self.target)
                hostname = parsed.hostname or self.target
                parts = hostname.split(".")
                domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

            enumerator = SubdomainEnumerator(
                timeout=self._config.get("subdomain_timeout", 5),
            )
            subdomains = enumerator.enumerate(domain)
            return [s.to_dict() for s in subdomains]
        except Exception as e:
            logger.error("subdomain_enum 失败: %s", e)
            return [{"success": False, "error": str(e)}]

    async def passive_recon(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """被动侦察 — 通过公开 API 收集子域名，零主动流量

        查询 crt.sh、HackerTarget、ThreatCrowd、URLScan.io、
        AlienVault OTX、RapidDNS 等公开数据源。

        Args:
            domain: 根域名，默认从 target 自动提取

        Returns:
            被动侦察结果 {"subdomains": [...], "by_source": {...}}
        """
        try:
            from core.recon.passive_recon import PassiveRecon

            if domain is None:
                from urllib.parse import urlparse

                parsed = urlparse(self.target)
                hostname = parsed.hostname or self.target
                parts = hostname.split(".")
                domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

            recon = PassiveRecon(
                timeout=self._config.get("passive_timeout", 10)
            )
            by_source = await recon.discover_subdomains_with_sources(domain)

            # 合并所有子域名
            all_subs = set()
            for subs in by_source.values():
                all_subs.update(subs)

            return {
                "success": True,
                "domain": domain,
                "subdomains": sorted(all_subs),
                "count": len(all_subs),
                "by_source": {
                    k: {"subdomains": v, "count": len(v)}
                    for k, v in by_source.items()
                },
            }
        except Exception as e:
            logger.error("passive_recon 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def nuclei_scan(
        self,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        template_dir: Optional[str] = None,
        concurrency: int = 10,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Nuclei 模板扫描

        使用纯 Python Nuclei 引擎扫描目标，无需 nuclei 二进制。

        Args:
            tags: 模板标签过滤（如 ["cve", "rce"]）
            severity: 严重性过滤（如 ["high", "critical"]）
            template_dir: 模板目录路径（默认自动搜索）
            concurrency: 最大并发数
            limit: 最大加载模板数

        Returns:
            扫描结果字典
        """
        try:
            from core.detectors.nuclei_engine import NucleiEngine

            engine = NucleiEngine(template_dir=template_dir)
            loaded = engine.load_templates(tags=tags, severity=severity, limit=limit)

            if loaded == 0:
                return {
                    "success": True,
                    "findings": [],
                    "templates_loaded": 0,
                    "message": "未找到匹配的 Nuclei 模板",
                }

            findings = await engine.scan(
                target=self.target,
                tags=tags,
                severity=severity,
                concurrency=concurrency,
            )

            return {
                "success": True,
                "url": self.target,
                "templates_loaded": loaded,
                "findings": findings,
                "total_findings": len(findings),
            }
        except Exception as e:
            logger.error("nuclei_scan 失败: %s", e)
            return {"success": False, "error": str(e)}

    def _resolve_ip(self) -> str:
        """从 target 提取或解析 IP 地址"""
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(self.target)
        hostname = parsed.hostname or self.target

        # 如果已经是 IP，直接返回
        try:
            socket.inet_aton(hostname)
            return hostname
        except OSError:
            pass

        # DNS 解析
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return hostname
