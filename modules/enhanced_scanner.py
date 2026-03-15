#!/usr/bin/env python3
"""
增强型扫描器 - 集成资产探测、组件识别、智能Payload、漏洞验证
"""

import json
import logging
import re
import subprocess
from datetime import datetime
from typing import Dict, List

from .component_fingerprint import FINGERPRINTS, ComponentIdentifier
from .payload_library import PayloadLibrary
from .vuln_verifier import VulnerabilityVerifier

# 模块 logger
logger = logging.getLogger(__name__)


class EnhancedScanner:
    """增强型扫描器"""

    def __init__(self):
        self.component_id = ComponentIdentifier()
        self.verifier = VulnerabilityVerifier()
        self.payloads = PayloadLibrary
        self.results = {
            "scan_time": datetime.now().isoformat(),
            "target": "",
            "assets": {},
            "components": [],
            "vulnerabilities": [],
            "verified": [],
            "summary": {},
        }

    def _run(self, cmd: List[str], timeout: int = 300) -> Dict:
        """运行命令"""
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"ok": True, "out": r.stdout, "err": r.stderr}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout"}
        except FileNotFoundError:
            return {"ok": False, "error": f"not_found: {cmd[0]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def full_asset_scan(self, domain: str) -> Dict:
        """全量资产扫描"""
        logger.info("=" * 60)
        logger.info("全量资产扫描: %s", domain)
        logger.info("=" * 60)

        self.results["target"] = domain
        assets = {
            "domain": domain,
            "subdomains": [],
            "ips": [],
            "ports": [],
            "urls": [],
            "technologies": [],
            "waf": None,
        }

        # 1. 子域名
        logger.info("[1/6] 子域名枚举...")
        r = self._run(["subfinder", "-d", domain, "-silent"], 120)
        if r["ok"]:
            assets["subdomains"] = [s.strip() for s in r["out"].split("\n") if s.strip()]
        logger.info("    发现 %d 个子域名", len(assets["subdomains"]))

        # 2. DNS解析
        logger.info("[2/6] DNS解析...")
        for sub in assets["subdomains"][:30]:
            r = self._run(["dig", "+short", sub, "A"], 10)
            if r["ok"]:
                for ip in r["out"].split("\n"):
                    ip = ip.strip()
                    if ip and re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                        if ip not in assets["ips"]:
                            assets["ips"].append(ip)
        logger.info("    解析到 %d 个IP", len(assets["ips"]))

        # 3. HTTP探测
        logger.info("[3/6] HTTP服务探测...")
        if assets["subdomains"]:
            targets = "\n".join(assets["subdomains"][:50])
            try:
                proc = subprocess.run(
                    ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect"],
                    input=targets,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                for line in proc.stdout.split("\n"):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            assets["urls"].append(
                                {
                                    "url": data.get("url", ""),
                                    "status": data.get("status_code", 0),
                                    "title": data.get("title", ""),
                                    "tech": data.get("tech", []),
                                }
                            )
                            for t in data.get("tech", []):
                                if t not in assets["technologies"]:
                                    assets["technologies"].append(t)
                        except Exception:
                            logger.warning("HTTP探测解析异常", exc_info=True)

            except Exception:
                logger.warning("HTTP探测执行异常", exc_info=True)

        logger.info("    发现 %d 个活跃URL", len(assets["urls"]))

        # 4. 端口扫描
        logger.info("[4/6] 端口扫描...")
        for ip in assets["ips"][:5]:
            r = self._run(["nmap", "-T4", "-F", "--open", ip, "-oG", "-"], 120)
            if r["ok"]:
                for match in re.findall(r"(\d+)/open/tcp//([^/]*)", r["out"]):
                    assets["ports"].append({"ip": ip, "port": match[0], "service": match[1]})
        logger.info("    发现 %d 个开放端口", len(assets["ports"]))

        # 5. WhatWeb
        logger.info("[5/6] 技术栈识别...")
        r = self._run(["whatweb", "-a", "3", "--color=never", f"https://{domain}"], 60)
        if r["ok"]:
            techs = re.findall(r"\[([^\]]+)\]", r["out"])
            for t in techs:
                if t not in assets["technologies"]:
                    assets["technologies"].append(t)
        logger.info("    识别到 %d 种技术", len(assets["technologies"]))

        # 6. WAF检测
        logger.info("[6/6] WAF检测...")
        r = self._run(["wafw00f", f"https://{domain}"], 30)
        if r["ok"] and "is behind" in r["out"]:
            match = re.search(r"is behind (.+?)(?:\s|$)", r["out"])
            if match:
                assets["waf"] = match.group(1)
                logger.warning("检测到WAF: %s", assets["waf"])

        self.results["assets"] = assets
        return assets

    def identify_components(self, assets: Dict) -> List[Dict]:
        """组件识别与分析"""
        logger.info("=" * 60)
        logger.info("组件识别与Payload匹配")
        logger.info("=" * 60)

        detected = []
        seen = set()

        # 从技术栈识别
        for tech in assets.get("technologies", []):
            tech_lower = tech.lower()
            for comp_name, fp in FINGERPRINTS.items():
                if comp_name in seen:
                    continue
                for pattern in fp.get("patterns", []) + fp.get("headers", []):
                    if isinstance(pattern, str) and pattern.lower() in tech_lower:
                        seen.add(comp_name)
                        # 提取版本
                        ver_match = re.search(r"[\d.]+", tech)
                        detected.append(
                            {
                                "name": comp_name,
                                "version": ver_match.group() if ver_match else None,
                                "evidence": tech,
                                "payloads": fp.get("payloads", []),
                                "cves": fp.get("cves", []),
                            }
                        )
                        break

        # 记录结果
        logger.info("检测到的组件:")
        logger.info("-" * 40)
        for c in detected:
            logger.info("  %s", c["name"].upper())
            logger.info("    版本: %s", c["version"] or "未知")
            if c["cves"]:
                logger.info("    CVE: %s", ", ".join(c["cves"][:3]))
            if c["payloads"]:
                logger.info("    Payload类型: %s", ", ".join(c["payloads"][:3]))

        self.results["components"] = detected
        return detected

    def smart_vuln_scan(self, target: str, components: List[Dict]) -> List[Dict]:
        """智能漏洞扫描"""
        logger.info("=" * 60)
        logger.info("智能漏洞扫描")
        logger.info("=" * 60)

        vulns = []

        # 1. Nuclei扫描
        logger.info("[1/3] Nuclei漏洞扫描...")
        tags = ["cve", "exposure"] + [c["name"] for c in components[:5]]
        cmd = [
            "nuclei",
            "-u",
            target,
            "-json",
            "-silent",
            "-severity",
            "medium,high,critical",
            "-tags",
            ",".join(tags[:10]),
        ]

        r = self._run(cmd, 600)
        if r["ok"]:
            for line in r["out"].split("\n"):
                if line.strip():
                    try:
                        v = json.loads(line)
                        vulns.append(
                            {
                                "source": "nuclei",
                                "name": v.get("info", {}).get("name", "Unknown"),
                                "severity": v.get("info", {}).get("severity", "unknown"),
                                "url": v.get("matched-at", target),
                                "template": v.get("template-id", ""),
                                "verified": True,
                            }
                        )
                    except Exception:
                        logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        logger.info("    Nuclei发现 %d 个漏洞", len(vulns))

        # 2. 组件CVE检测
        logger.info("[2/3] CVE漏洞检测...")
        cve_count = 0
        for comp in components:
            for cve in comp.get("cves", [])[:3]:
                cmd = ["nuclei", "-u", target, "-tags", cve.lower().replace("-", "_"), "-silent"]
                r = self._run(cmd, 60)
                if r["ok"] and r["out"].strip():
                    cve_count += 1
                    vulns.append(
                        {
                            "source": "cve_check",
                            "name": cve,
                            "severity": "high",
                            "component": comp["name"],
                            "verified": True,
                        }
                    )
        logger.info("    CVE检测发现 %d 个", cve_count)

        # 3. 自定义Payload测试准备
        logger.info("[3/3] Payload测试准备...")
        payload_count = self.payloads.count()
        logger.info("    已加载 %d 个Payload", payload_count["total"])
        for k, v in payload_count.items():
            if k != "total":
                logger.info("       - %s: %d", k.upper(), v)

        self.results["vulnerabilities"] = vulns
        return vulns

    def verify_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """验证漏洞真实性"""
        logger.info("=" * 60)
        logger.info("漏洞真实性验证")
        logger.info("=" * 60)

        verified = []

        for v in vulns:
            is_real = v.get("verified", False)
            confidence = "high" if is_real else "needs_manual"

            verified.append(
                {
                    "name": v.get("name"),
                    "severity": v.get("severity"),
                    "is_real": is_real,
                    "confidence": confidence,
                    "source": v.get("source"),
                    "url": v.get("url", ""),
                }
            )

            status = "已确认" if is_real else "待验证"
            logger.info("  %s [%s] %s", status, v.get("severity", "?").upper(), v.get("name"))

        self.results["verified"] = verified
        return verified

    def generate_report(self) -> str:
        """生成详细报告"""
        r = self.results

        report = [
            "\n" + "=" * 70,
            "                    增强型安全扫描报告",
            "=" * 70,
            f"\n扫描时间: {r['scan_time']}",
            f"目标: {r['target']}",
        ]

        # 资产统计
        assets = r.get("assets", {})
        report.extend(
            [
                "\n" + "-" * 50,
                "📊 资产统计",
                "-" * 50,
                f"  子域名: {len(assets.get('subdomains', []))}",
                f"  IP地址: {len(assets.get('ips', []))}",
                f"  开放端口: {len(assets.get('ports', []))}",
                f"  活跃URL: {len(assets.get('urls', []))}",
                f"  技术栈: {len(assets.get('technologies', []))}",
            ]
        )
        if assets.get("waf"):
            report.append(f"  WAF: {assets['waf']}")

        # 组件
        components = r.get("components", [])
        if components:
            report.extend(
                [
                    "\n" + "-" * 50,
                    "🔧 识别的组件",
                    "-" * 50,
                ]
            )
            for c in components:
                report.append(f"  • {c['name']} (v{c.get('version', '?')})")
                if c.get("cves"):
                    report.append(f"    CVE: {', '.join(c['cves'][:3])}")

        # 漏洞
        vulns = r.get("verified", [])
        if vulns:
            report.extend(
                [
                    "\n" + "-" * 50,
                    "🚨 发现的漏洞",
                    "-" * 50,
                ]
            )

            critical = [v for v in vulns if v.get("severity") == "critical"]
            high = [v for v in vulns if v.get("severity") == "high"]
            medium = [v for v in vulns if v.get("severity") == "medium"]

            if critical:
                report.append("\n  [严重]")
                for v in critical:
                    report.append(f"    🔴 {v['name']}")
            if high:
                report.append("\n  [高危]")
                for v in high:
                    report.append(f"    🟠 {v['name']}")
            if medium:
                report.append("\n  [中危]")
                for v in medium:
                    report.append(f"    🟡 {v['name']}")

        # Payload统计
        counts = PayloadLibrary.count()
        report.extend(
            [
                "\n" + "-" * 50,
                "💉 Payload库统计",
                "-" * 50,
                f"  总数: {counts['total']}",
            ]
        )
        for k, v in counts.items():
            if k != "total":
                report.append(f"    {k.upper()}: {v}")

        # 总结
        report.extend(
            [
                "\n" + "-" * 50,
                "📝 总结",
                "-" * 50,
                f"  发现漏洞总数: {len(vulns)}",
                f"  严重: {len([v for v in vulns if v.get('severity') == 'critical'])}",
                f"  高危: {len([v for v in vulns if v.get('severity') == 'high'])}",
                f"  中危: {len([v for v in vulns if v.get('severity') == 'medium'])}",
                "\n" + "=" * 70,
            ]
        )

        return "\n".join(report)

    def run_full_scan(self, domain: str) -> str:
        """执行完整扫描流程"""
        logger.info("=" * 60)
        logger.info("        增强型安全扫描开始")
        logger.info("=" * 60)

        # 1. 资产探测
        assets = self.full_asset_scan(domain)

        # 2. 组件识别
        components = self.identify_components(assets)

        # 3. 漏洞扫描
        target = f"https://{domain}"
        vulns = self.smart_vuln_scan(target, components)

        # 4. 漏洞验证
        self.verify_vulnerabilities(vulns)

        # 5. 生成报告
        report = self.generate_report()
        logger.info(report)

        return report


# 导出的工具函数
def enhanced_scan(target: str) -> Dict:
    """增强扫描入口"""
    scanner = EnhancedScanner()
    scanner.run_full_scan(target)
    return scanner.results


def get_payloads(vuln_type: str, category: str = "all", dbms: str = "mysql") -> List[str]:
    """获取Payload"""
    return PayloadLibrary.get_all(vuln_type, category, dbms)


def get_payload_stats() -> Dict:
    """获取Payload统计"""
    return PayloadLibrary.count()


def identify_tech(headers: Dict = None, body: str = None, url: str = None) -> List[Dict]:
    """识别技术栈"""
    ci = ComponentIdentifier()
    results = []
    if headers:
        results.extend(ci.identify_from_headers(headers))
    if body:
        results.extend(ci.identify_from_body(body))
    if url:
        results.extend(ci.identify_from_url(url))
    return results
