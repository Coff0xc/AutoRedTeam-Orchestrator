#!/usr/bin/env python3
"""
Nuclei全量集成模块 - 支持所有Nuclei模板的扫描
包含: CVE, 暴露, 错误配置, 默认凭据, 文件, 技术检测等
"""

import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Dict, List

# 模块 logger
logger = logging.getLogger(__name__)


class NucleiScanner:
    """Nuclei全量扫描器"""

    # Nuclei模板分类
    TEMPLATE_CATEGORIES = {
        "cves": "CVE漏洞",
        "vulnerabilities": "通用漏洞",
        "exposures": "信息暴露",
        "misconfiguration": "错误配置",
        "default-logins": "默认凭据",
        "file": "敏感文件",
        "fuzzing": "Fuzzing测试",
        "technologies": "技术检测",
        "workflows": "工作流",
        "takeovers": "子域名接管",
        "network": "网络服务",
        "dns": "DNS相关",
        "headless": "无头浏览器",
        "ssl": "SSL/TLS",
        "iot": "物联网设备",
        "cnvd": "CNVD漏洞",
        "osint": "开源情报",
    }

    # 严重性级别
    SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

    # 常用技术标签
    TECH_TAGS = [
        # Web服务器
        "apache",
        "nginx",
        "iis",
        "tomcat",
        "weblogic",
        "jboss",
        "websphere",
        # CMS
        "wordpress",
        "drupal",
        "joomla",
        "magento",
        "shopify",
        "prestashop",
        # 框架
        "spring",
        "struts",
        "thinkphp",
        "laravel",
        "django",
        "flask",
        "rails",
        "express",
        "fastapi",
        "gin",
        "fiber",
        # 数据库
        "mysql",
        "postgresql",
        "mongodb",
        "redis",
        "elasticsearch",
        "mssql",
        "oracle",
        "couchdb",
        "cassandra",
        "influxdb",
        # DevOps
        "jenkins",
        "gitlab",
        "github",
        "bitbucket",
        "circleci",
        "travis",
        "docker",
        "kubernetes",
        "ansible",
        "terraform",
        "prometheus",
        "grafana",
        # 云服务
        "aws",
        "azure",
        "gcp",
        "alibaba-cloud",
        "digitalocean",
        "heroku",
        # 中间件
        "kafka",
        "rabbitmq",
        "activemq",
        "zookeeper",
        "consul",
        "etcd",
        # 安全
        "waf",
        "firewall",
        "ids",
        "fortinet",
        "paloalto",
        "checkpoint",
        # 其他
        "php",
        "java",
        "nodejs",
        "python",
        "aspnet",
        "ruby",
        "owa",
        "exchange",
        "sharepoint",
        "confluence",
        "jira",
        "citrix",
        "vmware",
        "cisco",
        "huawei",
        "zte",
    ]

    # 预设扫描配置
    SCAN_PRESETS = {
        "quick": {
            "severity": "high,critical",
            "rate_limit": 150,
            "timeout": 10,
            "tags": "cve,rce,sqli,xss,lfi,ssrf",
        },
        "full": {
            "severity": "info,low,medium,high,critical",
            "rate_limit": 100,
            "timeout": 20,
            "tags": "",  # 全部
        },
        "cve_only": {
            "severity": "medium,high,critical",
            "rate_limit": 150,
            "timeout": 15,
            "tags": "cve",
        },
        "web": {
            "severity": "low,medium,high,critical",
            "rate_limit": 120,
            "timeout": 15,
            "tags": "sqli,xss,lfi,rce,ssrf,xxe,ssti,upload",
        },
        "exposure": {
            "severity": "info,low,medium",
            "rate_limit": 150,
            "timeout": 10,
            "tags": "exposure,config,token,credential,backup,log",
        },
        "network": {
            "severity": "medium,high,critical",
            "rate_limit": 80,
            "timeout": 20,
            "tags": "network",
        },
        "takeover": {
            "severity": "high,critical",
            "rate_limit": 100,
            "timeout": 15,
            "tags": "takeover",
        },
        "api": {
            "severity": "low,medium,high,critical",
            "rate_limit": 100,
            "timeout": 15,
            "tags": "api,graphql,swagger,openapi,jwt",
        },
        "cloud": {
            "severity": "medium,high,critical",
            "rate_limit": 100,
            "timeout": 20,
            "tags": "aws,azure,gcp,cloud,s3,kubernetes",
        },
        "auth": {
            "severity": "medium,high,critical",
            "rate_limit": 80,
            "timeout": 15,
            "tags": "auth-bypass,default-login,unauth,brute-force",
        },
        "2024_cves": {
            "severity": "high,critical",
            "rate_limit": 100,
            "timeout": 15,
            "tags": "cve2024,cve2023",
        },
    }

    # 智能模板映射 - 根据技术栈选择最佳模板
    SMART_TEMPLATE_MAP = {
        "wordpress": ["wordpress", "wp-plugin", "wp-theme", "php"],
        "spring": ["spring", "springboot", "java", "log4j"],
        "laravel": ["laravel", "php", "blade"],
        "django": ["django", "python"],
        "express": ["express", "nodejs", "javascript"],
        "nginx": ["nginx", "misconfig"],
        "apache": ["apache", "httpd"],
        "tomcat": ["tomcat", "java"],
        "jenkins": ["jenkins", "ci-cd"],
        "gitlab": ["gitlab", "git"],
        "elasticsearch": ["elasticsearch", "elastic"],
        "redis": ["redis", "cache"],
        "mongodb": ["mongodb", "nosql"],
        "aws": ["aws", "s3", "ec2", "cloud"],
        "kubernetes": ["kubernetes", "k8s", "helm"],
    }

    def __init__(self, output_dir: str = None):
        import tempfile

        self.output_dir = output_dir or os.path.join(tempfile.gettempdir(), "nuclei_results")
        os.makedirs(self.output_dir, exist_ok=True)
        self.results = []

    def _run_nuclei(self, cmd: List[str], timeout: int = 3600, retries: int = 2) -> Dict:
        """运行Nuclei命令 (带重试)"""
        last_error = None
        for attempt in range(retries + 1):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                return {
                    "success": True,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                    "code": proc.returncode,
                }
            except subprocess.TimeoutExpired:
                last_error = "Timeout"
                if attempt < retries:
                    logger.warning("超时，重试 %d/%d...", attempt + 1, retries)
                    continue
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": (
                        "Nuclei not found. Install: "
                        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                    ),
                }
            except Exception as e:
                last_error = str(e)
                if attempt < retries:
                    logger.warning("错误: %s，重试 %d/%d...", e, attempt + 1, retries)
                    continue
        return {"success": False, "error": last_error}

    def update_templates(self) -> Dict:
        """更新Nuclei模板到最新"""
        logger.info("更新Nuclei模板...")
        result = self._run_nuclei(["nuclei", "-ut"], timeout=300)
        if result["success"]:
            logger.info("模板更新完成")
        return result

    def list_templates(self, tags: str = None) -> Dict:
        """列出可用模板"""
        cmd = ["nuclei", "-tl"]
        if tags:
            cmd.extend(["-tags", tags])

        result = self._run_nuclei(cmd, timeout=60)
        if result["success"]:
            templates = [t.strip() for t in result["stdout"].split("\n") if t.strip()]
            return {"success": True, "templates": templates, "count": len(templates)}
        return result

    def get_template_stats(self) -> Dict:
        """获取模板统计信息"""
        cmd = ["nuclei", "-stats"]
        result = self._run_nuclei(cmd, timeout=30)
        return result

    def scan(
        self,
        target: str,
        preset: str = "quick",
        severity: str = None,
        tags: str = None,
        templates: str = None,
        exclude_tags: str = None,
        rate_limit: int = None,
        output_json: bool = True,
    ) -> Dict:
        """
        执行Nuclei扫描

        Args:
            target: 目标URL或文件
            preset: 预设配置 (quick/full/cve_only/web/exposure/network/takeover)
            severity: 严重性过滤 (info,low,medium,high,critical)
            tags: 标签过滤
            templates: 指定模板路径
            exclude_tags: 排除标签
            rate_limit: 速率限制
            output_json: JSON输出
        """
        # 获取预设配置
        config = self.SCAN_PRESETS.get(preset, self.SCAN_PRESETS["quick"]).copy()

        # 覆盖配置
        if severity:
            config["severity"] = severity
        if tags:
            config["tags"] = tags
        if rate_limit:
            config["rate_limit"] = rate_limit

        # 构建命令
        cmd = ["nuclei", "-u", target, "-silent"]

        if config.get("severity"):
            cmd.extend(["-severity", config["severity"]])

        if config.get("tags"):
            cmd.extend(["-tags", config["tags"]])

        if templates:
            cmd.extend(["-t", templates])

        if exclude_tags:
            cmd.extend(["-exclude-tags", exclude_tags])

        cmd.extend(["-rate-limit", str(config.get("rate_limit", 100))])
        cmd.extend(["-timeout", str(config.get("timeout", 15))])

        if output_json:
            cmd.append("-json")

        # 输出文件
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"scan_{timestamp}.json")
        cmd.extend(["-o", output_file])

        logger.info("执行Nuclei扫描: %s", target)
        logger.info("预设: %s, 严重性: %s", preset, config.get("severity"))
        logger.debug("命令: %s", " ".join(cmd))

        result = self._run_nuclei(cmd, timeout=config.get("timeout", 15) * 100)

        if result["success"]:
            # 解析结果
            vulns = self._parse_results(output_file)
            return {
                "success": True,
                "target": target,
                "preset": preset,
                "vulnerabilities": vulns,
                "count": len(vulns),
                "output_file": output_file,
                "summary": self._summarize(vulns),
            }

        return result

    def scan_multiple(self, targets: List[str], preset: str = "quick", **kwargs) -> Dict:
        """扫描多个目标"""
        # 写入目标文件
        targets_file = os.path.join(self.output_dir, "targets.txt")
        with open(targets_file, "w", encoding="utf-8") as f:
            f.write("\n".join(targets))

        # 构建命令
        config = self.SCAN_PRESETS.get(preset, self.SCAN_PRESETS["quick"])

        cmd = ["nuclei", "-l", targets_file, "-silent", "-json"]

        if config.get("severity"):
            cmd.extend(["-severity", config["severity"]])
        if config.get("tags"):
            cmd.extend(["-tags", config["tags"]])

        cmd.extend(["-rate-limit", str(config.get("rate_limit", 100))])

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"multi_scan_{timestamp}.json")
        cmd.extend(["-o", output_file])

        logger.info("扫描 %d 个目标...", len(targets))

        result = self._run_nuclei(cmd, timeout=3600)

        if result["success"]:
            vulns = self._parse_results(output_file)
            return {
                "success": True,
                "targets_count": len(targets),
                "vulnerabilities": vulns,
                "count": len(vulns),
                "output_file": output_file,
                "summary": self._summarize(vulns),
            }

        return result

    def scan_by_severity(self, target: str, severity: str) -> Dict:
        """按严重性扫描"""
        return self.scan(target, severity=severity)

    def scan_by_tags(self, target: str, tags: List[str]) -> Dict:
        """按标签扫描"""
        return self.scan(target, tags=",".join(tags))

    def scan_cves(self, target: str, cve_ids: List[str] = None) -> Dict:
        """CVE专项扫描"""
        if cve_ids:
            # 扫描特定CVE
            tags = ",".join([cve.lower().replace("-", "_") for cve in cve_ids])
            return self.scan(target, tags=tags)
        else:
            # 扫描所有CVE
            return self.scan(target, preset="cve_only")

    def scan_tech(self, target: str, tech: str) -> Dict:
        """特定技术扫描"""
        tech_lower = tech.lower()
        if tech_lower in self.TECH_TAGS:
            return self.scan(target, tags=tech_lower)
        return {"success": False, "error": f"Unknown tech: {tech}"}

    def smart_scan(self, target: str, detected_tech: List[str] = None) -> Dict:
        """
        智能扫描 - 根据检测到的技术栈自动选择最佳模板

        Args:
            target: 目标URL
            detected_tech: 检测到的技术栈列表
        """
        if not detected_tech:
            # 如果没有提供技术栈，使用quick预设
            return self.scan(target, preset="quick")

        # 收集相关标签
        tags = set()
        for tech in detected_tech:
            tech_lower = tech.lower()
            if tech_lower in self.SMART_TEMPLATE_MAP:
                tags.update(self.SMART_TEMPLATE_MAP[tech_lower])
            elif tech_lower in self.TECH_TAGS:
                tags.add(tech_lower)

        if tags:
            logger.info("智能扫描: 基于技术栈 %s 选择模板标签: %s", detected_tech, list(tags))
            return self.scan(target, tags=",".join(tags), severity="medium,high,critical")

        return self.scan(target, preset="quick")

    def verify_vulnerability(self, vuln: Dict, retry: bool = True) -> Dict:
        """
        验证漏洞 - 重新扫描以确认漏洞存在

        Args:
            vuln: 漏洞信息字典
            retry: 是否重试验证
        """
        template_id = vuln.get("template_id", "")
        matched_at = vuln.get("matched_at", vuln.get("host", ""))

        if not template_id or not matched_at:
            return {"verified": False, "error": "缺少模板ID或目标"}

        # 构建验证命令
        cmd = ["nuclei", "-u", matched_at, "-t", template_id, "-silent", "-json"]

        result = self._run_nuclei(cmd, timeout=30, retries=2 if retry else 0)

        if result["success"] and result.get("stdout", "").strip():
            try:
                verify_result = json.loads(result["stdout"].strip().split("\n")[0])
                return {
                    "verified": True,
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "details": verify_result,
                }
            except json.JSONDecodeError:
                pass

        return {"verified": False, "template_id": template_id, "matched_at": matched_at}

    def batch_verify(self, vulns: List[Dict], sample_size: int = 10) -> Dict:
        """
        批量验证漏洞 - 抽样验证以确认扫描质量

        Args:
            vulns: 漏洞列表
            sample_size: 抽样数量
        """
        import random

        # 优先验证高危漏洞
        high_critical = [v for v in vulns if v.get("severity", "").lower() in ("high", "critical")]
        others = [v for v in vulns if v.get("severity", "").lower() not in ("high", "critical")]

        # 选择样本
        sample = high_critical[: sample_size // 2] + random.sample(
            others, min(sample_size // 2, len(others))
        )

        verified = []
        failed = []

        for vuln in sample:
            result = self.verify_vulnerability(vuln)
            if result.get("verified"):
                verified.append(vuln)
            else:
                failed.append(vuln)

        return {
            "total_sampled": len(sample),
            "verified_count": len(verified),
            "failed_count": len(failed),
            "verification_rate": len(verified) / max(len(sample), 1),
            "verified": verified,
            "failed": failed,
        }

    def get_remediation(self, vuln: Dict) -> Dict:
        """获取漏洞修复建议"""
        severity = vuln.get("severity", "").lower()
        vuln_type = vuln.get("type", "")
        _ = vuln_type
        tags = vuln.get("tags", [])
        template_id = vuln.get("template_id", "")

        remediation = {
            "priority": {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(
                severity, 5
            ),
            "timeline": {
                "critical": "立即",
                "high": "24小时内",
                "medium": "1周内",
                "low": "1月内",
            }.get(severity, "计划中"),
            "actions": [],
        }

        # 根据漏洞类型生成修复建议
        if "sqli" in template_id.lower() or "sql" in str(tags).lower():
            remediation["actions"] = [
                "使用参数化查询或预编译语句",
                "实施输入验证和过滤",
                "最小化数据库账户权限",
                "部署WAF规则",
            ]
        elif "xss" in template_id.lower() or "xss" in str(tags).lower():
            remediation["actions"] = [
                "实施输出编码(HTML/JS/URL)",
                "使用Content-Security-Policy头",
                "启用HttpOnly和Secure Cookie标志",
                "实施输入验证",
            ]
        elif "rce" in template_id.lower() or "rce" in str(tags).lower():
            remediation["actions"] = [
                "立即升级到最新版本",
                "禁用危险函数(eval, exec等)",
                "实施严格的输入验证",
                "使用沙箱或容器隔离",
            ]
        elif "ssrf" in template_id.lower() or "ssrf" in str(tags).lower():
            remediation["actions"] = [
                "实施URL白名单验证",
                "禁止访问内网IP和元数据服务",
                "使用代理隔离外部请求",
                "限制出站网络访问",
            ]
        elif "lfi" in template_id.lower() or "file" in str(tags).lower():
            remediation["actions"] = [
                "实施路径规范化",
                "使用白名单验证文件路径",
                "限制文件访问权限",
                "禁用动态文件包含",
            ]
        else:
            remediation["actions"] = [
                "审查相关代码和配置",
                "应用供应商安全补丁",
                "实施纵深防御措施",
                "加强监控和日志记录",
            ]

        return remediation

    def _parse_results(self, output_file: str) -> List[Dict]:
        """解析扫描结果 (带去重)"""
        vulns = []
        seen = set()  # 用于去重

        if not os.path.exists(output_file):
            return vulns

        try:
            with open(output_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            # 生成唯一标识用于去重
                            dedup_key = (
                                vuln.get("template-id", ""),
                                vuln.get("matched-at", ""),
                                vuln.get("matcher-name", ""),
                            )
                            if dedup_key in seen:
                                continue
                            seen.add(dedup_key)

                            vulns.append(
                                {
                                    "template_id": vuln.get("template-id", ""),
                                    "name": vuln.get("info", {}).get("name", "Unknown"),
                                    "severity": vuln.get("info", {}).get("severity", "unknown"),
                                    "description": vuln.get("info", {}).get("description", ""),
                                    "tags": vuln.get("info", {}).get("tags", []),
                                    "reference": vuln.get("info", {}).get("reference", []),
                                    "matched_at": vuln.get("matched-at", ""),
                                    "matcher_name": vuln.get("matcher-name", ""),
                                    "extracted_results": vuln.get("extracted-results", []),
                                    "curl_command": vuln.get("curl-command", ""),
                                    "type": vuln.get("type", ""),
                                    "host": vuln.get("host", ""),
                                    "timestamp": vuln.get("timestamp", ""),
                                }
                            )
                        except json.JSONDecodeError as e:
                            logger.warning("JSON解析错误: %s", e)
                            continue
        except IOError as e:
            logger.warning("文件读取错误: %s", e)

        self.results = vulns
        return vulns

    def _summarize(self, vulns: List[Dict]) -> Dict:
        """生成摘要"""
        summary = {
            "total": len(vulns),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_type": {},
            "top_templates": [],
        }

        template_count = {}

        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in summary["by_severity"]:
                summary["by_severity"][sev] += 1

            vtype = v.get("type", "unknown")
            summary["by_type"][vtype] = summary["by_type"].get(vtype, 0) + 1

            tid = v.get("template_id", "")
            template_count[tid] = template_count.get(tid, 0) + 1

        # Top模板
        sorted_templates = sorted(template_count.items(), key=lambda x: x[1], reverse=True)
        summary["top_templates"] = sorted_templates[:10]

        return summary

    def generate_report(self, vulns: List[Dict] = None) -> str:
        """生成报告"""
        vulns = vulns or self.results
        summary = self._summarize(vulns)

        report = [
            "\n" + "=" * 70,
            "                    Nuclei扫描报告",
            "=" * 70,
            f"\n扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"发现漏洞总数: {summary['total']}",
            "\n" + "-" * 40,
            "按严重性分布:",
            "-" * 40,
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = summary["by_severity"][sev]
            if count > 0:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[
                    sev
                ]
                report.append(f"  {icon} {sev.upper()}: {count}")

        # 漏洞详情
        for sev in ["critical", "high", "medium"]:
            sev_vulns = [v for v in vulns if v.get("severity", "").lower() == sev]
            if sev_vulns:
                report.extend(["\n" + "-" * 40, f"{sev.upper()}级别漏洞:", "-" * 40])
                for v in sev_vulns[:10]:  # 最多显示10个
                    report.append(f"  • {v.get('name', 'Unknown')}")
                    report.append(f"    URL: {v.get('matched_at', 'N/A')}")
                    if v.get("reference"):
                        refs = (
                            v["reference"][:2]
                            if isinstance(v["reference"], list)
                            else [v["reference"]]
                        )
                        report.append(f"    参考: {', '.join(refs)}")

        report.append("\n" + "=" * 70)

        return "\n".join(report)


# 快捷函数
def nuclei_scan(target: str, preset: str = "quick", **kwargs) -> Dict:
    """快速Nuclei扫描"""
    scanner = NucleiScanner()
    return scanner.scan(target, preset, **kwargs)


def nuclei_cve_scan(target: str, cve_ids: List[str] = None) -> Dict:
    """CVE扫描"""
    scanner = NucleiScanner()
    return scanner.scan_cves(target, cve_ids)


def nuclei_full_scan(target: str) -> Dict:
    """全量扫描"""
    scanner = NucleiScanner()
    return scanner.scan(target, preset="full")


def nuclei_update() -> Dict:
    """更新模板"""
    scanner = NucleiScanner()
    return scanner.update_templates()
