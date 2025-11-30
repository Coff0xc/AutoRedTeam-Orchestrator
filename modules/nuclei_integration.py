#!/usr/bin/env python3
"""
Nuclei全量集成模块 - 支持所有Nuclei模板的扫描
包含: CVE, 暴露, 错误配置, 默认凭据, 文件, 技术检测等
"""

import subprocess
import json
import os
from typing import Dict, List, Optional
from datetime import datetime


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
        "apache", "nginx", "iis", "tomcat", "weblogic", "jboss", "websphere",
        # CMS
        "wordpress", "drupal", "joomla", "magento", "shopify", "prestashop",
        # 框架
        "spring", "struts", "thinkphp", "laravel", "django", "flask", "rails",
        "express", "fastapi", "gin", "fiber",
        # 数据库
        "mysql", "postgresql", "mongodb", "redis", "elasticsearch", "mssql",
        "oracle", "couchdb", "cassandra", "influxdb",
        # DevOps
        "jenkins", "gitlab", "github", "bitbucket", "circleci", "travis",
        "docker", "kubernetes", "ansible", "terraform", "prometheus", "grafana",
        # 云服务
        "aws", "azure", "gcp", "alibaba-cloud", "digitalocean", "heroku",
        # 中间件
        "kafka", "rabbitmq", "activemq", "zookeeper", "consul", "etcd",
        # 安全
        "waf", "firewall", "ids", "fortinet", "paloalto", "checkpoint",
        # 其他
        "php", "java", "nodejs", "python", "aspnet", "ruby",
        "owa", "exchange", "sharepoint", "confluence", "jira",
        "citrix", "vmware", "cisco", "huawei", "zte",
    ]
    
    # 预设扫描配置
    SCAN_PRESETS = {
        "quick": {
            "severity": "high,critical",
            "rate_limit": 150,
            "timeout": 10,
            "tags": "cve,rce,sqli,xss,lfi,ssrf"
        },
        "full": {
            "severity": "info,low,medium,high,critical",
            "rate_limit": 100,
            "timeout": 20,
            "tags": ""  # 全部
        },
        "cve_only": {
            "severity": "medium,high,critical",
            "rate_limit": 150,
            "timeout": 15,
            "tags": "cve"
        },
        "web": {
            "severity": "low,medium,high,critical",
            "rate_limit": 120,
            "timeout": 15,
            "tags": "sqli,xss,lfi,rce,ssrf,xxe,ssti,upload"
        },
        "exposure": {
            "severity": "info,low,medium",
            "rate_limit": 150,
            "timeout": 10,
            "tags": "exposure,config,token,credential,backup,log"
        },
        "network": {
            "severity": "medium,high,critical",
            "rate_limit": 80,
            "timeout": 20,
            "tags": "network"
        },
        "takeover": {
            "severity": "high,critical",
            "rate_limit": 100,
            "timeout": 15,
            "tags": "takeover"
        }
    }
    
    def __init__(self, output_dir: str = "/tmp/nuclei_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = []
    
    def _run_nuclei(self, cmd: List[str], timeout: int = 3600) -> Dict:
        """运行Nuclei命令"""
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"success": True, "stdout": proc.stdout, "stderr": proc.stderr, "code": proc.returncode}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout"}
        except FileNotFoundError:
            return {"success": False, "error": "Nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def update_templates(self) -> Dict:
        """更新Nuclei模板到最新"""
        print("[*] 更新Nuclei模板...")
        result = self._run_nuclei(["nuclei", "-ut"], timeout=300)
        if result["success"]:
            print("[+] 模板更新完成")
        return result
    
    def list_templates(self, tags: str = None) -> Dict:
        """列出可用模板"""
        cmd = ["nuclei", "-tl"]
        if tags:
            cmd.extend(["-tags", tags])
        
        result = self._run_nuclei(cmd, timeout=60)
        if result["success"]:
            templates = [t.strip() for t in result["stdout"].split('\n') if t.strip()]
            return {"success": True, "templates": templates, "count": len(templates)}
        return result
    
    def get_template_stats(self) -> Dict:
        """获取模板统计信息"""
        cmd = ["nuclei", "-stats"]
        result = self._run_nuclei(cmd, timeout=30)
        return result
    
    def scan(self, target: str, preset: str = "quick", 
             severity: str = None, tags: str = None,
             templates: str = None, exclude_tags: str = None,
             rate_limit: int = None, output_json: bool = True) -> Dict:
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
        
        print(f"[*] 执行Nuclei扫描: {target}")
        print(f"[*] 预设: {preset}, 严重性: {config.get('severity')}")
        print(f"[*] 命令: {' '.join(cmd)}")
        
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
                "summary": self._summarize(vulns)
            }
        
        return result
    
    def scan_multiple(self, targets: List[str], preset: str = "quick", **kwargs) -> Dict:
        """扫描多个目标"""
        # 写入目标文件
        targets_file = os.path.join(self.output_dir, "targets.txt")
        with open(targets_file, 'w') as f:
            f.write('\n'.join(targets))
        
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
        
        print(f"[*] 扫描 {len(targets)} 个目标...")
        
        result = self._run_nuclei(cmd, timeout=3600)
        
        if result["success"]:
            vulns = self._parse_results(output_file)
            return {
                "success": True,
                "targets_count": len(targets),
                "vulnerabilities": vulns,
                "count": len(vulns),
                "output_file": output_file,
                "summary": self._summarize(vulns)
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
    
    def _parse_results(self, output_file: str) -> List[Dict]:
        """解析扫描结果"""
        vulns = []
        
        if not os.path.exists(output_file):
            return vulns
        
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            vulns.append({
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
                            })
                        except json.JSONDecodeError:
                            continue
        except Exception:
            pass
        
        self.results = vulns
        return vulns
    
    def _summarize(self, vulns: List[Dict]) -> Dict:
        """生成摘要"""
        summary = {
            "total": len(vulns),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "by_type": {},
            "top_templates": []
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
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}[sev]
                report.append(f"  {icon} {sev.upper()}: {count}")
        
        # 漏洞详情
        for sev in ["critical", "high", "medium"]:
            sev_vulns = [v for v in vulns if v.get("severity", "").lower() == sev]
            if sev_vulns:
                report.extend(["\n" + "-" * 40, f"{sev.upper()}级别漏洞:", "-" * 40])
                for v in sev_vulns[:10]:  # 最多显示10个
                    report.append(f"  • {v.get('name', 'Unknown')}")
                    report.append(f"    URL: {v.get('matched_at', 'N/A')}")
                    if v.get('reference'):
                        refs = v['reference'][:2] if isinstance(v['reference'], list) else [v['reference']]
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
