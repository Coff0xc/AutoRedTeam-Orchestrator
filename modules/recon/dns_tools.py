#!/usr/bin/env python3
"""
DNS枚举和侦察工具集
"""

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List

try:
    import dns.query
    import dns.resolver
    import dns.zone

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from core.registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)

# 域名验证正则表达式 - 防止命令注入
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def validate_domain(domain: str) -> bool:
    """
    验证域名格式，防止命令注入

    Args:
        domain: 待验证的域名

    Returns:
        域名是否有效
    """
    if not domain or not isinstance(domain, str):
        return False
    # 检查长度
    if len(domain) > 253:
        return False
    # 检查格式
    if not DOMAIN_PATTERN.match(domain):
        return False
    # 检查危险字符
    dangerous_chars = [";", "|", "&", "$", "`", "\n", "\r", ">", "<", "'", '"', "\\"]
    for char in dangerous_chars:
        if char in domain:
            return False
    return True


@dataclass
class DNSEnumTool(BaseTool):
    """DNS枚举"""

    name: str = "dns_enum"
    description: str = "DNS枚举 - 查询DNS记录(A, AAAA, MX, NS, TXT, CNAME等)"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("domain", "string", "目标域名", required=True),
            ToolParameter(
                "record_types",
                "string",
                "记录类型(逗号分隔)",
                required=False,
                default="A,AAAA,MX,NS,TXT,CNAME,SOA",
            ),
            ToolParameter("nameserver", "string", "指定DNS服务器", required=False, default=None),
        ]
    )
    timeout: int = 60

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        if not DNS_AVAILABLE:
            return {"success": False, "error": "dnspython库未安装，请运行: pip install dnspython"}

        domain = params["domain"]

        # 输入验证 - 防止潜在的安全问题
        if not validate_domain(domain):
            return {"success": False, "error": f"无效的域名格式: {domain}"}

        record_types = params.get("record_types", "A,AAAA,MX,NS,TXT,CNAME,SOA").split(",")
        nameserver = params.get("nameserver")

        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
        resolver.timeout = 10
        resolver.lifetime = 30

        results = {"success": True, "domain": domain, "records": {}}

        for rtype in record_types:
            rtype = rtype.strip().upper()
            try:
                answers = resolver.resolve(domain, rtype)
                records = []
                for rdata in answers:
                    if rtype == "MX":
                        records.append(
                            {"priority": rdata.preference, "exchange": str(rdata.exchange)}
                        )
                    elif rtype == "SOA":
                        records.append(
                            {
                                "mname": str(rdata.mname),
                                "rname": str(rdata.rname),
                                "serial": rdata.serial,
                                "refresh": rdata.refresh,
                                "retry": rdata.retry,
                                "expire": rdata.expire,
                                "minimum": rdata.minimum,
                            }
                        )
                    else:
                        records.append(str(rdata))

                results["records"][rtype] = records

            except dns.resolver.NXDOMAIN:
                results["records"][rtype] = {"error": "域名不存在"}
            except dns.resolver.NoAnswer:
                results["records"][rtype] = {"error": "无记录"}
            except dns.resolver.NoNameservers:
                results["records"][rtype] = {"error": "无可用DNS服务器"}
            except Exception as e:
                results["records"][rtype] = {"error": str(e)}

        return results


@dataclass
class DNSReconTool(BaseTool):
    """DNSRecon扫描"""

    name: str = "dnsrecon"
    description: str = "DNSRecon - 全面DNS侦察工具"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("domain", "string", "目标域名", required=True),
            ToolParameter(
                "scan_type",
                "string",
                "扫描类型",
                required=False,
                default="std",
                choices=["std", "brt", "srv", "axfr", "bing", "yand", "crt", "snoop"],
            ),
            ToolParameter("threads", "integer", "线程数", required=False, default=10),
        ]
    )
    timeout: int = 300

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        domain = params["domain"]
        scan_type = params.get("scan_type", "std")
        threads = params.get("threads", 10)

        # 输入验证 - 防止命令注入
        if not validate_domain(domain):
            return {"success": False, "error": f"无效的域名格式: {domain}"}

        # 验证 scan_type 参数
        allowed_scan_types = ["std", "brt", "srv", "axfr", "bing", "yand", "crt", "snoop"]
        if scan_type not in allowed_scan_types:
            return {"success": False, "error": f"无效的扫描类型: {scan_type}"}

        # 验证 threads 参数
        if not isinstance(threads, int) or threads < 1 or threads > 100:
            threads = 10

        cmd = ["dnsrecon", "-d", domain, "-t", scan_type, "--threads", str(threads), "-j", "-"]

        try:
            logger.info(f"执行DNSRecon: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

            try:
                data = json.loads(result.stdout)
                return {
                    "success": True,
                    "domain": domain,
                    "scan_type": scan_type,
                    "results": data,
                    "command": " ".join(cmd),
                }
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "domain": domain,
                    "raw_output": result.stdout,
                    "command": " ".join(cmd),
                }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "dnsrecon未安装，请运行: apt install dnsrecon"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class DnsxTool(BaseTool):
    """Dnsx DNS工具包"""

    name: str = "dnsx"
    description: str = "Dnsx - 快速多功能DNS工具"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("domains", "string", "目标域名(逗号分隔)", required=True),
            ToolParameter("record_type", "string", "记录类型", required=False, default="A"),
            ToolParameter("resolver", "string", "DNS解析器", required=False, default=None),
            ToolParameter("wildcard", "boolean", "检测通配符", required=False, default=False),
        ]
    )
    timeout: int = 120

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        domains = params["domains"].split(",")
        record_type = params.get("record_type", "A")
        resolver = params.get("resolver")
        wildcard = params.get("wildcard", False)

        # 输入验证 - 验证每个域名
        validated_domains = []
        for domain in domains:
            domain = domain.strip()
            if not domain:
                continue
            if not validate_domain(domain):
                return {"success": False, "error": f"无效的域名格式: {domain}"}
            validated_domains.append(domain)

        if not validated_domains:
            return {"success": False, "error": "未提供有效的域名"}

        # 验证 record_type
        allowed_record_types = ["a", "aaaa", "cname", "ns", "txt", "mx", "ptr", "soa"]
        if record_type.lower() not in allowed_record_types:
            return {"success": False, "error": f"无效的记录类型: {record_type}"}

        # 将域名写入临时输入
        domain_input = "\n".join(validated_domains)

        cmd = ["dnsx", "-silent", "-json"]
        cmd.extend(["-" + record_type.lower()])

        if resolver:
            cmd.extend(["-r", resolver])
        if wildcard:
            cmd.append("-wd")

        try:
            logger.info(f"执行Dnsx: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, input=domain_input, capture_output=True, text=True, timeout=self.timeout
            )

            results = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        results.append({"raw": line})

            return {
                "success": True,
                "domains": domains,
                "record_type": record_type,
                "results": results,
                "count": len(results),
                "command": " ".join(cmd),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "查询超时"}
        except FileNotFoundError:
            return {
                "success": False,
                "error": "dnsx未安装，请运行: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class ZoneTransferTool(BaseTool):
    """DNS区域传送测试"""

    name: str = "zone_transfer"
    description: str = "DNS区域传送测试 - 检测AXFR漏洞"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("domain", "string", "目标域名", required=True),
            ToolParameter(
                "nameserver", "string", "指定NS服务器(可选)", required=False, default=None
            ),
        ]
    )
    timeout: int = 60

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        if not DNS_AVAILABLE:
            return {"success": False, "error": "dnspython库未安装"}

        domain = params["domain"]
        nameserver = params.get("nameserver")

        # 输入验证 - 防止潜在的安全问题
        if not validate_domain(domain):
            return {"success": False, "error": f"无效的域名格式: {domain}"}

        results = {
            "success": True,
            "domain": domain,
            "vulnerable": False,
            "nameservers_tested": [],
            "zone_data": [],
        }

        # 获取NS记录
        try:
            resolver = dns.resolver.Resolver()
            if nameserver:
                ns_list = [nameserver]
            else:
                ns_answers = resolver.resolve(domain, "NS")
                ns_list = [str(ns).rstrip(".") for ns in ns_answers]

            results["nameservers_tested"] = ns_list

            # 尝试区域传送
            for ns in ns_list:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))

                    results["vulnerable"] = True
                    zone_records = []
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                zone_records.append(
                                    {
                                        "name": str(name),
                                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                                        "data": str(rdata),
                                    }
                                )

                    results["zone_data"].append({"nameserver": ns, "records": zone_records})

                except Exception as e:
                    results["zone_data"].append({"nameserver": ns, "error": str(e)})

        except Exception as e:
            results["error"] = str(e)

        return results
