#!/usr/bin/env python3
"""
OSINT开源情报收集工具集
"""

import subprocess
import json
import logging
import os
from typing import Any, Dict, List
from dataclasses import dataclass, field

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class WhoisLookupTool(BaseTool):
    """Whois查询"""
    name: str = "whois_lookup"
    description: str = "Whois查询 - 获取域名/IP注册信息"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标域名或IP", required=True),
    ])
    timeout: int = 30
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(target)
                return {
                    "success": True,
                    "target": target,
                    "data": {
                        "domain_name": w.domain_name,
                        "registrar": w.registrar,
                        "whois_server": w.whois_server,
                        "creation_date": str(w.creation_date) if w.creation_date else None,
                        "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                        "updated_date": str(w.updated_date) if w.updated_date else None,
                        "name_servers": w.name_servers,
                        "status": w.status,
                        "emails": w.emails,
                        "dnssec": w.dnssec,
                        "name": w.name,
                        "org": w.org,
                        "address": w.address,
                        "city": w.city,
                        "state": w.state,
                        "zipcode": w.zipcode,
                        "country": w.country
                    }
                }
            except Exception as e:
                pass  # 回退到命令行
        
        # 使用命令行whois
        try:
            result = subprocess.run(
                ["whois", target],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            return {
                "success": True,
                "target": target,
                "raw_output": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "查询超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class TheHarvesterTool(BaseTool):
    """TheHarvester信息收集"""
    name: str = "theharvester"
    description: str = "TheHarvester - 收集邮箱、子域名、主机等信息"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("domain", "string", "目标域名", required=True),
        ToolParameter("sources", "string", "数据源(逗号分隔)", required=False,
                     default="google,bing,linkedin,twitter"),
        ToolParameter("limit", "integer", "结果数量限制", required=False, default=100),
    ])
    timeout: int = 300
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        domain = params["domain"]
        sources = params.get("sources", "google,bing,linkedin,twitter")
        limit = params.get("limit", 100)
        
        cmd = [
            "theHarvester", "-d", domain, 
            "-b", sources, 
            "-l", str(limit)
        ]
        
        try:
            logger.info(f"执行TheHarvester: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            output = result.stdout
            parsed = self._parse_output(output)
            parsed["command"] = ' '.join(cmd)
            
            return parsed
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "收集超时"}
        except FileNotFoundError:
            return {"success": False, "error": "theHarvester未安装，请运行: apt install theharvester"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """解析TheHarvester输出"""
        result = {
            "success": True,
            "emails": [],
            "hosts": [],
            "ips": [],
            "urls": [],
            "raw_output": output
        }
        
        lines = output.split('\n')
        section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if "Emails found:" in line or "emails found" in line.lower():
                section = "emails"
                continue
            elif "Hosts found:" in line or "hosts found" in line.lower():
                section = "hosts"
                continue
            elif "IPs found:" in line or "ips found" in line.lower():
                section = "ips"
                continue
            elif "URLs found:" in line or "urls found" in line.lower():
                section = "urls"
                continue
            elif line.startswith("[") or line.startswith("*"):
                section = None
                continue
            
            if section == "emails" and "@" in line:
                result["emails"].append(line)
            elif section == "hosts" and "." in line:
                result["hosts"].append(line)
            elif section == "ips":
                result["ips"].append(line)
            elif section == "urls":
                result["urls"].append(line)
        
        return result


@dataclass
class ShodanLookupTool(BaseTool):
    """Shodan查询"""
    name: str = "shodan_lookup"
    description: str = "Shodan - 查询IP/域名的互联网暴露信息"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP或域名", required=True),
        ToolParameter("api_key", "string", "Shodan API密钥", required=False, default=None),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        api_key = params.get("api_key") or os.getenv("SHODAN_API_KEY")
        
        if not api_key:
            return {
                "success": False,
                "error": "需要Shodan API密钥。设置环境变量 SHODAN_API_KEY 或传入 api_key 参数"
            }
        
        if SHODAN_AVAILABLE:
            try:
                api = shodan.Shodan(api_key)
                
                # 判断是IP还是域名
                import re
                ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                
                if re.match(ip_pattern, target):
                    # IP查询
                    host = api.host(target)
                    return {
                        "success": True,
                        "target": target,
                        "type": "ip",
                        "data": {
                            "ip": host.get("ip_str"),
                            "org": host.get("org"),
                            "asn": host.get("asn"),
                            "isp": host.get("isp"),
                            "country": host.get("country_name"),
                            "city": host.get("city"),
                            "ports": host.get("ports", []),
                            "hostnames": host.get("hostnames", []),
                            "vulns": host.get("vulns", []),
                            "last_update": host.get("last_update"),
                            "services": [
                                {
                                    "port": s.get("port"),
                                    "protocol": s.get("transport"),
                                    "service": s.get("product"),
                                    "version": s.get("version"),
                                    "banner": s.get("data", "")[:500]
                                }
                                for s in host.get("data", [])
                            ]
                        }
                    }
                else:
                    # 域名搜索
                    results = api.search(f"hostname:{target}")
                    hosts = []
                    for match in results.get("matches", [])[:20]:
                        hosts.append({
                            "ip": match.get("ip_str"),
                            "port": match.get("port"),
                            "org": match.get("org"),
                            "product": match.get("product"),
                            "version": match.get("version")
                        })
                    
                    return {
                        "success": True,
                        "target": target,
                        "type": "domain",
                        "total_results": results.get("total", 0),
                        "hosts": hosts
                    }
                    
            except shodan.APIError as e:
                return {"success": False, "error": f"Shodan API错误: {str(e)}"}
            except Exception as e:
                return {"success": False, "error": str(e)}
        
        # 使用命令行
        try:
            cmd = ["shodan", "host", target]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={**os.environ, "SHODAN_API_KEY": api_key}
            )
            
            return {
                "success": True,
                "target": target,
                "raw_output": result.stdout
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class CensysLookupTool(BaseTool):
    """Censys查询"""
    name: str = "censys_lookup"
    description: str = "Censys - 查询IP/域名的证书和服务信息"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("target", "string", "目标IP或域名", required=True),
        ToolParameter("api_id", "string", "Censys API ID", required=False, default=None),
        ToolParameter("api_secret", "string", "Censys API Secret", required=False, default=None),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        api_id = params.get("api_id") or os.getenv("CENSYS_API_ID")
        api_secret = params.get("api_secret") or os.getenv("CENSYS_API_SECRET")
        
        if not api_id or not api_secret:
            return {
                "success": False,
                "error": "需要Censys API凭证。设置 CENSYS_API_ID 和 CENSYS_API_SECRET 环境变量"
            }
        
        try:
            from censys.search import CensysHosts
            h = CensysHosts(api_id=api_id, api_secret=api_secret)
            
            import re
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            
            if re.match(ip_pattern, target):
                host = h.view(target)
                return {
                    "success": True,
                    "target": target,
                    "type": "ip",
                    "data": host
                }
            else:
                results = list(h.search(f"names: {target}", per_page=10))
                return {
                    "success": True,
                    "target": target,
                    "type": "domain",
                    "results": results
                }
                
        except ImportError:
            return {"success": False, "error": "censys库未安装，请运行: pip install censys"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class GoogleDorkTool(BaseTool):
    """Google Dork搜索"""
    name: str = "google_dork"
    description: str = "Google Dork - 使用高级搜索语法收集信息"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("domain", "string", "目标域名", required=True),
        ToolParameter("dork_type", "string", "Dork类型", required=False, default="all",
                     choices=["all", "files", "login", "sensitive", "dirs", "config"]),
    ])
    timeout: int = 30
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        domain = params["domain"]
        dork_type = params.get("dork_type", "all")
        
        # 预定义的Google Dorks
        dorks = {
            "files": [
                f'site:{domain} filetype:pdf',
                f'site:{domain} filetype:doc OR filetype:docx',
                f'site:{domain} filetype:xls OR filetype:xlsx',
                f'site:{domain} filetype:sql OR filetype:db',
                f'site:{domain} filetype:log',
                f'site:{domain} filetype:bak OR filetype:backup',
                f'site:{domain} filetype:conf OR filetype:config',
            ],
            "login": [
                f'site:{domain} inurl:login',
                f'site:{domain} inurl:admin',
                f'site:{domain} inurl:signin',
                f'site:{domain} intitle:"login"',
                f'site:{domain} inurl:auth',
            ],
            "sensitive": [
                f'site:{domain} "password" OR "passwd"',
                f'site:{domain} "username" filetype:log',
                f'site:{domain} inurl:wp-config',
                f'site:{domain} "api_key" OR "apikey"',
                f'site:{domain} "secret" filetype:json',
                f'site:{domain} intext:"index of /"',
            ],
            "dirs": [
                f'site:{domain} intitle:"index of"',
                f'site:{domain} inurl:/backup',
                f'site:{domain} inurl:/admin',
                f'site:{domain} inurl:/.git',
                f'site:{domain} inurl:/.svn',
            ],
            "config": [
                f'site:{domain} filetype:env',
                f'site:{domain} filetype:yml OR filetype:yaml',
                f'site:{domain} filetype:xml intext:password',
                f'site:{domain} filetype:ini',
                f'site:{domain} ".htaccess"',
            ]
        }
        
        selected_dorks = []
        if dork_type == "all":
            for dork_list in dorks.values():
                selected_dorks.extend(dork_list)
        else:
            selected_dorks = dorks.get(dork_type, [])
        
        return {
            "success": True,
            "domain": domain,
            "dork_type": dork_type,
            "dorks": selected_dorks,
            "note": "请手动在浏览器中执行这些搜索查询，或使用搜索API自动化"
        }
