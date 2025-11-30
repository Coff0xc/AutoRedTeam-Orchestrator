#!/usr/bin/env python3
"""
漏洞搜索和数据库查询工具集
"""

import subprocess
import json
import logging
import re
import requests
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class SearchsploitTool(BaseTool):
    """Searchsploit漏洞搜索"""
    name: str = "searchsploit"
    description: str = "Searchsploit - 搜索Exploit-DB漏洞数据库"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("query", "string", "搜索关键词", required=True),
        ToolParameter("exact", "boolean", "精确匹配", required=False, default=False),
        ToolParameter("exclude", "string", "排除关键词", required=False, default=""),
        ToolParameter("json_output", "boolean", "JSON输出", required=False, default=True),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        query = params["query"]
        exact = params.get("exact", False)
        exclude = params.get("exclude", "")
        json_output = params.get("json_output", True)
        
        cmd = ["searchsploit"]
        if exact:
            cmd.append("-e")
        if exclude:
            cmd.extend(["--exclude", exclude])
        if json_output:
            cmd.append("-j")
        
        cmd.append(query)
        
        try:
            logger.info(f"执行Searchsploit: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            exploits = []
            if json_output:
                try:
                    data = json.loads(result.stdout)
                    for exp in data.get("RESULTS_EXPLOIT", []):
                        exploits.append({
                            "title": exp.get("Title"),
                            "edb_id": exp.get("EDB-ID"),
                            "date": exp.get("Date"),
                            "author": exp.get("Author"),
                            "type": exp.get("Type"),
                            "platform": exp.get("Platform"),
                            "path": exp.get("Path")
                        })
                except json.JSONDecodeError:
                    exploits = self._parse_text(result.stdout)
            else:
                exploits = self._parse_text(result.stdout)
            
            return {
                "success": True,
                "query": query,
                "exploits": exploits,
                "total_found": len(exploits),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "搜索超时"}
        except FileNotFoundError:
            return {"success": False, "error": "searchsploit未安装，请运行: apt install exploitdb"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_text(self, output: str) -> List[Dict[str, str]]:
        """解析文本输出"""
        exploits = []
        for line in output.split('\n'):
            if '|' in line and 'Title' not in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    exploits.append({
                        "title": parts[0].strip(),
                        "path": parts[1].strip() if len(parts) > 1 else ""
                    })
        return exploits


@dataclass
class CVESearchTool(BaseTool):
    """CVE漏洞搜索"""
    name: str = "cve_search"
    description: str = "CVE搜索 - 搜索CVE漏洞数据库"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("query", "string", "搜索关键词或CVE ID", required=True),
        ToolParameter("vendor", "string", "厂商名称", required=False, default=""),
        ToolParameter("product", "string", "产品名称", required=False, default=""),
        ToolParameter("limit", "integer", "结果数量限制", required=False, default=20),
    ])
    timeout: int = 30
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        query = params["query"]
        vendor = params.get("vendor", "")
        product = params.get("product", "")
        limit = params.get("limit", 20)
        
        # CVE ID格式检查
        cve_pattern = r'^CVE-\d{4}-\d+$'
        
        try:
            if re.match(cve_pattern, query.upper()):
                # 查询特定CVE
                return self._search_cve_id(query.upper())
            else:
                # 关键词搜索
                return self._search_keyword(query, vendor, product, limit)
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _search_cve_id(self, cve_id: str) -> Dict[str, Any]:
        """搜索特定CVE"""
        # 使用NVD API
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    
                    # 提取CVSS分数
                    metrics = cve_data.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                    cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else {}
                    
                    return {
                        "success": True,
                        "cve_id": cve_id,
                        "cve": {
                            "id": cve_data.get("id"),
                            "description": cve_data.get("descriptions", [{}])[0].get("value"),
                            "published": cve_data.get("published"),
                            "lastModified": cve_data.get("lastModified"),
                            "cvss_v3": {
                                "score": cvss_v3.get("cvssData", {}).get("baseScore"),
                                "severity": cvss_v3.get("cvssData", {}).get("baseSeverity"),
                                "vector": cvss_v3.get("cvssData", {}).get("vectorString")
                            } if cvss_v3 else None,
                            "cvss_v2": {
                                "score": cvss_v2.get("cvssData", {}).get("baseScore"),
                                "vector": cvss_v2.get("cvssData", {}).get("vectorString")
                            } if cvss_v2 else None,
                            "references": [
                                ref.get("url") 
                                for ref in cve_data.get("references", [])
                            ][:10],
                            "weaknesses": [
                                w.get("description", [{}])[0].get("value")
                                for w in cve_data.get("weaknesses", [])
                            ]
                        }
                    }
            
            return {
                "success": False,
                "error": f"未找到CVE: {cve_id}"
            }
            
        except requests.Timeout:
            return {"success": False, "error": "API请求超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _search_keyword(self, keyword: str, vendor: str, product: str, 
                        limit: int) -> Dict[str, Any]:
        """关键词搜索CVE"""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 100)
        }
        
        try:
            response = requests.get(url, params=params, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                
                results = []
                for vuln in vulns[:limit]:
                    cve_data = vuln.get("cve", {})
                    metrics = cve_data.get("metrics", {})
                    cvss = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                    
                    results.append({
                        "id": cve_data.get("id"),
                        "description": cve_data.get("descriptions", [{}])[0].get("value", "")[:300],
                        "published": cve_data.get("published"),
                        "cvss_score": cvss.get("cvssData", {}).get("baseScore"),
                        "severity": cvss.get("cvssData", {}).get("baseSeverity")
                    })
                
                return {
                    "success": True,
                    "query": keyword,
                    "total_results": data.get("totalResults", 0),
                    "results": results
                }
            
            return {"success": False, "error": f"API返回错误: {response.status_code}"}
            
        except requests.Timeout:
            return {"success": False, "error": "API请求超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class VulnersSearchTool(BaseTool):
    """Vulners漏洞数据库搜索"""
    name: str = "vulners_search"
    description: str = "Vulners - 搜索多个漏洞数据库"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("query", "string", "搜索关键词", required=True),
        ToolParameter("software", "string", "软件名称", required=False, default=""),
        ToolParameter("version", "string", "软件版本", required=False, default=""),
        ToolParameter("limit", "integer", "结果数量", required=False, default=10),
    ])
    timeout: int = 30
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        query = params["query"]
        software = params.get("software", "")
        version = params.get("version", "")
        limit = params.get("limit", 10)
        
        if software:
            search_query = f"{software} {version}".strip()
        else:
            search_query = query
        
        url = "https://vulners.com/api/v3/search/lucene/"
        
        try:
            response = requests.post(
                url,
                json={
                    "query": search_query,
                    "skip": 0,
                    "size": limit
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("result") == "OK":
                    documents = data.get("data", {}).get("search", [])
                    
                    results = []
                    for doc in documents:
                        source = doc.get("_source", {})
                        results.append({
                            "id": source.get("id"),
                            "type": source.get("type"),
                            "title": source.get("title"),
                            "description": source.get("description", "")[:500],
                            "cvss_score": source.get("cvss", {}).get("score"),
                            "published": source.get("published"),
                            "href": source.get("href")
                        })
                    
                    return {
                        "success": True,
                        "query": search_query,
                        "results": results,
                        "total_found": len(results)
                    }
            
            return {"success": False, "error": "搜索失败"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
