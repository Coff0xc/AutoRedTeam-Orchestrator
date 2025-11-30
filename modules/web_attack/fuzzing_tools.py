#!/usr/bin/env python3
"""
Web模糊测试工具集
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
class FfufTool(BaseTool):
    """Ffuf Web Fuzzer"""
    name: str = "ffuf"
    description: str = "Ffuf - 快速Web模糊测试工具"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL(使用FUZZ作为占位符)", required=True),
        ToolParameter("wordlist", "string", "字典文件", required=True),
        ToolParameter("method", "string", "HTTP方法", required=False, default="GET",
                     choices=["GET", "POST", "PUT", "DELETE", "PATCH"]),
        ToolParameter("data", "string", "POST数据(使用FUZZ)", required=False, default=""),
        ToolParameter("headers", "string", "自定义Header(JSON)", required=False, default=""),
        ToolParameter("cookie", "string", "Cookie", required=False, default=""),
        ToolParameter("threads", "integer", "线程数", required=False, default=40),
        ToolParameter("filter_code", "string", "过滤状态码", required=False, default=""),
        ToolParameter("filter_size", "string", "过滤响应大小", required=False, default=""),
        ToolParameter("match_code", "string", "匹配状态码", required=False, default="200,204,301,302,307,401,403,405"),
        ToolParameter("recursion", "boolean", "递归扫描", required=False, default=False),
        ToolParameter("recursion_depth", "integer", "递归深度", required=False, default=2),
    ])
    timeout: int = 1800
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        wordlist = params["wordlist"]
        method = params.get("method", "GET")
        data = params.get("data", "")
        headers = params.get("headers", "")
        cookie = params.get("cookie", "")
        threads = params.get("threads", 40)
        filter_code = params.get("filter_code", "")
        filter_size = params.get("filter_size", "")
        match_code = params.get("match_code", "200,204,301,302,307,401,403,405")
        recursion = params.get("recursion", False)
        recursion_depth = params.get("recursion_depth", 2)
        
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-X", method,
            "-t", str(threads),
            "-o", "-",
            "-of", "json",
            "-s"  # 静默模式
        ]
        
        if data:
            cmd.extend(["-d", data])
        if cookie:
            cmd.extend(["-b", cookie])
        if headers:
            try:
                h_dict = json.loads(headers)
                for k, v in h_dict.items():
                    cmd.extend(["-H", f"{k}: {v}"])
            except json.JSONDecodeError:
                pass
        if filter_code:
            cmd.extend(["-fc", filter_code])
        if filter_size:
            cmd.extend(["-fs", filter_size])
        if match_code:
            cmd.extend(["-mc", match_code])
        if recursion:
            cmd.append("-recursion")
            cmd.extend(["-recursion-depth", str(recursion_depth)])
        
        try:
            logger.info(f"执行Ffuf: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            findings = []
            try:
                data = json.loads(result.stdout)
                for res in data.get("results", []):
                    findings.append({
                        "input": res.get("input", {}).get("FUZZ"),
                        "url": res.get("url"),
                        "status_code": res.get("status"),
                        "size": res.get("length"),
                        "words": res.get("words"),
                        "lines": res.get("lines"),
                        "content_type": res.get("content-type"),
                        "redirect_location": res.get("redirectlocation")
                    })
            except json.JSONDecodeError:
                # 尝试解析文本输出
                findings = self._parse_text(result.stdout)
            
            return {
                "success": True,
                "url": url,
                "findings": findings,
                "total_found": len(findings),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Fuzzing超时"}
        except FileNotFoundError:
            return {"success": False, "error": "ffuf未安装，请运行: apt install ffuf"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_text(self, output: str) -> List[Dict[str, Any]]:
        """解析文本输出"""
        findings = []
        for line in output.strip().split('\n'):
            if line and '[Status:' in line:
                pattern = r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)"
                match = re.search(pattern, line)
                if match:
                    findings.append({
                        "input": match.group(1),
                        "status_code": int(match.group(2)),
                        "size": int(match.group(3))
                    })
        return findings


@dataclass
class WfuzzTool(BaseTool):
    """Wfuzz Web Fuzzer"""
    name: str = "wfuzz"
    description: str = "Wfuzz - Web应用模糊测试工具"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL(使用FUZZ占位符)", required=True),
        ToolParameter("wordlist", "string", "字典文件", required=True),
        ToolParameter("method", "string", "HTTP方法", required=False, default="GET"),
        ToolParameter("data", "string", "POST数据", required=False, default=""),
        ToolParameter("cookie", "string", "Cookie", required=False, default=""),
        ToolParameter("headers", "string", "Header(JSON)", required=False, default=""),
        ToolParameter("hide_code", "string", "隐藏状态码", required=False, default="404"),
        ToolParameter("hide_chars", "string", "隐藏字符数", required=False, default=""),
        ToolParameter("hide_words", "string", "隐藏单词数", required=False, default=""),
        ToolParameter("hide_lines", "string", "隐藏行数", required=False, default=""),
        ToolParameter("threads", "integer", "并发数", required=False, default=10),
    ])
    timeout: int = 1800
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        wordlist = params["wordlist"]
        method = params.get("method", "GET")
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        headers = params.get("headers", "")
        hide_code = params.get("hide_code", "404")
        hide_chars = params.get("hide_chars", "")
        hide_words = params.get("hide_words", "")
        hide_lines = params.get("hide_lines", "")
        threads = params.get("threads", 10)
        
        cmd = [
            "wfuzz",
            "-w", wordlist,
            "-t", str(threads),
            "-f", "-,json"  # JSON输出到stdout
        ]
        
        if method != "GET":
            cmd.extend(["-X", method])
        if data:
            cmd.extend(["-d", data])
        if cookie:
            cmd.extend(["-b", cookie])
        if headers:
            try:
                h_dict = json.loads(headers)
                for k, v in h_dict.items():
                    cmd.extend(["-H", f"{k}: {v}"])
            except json.JSONDecodeError:
                pass
        if hide_code:
            cmd.extend(["--hc", hide_code])
        if hide_chars:
            cmd.extend(["--hh", hide_chars])
        if hide_words:
            cmd.extend(["--hw", hide_words])
        if hide_lines:
            cmd.extend(["--hl", hide_lines])
        
        cmd.append(url)
        
        try:
            logger.info(f"执行Wfuzz: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            findings = []
            try:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        data = json.loads(line)
                        findings.append({
                            "payload": data.get("payload"),
                            "url": data.get("url"),
                            "status_code": data.get("code"),
                            "chars": data.get("chars"),
                            "words": data.get("words"),
                            "lines": data.get("lines")
                        })
            except json.JSONDecodeError:
                findings = self._parse_text(result.stdout)
            
            return {
                "success": True,
                "url": url,
                "findings": findings,
                "total_found": len(findings),
                "command": ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Fuzzing超时"}
        except FileNotFoundError:
            return {"success": False, "error": "wfuzz未安装，请运行: apt install wfuzz"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _parse_text(self, output: str) -> List[Dict[str, Any]]:
        """解析文本输出"""
        findings = []
        for line in output.strip().split('\n'):
            if line and 'C=' in line:
                pattern = r'"([^"]+)".*C=(\d+).*Ch=(\d+).*W=(\d+).*L=(\d+)'
                match = re.search(pattern, line)
                if match:
                    findings.append({
                        "payload": match.group(1),
                        "status_code": int(match.group(2)),
                        "chars": int(match.group(3)),
                        "words": int(match.group(4)),
                        "lines": int(match.group(5))
                    })
        return findings


@dataclass
class ParamFuzzTool(BaseTool):
    """参数发现工具"""
    name: str = "param_fuzz"
    description: str = "参数发现 - 发现隐藏的HTTP参数"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL", required=True),
        ToolParameter("wordlist", "string", "参数字典", required=False,
                     default="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"),
        ToolParameter("method", "string", "HTTP方法", required=False, default="GET"),
        ToolParameter("threads", "integer", "线程数", required=False, default=40),
    ])
    timeout: int = 900
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        wordlist = params.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt")
        method = params.get("method", "GET")
        threads = params.get("threads", 40)
        
        # 使用arjun或ffuf进行参数发现
        # 首先尝试arjun
        try:
            cmd = ["arjun", "-u", url, "-m", method, "-t", str(threads), "-oJ", "-"]
            logger.info(f"执行Arjun: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            params_found = []
            try:
                data = json.loads(result.stdout)
                for param_url, param_list in data.items():
                    for p in param_list:
                        params_found.append({"url": param_url, "parameter": p})
            except json.JSONDecodeError:
                # 解析文本
                for line in result.stdout.split('\n'):
                    if 'parameter' in line.lower():
                        params_found.append({"raw": line.strip()})
            
            return {
                "success": True,
                "url": url,
                "parameters": params_found,
                "total_found": len(params_found),
                "command": ' '.join(cmd)
            }
            
        except FileNotFoundError:
            # 回退到ffuf
            return self._fuzz_with_ffuf(url, wordlist, method, threads)
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "扫描超时"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _fuzz_with_ffuf(self, url: str, wordlist: str, method: str, threads: int) -> Dict[str, Any]:
        """使用ffuf进行参数fuzzing"""
        # 构建带参数的URL
        if "?" in url:
            fuzz_url = f"{url}&FUZZ=test"
        else:
            fuzz_url = f"{url}?FUZZ=test"
        
        cmd = [
            "ffuf", "-u", fuzz_url,
            "-w", wordlist,
            "-X", method,
            "-t", str(threads),
            "-mc", "all",
            "-fs", "0",  # 过滤空响应
            "-s",
            "-o", "-",
            "-of", "json"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            params_found = []
            try:
                data = json.loads(result.stdout)
                for res in data.get("results", []):
                    params_found.append({
                        "parameter": res.get("input", {}).get("FUZZ"),
                        "status_code": res.get("status"),
                        "size": res.get("length")
                    })
            except json.JSONDecodeError:
                pass
            
            return {
                "success": True,
                "url": url,
                "parameters": params_found,
                "total_found": len(params_found),
                "command": ' '.join(cmd),
                "note": "使用ffuf回退模式"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
