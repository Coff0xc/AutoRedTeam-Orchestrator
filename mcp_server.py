#!/usr/bin/env python3
"""
AutoRedTeam MCP Server
将红队工具封装为MCP协议，供AI调用
"""

import asyncio
import json
import sys
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

# MCP协议实现
class MCPServer:
    """MCP服务器 - 标准输入输出通信"""
    
    def __init__(self):
        self.tools = {}
        self.logger = logging.getLogger("mcp_server")
        self._register_tools()
    
    def _register_tools(self):
        """注册所有可用工具"""
        self.tools = {
            "redteam_scan": {
                "description": "对目标域名执行全自动红队渗透扫描，包括资产发现、端口扫描、漏洞检测和AI验证",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标域名，如 example.com"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "超时时间(秒)，默认300",
                            "default": 300
                        }
                    },
                    "required": ["target"]
                }
            },
            "subdomain_enum": {
                "description": "子域名枚举 - 使用Subfinder发现目标的所有子域名",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "目标主域名"
                        }
                    },
                    "required": ["domain"]
                }
            },
            "port_scan": {
                "description": "端口扫描 - 使用Nmap扫描目标IP的开放端口和服务",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标IP或域名"
                        },
                        "ports": {
                            "type": "string",
                            "description": "端口范围，如 '1-1000' 或 '80,443,8080'",
                            "default": "1-1000"
                        }
                    },
                    "required": ["target"]
                }
            },
            "vuln_scan": {
                "description": "漏洞扫描 - 使用Nuclei对Web目标进行漏洞检测",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "目标URL，如 https://example.com"
                        },
                        "severity": {
                            "type": "string",
                            "description": "漏洞严重级别过滤: critical,high,medium,low",
                            "default": "critical,high,medium"
                        }
                    },
                    "required": ["target"]
                }
            },
            "web_fingerprint": {
                "description": "Web指纹识别 - 识别目标网站的技术栈、WAF、CMS等",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "目标URL"
                        }
                    },
                    "required": ["url"]
                }
            },
            "osint_gather": {
                "description": "OSINT情报收集 - 从多个在线源收集目标域名的情报",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {
                            "type": "string",
                            "description": "目标域名"
                        }
                    },
                    "required": ["domain"]
                }
            },
            "service_exploit": {
                "description": "服务漏洞检测 - 检测Redis/MongoDB/MySQL等服务的未授权访问",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "host": {
                            "type": "string",
                            "description": "目标主机IP"
                        },
                        "port": {
                            "type": "integer",
                            "description": "服务端口"
                        },
                        "service": {
                            "type": "string",
                            "description": "服务类型: redis, mongodb, mysql, elasticsearch",
                            "enum": ["redis", "mongodb", "mysql", "elasticsearch", "memcached"]
                        }
                    },
                    "required": ["host", "port", "service"]
                }
            },
            "check_tools": {
                "description": "检查所有必需工具的安装状态",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            "get_payloads": {
                "description": "获取指定类型的攻击Payload列表",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "vuln_type": {
                            "type": "string",
                            "description": "漏洞类型: sqli, xss, lfi, rce, ssrf, xxe, ssti",
                            "enum": ["sqli", "xss", "lfi", "rce", "ssrf", "xxe", "ssti"]
                        },
                        "limit": {
                            "type": "integer",
                            "description": "返回数量限制",
                            "default": 20
                        }
                    },
                    "required": ["vuln_type"]
                }
            }
        }
    
    async def handle_request(self, request: Dict) -> Dict:
        """处理MCP请求"""
        method = request.get("method", "")
        req_id = request.get("id")
        params = request.get("params", {})
        
        try:
            if method == "initialize":
                return self._response(req_id, {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "autored-team",
                        "version": "1.0.0"
                    }
                })
            
            elif method == "tools/list":
                tools_list = [
                    {"name": name, "description": info["description"], "inputSchema": info["inputSchema"]}
                    for name, info in self.tools.items()
                ]
                return self._response(req_id, {"tools": tools_list})
            
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                result = await self._execute_tool(tool_name, tool_args)
                return self._response(req_id, {
                    "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]
                })
            
            else:
                return self._error(req_id, -32601, f"Method not found: {method}")
                
        except Exception as e:
            return self._error(req_id, -32603, str(e))
    
    async def _execute_tool(self, tool_name: str, args: Dict) -> Dict:
        """执行具体工具"""
        
        if tool_name == "redteam_scan":
            return await self._run_full_scan(args["target"], args.get("timeout", 300))
        
        elif tool_name == "subdomain_enum":
            return await self._run_subdomain_enum(args["domain"])
        
        elif tool_name == "port_scan":
            return await self._run_port_scan(args["target"], args.get("ports", "1-1000"))
        
        elif tool_name == "vuln_scan":
            return await self._run_vuln_scan(args["target"], args.get("severity", "critical,high,medium"))
        
        elif tool_name == "web_fingerprint":
            return await self._run_fingerprint(args["url"])
        
        elif tool_name == "osint_gather":
            return await self._run_osint(args["domain"])
        
        elif tool_name == "service_exploit":
            return await self._run_service_scan(args["host"], args["port"], args["service"])
        
        elif tool_name == "check_tools":
            return self._check_tools()
        
        elif tool_name == "get_payloads":
            return self._get_payloads(args["vuln_type"], args.get("limit", 20))
        
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    
    async def _run_full_scan(self, target: str, timeout: int) -> Dict:
        """执行完整红队扫描"""
        from core import RedTeamOrchestrator
        
        orchestrator = RedTeamOrchestrator({"timeout": timeout})
        report = await orchestrator.run(target)
        return report
    
    async def _run_subdomain_enum(self, domain: str) -> Dict:
        """子域名枚举"""
        from modules.recon import SubdomainScanner
        
        scanner = SubdomainScanner()
        result = await scanner.run(domain)
        return {
            "domain": domain,
            "subdomains": result.get("subdomains", []),
            "count": len(result.get("subdomains", []))
        }
    
    async def _run_port_scan(self, target: str, ports: str) -> Dict:
        """端口扫描"""
        from modules.mapping import PortScanner
        
        scanner = PortScanner()
        result = await scanner.scan(target, ports)
        return result
    
    async def _run_vuln_scan(self, target: str, severity: str) -> Dict:
        """漏洞扫描"""
        from modules.attack import VulnScanner
        
        scanner = VulnScanner()
        result = await scanner.scan_url(target, severity=severity)
        return result
    
    async def _run_fingerprint(self, url: str) -> Dict:
        """Web指纹识别"""
        from modules.mapping import FingerprintEngine
        import aiohttp
        
        engine = FingerprintEngine()
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as resp:
                headers = dict(resp.headers)
                body = await resp.text()
                result = engine.analyze(url, resp.status, headers, body)
        
        return {
            "url": url,
            "technologies": [{"name": t.name, "category": t.category} for t in result.get("technologies", [])],
            "waf": result.get("waf", []),
            "cdn": result.get("cdn", []),
            "server": result.get("server", "")
        }
    
    async def _run_osint(self, domain: str) -> Dict:
        """OSINT情报收集"""
        from modules.recon import OSINTAggregator
        from core import AsyncEngine
        
        engine = AsyncEngine()
        aggregator = OSINTAggregator()
        
        async with engine:
            result = await aggregator.gather_all(domain, engine)
        
        return {
            "domain": domain,
            "subdomains": result.get("subdomains", [])[:50],
            "ips": result.get("ips", [])[:20],
            "sources_used": aggregator.get_source_count()
        }
    
    async def _run_service_scan(self, host: str, port: int, service: str) -> Dict:
        """服务漏洞检测"""
        from modules.attack import ServiceScanner
        
        scanner = ServiceScanner()
        result = await scanner.scan_service(host, port, service)
        return result
    
    def _check_tools(self) -> Dict:
        """检查工具状态"""
        from core import ToolExecutor
        
        executor = ToolExecutor()
        status = executor.get_tool_status()
        
        return {
            "tools": status,
            "all_available": all(status.values())
        }
    
    def _get_payloads(self, vuln_type: str, limit: int) -> Dict:
        """获取Payload"""
        from core.payloads import (
            ALL_SQLI, ALL_XSS, ALL_LFI, ALL_RCE, ALL_SSRF, ALL_XXE, ALL_SSTI
        )
        
        payload_map = {
            "sqli": ALL_SQLI,
            "xss": ALL_XSS,
            "lfi": ALL_LFI,
            "rce": ALL_RCE,
            "ssrf": ALL_SSRF,
            "xxe": ALL_XXE,
            "ssti": ALL_SSTI,
        }
        
        payloads = payload_map.get(vuln_type, [])[:limit]
        
        return {
            "vuln_type": vuln_type,
            "count": len(payloads),
            "payloads": payloads
        }
    
    def _response(self, req_id: Any, result: Dict) -> Dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
    
    def _error(self, req_id: Any, code: int, message: str) -> Dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
    
    async def run(self):
        """运行MCP服务器 - stdio模式"""
        self.logger.info("AutoRedTeam MCP Server started")
        
        while True:
            try:
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                
                request = json.loads(line.strip())
                response = await self.handle_request(request)
                
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                
            except json.JSONDecodeError:
                continue
            except Exception as e:
                self.logger.error(f"Error: {e}")


def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler("/tmp/autored_mcp.log")]
    )
    
    server = MCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
