#!/usr/bin/env python3
"""
AI Red Team MCP Server - 完整版
集成所有50+红队工具的MCP协议实现
"""

import json
import sys
import asyncio
import logging
import subprocess
import os
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('/tmp/mcp_redteam.log'), logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)


@dataclass
class MCPTool:
    name: str
    description: str
    inputSchema: Dict[str, Any]


class MCPServer:
    """完整版MCP服务器"""
    
    def __init__(self):
        self.tools: Dict[str, Callable] = {}
        self.tool_definitions: List[MCPTool] = []
        self._handlers = {
            "initialize": self._handle_initialize,
            "initialized": self._handle_initialized,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "resources/list": self._handle_resources_list,
            "prompts/list": self._handle_prompts_list,
        }
        self.executor = ThreadPoolExecutor(max_workers=10)
        self._register_all_tools()
    
    def register_tool(self, name: str, desc: str, schema: Dict, handler: Callable):
        self.tools[name] = handler
        self.tool_definitions.append(MCPTool(name=name, description=desc, inputSchema=schema))
    
    async def handle_message(self, message: Dict) -> Optional[Dict]:
        method = message.get("method")
        params = message.get("params", {})
        msg_id = message.get("id")
        
        if msg_id is None:
            return None
            
        if method in self._handlers:
            try:
                result = await self._handlers[method](params)
                return {"jsonrpc": "2.0", "id": msg_id, "result": result}
            except Exception as e:
                return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -1, "message": str(e)}}
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -1, "message": f"未知方法: {method}"}}
    
    async def _handle_initialize(self, params: Dict) -> Dict:
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": True}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "ai-redteam-mcp", "version": "2.0.0"}
        }
    
    async def _handle_initialized(self, params: Dict) -> Dict:
        return {}
    
    async def _handle_tools_list(self, params: Dict) -> Dict:
        return {"tools": [{"name": t.name, "description": t.description, "inputSchema": t.inputSchema} for t in self.tool_definitions]}
    
    async def _handle_tools_call(self, params: Dict) -> Dict:
        name = params.get("name")
        args = params.get("arguments", {})
        if name not in self.tools:
            raise ValueError(f"工具不存在: {name}")
        handler = self.tools[name]
        if asyncio.iscoroutinefunction(handler):
            result = await handler(args)
        else:
            result = await asyncio.get_event_loop().run_in_executor(self.executor, handler, args)
        return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]}
    
    async def _handle_resources_list(self, params: Dict) -> Dict:
        return {"resources": []}
    
    async def _handle_prompts_list(self, params: Dict) -> Dict:
        return {"prompts": []}
    
    async def run_stdio(self):
        logger.info(f"MCP服务器启动 - {len(self.tool_definitions)} 个工具")
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                response = await self.handle_message(json.loads(line.decode()))
                if response:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                logger.error(f"错误: {e}")

    def _run_cmd(self, cmd: List[str], timeout: int = 300) -> Dict:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"success": True, "stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode, "command": " ".join(cmd)}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "超时"}
        except FileNotFoundError:
            return {"success": False, "error": f"未找到: {cmd[0]}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _register_all_tools(self):
        """注册所有工具"""
        from mcp_tools import register_all_tools
        register_all_tools(self)


if __name__ == "__main__":
    server = MCPServer()
    asyncio.run(server.run_stdio())
