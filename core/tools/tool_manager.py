#!/usr/bin/env python3
"""
外部工具管理器 - Enhanced Tool Manager

功能:
- 统一管理外部安全工具 (nmap, nuclei, sqlmap, ffuf, masscan)
- 支持自定义工具路径配置
- 结果解析与结构化输出
- 工具链编排执行
- 与内置模块的智能结合

使用示例:
    from core.tools import ToolManager

    manager = ToolManager()

    # 单个工具调用
    result = await manager.run("nmap", target="192.168.1.1", preset="full")

    # 工具链执行
    results = await manager.run_chain("full_recon", target="example.com")
"""

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import defusedxml.ElementTree as ET  # 防止 XXE 攻击

logger = logging.getLogger(__name__)

# 尝试加载 YAML
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.warning("PyYAML 未安装，将使用默认配置")


class ToolStatus(Enum):
    """工具状态"""

    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class ToolInfo:
    """工具信息"""

    name: str
    path: Optional[str] = None
    status: ToolStatus = ToolStatus.NOT_FOUND
    version: Optional[str] = None
    description: str = ""
    is_python_script: bool = False
    default_args: Dict[str, List[str]] = field(default_factory=dict)
    fallback: Optional[str] = None


@dataclass
class ToolResult:
    """工具执行结果"""

    tool: str
    success: bool
    target: str
    raw_output: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    command: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "success": self.success,
            "target": self.target,
            "parsed_data": self.parsed_data,
            "error": self.error,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp,
        }


class ResultParser:
    """工具输出解析器"""

    @staticmethod
    def parse_nmap_xml(xml_content: str) -> Dict[str, Any]:
        """解析 Nmap XML 输出"""
        result = {
            "hosts": [],
            "scan_info": {},
        }

        try:
            root = ET.fromstring(xml_content)

            # 扫描信息
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                result["scan_info"] = {
                    "type": scaninfo.get("type", ""),
                    "protocol": scaninfo.get("protocol", ""),
                    "services": scaninfo.get("services", ""),
                }

            # 主机信息
            for host in root.findall("host"):
                host_info = {
                    "status": "unknown",
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": [],
                }

                # 状态
                status = host.find("status")
                if status is not None:
                    host_info["status"] = status.get("state", "unknown")

                # IP 地址
                for addr in host.findall("address"):
                    host_info["addresses"].append(
                        {
                            "addr": addr.get("addr", ""),
                            "addrtype": addr.get("addrtype", ""),
                        }
                    )

                # 主机名
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hostname in hostnames.findall("hostname"):
                        host_info["hostnames"].append(hostname.get("name", ""))

                # 端口
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_info = {
                            "port": int(port.get("portid", 0)),
                            "protocol": port.get("protocol", "tcp"),
                            "state": "unknown",
                            "service": "",
                            "version": "",
                            "scripts": [],
                        }

                        state = port.find("state")
                        if state is not None:
                            port_info["state"] = state.get("state", "unknown")

                        service = port.find("service")
                        if service is not None:
                            port_info["service"] = service.get("name", "")
                            port_info["product"] = service.get("product", "")
                            port_info["version"] = service.get("version", "")
                            port_info["extrainfo"] = service.get("extrainfo", "")

                        # NSE 脚本输出
                        for script in port.findall("script"):
                            port_info["scripts"].append(
                                {
                                    "id": script.get("id", ""),
                                    "output": script.get("output", ""),
                                }
                            )

                        host_info["ports"].append(port_info)

                # OS 检测
                os_elem = host.find("os")
                if os_elem is not None:
                    for osmatch in os_elem.findall("osmatch"):
                        host_info["os"].append(
                            {
                                "name": osmatch.get("name", ""),
                                "accuracy": osmatch.get("accuracy", ""),
                            }
                        )

                result["hosts"].append(host_info)

        except ET.ParseError as e:
            logger.error(f"Nmap XML 解析失败: {e}")

        return result

    @staticmethod
    def parse_nuclei_jsonl(output: str) -> List[Dict[str, Any]]:
        """解析 Nuclei JSONL 输出"""
        findings = []

        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                finding = json.loads(line)
                findings.append(
                    {
                        "template_id": finding.get("template-id", ""),
                        "template_name": finding.get("info", {}).get("name", ""),
                        "severity": finding.get("info", {}).get("severity", "info"),
                        "type": finding.get("type", ""),
                        "host": finding.get("host", ""),
                        "matched_at": finding.get("matched-at", ""),
                        "extracted_results": finding.get("extracted-results", []),
                        "curl_command": finding.get("curl-command", ""),
                        "description": finding.get("info", {}).get("description", ""),
                        "reference": finding.get("info", {}).get("reference", []),
                        "tags": finding.get("info", {}).get("tags", []),
                        "cve": finding.get("info", {}).get("classification", {}).get("cve-id", []),
                    }
                )
            except json.JSONDecodeError:
                # 可能是普通文本输出
                if line.strip():
                    findings.append({"raw": line.strip()})

        return findings

    @staticmethod
    def parse_sqlmap_output(output: str) -> Dict[str, Any]:
        """解析 SQLMap 输出"""
        result = {
            "vulnerable": False,
            "injection_points": [],
            "dbms": None,
            "databases": [],
            "tables": [],
            "payloads": [],
        }

        lines = output.split("\n")

        for line in lines:
            line = line.strip()

            # 检测是否存在注入
            if "is vulnerable" in line.lower() or "sqlmap identified" in line.lower():
                result["vulnerable"] = True

            # DBMS 类型
            if "back-end DBMS:" in line:
                result["dbms"] = line.split(":")[-1].strip()

            # 注入类型
            if "Type:" in line and "injectable" not in line:
                result["injection_points"].append(line)

            # Payload
            if "Payload:" in line:
                result["payloads"].append(line.split("Payload:")[-1].strip())

            # 数据库
            if "[*]" in line and "available databases" not in line:
                if line.startswith("[*]"):
                    db_name = line.replace("[*]", "").strip()
                    if db_name and not db_name.startswith("fetching"):
                        result["databases"].append(db_name)

        return result

    @staticmethod
    def parse_ffuf_json(output: str) -> Dict[str, Any]:
        """解析 ffuf JSON 输出"""
        result = {
            "results": [],
            "config": {},
        }

        try:
            data = json.loads(output)
            result["config"] = data.get("config", {})

            for r in data.get("results", []):
                result["results"].append(
                    {
                        "input": r.get("input", {}),
                        "position": r.get("position", 0),
                        "status": r.get("status", 0),
                        "length": r.get("length", 0),
                        "words": r.get("words", 0),
                        "lines": r.get("lines", 0),
                        "content_type": r.get("content-type", ""),
                        "redirect_location": r.get("redirectlocation", ""),
                        "url": r.get("url", ""),
                    }
                )
        except json.JSONDecodeError:
            # 解析文本格式
            for line in output.strip().split("\n"):
                if line.strip() and not line.startswith("["):
                    parts = line.split()
                    if len(parts) >= 2:
                        result["results"].append(
                            {
                                "url": parts[-1],
                                "status": parts[0] if parts[0].isdigit() else 0,
                            }
                        )

        return result

    @staticmethod
    def parse_masscan_json(output: str) -> Dict[str, Any]:
        """解析 Masscan JSON 输出"""
        result = {
            "hosts": {},
        }

        try:
            # Masscan 输出可能是 JSON 数组或 NDJSON
            if output.strip().startswith("["):
                data = json.loads(output)
            else:
                data = [json.loads(line) for line in output.strip().split("\n") if line.strip()]

            for entry in data:
                ip = entry.get("ip", "")
                if ip not in result["hosts"]:
                    result["hosts"][ip] = {"ports": []}

                for port in entry.get("ports", []):
                    result["hosts"][ip]["ports"].append(
                        {
                            "port": port.get("port", 0),
                            "protocol": port.get("proto", "tcp"),
                            "status": port.get("status", "open"),
                            "service": port.get("service", {}).get("name", ""),
                        }
                    )

        except json.JSONDecodeError as e:
            logger.debug(f"Masscan JSON 解析失败，尝试文本解析: {e}")
            # 文本格式解析
            for line in output.strip().split("\n"):
                match = re.search(r"(\d+)/(\w+)\s+(\w+)\s+(\S+)", line)
                if match:
                    port, proto, status, ip = match.groups()
                    if ip not in result["hosts"]:
                        result["hosts"][ip] = {"ports": []}
                    result["hosts"][ip]["ports"].append(
                        {
                            "port": int(port),
                            "protocol": proto,
                            "status": status,
                        }
                    )

        return result


class ToolManager:
    """外部工具管理器"""

    # 默认工具配置
    DEFAULT_CONFIG = {
        "tools": {
            "nmap": {
                "enabled": True,
                "path": None,
                "description": "端口扫描与服务识别",
                "default_args": {
                    "quick": ["-sT", "-T4", "--open"],
                    "full": ["-sT", "-sV", "-sC", "-T4", "--open"],
                    "version": ["-sV", "-sC"],
                    "vuln": ["-sV", "--script=vuln"],
                },
            },
            "nuclei": {
                "enabled": True,
                "path": None,
                "description": "基于模板的漏洞扫描",
                "default_args": {
                    "quick": ["-silent", "-severity", "critical,high"],
                    "full": ["-silent", "-j"],
                    "cve": ["-silent", "-tags", "cve", "-j"],
                },
            },
            "sqlmap": {
                "enabled": True,
                "path": None,
                "python_script": True,
                "description": "SQL注入检测与利用",
                "default_args": {
                    "detect": ["--batch", "--level=2", "--risk=1"],
                    "exploit": ["--batch", "--level=5", "--risk=3"],
                    "dump": ["--batch", "--dump"],
                },
            },
            "ffuf": {
                "enabled": True,
                "path": None,
                "description": "Web模糊测试",
                "default_args": {
                    "dir": ["-t", "50", "-fc", "404", "-of", "json"],
                    "param": ["-t", "50", "-mc", "200,301,302", "-of", "json"],
                },
            },
            "masscan": {
                "enabled": True,
                "path": None,
                "description": "超高速端口扫描",
                "default_args": {
                    "quick": ["--rate=10000", "-oJ", "-"],
                    "full": ["--rate=1000", "-p1-65535", "-oJ", "-"],
                },
            },
        },
        "performance": {
            "max_concurrent_tools": 3,
            "default_timeout": 300,
        },
    }

    def __init__(self, config_path: Optional[str] = None):
        """初始化工具管理器

        Args:
            config_path: 配置文件路径，默认为 config/external_tools.yaml
        """
        self.project_root = Path(__file__).parent.parent.parent
        self.config_path = config_path or self.project_root / "config" / "external_tools.yaml"
        self.config = self._load_config()
        self.tools: Dict[str, ToolInfo] = {}
        self._discover_tools()

    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        config = self.DEFAULT_CONFIG.copy()

        if HAS_YAML and Path(self.config_path).exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    yaml_config = yaml.safe_load(f)
                    if yaml_config:
                        # 变量替换
                        yaml_str = yaml.dump(yaml_config)
                        yaml_str = yaml_str.replace(
                            "${base_path}", yaml_config.get("base_path", "")
                        )
                        yaml_str = yaml_str.replace("${project_root}", str(self.project_root))
                        yaml_config = yaml.safe_load(yaml_str)

                        # 合并配置
                        if "tools" in yaml_config:
                            for tool, tool_config in yaml_config["tools"].items():
                                if tool in config["tools"]:
                                    config["tools"][tool].update(tool_config)
                                else:
                                    config["tools"][tool] = tool_config

                        if "performance" in yaml_config:
                            config["performance"].update(yaml_config["performance"])

                logger.info(f"已加载配置: {self.config_path}")
            except (yaml.YAMLError, IOError, OSError) as e:
                logger.warning(f"加载配置失败，使用默认配置: {e}")

        return config

    def _discover_tools(self) -> None:
        """发现并验证工具"""
        for name, tool_config in self.config.get("tools", {}).items():
            info = ToolInfo(
                name=name,
                description=tool_config.get("description", ""),
                default_args=tool_config.get("default_args", {}),
                is_python_script=tool_config.get("python_script", False),
                fallback=tool_config.get("fallback"),
            )

            if not tool_config.get("enabled", True):
                info.status = ToolStatus.DISABLED
                self.tools[name] = info
                continue

            # 查找工具路径
            custom_path = tool_config.get("path")
            if custom_path:
                # 安全检查：规范化路径并验证
                resolved_path = self._validate_tool_path(custom_path, name)
                if resolved_path:
                    info.path = resolved_path
                    info.status = ToolStatus.AVAILABLE
                else:
                    info.status = ToolStatus.NOT_FOUND
                    logger.warning(f"工具 {name} 路径验证失败: {custom_path}")
            else:
                # 尝试系统 PATH
                which_result = shutil.which(name)
                if which_result:
                    info.path = which_result
                    info.status = ToolStatus.AVAILABLE
                else:
                    info.status = ToolStatus.NOT_FOUND

            # 获取版本信息
            if info.status == ToolStatus.AVAILABLE:
                info.version = self._get_tool_version(info)

            self.tools[name] = info

    def _validate_tool_path(self, path: str, tool_name: str) -> Optional[str]:
        """验证工具路径的安全性

        Args:
            path: 配置的工具路径
            tool_name: 工具名称

        Returns:
            验证后的绝对路径，如果验证失败返回 None

        安全检查:
        1. 路径规范化（解析符号链接）
        2. 验证文件存在且可执行
        3. 防止路径遍历攻击
        4. 验证不在敏感目录
        """
        try:
            # 规范化路径（解析符号链接和相对路径）
            resolved = Path(path).resolve()

            # 检查文件是否存在
            if not resolved.exists():
                logger.debug(f"工具路径不存在: {resolved}")
                return None

            # 检查是否是文件（不是目录）
            if not resolved.is_file():
                logger.warning(f"工具路径不是文件: {resolved}")
                return None

            # 防止访问敏感系统目录
            sensitive_dirs = [
                Path("/etc"),
                Path("/var/log"),
                Path("/root"),
                Path("C:/Windows/System32"),
                Path("C:/Windows/SysWOW64"),
            ]

            for sensitive_dir in sensitive_dirs:
                try:
                    if sensitive_dir.exists() and resolved.is_relative_to(sensitive_dir):
                        logger.warning(f"工具 {tool_name} 路径在敏感目录中被拒绝: {resolved}")
                        return None
                except (ValueError, TypeError):
                    # is_relative_to 在不相关路径时抛出 ValueError
                    pass

            # 验证路径中不包含路径遍历序列
            path_str = str(resolved)
            if ".." in path_str:
                logger.warning(f"工具路径包含路径遍历序列: {path}")
                return None

            return str(resolved)

        except (OSError, ValueError) as e:
            logger.warning(f"工具路径验证失败 {path}: {e}")
            return None

    def _get_tool_version(self, info: ToolInfo) -> Optional[str]:
        """获取工具版本"""
        try:
            if info.is_python_script:
                cmd = [sys.executable, info.path, "--version"]
            else:
                cmd = [info.path, "--version"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            output = result.stdout or result.stderr
            # 提取版本号
            match = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
            if match:
                return match.group(1)
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError) as e:
            logger.debug(f"获取 {info.name} 版本失败: {e}")

        return None

    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有工具状态"""
        status = {}
        for name, info in self.tools.items():
            status[name] = {
                "status": info.status.value,
                "path": info.path,
                "version": info.version,
                "description": info.description,
            }
        return status

    def get_all_tools_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有工具状态 (别名)"""
        status = {}
        for name, info in self.tools.items():
            status[name] = {
                "available": info.status == ToolStatus.AVAILABLE,
                "status": info.status.value,
                "path": info.path,
                "version": info.version,
                "description": info.description,
                "fallback": info.fallback,
            }
        return status

    def is_available(self, tool_name: str) -> bool:
        """检查工具是否可用"""
        info = self.tools.get(tool_name)
        return info is not None and info.status == ToolStatus.AVAILABLE

    def is_tool_available(self, tool_name: str) -> bool:
        """检查工具是否可用 (别名)"""
        return self.is_available(tool_name)

    async def run(
        self,
        tool: str,
        target: str,
        preset: str = "quick",
        extra_args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
        parse_output: bool = True,
    ) -> ToolResult:
        """运行工具

        Args:
            tool: 工具名称 (nmap, nuclei, sqlmap, ffuf, masscan)
            target: 目标 (IP/域名/URL)
            preset: 预设配置 (quick, full, 等)
            extra_args: 额外参数
            timeout: 超时时间
            parse_output: 是否解析输出

        Returns:
            ToolResult 对象
        """
        info = self.tools.get(tool)

        if info is None:
            return ToolResult(tool=tool, success=False, target=target, error=f"未知工具: {tool}")

        if info.status != ToolStatus.AVAILABLE:
            # 尝试回退
            if info.fallback and info.fallback != "internal":
                logger.info(f"{tool} 不可用，尝试使用 {info.fallback}")
                return await self.run(
                    info.fallback, target, preset, extra_args, timeout, parse_output
                )
            return ToolResult(
                tool=tool, success=False, target=target, error=f"工具不可用: {info.status.value}"
            )

        # 构建命令（返回命令和元数据）
        cmd, metadata = self._build_command(info, target, preset, extra_args)
        timeout = timeout or self.config.get("performance", {}).get("default_timeout", 300)

        # 执行
        start_time = datetime.now()
        process: Optional[asyncio.subprocess.Process] = None
        try:
            if info.is_python_script:
                full_cmd = [sys.executable] + cmd
            else:
                full_cmd = cmd

            logger.info(f"执行: {' '.join(full_cmd)}")

            process = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

            execution_time = (datetime.now() - start_time).total_seconds()

            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")

            # 解析输出（传递元数据用于获取临时文件路径）
            parsed_data = {}
            if parse_output and output:
                parsed_data = self._parse_output(tool, output, metadata)

            return ToolResult(
                tool=tool,
                success=process.returncode == 0,
                target=target,
                raw_output=output,
                parsed_data=parsed_data,
                error=error_output if process.returncode != 0 else None,
                execution_time=execution_time,
                command=" ".join(full_cmd),
            )

        except asyncio.TimeoutError:
            # 超时时必须终止子进程，防止僵尸进程
            if process is not None:
                try:
                    process.kill()
                    await process.wait()  # 等待进程完全终止
                except ProcessLookupError:
                    pass  # 进程已经结束
                except OSError as e:
                    logger.warning(f"终止超时进程失败: {e}")
            return ToolResult(
                tool=tool,
                success=False,
                target=target,
                error=f"执行超时 ({timeout}s)",
                execution_time=timeout,
            )
        except (OSError, ValueError, asyncio.CancelledError) as e:
            # 异常时也要清理进程
            if process is not None:
                try:
                    process.kill()
                    await process.wait()
                except (ProcessLookupError, OSError):
                    pass  # 进程已终止或无法访问
            return ToolResult(
                tool=tool,
                success=False,
                target=target,
                error=str(e),
            )
        finally:
            # 清理临时文件
            nmap_xml = metadata.get("nmap_xml_output")
            if nmap_xml and Path(nmap_xml).exists():
                try:
                    os.unlink(nmap_xml)
                except (OSError, PermissionError) as e:
                    logger.debug(f"清理临时文件失败: {e}")

    def _build_command(
        self, info: ToolInfo, target: str, preset: str, extra_args: Optional[List[str]]
    ) -> Tuple[List[str], Dict[str, Any]]:
        """构建命令行

        Returns:
            Tuple[命令列表, 元数据字典]
            元数据包含临时文件路径等需要后续处理的信息
        """
        cmd = [info.path]
        metadata: Dict[str, Any] = {}

        # 添加预设参数
        preset_args = info.default_args.get(preset, [])
        cmd.extend(preset_args)

        # 工具特定的目标参数
        if info.name == "nmap":
            # 使用 XML 输出以便解析
            # 通过元数据返回 XML 路径，避免实例变量并发问题
            with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
                xml_output = f.name
            cmd.extend(["-oX", xml_output])
            cmd.append(target)
            metadata["nmap_xml_output"] = xml_output
        elif info.name == "nuclei":
            cmd.extend(["-u", target])
        elif info.name == "sqlmap":
            cmd.extend(["-u", target])
        elif info.name == "ffuf":
            # ffuf 需要 FUZZ 占位符
            if "FUZZ" not in target:
                target = target.rstrip("/") + "/FUZZ"
            cmd.extend(["-u", target])
        elif info.name == "masscan":
            cmd.append(target)
        else:
            cmd.append(target)

        # 添加额外参数
        if extra_args:
            cmd.extend(extra_args)

        return cmd, metadata

    def _parse_output(
        self, tool: str, output: str, metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """解析工具输出

        Args:
            tool: 工具名称
            output: 标准输出内容
            metadata: 元数据（包含临时文件路径等）

        Returns:
            解析后的结构化数据
        """
        metadata = metadata or {}

        if tool == "nmap":
            # 从元数据获取 XML 路径（线程安全）
            xml_path = metadata.get("nmap_xml_output")
            if xml_path and Path(xml_path).exists():
                try:
                    with open(xml_path, "r", encoding="utf-8") as f:
                        xml_content = f.read()
                    # 注意: 临时文件在 run() 的 finally 块中清理
                    return ResultParser.parse_nmap_xml(xml_content)
                except (IOError, OSError, ValueError, ET.ParseError) as e:
                    logger.warning(f"解析 Nmap XML 失败: {e}")
            return {"raw": output}

        elif tool == "nuclei":
            return {"findings": ResultParser.parse_nuclei_jsonl(output)}

        elif tool == "sqlmap":
            return ResultParser.parse_sqlmap_output(output)

        elif tool == "ffuf":
            return ResultParser.parse_ffuf_json(output)

        elif tool == "masscan":
            return ResultParser.parse_masscan_json(output)

        return {"raw": output}

    async def run_chain(self, chain_name: str, target: str, **kwargs) -> List[ToolResult]:
        """运行工具链

        Args:
            chain_name: 链名称 (full_recon, vuln_scan, etc.)
            target: 目标

        Returns:
            结果列表
        """
        chains = self.config.get("chains", {})
        chain = chains.get(chain_name)

        if not chain:
            return [
                ToolResult(
                    tool="chain", success=False, target=target, error=f"未知工具链: {chain_name}"
                )
            ]

        results = []
        previous_result = None

        for step in chain:
            tool_name = step.get("name")
            args = step.get("args", [])
            condition = step.get("condition")
            depends_on = step.get("depends_on")

            # 检查条件
            if condition:
                if condition == "has_params" and "?" not in target:
                    logger.info(f"跳过 {tool_name}: 条件不满足 ({condition})")
                    continue

            # 处理依赖
            if depends_on and previous_result:
                # 从前一个结果中提取端口
                if depends_on in ["masscan", "nmap"]:
                    ports = self._extract_ports(previous_result)
                    if ports:
                        args = [a.replace("-p1-10000", f"-p{ports}") for a in args]

            # 执行
            result = await self.run(tool_name, target, extra_args=args, **kwargs)
            results.append(result)
            previous_result = result

            if not result.success:
                logger.warning(f"工具链步骤失败: {tool_name}")
                # 继续执行后续步骤

        return results

    def _extract_ports(self, result: ToolResult) -> str:
        """从扫描结果中提取端口"""
        ports = []

        data = result.parsed_data

        # Nmap 格式
        if "hosts" in data:
            for host in data.get("hosts", []):
                for port_info in host.get("ports", []):
                    if port_info.get("state") == "open":
                        ports.append(str(port_info.get("port")))

        # Masscan 格式
        if "hosts" in data and isinstance(data["hosts"], dict):
            for _, host_info in data["hosts"].items():
                for port_info in host_info.get("ports", []):
                    ports.append(str(port_info.get("port")))

        return ",".join(sorted(set(ports)))


# ==================== 便捷函数 ====================

_manager: Optional[ToolManager] = None


def get_tool_manager() -> ToolManager:
    """获取全局工具管理器实例"""
    global _manager
    if _manager is None:
        _manager = ToolManager()
    return _manager


# 别名 - 兼容性
get_manager = get_tool_manager


async def run_nmap(
    target: str,
    ports: str = "1-1000",
    preset: str = "full",
    extra_args: Optional[List[str]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """运行 Nmap 扫描"""
    args = extra_args or []
    args.extend(["-p", ports])
    result = await get_tool_manager().run("nmap", target, preset, extra_args=args, **kwargs)
    return result.to_dict()


async def run_nuclei(
    target: str, preset: str = "full", extra_args: Optional[List[str]] = None, **kwargs
) -> Dict[str, Any]:
    """运行 Nuclei 漏洞扫描"""
    result = await get_tool_manager().run("nuclei", target, preset, extra_args=extra_args, **kwargs)
    return result.to_dict()


async def run_sqlmap(
    url: str, preset: str = "detect", extra_args: Optional[List[str]] = None, **kwargs
) -> Dict[str, Any]:
    """运行 SQLMap"""
    result = await get_tool_manager().run("sqlmap", url, preset, extra_args=extra_args, **kwargs)
    return result.to_dict()


async def run_ffuf(
    url: str,
    wordlist: Optional[str] = None,
    preset: str = "dir",
    extra_args: Optional[List[str]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """运行 ffuf"""
    args = extra_args or []
    if wordlist:
        args.extend(["-w", wordlist])
    result = await get_tool_manager().run(
        "ffuf", url, preset, extra_args=args if args else None, **kwargs
    )
    return result.to_dict()


async def run_masscan(
    target: str, ports: str = "1-10000", extra_args: Optional[List[str]] = None, **kwargs
) -> Dict[str, Any]:
    """运行 Masscan"""
    args = extra_args or []
    args.extend(["-p", ports])
    result = await get_tool_manager().run("masscan", target, "quick", extra_args=args, **kwargs)
    return result.to_dict()


def check_tools() -> Dict[str, Dict[str, Any]]:
    """检查所有工具状态"""
    return get_manager().get_status()


# 导出
__all__ = [
    "ToolManager",
    "ToolResult",
    "ToolInfo",
    "ToolStatus",
    "ResultParser",
    "get_tool_manager",
    "get_manager",
    "run_nmap",
    "run_nuclei",
    "run_sqlmap",
    "run_ffuf",
    "run_masscan",
    "check_tools",
]
