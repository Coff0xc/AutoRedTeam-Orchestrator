#!/usr/bin/env python3
"""
Nmap扫描工具集
"""

import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List

import defusedxml.ElementTree as ET  # 防止 XXE 攻击

from core.registry import BaseTool, ToolCategory, ToolParameter
from utils.terminal_output import run_with_realtime_output

logger = logging.getLogger(__name__)


class NmapBaseTool(BaseTool):
    """Nmap工具基类"""

    def _run_nmap(self, args: List[str], target: str) -> Dict[str, Any]:
        """运行Nmap命令"""
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_output = tmp.name

        try:
            # 增加 -v 参数以确保在终端有实时输出
            # 注意：我们同时输出到 stdout (实时显示) 和 XML文件 (程序解析)
            if "-v" not in args:
                args.insert(0, "-v")

            cmd = ["nmap"] + args + ["-oX", xml_output, target]

            # 使用实时输出运行器
            result = run_with_realtime_output(
                cmd, tool_name=self.name, target=target, timeout=self.timeout
            )

            if not result["success"] and not os.path.exists(xml_output):
                return {
                    "success": False,
                    "error": result.get("error", "Unknown error"),
                    "stderr": result.get("stderr"),
                    "command": " ".join(cmd),
                }

            # 解析XML输出
            if os.path.exists(xml_output) and os.path.getsize(xml_output) > 0:
                parsed = self._parse_nmap_xml(xml_output)
                parsed["command"] = " ".join(cmd)
                parsed["raw_output"] = result.get("stdout", "")
                return parsed
            else:
                return {
                    "success": False,
                    "error": "未生成XML输出文件",
                    "raw_output": result.get("stdout", ""),
                }

        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if os.path.exists(xml_output):
                os.unlink(xml_output)

    def _parse_nmap_xml(self, xml_file: str) -> Dict[str, Any]:
        """解析Nmap XML输出"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            result = {"success": True, "hosts": [], "scan_info": {}}

            # 扫描信息
            scaninfo = root.find("scaninfo")
            if scaninfo is not None:
                result["scan_info"] = {
                    "type": scaninfo.get("type"),
                    "protocol": scaninfo.get("protocol"),
                    "services": scaninfo.get("services"),
                }

            # 主机信息
            for host in root.findall("host"):
                host_data = self._parse_host(host)
                if host_data:
                    result["hosts"].append(host_data)

            result["host_count"] = len(result["hosts"])

            return result

        except Exception as e:
            logger.error(f"解析Nmap XML失败: {e}")
            return {"success": False, "error": f"XML解析失败: {str(e)}"}

    def _parse_host(self, host_elem) -> Dict[str, Any]:
        """解析主机信息"""
        host_data = {"status": "unknown", "addresses": [], "hostnames": [], "ports": [], "os": None}

        # 状态
        status = host_elem.find("status")
        if status is not None:
            host_data["status"] = status.get("state")

        # 地址
        for addr in host_elem.findall("address"):
            host_data["addresses"].append({"addr": addr.get("addr"), "type": addr.get("addrtype")})

        # 主机名
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            for hostname in hostnames.findall("hostname"):
                host_data["hostnames"].append(
                    {"name": hostname.get("name"), "type": hostname.get("type")}
                )

        # 端口
        ports = host_elem.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                port_data = {
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "state": "unknown",
                    "service": None,
                }

                state = port.find("state")
                if state is not None:
                    port_data["state"] = state.get("state")

                service = port.find("service")
                if service is not None:
                    port_data["service"] = {
                        "name": service.get("name"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "extrainfo": service.get("extrainfo"),
                    }

                # 脚本输出
                scripts = []
                for script in port.findall("script"):
                    scripts.append({"id": script.get("id"), "output": script.get("output")})
                if scripts:
                    port_data["scripts"] = scripts

                host_data["ports"].append(port_data)

        # 操作系统检测
        os_elem = host_elem.find("os")
        if os_elem is not None:
            os_matches = []
            for osmatch in os_elem.findall("osmatch"):
                os_matches.append(
                    {"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")}
                )
            if os_matches:
                host_data["os"] = os_matches

        return host_data


@dataclass
class NmapScanTool(NmapBaseTool):
    """Nmap标准扫描"""

    name: str = "nmap_scan"
    description: str = "Nmap端口扫描 - 扫描目标的开放端口和服务"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("target", "string", "目标IP或域名", required=True),
            ToolParameter(
                "ports", "string", "端口范围 (如: 1-1000, 22,80,443)", required=False, default="-"
            ),
            ToolParameter(
                "scan_type",
                "string",
                "扫描类型",
                required=False,
                default="sS",
                choices=["sS", "sT", "sU", "sA", "sW"],
            ),
            ToolParameter("timing", "string", "时序模板 (T0-T5)", required=False, default="T4"),
        ]
    )
    requires_root: bool = True
    timeout: int = 600

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        ports = params.get("ports", "-")
        scan_type = params.get("scan_type", "sS")
        timing = params.get("timing", "T4")

        args = [f"-{scan_type}", f"-{timing}"]
        if ports != "-":
            args.extend(["-p", ports])

        return self._run_nmap(args, target)


@dataclass
class NmapQuickScanTool(NmapBaseTool):
    """Nmap快速扫描"""

    name: str = "nmap_quick"
    description: str = "Nmap快速扫描 - 快速扫描常用端口"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("target", "string", "目标IP或域名", required=True),
        ]
    )
    requires_root: bool = True
    timeout: int = 120

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        args = ["-sS", "-T4", "-F"]  # 快速扫描常用端口
        return self._run_nmap(args, target)


@dataclass
class NmapServiceScanTool(NmapBaseTool):
    """Nmap服务版本扫描"""

    name: str = "nmap_service"
    description: str = "Nmap服务扫描 - 识别服务版本信息"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("target", "string", "目标IP或域名", required=True),
            ToolParameter("ports", "string", "端口范围", required=False, default="-"),
            ToolParameter("intensity", "integer", "版本检测强度 (0-9)", required=False, default=7),
        ]
    )
    requires_root: bool = True
    timeout: int = 900

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        ports = params.get("ports", "-")
        intensity = params.get("intensity", 7)

        args = ["-sV", f"--version-intensity={intensity}", "-T4"]
        if ports != "-":
            args.extend(["-p", ports])

        return self._run_nmap(args, target)


@dataclass
class NmapOSScanTool(NmapBaseTool):
    """Nmap操作系统检测"""

    name: str = "nmap_os"
    description: str = "Nmap操作系统检测 - 识别目标操作系统"
    category: ToolCategory = ToolCategory.RECON
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("target", "string", "目标IP或域名", required=True),
        ]
    )
    requires_root: bool = True
    timeout: int = 300

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        args = ["-O", "--osscan-guess", "-T4"]
        return self._run_nmap(args, target)


@dataclass
class NmapVulnScanTool(NmapBaseTool):
    """Nmap漏洞扫描"""

    name: str = "nmap_vuln"
    description: str = "Nmap漏洞扫描 - 使用NSE脚本检测已知漏洞"
    category: ToolCategory = ToolCategory.VULN_SCAN
    parameters: List[ToolParameter] = field(
        default_factory=lambda: [
            ToolParameter("target", "string", "目标IP或域名", required=True),
            ToolParameter("ports", "string", "端口范围", required=False, default="-"),
            ToolParameter(
                "scripts",
                "string",
                "NSE脚本类别",
                required=False,
                default="vuln",
                choices=["vuln", "exploit", "auth", "default", "discovery", "safe"],
            ),
        ]
    )
    requires_root: bool = True
    timeout: int = 1800

    def execute(self, params: Dict[str, Any], session_id: str = None) -> Dict[str, Any]:
        target = params["target"]
        ports = params.get("ports", "-")
        scripts = params.get("scripts", "vuln")

        args = ["-sV", f"--script={scripts}", "-T4"]
        if ports != "-":
            args.extend(["-p", ports])

        return self._run_nmap(args, target)
