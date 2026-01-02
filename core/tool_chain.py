#!/usr/bin/env python3
"""
工具链自动编排 - 根据扫描结果自动选择下一步工具
"""

import asyncio
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ToolNode:
    """工具节点"""
    name: str
    params: Dict = field(default_factory=dict)
    status: ToolStatus = ToolStatus.PENDING
    result: Optional[Dict] = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@dataclass
class ResultContext:
    """工具间结果传递上下文"""
    data: Dict = field(default_factory=dict)

    def set(self, tool: str, result: Dict):
        self.data[tool] = result

    def get(self, tool: str) -> Optional[Dict]:
        return self.data.get(tool)

    def get_ports(self) -> List[int]:
        nmap_result = self.data.get("nmap_scan", {})
        return nmap_result.get("ports", [])

    def get_services(self) -> Dict[int, str]:
        nmap_result = self.data.get("nmap_scan", {})
        return nmap_result.get("services", {})

    def get_subdomains(self) -> List[str]:
        subdomain_result = self.data.get("subdomain_enum", {})
        return subdomain_result.get("subdomains", [])

    def get_technologies(self) -> Dict[str, str]:
        httpx_result = self.data.get("httpx_probe", {})
        return httpx_result.get("technologies", {})

    def get_vulnerabilities(self) -> List[Dict]:
        vuln_result = self.data.get("nuclei_scan", {})
        return vuln_result.get("vulnerabilities", [])

    def has_web_service(self) -> bool:
        ports = self.get_ports()
        return any(p in [80, 443, 8080, 8443, 8000, 3000] for p in ports)

    def has_database(self) -> bool:
        ports = self.get_ports()
        return any(p in [3306, 5432, 1433, 1521, 27017, 6379] for p in ports)


class ToolChain:
    """工具链定义"""

    # 工具依赖图
    DEPENDENCY_GRAPH = {
        # 信息收集阶段
        "subdomain_enum": [],
        "nmap_scan": [],
        "httpx_probe": ["subdomain_enum"],

        # 指纹识别阶段
        "whatweb": ["httpx_probe"],
        "wappalyzer": ["httpx_probe"],

        # 漏洞扫描阶段
        "nuclei_scan": ["httpx_probe"],
        "nikto_scan": ["httpx_probe"],

        # Web攻击阶段
        "sqli_test": ["nuclei_scan"],
        "xss_scan": ["nuclei_scan"],
        "dir_scan": ["httpx_probe"],

        # 漏洞验证阶段
        "verify_vuln": ["nuclei_scan", "sqli_test", "xss_scan"],

        # 利用阶段
        "exploit_search": ["verify_vuln"],
    }

    # 工具触发条件
    TRIGGER_CONDITIONS = {
        "web_vuln_scan": lambda ctx: ctx.has_web_service(),
        "smb_enum": lambda ctx: 445 in ctx.get_ports(),
        "mysql_audit": lambda ctx: 3306 in ctx.get_ports(),
        "redis_scan": lambda ctx: 6379 in ctx.get_ports(),
        "mongodb_scan": lambda ctx: 27017 in ctx.get_ports(),
        "ssh_audit": lambda ctx: 22 in ctx.get_ports(),
        "ftp_scan": lambda ctx: 21 in ctx.get_ports(),
    }

    @classmethod
    def get_dependencies(cls, tool: str) -> List[str]:
        return cls.DEPENDENCY_GRAPH.get(tool, [])

    @classmethod
    def get_next_tools(cls, completed_tool: str, context: ResultContext) -> List[str]:
        """根据完成的工具和上下文获取下一步工具"""
        next_tools = []

        # 查找依赖当前工具的所有工具
        for tool, deps in cls.DEPENDENCY_GRAPH.items():
            if completed_tool in deps:
                next_tools.append(tool)

        # 检查条件触发的工具
        for tool, condition in cls.TRIGGER_CONDITIONS.items():
            if condition(context) and tool not in next_tools:
                next_tools.append(tool)

        return next_tools


class ChainExecutor:
    """工具链执行器"""

    def __init__(self, tool_registry: Optional[Any] = None):
        self.tool_registry = tool_registry
        self.context = ResultContext()
        self.nodes: Dict[str, ToolNode] = {}
        self.execution_order: List[str] = []

    def build_chain(self, start_tools: List[str], target: str) -> List[ToolNode]:
        """构建执行链"""
        chain = []
        visited = set()
        queue = list(start_tools)

        while queue:
            tool = queue.pop(0)
            if tool in visited:
                continue

            visited.add(tool)
            node = ToolNode(name=tool, params={"target": target})
            chain.append(node)
            self.nodes[tool] = node

            # 添加依赖工具
            for dep in ToolChain.get_dependencies(tool):
                if dep not in visited:
                    queue.append(dep)

        # 拓扑排序
        return self._topological_sort(chain)

    def _topological_sort(self, nodes: List[ToolNode]) -> List[ToolNode]:
        """拓扑排序确保依赖顺序"""
        in_degree = {n.name: 0 for n in nodes}
        graph = {n.name: [] for n in nodes}

        for node in nodes:
            for dep in ToolChain.get_dependencies(node.name):
                if dep in graph:
                    graph[dep].append(node.name)
                    in_degree[node.name] += 1

        queue = [n for n in in_degree if in_degree[n] == 0]
        sorted_names = []

        while queue:
            name = queue.pop(0)
            sorted_names.append(name)
            for neighbor in graph.get(name, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        return [self.nodes[name] for name in sorted_names if name in self.nodes]

    async def execute(self, chain: List[ToolNode], target: str) -> Dict:
        """执行工具链"""
        results = {"target": target, "tools": {}, "summary": {}}

        for node in chain:
            # 检查依赖是否完成
            if not self._check_dependencies(node):
                node.status = ToolStatus.SKIPPED
                logger.info(f"跳过 {node.name}: 依赖未满足")
                continue

            # 执行工具
            logger.info(f"执行 {node.name}...")
            node.status = ToolStatus.RUNNING
            node.start_time = datetime.now()

            try:
                result = await self._run_tool(node, target)
                node.result = result
                node.status = ToolStatus.COMPLETED
                self.context.set(node.name, result)
                results["tools"][node.name] = result

                # 动态添加后续工具
                self._adjust_chain(chain, node)

            except Exception as e:
                node.status = ToolStatus.FAILED
                node.error = str(e)
                logger.error(f"{node.name} 执行失败: {e}")

            finally:
                node.end_time = datetime.now()

        # 生成摘要
        results["summary"] = self._generate_summary(chain)
        return results

    def _check_dependencies(self, node: ToolNode) -> bool:
        """检查依赖是否满足"""
        for dep in ToolChain.get_dependencies(node.name):
            if dep in self.nodes:
                dep_node = self.nodes[dep]
                if dep_node.status != ToolStatus.COMPLETED:
                    return False
        return True

    async def _run_tool(self, node: ToolNode, target: str) -> Dict:
        """运行单个工具"""
        if self.tool_registry:
            return await self.tool_registry.execute_async(node.name, node.params)

        # 模拟执行
        await asyncio.sleep(0.1)
        return {"status": "simulated", "tool": node.name, "target": target}

    def _adjust_chain(self, chain: List[ToolNode], completed_node: ToolNode):
        """根据结果动态调整链"""
        next_tools = ToolChain.get_next_tools(completed_node.name, self.context)

        for tool in next_tools:
            if tool not in self.nodes:
                new_node = ToolNode(
                    name=tool,
                    params={"target": completed_node.params.get("target")}
                )
                self.nodes[tool] = new_node
                chain.append(new_node)
                logger.info(f"动态添加工具: {tool}")

    def _generate_summary(self, chain: List[ToolNode]) -> Dict:
        """生成执行摘要"""
        completed = sum(1 for n in chain if n.status == ToolStatus.COMPLETED)
        failed = sum(1 for n in chain if n.status == ToolStatus.FAILED)
        skipped = sum(1 for n in chain if n.status == ToolStatus.SKIPPED)

        return {
            "total_tools": len(chain),
            "completed": completed,
            "failed": failed,
            "skipped": skipped,
            "success_rate": completed / len(chain) if chain else 0,
            "execution_order": [n.name for n in chain],
        }


class AutoReconChain:
    """自动化侦察链 - 预定义的常用工具链"""

    @staticmethod
    def web_recon(target: str) -> List[str]:
        """Web应用侦察链"""
        return [
            "subdomain_enum",
            "httpx_probe",
            "whatweb",
            "dir_scan",
            "nuclei_scan",
        ]

    @staticmethod
    def full_recon(target: str) -> List[str]:
        """全量侦察链"""
        return [
            "subdomain_enum",
            "nmap_scan",
            "httpx_probe",
            "whatweb",
            "dir_scan",
            "nuclei_scan",
            "nikto_scan",
        ]

    @staticmethod
    def vuln_scan(target: str) -> List[str]:
        """漏洞扫描链"""
        return [
            "httpx_probe",
            "nuclei_scan",
            "sqli_test",
            "xss_scan",
            "verify_vuln",
        ]

    @staticmethod
    def internal_recon(target: str) -> List[str]:
        """内网侦察链"""
        return [
            "nmap_scan",
            "smb_enum",
            "ldap_enum",
            "kerberos_enum",
        ]


async def run_auto_chain(target: str, chain_type: str = "web_recon") -> Dict:
    """运行自动化工具链"""
    executor = ChainExecutor()

    # 选择工具链
    chain_map = {
        "web_recon": AutoReconChain.web_recon,
        "full_recon": AutoReconChain.full_recon,
        "vuln_scan": AutoReconChain.vuln_scan,
        "internal_recon": AutoReconChain.internal_recon,
    }

    chain_func = chain_map.get(chain_type, AutoReconChain.web_recon)
    start_tools = chain_func(target)

    # 构建并执行链
    chain = executor.build_chain(start_tools, target)
    results = await executor.execute(chain, target)

    return results
