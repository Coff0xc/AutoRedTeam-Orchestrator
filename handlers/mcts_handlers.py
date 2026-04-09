"""
MCTS 攻击路径规划处理器
提供: plan_attack_path (使用蒙特卡洛树搜索规划最优攻击路径)

授权级别:
- CRITICAL: plan_attack_path (攻击规划)
"""

from typing import Any, Dict, List, Optional

# 授权中间件
from core.security import require_critical_auth

from .error_handling import ErrorCategory, extract_target, handle_errors, validate_inputs
from .tooling import tool


def register_mcts_tools(mcp, counter, logger):
    """注册MCTS攻击规划工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target="target")
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def plan_attack_path(
        target: str,
        target_type: str = "ip",
        open_ports: Optional[Dict[str, str]] = None,
        technologies: Optional[List[str]] = None,
        vulnerabilities: Optional[List[Dict]] = None,
        credentials: Optional[List[Dict]] = None,
        access_level: int = 0,
        iterations: int = 200,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """使用 MCTS 树搜索规划最优攻击路径

        基于当前目标状态（开放端口、已知漏洞、凭证、访问级别），
        通过蒙特卡洛树搜索模拟数百种攻击路径，返回最优攻击序列。

        Args:
            target: 目标地址 (IP/域名/URL)
            target_type: 目标类型 ("ip", "domain", "url", "network")
            open_ports: 已知开放端口 ({"80": "http", "22": "ssh"}, JSON不支持int key)
            technologies: 已知技术栈
            vulnerabilities: 已知漏洞列表 ([{"name": "...", "severity": "high"}])
            credentials: 已获取凭证 ([{"type": "password", "username": "..."}])
            access_level: 当前访问级别 (0=none, 1=user, 2=admin)
            iterations: MCTS迭代次数 (越多越精确，默认200)
            session_id: 从知识图谱会话加载已有信息
        """
        import asyncio

        from core.mcts_planner import AttackState, MCTSPlanner

        # 构建 AttackState
        # JSON 传输中 key 是 str, 需要转为 int
        ports_int: Dict[int, str] = {}
        if open_ports:
            for port_str, service in open_ports.items():
                try:
                    ports_int[int(port_str)] = service
                except (ValueError, TypeError):
                    logger.warning("忽略无效端口: %s", port_str)

        state = AttackState(
            target=target,
            target_type=target_type,
            open_ports=ports_int,
            technologies=technologies or [],
            vulnerabilities=vulnerabilities or [],
            credentials=credentials or [],
            access_level=access_level,
        )

        # 如果提供了 session_id, 尝试从知识图谱补充已知信息
        if session_id:
            try:
                from core.knowledge import KnowledgeManager

                km = KnowledgeManager()
                # 查找目标关联的服务和漏洞
                targets = km.find_targets(target=target)
                for t in targets:
                    services = km.find_services_for_target(t.id)
                    for svc in services:
                        port = svc.properties.get("port")
                        service_name = svc.properties.get("service", "unknown")
                        if port and int(port) not in state.open_ports:
                            state.add_open_port(int(port), service_name)
                        # 查找服务关联的漏洞
                        vulns = km.find_vulns_for_service(svc.id)
                        for v in vulns:
                            state.add_vulnerability(v.to_dict())
            except Exception as e:
                logger.warning("从知识图谱加载会话信息失败: %s", e)

        # 在线程池中执行 MCTS 规划 (CPU密集型)
        planner = MCTSPlanner()
        result = await asyncio.to_thread(planner.plan, state, iterations)

        logger.info(
            "MCTS攻击规划完成: target=%s, iterations=%d, 推荐动作=%d",
            target,
            iterations,
            len(result.get("recommended_actions", [])),
        )
        return {
            "success": True,
            "target": target,
            "target_type": target_type,
            **result,
        }

    counter.add("mcts", 1)
    logger.info("MCTS攻击规划工具注册完成 (1个工具)")
