#!/usr/bin/env python3
"""
MCTS (Monte Carlo Tree Search) 攻击路径规划器

基于蒙特卡洛树搜索的智能攻击路径规划，替代纯规则匹配的静态引擎。

核心思想：
- 将渗透测试建模为决策树
- 每个节点代表一个攻击状态
- 每条边代表一个攻击动作
- 通过模拟和反向传播学习最优攻击路径

Usage:
    from core.mcts_planner import MCTSPlanner, AttackState

    planner = MCTSPlanner()
    state = AttackState(target="192.168.1.1", target_type="ip")
    state.add_open_port(80, "http")
    state.add_open_port(22, "ssh")

    plan = planner.plan(state, iterations=100)
"""

import hashlib
import logging
import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# 默认探索权重常量 (sqrt(2))
DEFAULT_EXPLORATION_WEIGHT = math.sqrt(2)


class ActionType(Enum):
    """攻击动作类型"""

    PORT_SCAN = "port_scan"
    SERVICE_DETECT = "service_detect"
    VULN_SCAN = "vuln_scan"
    WEB_SCAN = "web_scan"
    BRUTE_FORCE = "brute_force"
    EXPLOIT = "exploit"
    PRIVESC = "privesc"
    LATERAL_MOVE = "lateral_move"
    DATA_EXFIL = "data_exfil"
    CREDENTIAL_DUMP = "credential_dump"


@dataclass
class Action:
    """攻击动作"""

    type: ActionType
    name: str
    tool: str
    params: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.5  # 0-1, 越高越危险
    estimated_reward: float = 0.5  # 预估收益

    def __hash__(self):
        return hash((self.type, self.name, self.tool))

    def __eq__(self, other):
        if not isinstance(other, Action):
            return NotImplemented
        return self.type == other.type and self.name == other.name and self.tool == other.tool


@dataclass
class AttackState:
    """攻击状态

    记录渗透测试过程中的完整状态信息
    """

    target: str
    target_type: str  # ip, domain, url, network
    open_ports: Dict[int, str] = field(default_factory=dict)  # port -> service
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    access_level: int = 0  # 0=none, 1=user, 2=root/admin
    completed_actions: Set[str] = field(default_factory=set)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def add_open_port(self, port: int, service: str = "unknown"):
        """添加发现的端口"""
        self.open_ports[port] = service

    def add_vulnerability(self, vuln: Dict[str, Any]):
        """添加发现的漏洞"""
        self.vulnerabilities.append(vuln)

    def add_credential(self, cred: Dict[str, Any]):
        """添加获取的凭证"""
        self.credentials.append(cred)

    def state_hash(self) -> str:
        """计算状态哈希（用于去重和缓存）"""
        state_str = (
            f"{self.target}|{self.target_type}|"
            f"{sorted(self.open_ports.items())}|"
            f"{len(self.vulnerabilities)}|"
            f"{len(self.credentials)}|"
            f"{self.access_level}|"
            f"{sorted(self.completed_actions)}"
        )
        return hashlib.sha256(state_str.encode()).hexdigest()[:16]

    def clone(self) -> "AttackState":
        """深拷贝状态"""
        new_state = AttackState(
            target=self.target,
            target_type=self.target_type,
            open_ports=dict(self.open_ports),
            technologies=list(self.technologies),
            vulnerabilities=[dict(v) for v in self.vulnerabilities],
            credentials=[dict(c) for c in self.credentials],
            access_level=self.access_level,
            completed_actions=set(self.completed_actions),
            findings=[dict(f) for f in self.findings],
        )
        return new_state

    def is_terminal(self) -> bool:
        """是否为终态（达到目标或无可用动作）"""
        return self.access_level >= 2

    def reward(self) -> float:
        """计算当前状态的奖励值"""
        r = 0.0

        # 端口发现奖励
        r += min(len(self.open_ports) * 0.05, 0.2)

        # 漏洞发现奖励
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "low")
            severity_reward = {
                "critical": 0.3,
                "high": 0.2,
                "medium": 0.1,
                "low": 0.05,
            }
            r += severity_reward.get(severity, 0.05)

        # 凭证获取奖励
        r += len(self.credentials) * 0.15

        # 权限提升奖励
        r += self.access_level * 0.25

        return min(r, 1.0)


class MCTSNode:
    """MCTS 树节点"""

    def __init__(
        self,
        state: AttackState,
        action: Optional[Action] = None,
        parent: Optional["MCTSNode"] = None,
    ):
        self.state = state
        self.action = action  # 到达此节点的动作
        self.parent = parent
        self.children: List["MCTSNode"] = []
        self.visits: int = 0
        self.total_reward: float = 0.0
        self._untried_actions: Optional[List[Action]] = None

    @property
    def is_fully_expanded(self) -> bool:
        """是否所有动作都已扩展"""
        return self._untried_actions is not None and len(self._untried_actions) == 0

    @property
    def is_terminal(self) -> bool:
        """是否为终态"""
        return self.state.is_terminal()

    @property
    def average_reward(self) -> float:
        """平均奖励"""
        if self.visits == 0:
            return 0.0
        return self.total_reward / self.visits

    def ucb1(self, exploration_weight: float = DEFAULT_EXPLORATION_WEIGHT) -> float:
        """UCB1 选择公式

        Args:
            exploration_weight: 探索权重 (默认 sqrt(2))

        Returns:
            UCB1 值
        """
        if self.visits == 0:
            return float("inf")

        # Guard for parent is None or parent has no visits
        if self.parent is None or self.parent.visits == 0:
            return self.total_reward / self.visits

        exploitation = self.total_reward / self.visits
        exploration = exploration_weight * math.sqrt(
            math.log(self.parent.visits) / self.visits
        )

        return exploitation + exploration

    def best_child(self, exploration_weight: float = DEFAULT_EXPLORATION_WEIGHT) -> Optional["MCTSNode"]:
        """选择最优子节点"""
        if not self.children:
            return None
        return max(self.children, key=lambda c: c.ucb1(exploration_weight))

    def best_action_child(self) -> Optional["MCTSNode"]:
        """选择最佳动作子节点（用于最终决策，使用访问次数）"""
        if not self.children:
            return None
        return max(self.children, key=lambda c: c.visits)


class ActionGenerator:
    """动作生成器

    根据当前状态生成可执行的攻击动作集合
    """

    # 端口 -> 服务映射
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 445: "smb", 1433: "mssql", 1521: "oracle",
        3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-alt",
        8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
    }

    # 服务 -> 可用攻击动作
    SERVICE_ACTIONS = {
        "http": [
            Action(ActionType.WEB_SCAN, "Web漏洞扫描", "nikto"),
            Action(ActionType.WEB_SCAN, "目录枚举", "dirb"),
            Action(ActionType.VULN_SCAN, "Nuclei扫描", "nuclei"),
            Action(ActionType.BRUTE_FORCE, "Web认证爆破", "hydra", risk_score=0.6),
        ],
        "https": [
            Action(ActionType.WEB_SCAN, "HTTPS漏洞扫描", "nikto"),
            Action(ActionType.WEB_SCAN, "SSL/TLS检测", "sslscan"),
            Action(ActionType.VULN_SCAN, "Nuclei扫描", "nuclei"),
        ],
        "ssh": [
            Action(ActionType.BRUTE_FORCE, "SSH爆破", "hydra", risk_score=0.4, estimated_reward=0.3),
        ],
        "ftp": [
            Action(ActionType.BRUTE_FORCE, "FTP爆破", "hydra", risk_score=0.3, estimated_reward=0.4),
            Action(ActionType.VULN_SCAN, "FTP匿名检测", "nmap", estimated_reward=0.5),
        ],
        "smb": [
            Action(ActionType.VULN_SCAN, "SMB漏洞检测", "nmap", estimated_reward=0.6),
            Action(ActionType.BRUTE_FORCE, "SMB爆破", "hydra", risk_score=0.5),
            Action(ActionType.EXPLOIT, "EternalBlue利用", "msf", risk_score=0.7, estimated_reward=0.9),
        ],
        "mysql": [
            Action(ActionType.BRUTE_FORCE, "MySQL爆破", "hydra", risk_score=0.4),
            Action(ActionType.VULN_SCAN, "MySQL漏洞检测", "nmap"),
        ],
        "redis": [
            Action(ActionType.EXPLOIT, "Redis未授权访问", "redis-cli", risk_score=0.3, estimated_reward=0.8),
        ],
        "mongodb": [
            Action(ActionType.EXPLOIT, "MongoDB未授权访问", "mongo", risk_score=0.3, estimated_reward=0.7),
        ],
        "elasticsearch": [
            Action(ActionType.EXPLOIT, "ES未授权访问", "curl", risk_score=0.3, estimated_reward=0.7),
        ],
        "rdp": [
            Action(ActionType.BRUTE_FORCE, "RDP爆破", "hydra", risk_score=0.5),
            Action(ActionType.VULN_SCAN, "BlueKeep检测", "nmap", estimated_reward=0.7),
        ],
    }

    def generate(self, state: AttackState) -> List[Action]:
        """根据状态生成可用动作"""
        actions = []

        # 阶段1：基础侦察
        if "port_scan" not in state.completed_actions:
            actions.append(
                Action(ActionType.PORT_SCAN, "全端口扫描", "nmap",
                       params={"target": state.target}, estimated_reward=0.3)
            )

        if state.open_ports and "service_detect" not in state.completed_actions:
            actions.append(
                Action(ActionType.SERVICE_DETECT, "服务识别", "nmap",
                       params={"ports": list(state.open_ports.keys())},
                       estimated_reward=0.2)
            )

        # 阶段2：基于发现的服务生成动作
        for port, service in state.open_ports.items():
            service_lower = service.lower()

            # 查找匹配的服务动作
            for svc_key, svc_actions in self.SERVICE_ACTIONS.items():
                if svc_key in service_lower or service_lower in svc_key:
                    for action in svc_actions:
                        action_key = f"{action.name}_{port}"
                        if action_key not in state.completed_actions:
                            # 创建带端口参数的动作副本
                            new_action = Action(
                                type=action.type,
                                name=f"{action.name}(:{port})",
                                tool=action.tool,
                                params={"port": port, "target": state.target},
                                risk_score=action.risk_score,
                                estimated_reward=action.estimated_reward,
                            )
                            actions.append(new_action)

        # 阶段3：基于发现的漏洞生成利用动作
        for vuln in state.vulnerabilities:
            vuln_key = f"exploit_{vuln.get('id', vuln.get('name', ''))}"
            if vuln_key not in state.completed_actions:
                severity = vuln.get("severity", "medium")
                reward = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3}
                actions.append(
                    Action(
                        ActionType.EXPLOIT,
                        f"利用{vuln.get('id', vuln.get('name', 'unknown'))}",
                        "metasploit",
                        params={"vuln": vuln},
                        risk_score=0.7,
                        estimated_reward=reward.get(severity, 0.5),
                    )
                )

        # 阶段4：有凭证时的动作
        if state.credentials:
            if "lateral_move" not in state.completed_actions:
                actions.append(
                    Action(ActionType.LATERAL_MOVE, "横向移动", "ssh",
                           risk_score=0.6, estimated_reward=0.7)
                )

        # 阶段5：有初始访问时的权限提升
        if state.access_level == 1 and "privesc" not in state.completed_actions:
            actions.append(
                Action(ActionType.PRIVESC, "权限提升", "linpeas",
                       risk_score=0.5, estimated_reward=0.8)
            )

        # 阶段6：高权限数据获取
        if state.access_level >= 1 and "credential_dump" not in state.completed_actions:
            actions.append(
                Action(ActionType.CREDENTIAL_DUMP, "凭证提取", "mimikatz",
                       risk_score=0.6, estimated_reward=0.6)
            )

        return actions


class AttackSimulator:
    """攻击模拟器

    模拟攻击动作执行的结果（用于 MCTS 的 simulation 阶段）
    """

    # 动作类型的基础成功率
    BASE_SUCCESS_RATES = {
        ActionType.PORT_SCAN: 0.95,
        ActionType.SERVICE_DETECT: 0.90,
        ActionType.VULN_SCAN: 0.85,
        ActionType.WEB_SCAN: 0.80,
        ActionType.BRUTE_FORCE: 0.20,
        ActionType.EXPLOIT: 0.40,
        ActionType.PRIVESC: 0.30,
        ActionType.LATERAL_MOVE: 0.35,
        ActionType.DATA_EXFIL: 0.70,
        ActionType.CREDENTIAL_DUMP: 0.50,
    }

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    def simulate_action(self, state: AttackState, action: Action) -> AttackState:
        """模拟执行一个动作，返回新状态"""
        new_state = state.clone()
        new_state.completed_actions.add(action.name)

        success_rate = self.BASE_SUCCESS_RATES.get(action.type, 0.5)

        if self._rng.random() < success_rate:
            self._apply_success(new_state, action)
        else:
            self._apply_failure(new_state, action)

        return new_state

    def _apply_success(self, state: AttackState, action: Action):
        """应用成功结果"""
        if action.type == ActionType.PORT_SCAN:
            # 模拟发现端口
            common_ports = [22, 80, 443, 3306, 8080]
            for port in common_ports:
                if self._rng.random() < 0.4:
                    service = ActionGenerator.PORT_SERVICE_MAP.get(port, "unknown")
                    state.add_open_port(port, service)

        elif action.type == ActionType.SERVICE_DETECT:
            # 更新服务信息
            for port in list(state.open_ports.keys()):
                if state.open_ports[port] == "unknown":
                    state.open_ports[port] = ActionGenerator.PORT_SERVICE_MAP.get(port, "unknown")

        elif action.type == ActionType.VULN_SCAN:
            if self._rng.random() < 0.3:
                state.add_vulnerability({
                    "name": "Simulated Vuln",
                    "severity": self._rng.choice(["critical", "high", "medium", "low"]),
                    "simulated": True,
                })

        elif action.type == ActionType.WEB_SCAN:
            if self._rng.random() < 0.4:
                state.add_vulnerability({
                    "name": "Web Vuln",
                    "severity": self._rng.choice(["high", "medium"]),
                    "simulated": True,
                })

        elif action.type == ActionType.BRUTE_FORCE:
            if self._rng.random() < 0.3:
                state.add_credential({"type": "password", "simulated": True})

        elif action.type == ActionType.EXPLOIT:
            if state.access_level < 1:
                state.access_level = 1
            state.findings.append({"type": "exploit_success", "action": action.name})

        elif action.type == ActionType.PRIVESC:
            state.access_level = 2

        elif action.type == ActionType.CREDENTIAL_DUMP:
            state.add_credential({"type": "hash", "simulated": True})

        elif action.type == ActionType.LATERAL_MOVE:
            state.findings.append({"type": "lateral_success", "action": action.name})

    def _apply_failure(self, state: AttackState, action: Action):
        """应用失败结果（通常无状态变化）"""
        state.findings.append({"type": "action_failed", "action": action.name})


class MCTSPlanner:
    """MCTS 攻击路径规划器

    使用蒙特卡洛树搜索找到最优攻击路径

    Args:
        exploration_weight: UCB1 探索权重 (默认 sqrt(2))
        max_depth: 最大搜索深度
        seed: 随机种子（用于可复现性）
    """

    def __init__(
        self,
        exploration_weight: float = DEFAULT_EXPLORATION_WEIGHT,
        max_depth: int = 10,
        seed: Optional[int] = None,
    ):
        self.exploration_weight = exploration_weight
        self.max_depth = max_depth
        self.action_generator = ActionGenerator()
        self.simulator = AttackSimulator(seed=seed)
        self._rng = random.Random(seed)

    def plan(
        self,
        initial_state: AttackState,
        iterations: int = 100,
    ) -> Dict[str, Any]:
        """执行 MCTS 规划

        Args:
            initial_state: 初始攻击状态
            iterations: MCTS 迭代次数

        Returns:
            包含推荐动作序列和统计信息的字典
        """
        logger.debug("MCTS规划开始: %d次迭代, 最大深度=%d", iterations, self.max_depth)

        root = MCTSNode(state=initial_state)

        for i in range(iterations):
            node = self._select(root)
            if not node.is_terminal:
                node = self._expand(node)
            reward = self._simulate(node)
            self._backpropagate(node, reward)

        # 提取最优路径
        best_path = self._extract_best_path(root)
        stats = self._collect_stats(root)

        return {
            "recommended_actions": [
                {
                    "name": action.name,
                    "type": action.type.value,
                    "tool": action.tool,
                    "params": action.params,
                    "risk_score": action.risk_score,
                    "estimated_reward": action.estimated_reward,
                    "visit_count": visits,
                    "average_reward": avg_reward,
                }
                for action, visits, avg_reward in best_path
            ],
            "total_iterations": iterations,
            "tree_stats": stats,
        }

    def _select(self, node: MCTSNode) -> MCTSNode:
        """Selection 阶段：从根节点向下选择"""
        current = node
        depth = 0

        while not current.is_terminal and depth < self.max_depth:
            if not current.is_fully_expanded:
                return current
            best = current.best_child(self.exploration_weight)
            if best is None:
                return current
            current = best
            depth += 1

        return current

    def _expand(self, node: MCTSNode) -> MCTSNode:
        """Expansion 阶段：扩展一个新子节点"""
        if node._untried_actions is None:
            node._untried_actions = self.action_generator.generate(node.state)

        if not node._untried_actions:
            return node

        action = node._untried_actions.pop()

        # 模拟执行动作
        new_state = self.simulator.simulate_action(node.state, action)

        child = MCTSNode(state=new_state, action=action, parent=node)
        node.children.append(child)

        return child

    def _simulate(self, node: MCTSNode) -> float:
        """Simulation 阶段：随机模拟到终态"""
        state = node.state.clone()
        depth = 0

        while not state.is_terminal() and depth < self.max_depth:
            actions = self.action_generator.generate(state)
            if not actions:
                break

            # 随机选择动作（可加启发式偏向高收益动作）
            weights = [a.estimated_reward + 0.1 for a in actions]
            action = self._rng.choices(actions, weights=weights, k=1)[0]

            state = self.simulator.simulate_action(state, action)
            depth += 1

        return state.reward()

    def _backpropagate(self, node: MCTSNode, reward: float):
        """Backpropagation 阶段：反向传播奖励"""
        current = node
        while current is not None:
            current.visits += 1
            current.total_reward += reward
            current = current.parent

    def _extract_best_path(
        self, root: MCTSNode
    ) -> List[Tuple[Action, int, float]]:
        """提取最优路径"""
        path = []
        current = root

        while current.children:
            best = current.best_action_child()
            if best is None:
                break
            if best.action:
                path.append((
                    best.action,
                    best.visits,
                    best.average_reward,
                ))
            current = best

        return path

    def _collect_stats(self, root: MCTSNode) -> Dict[str, Any]:
        """收集树统计信息"""
        total_nodes = 0
        max_depth = 0
        leaf_nodes = 0

        def _traverse(node: MCTSNode, depth: int):
            nonlocal total_nodes, max_depth, leaf_nodes
            total_nodes += 1
            max_depth = max(max_depth, depth)
            if not node.children:
                leaf_nodes += 1
            for child in node.children:
                _traverse(child, depth + 1)

        _traverse(root, 0)

        return {
            "total_nodes": total_nodes,
            "max_depth": max_depth,
            "leaf_nodes": leaf_nodes,
            "root_visits": root.visits,
            "root_average_reward": root.average_reward,
        }

    def get_action_rankings(self, root_state: AttackState, iterations: int = 50) -> List[Dict]:
        """获取动作排名

        对初始状态的所有可用动作进行排名

        Args:
            root_state: 初始状态
            iterations: MCTS 迭代次数

        Returns:
            按推荐度排序的动作列表
        """
        result = self.plan(root_state, iterations)
        return result["recommended_actions"]
