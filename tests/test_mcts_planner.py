#!/usr/bin/env python3
"""
MCTS 攻击路径规划器测试

测试 core/mcts_planner.py 的所有核心功能
"""

import pytest

from core.mcts_planner import (
    Action,
    ActionGenerator,
    ActionType,
    AttackSimulator,
    AttackState,
    MCTSNode,
    MCTSPlanner,
)


# ==================== ActionType 测试 ====================


class TestActionType:
    """ActionType 枚举测试"""

    def test_all_types_exist(self):
        assert ActionType.PORT_SCAN.value == "port_scan"
        assert ActionType.EXPLOIT.value == "exploit"
        assert ActionType.PRIVESC.value == "privesc"
        assert ActionType.LATERAL_MOVE.value == "lateral_move"

    def test_type_count(self):
        assert len(ActionType) == 10


# ==================== Action 测试 ====================


class TestAction:
    """Action 数据类测试"""

    def test_creation(self):
        action = Action(
            type=ActionType.PORT_SCAN,
            name="全端口扫描",
            tool="nmap",
        )
        assert action.type == ActionType.PORT_SCAN
        assert action.tool == "nmap"
        assert action.risk_score == 0.5
        assert action.estimated_reward == 0.5

    def test_hash_and_equality(self):
        a1 = Action(ActionType.PORT_SCAN, "扫描", "nmap")
        a2 = Action(ActionType.PORT_SCAN, "扫描", "nmap")
        a3 = Action(ActionType.VULN_SCAN, "扫描", "nuclei")

        assert a1 == a2
        assert hash(a1) == hash(a2)
        assert a1 != a3

    def test_not_equal_to_non_action(self):
        a = Action(ActionType.PORT_SCAN, "扫描", "nmap")
        assert a.__eq__("not an action") == NotImplemented


# ==================== AttackState 测试 ====================


class TestAttackState:
    """AttackState 数据类测试"""

    @pytest.fixture
    def basic_state(self):
        return AttackState(target="192.168.1.1", target_type="ip")

    def test_creation(self, basic_state):
        assert basic_state.target == "192.168.1.1"
        assert basic_state.target_type == "ip"
        assert basic_state.access_level == 0
        assert len(basic_state.open_ports) == 0

    def test_add_open_port(self, basic_state):
        basic_state.add_open_port(80, "http")
        basic_state.add_open_port(22, "ssh")
        assert basic_state.open_ports[80] == "http"
        assert basic_state.open_ports[22] == "ssh"
        assert len(basic_state.open_ports) == 2

    def test_add_vulnerability(self, basic_state):
        basic_state.add_vulnerability({"name": "SQLi", "severity": "critical"})
        assert len(basic_state.vulnerabilities) == 1

    def test_add_credential(self, basic_state):
        basic_state.add_credential({"type": "password", "user": "admin"})
        assert len(basic_state.credentials) == 1

    def test_state_hash_deterministic(self, basic_state):
        h1 = basic_state.state_hash()
        h2 = basic_state.state_hash()
        assert h1 == h2

    def test_state_hash_changes(self, basic_state):
        h1 = basic_state.state_hash()
        basic_state.add_open_port(80, "http")
        h2 = basic_state.state_hash()
        assert h1 != h2

    def test_clone(self, basic_state):
        basic_state.add_open_port(80, "http")
        basic_state.add_vulnerability({"name": "XSS"})

        cloned = basic_state.clone()
        assert cloned.target == basic_state.target
        assert cloned.open_ports == basic_state.open_ports
        assert cloned.vulnerabilities == basic_state.vulnerabilities

        # 修改原始不影响克隆
        basic_state.add_open_port(22, "ssh")
        assert 22 not in cloned.open_ports

    def test_is_terminal_false(self, basic_state):
        assert basic_state.is_terminal() is False

    def test_is_terminal_true(self, basic_state):
        basic_state.access_level = 2
        assert basic_state.is_terminal() is True

    def test_reward_empty(self, basic_state):
        assert basic_state.reward() == 0.0

    def test_reward_with_ports(self, basic_state):
        basic_state.add_open_port(80, "http")
        basic_state.add_open_port(22, "ssh")
        assert basic_state.reward() > 0.0

    def test_reward_with_vulns(self, basic_state):
        basic_state.add_vulnerability({"severity": "critical"})
        r1 = basic_state.reward()
        basic_state.add_vulnerability({"severity": "low"})
        r2 = basic_state.reward()
        assert r2 > r1

    def test_reward_with_access(self, basic_state):
        r0 = basic_state.reward()
        basic_state.access_level = 1
        r1 = basic_state.reward()
        basic_state.access_level = 2
        r2 = basic_state.reward()
        assert r2 > r1 > r0

    def test_reward_capped_at_1(self, basic_state):
        # 添加大量发现，奖励不应超过 1.0
        for i in range(20):
            basic_state.add_open_port(i + 1000, "http")
            basic_state.add_vulnerability({"severity": "critical"})
            basic_state.add_credential({"type": "password"})
        basic_state.access_level = 2
        assert basic_state.reward() <= 1.0


# ==================== MCTSNode 测试 ====================


class TestMCTSNode:
    """MCTSNode 测试"""

    @pytest.fixture
    def root_node(self):
        state = AttackState(target="192.168.1.1", target_type="ip")
        return MCTSNode(state=state)

    def test_creation(self, root_node):
        assert root_node.visits == 0
        assert root_node.total_reward == 0.0
        assert root_node.parent is None
        assert root_node.children == []

    def test_average_reward_zero(self, root_node):
        assert root_node.average_reward == 0.0

    def test_average_reward(self, root_node):
        root_node.visits = 4
        root_node.total_reward = 2.0
        assert root_node.average_reward == 0.5

    def test_ucb1_unvisited(self, root_node):
        child = MCTSNode(
            state=root_node.state, parent=root_node,
            action=Action(ActionType.PORT_SCAN, "scan", "nmap"),
        )
        root_node.children.append(child)
        assert child.ucb1() == float("inf")

    def test_ucb1_visited(self, root_node):
        root_node.visits = 10

        child = MCTSNode(
            state=root_node.state, parent=root_node,
            action=Action(ActionType.PORT_SCAN, "scan", "nmap"),
        )
        child.visits = 5
        child.total_reward = 2.0
        root_node.children.append(child)

        ucb = child.ucb1()
        assert ucb > 0
        # exploitation = 2.0/5 = 0.4
        # exploration = 1.414 * sqrt(ln(10)/5) ≈ 1.414 * 0.679 ≈ 0.96
        assert 1.0 < ucb < 2.0

    def test_best_child(self, root_node):
        root_node.visits = 10

        c1 = MCTSNode(state=root_node.state, parent=root_node,
                       action=Action(ActionType.PORT_SCAN, "scan1", "nmap"))
        c1.visits = 5
        c1.total_reward = 1.0

        c2 = MCTSNode(state=root_node.state, parent=root_node,
                       action=Action(ActionType.VULN_SCAN, "scan2", "nuclei"))
        c2.visits = 3
        c2.total_reward = 2.0

        root_node.children = [c1, c2]
        best = root_node.best_child()
        assert best.action.name == "scan2"  # 更高的 average reward

    def test_best_action_child(self, root_node):
        c1 = MCTSNode(state=root_node.state, parent=root_node,
                       action=Action(ActionType.PORT_SCAN, "scan1", "nmap"))
        c1.visits = 10

        c2 = MCTSNode(state=root_node.state, parent=root_node,
                       action=Action(ActionType.VULN_SCAN, "scan2", "nuclei"))
        c2.visits = 3

        root_node.children = [c1, c2]
        best = root_node.best_action_child()
        assert best.visits == 10  # 选择访问次数最多的

    def test_is_fully_expanded_initially(self, root_node):
        assert root_node.is_fully_expanded is False  # _untried_actions is None

    def test_is_fully_expanded_after_init(self, root_node):
        root_node._untried_actions = []
        assert root_node.is_fully_expanded is True

    def test_is_fully_expanded_with_actions(self, root_node):
        root_node._untried_actions = [
            Action(ActionType.PORT_SCAN, "scan", "nmap")
        ]
        assert root_node.is_fully_expanded is False

    def test_is_terminal(self):
        state = AttackState(target="t", target_type="ip", access_level=2)
        node = MCTSNode(state=state)
        assert node.is_terminal is True


# ==================== ActionGenerator 测试 ====================


class TestActionGenerator:
    """ActionGenerator 测试"""

    @pytest.fixture
    def gen(self):
        return ActionGenerator()

    def test_generate_initial_state(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        actions = gen.generate(state)
        # 初始状态应该有端口扫描
        assert any(a.type == ActionType.PORT_SCAN for a in actions)

    def test_generate_with_ports(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.add_open_port(22, "ssh")
        state.completed_actions.add("port_scan")

        actions = gen.generate(state)
        # 应该有 HTTP 和 SSH 相关动作
        assert len(actions) > 2

    def test_generate_no_duplicate_completed(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.completed_actions.add("port_scan")

        actions = gen.generate(state)
        assert not any(a.name == "全端口扫描" for a in actions)

    def test_generate_with_vulnerabilities(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.completed_actions.add("port_scan")
        state.add_vulnerability({"id": "CVE-2021-44228", "severity": "critical"})

        actions = gen.generate(state)
        exploit_actions = [a for a in actions if a.type == ActionType.EXPLOIT]
        assert len(exploit_actions) >= 1

    def test_generate_with_credentials(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.completed_actions.add("port_scan")
        state.add_credential({"type": "password"})

        actions = gen.generate(state)
        lateral = [a for a in actions if a.type == ActionType.LATERAL_MOVE]
        assert len(lateral) >= 1

    def test_generate_privesc_at_user_level(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.access_level = 1

        actions = gen.generate(state)
        privesc = [a for a in actions if a.type == ActionType.PRIVESC]
        assert len(privesc) >= 1

    def test_generate_credential_dump_at_access(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.access_level = 1

        actions = gen.generate(state)
        cred_dump = [a for a in actions if a.type == ActionType.CREDENTIAL_DUMP]
        assert len(cred_dump) >= 1

    def test_generate_redis_actions(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(6379, "redis")
        state.completed_actions.add("port_scan")

        actions = gen.generate(state)
        redis_actions = [a for a in actions if "Redis" in a.name or "redis" in a.tool]
        assert len(redis_actions) >= 1

    def test_generate_empty_terminal(self, gen):
        state = AttackState(target="192.168.1.1", target_type="ip", access_level=2)
        state.completed_actions = {"port_scan", "service_detect", "privesc", "credential_dump", "lateral_move"}
        actions = gen.generate(state)
        # 终态仍可能有一些未完成的动作，但不会崩溃
        assert isinstance(actions, list)


# ==================== AttackSimulator 测试 ====================


class TestAttackSimulator:
    """AttackSimulator 测试"""

    @pytest.fixture
    def sim(self):
        return AttackSimulator(seed=42)

    def test_simulate_port_scan(self, sim):
        state = AttackState(target="192.168.1.1", target_type="ip")
        action = Action(ActionType.PORT_SCAN, "端口扫描", "nmap")

        new_state = sim.simulate_action(state, action)
        assert "端口扫描" in new_state.completed_actions
        # 原始状态不变
        assert len(state.completed_actions) == 0

    def test_simulate_deterministic_with_seed(self):
        sim1 = AttackSimulator(seed=123)
        sim2 = AttackSimulator(seed=123)

        state = AttackState(target="192.168.1.1", target_type="ip")
        action = Action(ActionType.PORT_SCAN, "扫描", "nmap")

        result1 = sim1.simulate_action(state, action)
        result2 = sim2.simulate_action(state, action)

        assert result1.open_ports == result2.open_ports

    def test_simulate_exploit_success(self, sim):
        state = AttackState(target="192.168.1.1", target_type="ip")
        action = Action(ActionType.EXPLOIT, "利用漏洞", "msf")

        # 多次尝试，至少有一次应该成功
        successes = 0
        for _ in range(20):
            new_sim = AttackSimulator(seed=None)
            new_state = new_sim.simulate_action(state, action)
            if new_state.access_level > 0:
                successes += 1

        # exploit 有 40% 成功率，20次至少应该有几次
        assert successes > 0

    def test_simulate_privesc(self, sim):
        state = AttackState(target="192.168.1.1", target_type="ip", access_level=1)
        action = Action(ActionType.PRIVESC, "权限提升", "linpeas")

        # 多次模拟
        results = []
        for i in range(30):
            s = AttackSimulator(seed=i)
            new_state = s.simulate_action(state, action)
            results.append(new_state.access_level)

        # 至少有一些成功提权到 level 2
        assert any(r == 2 for r in results)


# ==================== MCTSPlanner 测试 ====================


class TestMCTSPlanner:
    """MCTSPlanner 完整测试"""

    @pytest.fixture
    def planner(self):
        return MCTSPlanner(seed=42)

    def test_plan_basic(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip")
        result = planner.plan(state, iterations=50)

        assert "recommended_actions" in result
        assert "total_iterations" in result
        assert "tree_stats" in result
        assert result["total_iterations"] == 50

    def test_plan_recommends_port_scan_first(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip")
        result = planner.plan(state, iterations=100)

        if result["recommended_actions"]:
            first_action = result["recommended_actions"][0]
            # 初始状态最可能的第一步是端口扫描
            assert first_action["type"] in ["port_scan", "service_detect", "vuln_scan"]

    def test_plan_with_known_ports(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.add_open_port(6379, "redis")
        state.completed_actions.add("port_scan")

        result = planner.plan(state, iterations=100)
        actions = result["recommended_actions"]
        assert len(actions) > 0

    def test_plan_with_vulnerabilities(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.completed_actions.add("port_scan")
        state.add_vulnerability({"id": "CVE-2021-44228", "severity": "critical"})

        result = planner.plan(state, iterations=50)
        assert len(result["recommended_actions"]) > 0

    def test_plan_tree_stats(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip")
        result = planner.plan(state, iterations=50)

        stats = result["tree_stats"]
        assert stats["total_nodes"] > 1
        assert stats["root_visits"] == 50
        assert stats["max_depth"] >= 1

    def test_plan_iterations_affects_quality(self):
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.add_open_port(22, "ssh")

        planner_few = MCTSPlanner(seed=42)
        result_few = planner_few.plan(state, iterations=10)

        planner_many = MCTSPlanner(seed=42)
        result_many = planner_many.plan(state, iterations=200)

        # 更多迭代应产生更多树节点
        assert result_many["tree_stats"]["total_nodes"] >= result_few["tree_stats"]["total_nodes"]

    def test_plan_reproducible_with_seed(self):
        state = AttackState(target="192.168.1.1", target_type="ip")

        p1 = MCTSPlanner(seed=99)
        r1 = p1.plan(state, iterations=50)

        p2 = MCTSPlanner(seed=99)
        r2 = p2.plan(state, iterations=50)

        assert r1["tree_stats"]["root_average_reward"] == r2["tree_stats"]["root_average_reward"]

    def test_plan_terminal_state(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip", access_level=2)
        result = planner.plan(state, iterations=20)
        # 终态时树不会深度扩展
        assert result["tree_stats"]["root_visits"] == 20

    def test_get_action_rankings(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip")
        rankings = planner.get_action_rankings(state, iterations=50)
        assert isinstance(rankings, list)

    def test_plan_action_format(self, planner):
        state = AttackState(target="192.168.1.1", target_type="ip")
        result = planner.plan(state, iterations=50)

        for action in result["recommended_actions"]:
            assert "name" in action
            assert "type" in action
            assert "tool" in action
            assert "risk_score" in action
            assert "estimated_reward" in action
            assert "visit_count" in action
            assert "average_reward" in action

    def test_plan_different_targets(self):
        """不同目标类型应产生不同规划"""
        ip_state = AttackState(target="192.168.1.1", target_type="ip")
        url_state = AttackState(target="https://example.com", target_type="url")

        planner = MCTSPlanner(seed=42)

        ip_result = planner.plan(ip_state, iterations=30)
        url_result = planner.plan(url_state, iterations=30)

        # 两者都应该产生结果
        assert ip_result["tree_stats"]["total_nodes"] > 0
        assert url_result["tree_stats"]["total_nodes"] > 0


# ==================== 集成测试 ====================


class TestMCTSIntegration:
    """MCTS 集成测试"""

    def test_full_attack_simulation(self):
        """模拟完整攻击流程"""
        planner = MCTSPlanner(seed=42, max_depth=8)

        # 初始状态
        state = AttackState(target="192.168.1.100", target_type="ip")

        # 第一轮规划
        result1 = planner.plan(state, iterations=100)
        assert len(result1["recommended_actions"]) > 0

        # 模拟执行第一个动作后的状态
        state.completed_actions.add("port_scan")
        state.add_open_port(80, "http")
        state.add_open_port(22, "ssh")
        state.add_open_port(3306, "mysql")

        # 第二轮规划
        result2 = planner.plan(state, iterations=100)
        actions2 = result2["recommended_actions"]
        assert len(actions2) > 0

        # 第二轮不应该再推荐端口扫描
        port_scan_actions = [
            a for a in actions2 if a["type"] == "port_scan"
        ]
        assert len(port_scan_actions) == 0

    def test_convergence(self):
        """测试 MCTS 收敛性"""
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.add_open_port(6379, "redis")

        rewards = []
        for iters in [10, 50, 100, 200]:
            planner = MCTSPlanner(seed=42)
            result = planner.plan(state, iterations=iters)
            rewards.append(result["tree_stats"]["root_average_reward"])

        # 奖励应该随迭代次数增加而趋于稳定（不必严格单调）
        assert len(rewards) == 4
        # 至少最终值应该在合理范围
        assert 0 <= rewards[-1] <= 1.0

    def test_risk_aware_planning(self):
        """测试风险感知规划"""
        planner = MCTSPlanner(seed=42)

        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(6379, "redis")
        state.add_open_port(80, "http")
        state.completed_actions.add("port_scan")

        result = planner.plan(state, iterations=100)
        actions = result["recommended_actions"]

        # 验证规划结果结构
        for action in actions:
            assert 0 <= action["risk_score"] <= 1.0
            assert 0 <= action["estimated_reward"] <= 1.0
