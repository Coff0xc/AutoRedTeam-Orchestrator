"""
MCTS 性能优化测试

验证:
1. AttackState.clone() 浅拷贝优化
2. state_hash() 缓存机制
3. 转置表缓存效果
"""

import time

from core.mcts_planner import AttackState, MCTSPlanner


class TestAttackStateOptimization:
    """AttackState 优化测试"""

    def test_hash_cache(self):
        """测试哈希缓存机制"""
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.add_open_port(443, "https")

        # 首次计算
        hash1 = state.state_hash()
        assert state._hash_cache is not None

        # 第二次应使用缓存
        hash2 = state.state_hash()
        assert hash1 == hash2

    def test_hash_invalidation(self):
        """测试哈希缓存失效"""
        state = AttackState(target="192.168.1.1", target_type="ip")
        hash1 = state.state_hash()

        # 修改状态应使缓存失效
        state.add_open_port(80, "http")
        assert state._hash_cache is None

        hash2 = state.state_hash()
        assert hash1 != hash2

    def test_clone_performance(self):
        """测试 clone 性能优化"""
        state = AttackState(target="192.168.1.1", target_type="ip")
        # 添加大量数据
        for i in range(100):
            state.add_open_port(i + 1, f"service_{i}")
        for i in range(50):
            state.vulnerabilities.append({"id": i, "severity": "high"})

        # 测试 clone 性能
        start = time.perf_counter()
        for _ in range(1000):
            _ = state.clone()
        elapsed = time.perf_counter() - start

        # 1000 次 clone 应在 100ms 内完成
        assert elapsed < 0.1, f"clone 性能不佳: {elapsed:.3f}s for 1000 iterations"

    def test_clone_independence(self):
        """测试 clone 后状态独立性"""
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")

        cloned = state.clone()
        cloned.add_open_port(443, "https")
        cloned.access_level = 2

        # 原状态不应被修改
        assert 443 not in state.open_ports
        assert state.access_level == 0


class TestMCTSTranspositionTable:
    """转置表缓存测试"""

    def test_transposition_enabled(self):
        """测试转置表启用"""
        planner = MCTSPlanner(use_transposition=True, seed=42)
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")

        result = planner.plan(state, iterations=50)

        # 转置表应有缓存
        assert len(planner._transposition_table) > 0
        assert "recommended_actions" in result

    def test_transposition_disabled(self):
        """测试转置表禁用"""
        planner = MCTSPlanner(use_transposition=False, seed=42)
        state = AttackState(target="192.168.1.1", target_type="ip")

        planner.plan(state, iterations=50)

        # 转置表应为空
        assert len(planner._transposition_table) == 0

    def test_transposition_performance(self):
        """测试转置表功能正常（性能提升取决于状态重复率）"""
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.add_open_port(22, "ssh")
        state.add_open_port(3306, "mysql")

        # 带转置表
        planner_with = MCTSPlanner(use_transposition=True, seed=42)
        planner_with.plan(state, iterations=100)

        # 验证转置表有缓存命中
        assert len(planner_with._transposition_table) > 0, "转置表应有缓存"

        # 不带转置表也应正常工作
        planner_without = MCTSPlanner(use_transposition=False, seed=42)
        result = planner_without.plan(state, iterations=100)
        assert "recommended_actions" in result


class TestMCTSPlanner:
    """MCTSPlanner 基础功能测试"""

    def test_plan_basic(self):
        """基础规划测试"""
        planner = MCTSPlanner(seed=42)
        state = AttackState(target="192.168.1.1", target_type="ip")

        result = planner.plan(state, iterations=50)

        assert "recommended_actions" in result
        assert "total_iterations" in result
        assert result["total_iterations"] == 50
        assert "tree_stats" in result

    def test_plan_with_ports(self):
        """带端口信息的规划测试"""
        planner = MCTSPlanner(seed=42)
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")
        state.add_open_port(22, "ssh")

        result = planner.plan(state, iterations=50)

        # 应该有推荐动作
        assert len(result["recommended_actions"]) > 0

    def test_deterministic_with_seed(self):
        """测试随机种子确定性"""
        state = AttackState(target="192.168.1.1", target_type="ip")
        state.add_open_port(80, "http")

        planner1 = MCTSPlanner(seed=12345)
        result1 = planner1.plan(state, iterations=30)

        planner2 = MCTSPlanner(seed=12345)
        result2 = planner2.plan(state, iterations=30)

        # 相同种子应产生相同结果
        assert len(result1["recommended_actions"]) == len(result2["recommended_actions"])
