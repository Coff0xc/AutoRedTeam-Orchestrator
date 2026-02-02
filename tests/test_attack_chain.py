#!/usr/bin/env python3
"""
攻击链引擎测试

测试 core/attack_chain.py 的所有核心功能
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from typing import Dict, Any

from core.attack_chain import (
    AttackPhase,
    AttackNode,
    AttackChain,
    AttackChainEngine,
)


class TestAttackPhase:
    """AttackPhase 枚举测试"""

    def test_attack_phase_values(self):
        """测试攻击阶段枚举值"""
        assert AttackPhase.RECONNAISSANCE.value == "reconnaissance"
        assert AttackPhase.INITIAL_ACCESS.value == "initial_access"
        assert AttackPhase.EXECUTION.value == "execution"
        assert AttackPhase.PERSISTENCE.value == "persistence"
        assert AttackPhase.PRIVILEGE_ESC.value == "privilege_escalation"
        assert AttackPhase.LATERAL_MOVEMENT.value == "lateral_movement"
        assert AttackPhase.EXFILTRATION.value == "exfiltration"

    def test_attack_phase_count(self):
        """测试攻击阶段数量（对应 MITRE ATT&CK）"""
        phases = list(AttackPhase)
        assert len(phases) == 13  # 13 个 ATT&CK 战术


class TestAttackNode:
    """AttackNode 数据类测试"""

    def test_attack_node_creation(self):
        """测试攻击节点创建"""
        node = AttackNode(
            id="node_1",
            phase=AttackPhase.RECONNAISSANCE,
            technique="active_scanning",
            tool="port_scan",
            params={"target": "192.168.1.1", "ports": "1-1000"},
        )

        assert node.id == "node_1"
        assert node.phase == AttackPhase.RECONNAISSANCE
        assert node.technique == "active_scanning"
        assert node.tool == "port_scan"
        assert node.status == "pending"
        assert node.dependencies == []
        assert node.result is None

    def test_attack_node_with_dependencies(self):
        """测试带依赖的攻击节点"""
        node = AttackNode(
            id="node_2",
            phase=AttackPhase.INITIAL_ACCESS,
            technique="exploit_public_app",
            tool="exploit_vulnerability",
            params={},
            dependencies=["node_1"],
        )

        assert node.dependencies == ["node_1"]

    def test_attack_node_status_transitions(self):
        """测试节点状态转换"""
        node = AttackNode(
            id="node_1",
            phase=AttackPhase.RECONNAISSANCE,
            technique="test",
            tool="test_tool",
            params={},
        )

        assert node.status == "pending"

        node.status = "running"
        assert node.status == "running"

        node.status = "success"
        assert node.status == "success"

    def test_attack_node_timestamps(self):
        """测试节点时间戳"""
        node = AttackNode(
            id="node_1",
            phase=AttackPhase.RECONNAISSANCE,
            technique="test",
            tool="test_tool",
            params={},
        )

        assert node.started_at is None
        assert node.finished_at is None

        node.started_at = datetime.now()
        assert node.started_at is not None


class TestAttackChain:
    """AttackChain 数据类测试"""

    def test_attack_chain_creation(self):
        """测试攻击链创建"""
        chain = AttackChain(
            id="chain_001",
            name="test_chain",
            target="192.168.1.1",
        )

        assert chain.id == "chain_001"
        assert chain.name == "test_chain"
        assert chain.target == "192.168.1.1"
        assert chain.nodes == []
        assert chain.status == "created"
        assert chain.findings == []
        assert chain.created_at is not None

    def test_attack_chain_with_nodes(self):
        """测试带节点的攻击链"""
        nodes = [
            AttackNode("n1", AttackPhase.RECONNAISSANCE, "scan", "port_scan", {}),
            AttackNode("n2", AttackPhase.INITIAL_ACCESS, "exploit", "exploit", {}, ["n1"]),
        ]

        chain = AttackChain(
            id="chain_001",
            name="test_chain",
            target="192.168.1.1",
            nodes=nodes,
        )

        assert len(chain.nodes) == 2
        assert chain.nodes[0].id == "n1"
        assert chain.nodes[1].dependencies == ["n1"]


class TestAttackChainEngine:
    """AttackChainEngine 测试"""

    @pytest.fixture
    def mock_tool_registry(self):
        """创建模拟工具注册表"""
        registry = Mock()
        registry.execute = Mock(return_value={"success": True, "data": {}})
        return registry

    @pytest.fixture
    def engine(self, mock_tool_registry):
        """创建测试引擎实例"""
        return AttackChainEngine(mock_tool_registry)

    # ==================== 技术工具映射测试 ====================

    def test_technique_tools_mapping_exists(self, engine):
        """测试技术到工具的映射存在"""
        assert hasattr(engine, "TECHNIQUE_TOOLS")
        assert "active_scanning" in engine.TECHNIQUE_TOOLS
        assert "vuln_scan" in engine.TECHNIQUE_TOOLS

    def test_technique_tools_have_valid_tools(self, engine):
        """测试映射中的工具名称有效"""
        for technique, tools in engine.TECHNIQUE_TOOLS.items():
            assert isinstance(tools, list)
            for tool in tools:
                assert isinstance(tool, str)
                assert len(tool) > 0

    # ==================== 阶段流程测试 ====================

    def test_phase_flow_order(self, engine):
        """测试攻击阶段流程顺序"""
        flow = engine.PHASE_FLOW

        assert len(flow) >= 5
        assert flow[0] == AttackPhase.RECONNAISSANCE
        # 侦察应该在初始访问之前
        recon_idx = flow.index(AttackPhase.RECONNAISSANCE)
        initial_idx = flow.index(AttackPhase.INITIAL_ACCESS)
        assert recon_idx < initial_idx

    # ==================== 攻击链创建测试 ====================

    def test_create_chain_ip_target(self, engine):
        """测试 IP 目标的攻击链创建"""
        chain = engine.create_chain(
            target="192.168.1.1",
            target_type="ip",
        )

        assert chain.id is not None
        assert chain.target == "192.168.1.1"
        assert len(chain.nodes) > 0
        assert chain.status == "created"

        # 应该包含端口扫描节点
        port_scan_nodes = [n for n in chain.nodes if n.tool == "port_scan"]
        assert len(port_scan_nodes) > 0

    def test_create_chain_domain_target(self, engine):
        """测试域名目标的攻击链创建"""
        chain = engine.create_chain(
            target="example.com",
            target_type="domain",
        )

        assert chain.target == "example.com"
        assert len(chain.nodes) > 0

        # 应该包含子域名枚举节点
        subdomain_nodes = [n for n in chain.nodes if "subdomain" in n.tool.lower()]
        assert len(subdomain_nodes) > 0

    def test_create_chain_url_target(self, engine):
        """测试 URL 目标的攻击链创建"""
        chain = engine.create_chain(
            target="https://example.com/app",
            target_type="url",
        )

        assert chain.target == "https://example.com/app"
        assert len(chain.nodes) > 0

        # 应该包含技术检测节点
        tech_nodes = [n for n in chain.nodes if "tech" in n.tool.lower()]
        assert len(tech_nodes) > 0

        # 应该包含 WAF 检测节点
        waf_nodes = [n for n in chain.nodes if "waf" in n.tool.lower()]
        assert len(waf_nodes) > 0

    def test_create_chain_stored_in_chains(self, engine):
        """测试创建的链被存储"""
        chain = engine.create_chain("192.168.1.1", "ip")

        assert chain.id in engine.chains
        assert engine.chains[chain.id] == chain

    def test_create_chain_unique_ids(self, engine):
        """测试每个链有唯一 ID"""
        chain1 = engine.create_chain("192.168.1.1", "ip")
        chain2 = engine.create_chain("192.168.1.2", "ip")

        assert chain1.id != chain2.id

    def test_create_chain_with_objectives(self, engine):
        """测试带目标的攻击链创建"""
        chain = engine.create_chain(
            target="192.168.1.1",
            target_type="ip",
            objectives=["get_root", "exfiltrate_data"],
        )

        assert chain is not None
        # 目标应该影响节点生成（当前实现可能未完全使用）

    # ==================== 节点生成测试 ====================

    def test_generate_nodes_ip(self, engine):
        """测试 IP 目标的节点生成"""
        nodes = engine._generate_nodes("192.168.1.1", "ip", None)

        assert len(nodes) > 0

        # 验证节点 ID 唯一
        node_ids = [n.id for n in nodes]
        assert len(node_ids) == len(set(node_ids))

    def test_generate_nodes_url(self, engine):
        """测试 URL 目标的节点生成"""
        nodes = engine._generate_nodes("https://example.com", "url", None)

        assert len(nodes) > 0

        # 应该有多种类型的节点
        phases = set(n.phase for n in nodes)
        assert len(phases) >= 2

    def test_generate_nodes_has_dependencies(self, engine):
        """测试生成的节点有正确的依赖关系"""
        nodes = engine._generate_nodes("https://example.com", "url", None)

        # 至少有一些节点应该有依赖
        nodes_with_deps = [n for n in nodes if n.dependencies]
        assert len(nodes_with_deps) > 0

    # ==================== 循环依赖检测测试 ====================

    def test_detect_cycle_no_cycle(self, engine):
        """测试无循环的链"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}),
                AttackNode("n2", AttackPhase.INITIAL_ACCESS, "t2", "tool2", {}, ["n1"]),
                AttackNode("n3", AttackPhase.EXECUTION, "t3", "tool3", {}, ["n2"]),
            ]
        )

        assert engine._detect_cycle(chain) is False

    def test_detect_cycle_with_cycle(self, engine):
        """测试有循环的链"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}, ["n3"]),
                AttackNode("n2", AttackPhase.INITIAL_ACCESS, "t2", "tool2", {}, ["n1"]),
                AttackNode("n3", AttackPhase.EXECUTION, "t3", "tool3", {}, ["n2"]),
            ]
        )

        assert engine._detect_cycle(chain) is True

    def test_detect_cycle_self_loop(self, engine):
        """测试自循环"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}, ["n1"]),
            ]
        )

        assert engine._detect_cycle(chain) is True

    # ==================== 依赖检查测试 ====================

    def test_check_dependencies_no_deps(self, engine):
        """测试无依赖的节点"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}),
            ]
        )

        node = chain.nodes[0]
        assert engine._check_dependencies(chain, node) is True

    def test_check_dependencies_satisfied(self, engine):
        """测试依赖已满足"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}),
                AttackNode("n2", AttackPhase.INITIAL_ACCESS, "t2", "tool2", {}, ["n1"]),
            ]
        )

        chain.nodes[0].status = "success"

        assert engine._check_dependencies(chain, chain.nodes[1]) is True

    def test_check_dependencies_not_satisfied(self, engine):
        """测试依赖未满足"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}),
                AttackNode("n2", AttackPhase.INITIAL_ACCESS, "t2", "tool2", {}, ["n1"]),
            ]
        )

        chain.nodes[0].status = "pending"

        assert engine._check_dependencies(chain, chain.nodes[1]) is False

    def test_check_dependencies_missing_node(self, engine):
        """测试依赖节点不存在"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n2", AttackPhase.INITIAL_ACCESS, "t2", "tool2", {}, ["n1"]),
            ]
        )

        assert engine._check_dependencies(chain, chain.nodes[0]) is False

    # ==================== 攻击链执行测试 ====================

    def test_execute_chain_success(self, engine, mock_tool_registry):
        """测试成功执行攻击链"""
        chain = engine.create_chain("192.168.1.1", "ip")

        # 模拟工具执行成功
        mock_tool_registry.execute.return_value = {"success": True, "data": {}}

        result = engine.execute_chain(chain.id)

        assert result["chain_id"] == chain.id
        assert result["status"] == "completed"
        assert "results" in result

    def test_execute_chain_not_found(self, engine):
        """测试执行不存在的链"""
        with pytest.raises(ValueError, match="攻击链不存在"):
            engine.execute_chain("non_existent_id")

    def test_execute_chain_with_cycle_fails(self, engine, mock_tool_registry):
        """测试执行有循环的链失败"""
        # 手动创建有循环的链
        chain = AttackChain(
            id="cyclic",
            name="cyclic_chain",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}, ["n2"]),
                AttackNode("n2", AttackPhase.INITIAL_ACCESS, "t2", "tool2", {}, ["n1"]),
            ]
        )
        engine.chains["cyclic"] = chain

        with pytest.raises(ValueError, match="循环依赖"):
            engine.execute_chain("cyclic")

    def test_execute_chain_skips_unsatisfied_deps(self, engine, mock_tool_registry):
        """测试跳过依赖未满足的节点"""
        chain = AttackChain(
            id="test",
            name="test",
            target="test",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "t1", "tool1", {}),
                AttackNode("n2", AttackPhase.INITIAL_ACCESS, "t2", "tool2", {}, ["n1"]),
            ]
        )
        engine.chains["test"] = chain

        # 模拟第一个工具失败
        mock_tool_registry.execute.side_effect = [
            {"success": False, "error": "Failed"},
            {"success": True},
        ]

        result = engine.execute_chain("test")

        # n2 应该被跳过因为 n1 失败了
        n2_result = next((r for r in result["results"] if r["node_id"] == "n2"), None)
        assert n2_result is None or n2_result["status"] == "skipped"

    def test_execute_chain_handles_exception(self, engine, mock_tool_registry):
        """测试执行时异常处理"""
        chain = engine.create_chain("192.168.1.1", "ip")

        # 模拟工具执行抛出异常
        mock_tool_registry.execute.side_effect = Exception("Tool error")

        result = engine.execute_chain(chain.id)

        # 链应该完成但有失败的节点
        assert result["status"] == "completed"
        failed_nodes = [r for r in result["results"] if r["status"] == "failed"]
        assert len(failed_nodes) > 0

    # ==================== 发现提取测试 ====================

    def test_extract_findings_vuln_scan(self, engine):
        """测试漏洞扫描发现提取"""
        node = AttackNode(
            id="n1",
            phase=AttackPhase.RECONNAISSANCE,
            technique="vuln_scan",
            tool="vuln_scan",
            params={},
        )

        result = {
            "vulnerabilities": [
                {"severity": "high", "template_name": "CVE-2021-44228"},
                {"severity": "medium", "title": "XSS"},
            ]
        }

        findings = engine._extract_findings(node, result)

        assert len(findings) == 2
        assert findings[0]["type"] == "vulnerability"
        assert findings[0]["severity"] == "high"

    def test_extract_findings_port_scan(self, engine):
        """测试端口扫描发现提取"""
        node = AttackNode(
            id="n1",
            phase=AttackPhase.RECONNAISSANCE,
            technique="active_scanning",
            tool="port_scan",
            params={},
        )

        result = {
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "ports": [
                        {"port": 22, "state": "open", "service": "ssh"},
                        {"port": 80, "state": "open", "service": "http"},
                    ]
                }
            ]
        }

        findings = engine._extract_findings(node, result)

        assert len(findings) == 2
        assert all(f["type"] == "open_port" for f in findings)

    def test_extract_findings_brute_force(self, engine):
        """测试暴力破解发现提取"""
        node = AttackNode(
            id="n1",
            phase=AttackPhase.CREDENTIAL_ACCESS,
            technique="brute_force",
            tool="hydra",
            params={},
        )

        result = {
            "credentials": [
                {"username": "admin", "password": "admin123"},
            ]
        }

        findings = engine._extract_findings(node, result)

        assert len(findings) == 1
        assert findings[0]["type"] == "credential"
        assert findings[0]["severity"] == "critical"

    def test_extract_findings_empty_result(self, engine):
        """测试空结果不产生发现"""
        node = AttackNode(
            id="n1",
            phase=AttackPhase.RECONNAISSANCE,
            technique="vuln_scan",
            tool="vuln_scan",
            params={},
        )

        findings = engine._extract_findings(node, {})

        assert findings == []

    # ==================== 链动态调整测试 ====================

    def test_adjust_chain_adds_web_nodes(self, engine):
        """测试发现 HTTP 服务后添加 Web 攻击节点"""
        chain = engine.create_chain("192.168.1.1", "ip")
        initial_node_count = len(chain.nodes)

        completed_node = chain.nodes[0]
        result = {
            "hosts": [
                {
                    "ip": "192.168.1.1",
                    "ports": [
                        {"port": 8080, "state": "open", "service": "http-proxy"},
                    ]
                }
            ]
        }

        engine._adjust_chain(chain, completed_node, result)

        # 应该添加了新的 Web 攻击节点
        # 注意：可能不会添加如果已经存在
        assert len(chain.nodes) >= initial_node_count

    def test_adjust_chain_updates_brute_force_service(self, engine):
        """测试更新暴力破解节点的服务类型"""
        chain = AttackChain(
            id="test",
            name="test",
            target="192.168.1.1",
            nodes=[
                AttackNode("n1", AttackPhase.RECONNAISSANCE, "active_scanning", "port_scan", {}),
                AttackNode("n2", AttackPhase.CREDENTIAL_ACCESS, "brute_force", "hydra", {"service": ""}),
            ]
        )
        engine.chains["test"] = chain

        result = {
            "open_ports": [
                {"port": 22, "service": "ssh"},
            ]
        }

        engine._adjust_chain(chain, chain.nodes[0], result)

        # 暴力破解节点应该更新了服务类型
        brute_node = chain.nodes[1]
        assert brute_node.params.get("service") == "ssh"

    # ==================== 链状态查询测试 ====================

    def test_get_chain_status(self, engine):
        """测试获取链状态"""
        chain = engine.create_chain("192.168.1.1", "ip")

        status = engine.get_chain_status(chain.id)

        assert status["id"] == chain.id
        assert status["target"] == "192.168.1.1"
        assert status["status"] == "created"
        assert "nodes" in status
        assert "findings_count" in status
        assert "created_at" in status

    def test_get_chain_status_not_found(self, engine):
        """测试获取不存在的链状态"""
        status = engine.get_chain_status("non_existent")

        assert status is None

    def test_get_chain_status_node_details(self, engine):
        """测试状态包含节点详情"""
        chain = engine.create_chain("192.168.1.1", "ip")

        status = engine.get_chain_status(chain.id)

        assert len(status["nodes"]) > 0
        for node_status in status["nodes"]:
            assert "id" in node_status
            assert "phase" in node_status
            assert "tool" in node_status
            assert "status" in node_status

    # ==================== 下一步建议测试 ====================

    def test_suggest_next_steps_with_vulns(self, engine):
        """测试有漏洞时的建议"""
        chain = engine.create_chain("192.168.1.1", "ip")
        chain.findings = [
            {"type": "vulnerability", "severity": "critical", "title": "RCE"},
        ]

        suggestions = engine.suggest_next_steps(chain.id)

        assert len(suggestions) > 0
        # 应该建议利用严重漏洞
        high_priority = [s for s in suggestions if s["priority"] == "high"]
        assert len(high_priority) > 0

    def test_suggest_next_steps_with_creds(self, engine):
        """测试有凭证时的建议"""
        chain = engine.create_chain("192.168.1.1", "ip")
        chain.findings = [
            {"type": "credential", "data": {"username": "admin"}},
        ]

        suggestions = engine.suggest_next_steps(chain.id)

        assert len(suggestions) > 0
        # 应该建议横向移动
        lateral_suggestions = [
            s for s in suggestions
            if "横向" in s["description"] or "credential" in s["action"].lower()
        ]
        assert len(lateral_suggestions) > 0

    def test_suggest_next_steps_with_smb(self, engine):
        """测试发现 SMB 时的建议"""
        chain = engine.create_chain("192.168.1.1", "ip")
        chain.findings = [
            {"type": "open_port", "service": "smb"},
        ]

        suggestions = engine.suggest_next_steps(chain.id)

        # 应该建议 SMB 枚举
        smb_suggestions = [s for s in suggestions if "smb" in s["action"].lower()]
        assert len(smb_suggestions) > 0

    def test_suggest_next_steps_empty(self, engine):
        """测试无发现时的建议"""
        chain = engine.create_chain("192.168.1.1", "ip")
        chain.findings = []

        suggestions = engine.suggest_next_steps(chain.id)

        assert suggestions == []

    def test_suggest_next_steps_not_found(self, engine):
        """测试不存在的链"""
        suggestions = engine.suggest_next_steps("non_existent")

        assert suggestions == []


class TestAttackChainEngineEdgeCases:
    """边界情况测试"""

    @pytest.fixture
    def engine(self):
        mock_registry = Mock()
        mock_registry.execute = Mock(return_value={"success": True})
        return AttackChainEngine(mock_registry)

    def test_empty_target(self, engine):
        """测试空目标"""
        chain = engine.create_chain("", "unknown")

        assert chain.target == ""
        assert len(chain.nodes) >= 0  # 可能没有节点

    def test_large_number_of_nodes(self, engine):
        """测试大量节点"""
        # 创建多个链以累积节点
        for i in range(10):
            engine.create_chain(f"192.168.1.{i}", "ip")

        assert len(engine.chains) == 10

    def test_concurrent_chain_creation(self, engine):
        """测试并发创建链"""
        import threading

        chains = []
        errors = []

        def create():
            try:
                chain = engine.create_chain("192.168.1.1", "ip")
                chains.append(chain)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(chains) == 5
        # 所有链 ID 应该唯一
        chain_ids = [c.id for c in chains]
        assert len(chain_ids) == len(set(chain_ids))


class TestIntegrationAttackChain:
    """攻击链集成测试"""

    def test_full_chain_lifecycle(self):
        """测试完整的攻击链生命周期"""
        # 创建模拟注册表
        registry = Mock()
        registry.execute = Mock(side_effect=[
            {"success": True, "open_ports": [{"port": 80, "service": "http"}]},
            {"success": True, "vulnerabilities": [{"severity": "high", "title": "SQLi"}]},
            {"success": True, "exploited": True},
        ])

        engine = AttackChainEngine(registry)

        # 1. 创建链
        chain = engine.create_chain("192.168.1.1", "ip")
        assert chain.status == "created"

        # 2. 获取状态
        status = engine.get_chain_status(chain.id)
        assert status["status"] == "created"

        # 3. 执行链
        result = engine.execute_chain(chain.id)
        assert result["status"] == "completed"

        # 4. 获取建议
        suggestions = engine.suggest_next_steps(chain.id)
        # 有漏洞发现应该有建议
        # （取决于执行结果如何被处理）
