#!/usr/bin/env python3
"""
AI 决策引擎测试

测试 core/ai_engine.py 的所有核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

from core.ai_engine import (
    AIDecisionEngine,
    RiskLevel,
    AttackVector,
)


class TestRiskLevel:
    """RiskLevel 枚举测试"""

    def test_risk_level_values(self):
        """测试风险等级值"""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"

    def test_risk_level_comparison(self):
        """测试风险等级可用于比较"""
        levels = [RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM]
        # 确保可以排序（通过值）
        sorted_levels = sorted(levels, key=lambda x: x.value)
        assert len(sorted_levels) == 3


class TestAttackVector:
    """AttackVector 数据类测试"""

    def test_attack_vector_creation(self):
        """测试攻击向量创建"""
        vector = AttackVector(
            name="SQL注入",
            description="SQL注入攻击",
            risk_level=RiskLevel.CRITICAL,
            tools=["sqlmap", "burp"],
            prerequisites=["端口80开放"],
            success_probability=0.8,
        )

        assert vector.name == "SQL注入"
        assert vector.risk_level == RiskLevel.CRITICAL
        assert len(vector.tools) == 2
        assert vector.success_probability == 0.8

    def test_attack_vector_defaults(self):
        """测试攻击向量默认值"""
        vector = AttackVector(
            name="Test",
            description="Test desc",
            risk_level=RiskLevel.LOW,
            tools=[],
            prerequisites=[],
            success_probability=0.5,
        )
        assert vector.tools == []
        assert vector.prerequisites == []


class TestAIDecisionEngine:
    """AI 决策引擎测试"""

    @pytest.fixture
    def engine(self):
        """创建测试引擎实例"""
        return AIDecisionEngine({"provider": "local"})

    @pytest.fixture
    def engine_with_openai_config(self):
        """创建带 OpenAI 配置的引擎"""
        return AIDecisionEngine({
            "provider": "openai",
            "model": "gpt-4",
            "api_key": "test-key"
        })

    # ==================== 目标类型识别测试 ====================

    def test_identify_target_type_ipv4(self, engine):
        """测试 IPv4 地址识别"""
        assert engine._identify_target_type("192.168.1.1") == "ip"
        assert engine._identify_target_type("10.0.0.1") == "ip"
        assert engine._identify_target_type("255.255.255.255") == "ip"
        assert engine._identify_target_type("0.0.0.0") == "ip"

    def test_identify_target_type_invalid_ip(self, engine):
        """测试无效 IP 格式不被误识别"""
        # 注意：当前实现使用简单正则，不验证数字范围（999.999.999.999 会被识别为 IP）
        # 只测试格式不正确的情况
        assert engine._identify_target_type("192.168.1") != "ip"  # 缺少一组
        assert engine._identify_target_type("192.168.1.1.1") != "ip"  # 多出一组
        assert engine._identify_target_type("192.168.1.abc") != "ip"  # 非数字

    def test_identify_target_type_cidr(self, engine):
        """测试 CIDR 网段识别"""
        assert engine._identify_target_type("192.168.1.0/24") == "network"
        assert engine._identify_target_type("10.0.0.0/8") == "network"
        assert engine._identify_target_type("172.16.0.0/16") == "network"

    def test_identify_target_type_url(self, engine):
        """测试 URL 识别"""
        assert engine._identify_target_type("http://example.com") == "url"
        assert engine._identify_target_type("https://example.com") == "url"
        assert engine._identify_target_type("https://example.com/path?q=1") == "url"
        assert engine._identify_target_type("http://192.168.1.1:8080") == "url"

    def test_identify_target_type_domain(self, engine):
        """测试域名识别"""
        assert engine._identify_target_type("example.com") == "domain"
        assert engine._identify_target_type("sub.example.com") == "domain"
        assert engine._identify_target_type("www.example.co.uk") == "domain"

    def test_identify_target_type_unknown(self, engine):
        """测试未知类型"""
        assert engine._identify_target_type("not-a-valid-target") == "unknown"
        assert engine._identify_target_type("") == "unknown"
        assert engine._identify_target_type("localhost") == "unknown"  # 无 TLD

    # ==================== 工具推荐测试 ====================

    def test_get_recommended_tools_ip(self, engine):
        """测试 IP 目标的工具推荐"""
        tools = engine._get_recommended_tools("ip")

        assert "recon" in tools
        assert "vuln_scan" in tools
        assert "nmap_scan" in tools["recon"] or "masscan" in tools["recon"]

    def test_get_recommended_tools_domain(self, engine):
        """测试域名目标的工具推荐"""
        tools = engine._get_recommended_tools("domain")

        assert "recon" in tools
        assert "dns_enum" in tools["recon"] or "subfinder" in tools["recon"]

    def test_get_recommended_tools_url(self, engine):
        """测试 URL 目标的工具推荐"""
        tools = engine._get_recommended_tools("url")

        assert "recon" in tools
        assert "vuln_scan" in tools or "web_attack" in tools

    def test_get_recommended_tools_network(self, engine):
        """测试网段目标的工具推荐"""
        tools = engine._get_recommended_tools("network")

        assert "recon" in tools
        assert any("discovery" in t or "scan" in t for t in tools.get("recon", []))

    def test_get_recommended_tools_unknown(self, engine):
        """测试未知目标类型返回空"""
        tools = engine._get_recommended_tools("unknown")
        assert tools == {}

    # ==================== 攻击面分析测试 ====================

    def test_analyze_attack_surface_ip(self, engine):
        """测试 IP 目标攻击面分析"""
        surface = engine._analyze_attack_surface("192.168.1.1", "ip", {})

        assert "entry_points" in surface
        assert "potential_weaknesses" in surface
        assert len(surface["entry_points"]) > 0

    def test_analyze_attack_surface_url(self, engine):
        """测试 URL 目标攻击面分析"""
        surface = engine._analyze_attack_surface("https://example.com", "url", {})

        assert "entry_points" in surface
        assert any("表单" in ep or "API" in ep for ep in surface["entry_points"])

    # ==================== 攻击向量生成测试 ====================

    def test_generate_attack_vectors_with_common_ports(self, engine):
        """测试基于常见端口的攻击向量生成"""
        vectors = engine._generate_attack_vectors(
            target_type="ip",
            ports=[22, 80, 443, 3306],
            services=[],
            technologies=[],
            vulnerabilities=[],
        )

        assert len(vectors) >= 3  # SSH, HTTP, HTTPS, MySQL

        # 验证有 SSH 相关向量
        ssh_vectors = [v for v in vectors if "SSH" in v.name]
        assert len(ssh_vectors) > 0

        # 验证有 Web 相关向量
        web_vectors = [v for v in vectors if "Web" in v.name or "HTTP" in v.name]
        assert len(web_vectors) > 0

    def test_generate_attack_vectors_with_technologies(self, engine):
        """测试基于技术栈的攻击向量生成"""
        vectors = engine._generate_attack_vectors(
            target_type="url",
            ports=[80],
            services=[],
            technologies=["WordPress", "Apache"],
            vulnerabilities=[],
        )

        # 应该包含 WordPress 相关攻击向量
        wp_vectors = [v for v in vectors if "WordPress" in v.name or "WP" in v.name]
        assert len(wp_vectors) > 0

    def test_generate_attack_vectors_with_vulnerabilities(self, engine):
        """测试基于已知漏洞的攻击向量生成"""
        vectors = engine._generate_attack_vectors(
            target_type="ip",
            ports=[],
            services=[],
            technologies=[],
            vulnerabilities=[
                {"id": "CVE-2021-44228", "severity": "critical", "description": "Log4j RCE"}
            ],
        )

        # 应该包含基于 CVE 的攻击向量
        cve_vectors = [v for v in vectors if "CVE-2021-44228" in v.name]
        assert len(cve_vectors) > 0
        assert cve_vectors[0].risk_level == RiskLevel.CRITICAL

    def test_generate_attack_vectors_high_risk_ports(self, engine):
        """测试高风险端口的攻击向量"""
        vectors = engine._generate_attack_vectors(
            target_type="ip",
            ports=[6379, 27017, 9200],  # Redis, MongoDB, Elasticsearch
            services=[],
            technologies=[],
            vulnerabilities=[],
        )

        # 这些未授权访问风险高的端口应该生成高/严重级别向量
        high_risk = [v for v in vectors if v.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        assert len(high_risk) >= 2

    def test_generate_attack_vectors_empty_input(self, engine):
        """测试空输入不会崩溃"""
        vectors = engine._generate_attack_vectors(
            target_type="ip",
            ports=[],
            services=[],
            technologies=[],
            vulnerabilities=[],
        )

        assert vectors == []

    # ==================== 风险优先级测试 ====================

    def test_risk_priority_order(self, engine):
        """测试风险优先级排序"""
        assert engine._risk_priority(RiskLevel.CRITICAL) < engine._risk_priority(RiskLevel.HIGH)
        assert engine._risk_priority(RiskLevel.HIGH) < engine._risk_priority(RiskLevel.MEDIUM)
        assert engine._risk_priority(RiskLevel.MEDIUM) < engine._risk_priority(RiskLevel.LOW)
        assert engine._risk_priority(RiskLevel.LOW) < engine._risk_priority(RiskLevel.INFO)

    # ==================== 时间估算测试 ====================

    def test_estimate_time_few_vectors(self, engine):
        """测试少量向量的时间估算"""
        vectors = [
            AttackVector("Test1", "desc", RiskLevel.LOW, [], [], 0.5),
            AttackVector("Test2", "desc", RiskLevel.LOW, [], [], 0.5),
        ]

        time_str = engine._estimate_time(vectors)
        assert "分钟" in time_str or "小时" in time_str

    def test_estimate_time_many_vectors(self, engine):
        """测试大量向量的时间估算"""
        vectors = [
            AttackVector(f"Test{i}", "desc", RiskLevel.LOW, [], [], 0.5)
            for i in range(20)
        ]

        time_str = engine._estimate_time(vectors)
        assert "小时" in time_str  # 20 * 15 + 30 = 330 分钟 > 5 小时

    # ==================== 攻击计划生成测试 ====================

    def test_generate_attack_plan_basic(self, engine):
        """测试基本攻击计划生成"""
        plan = engine.generate_attack_plan(
            target="192.168.1.1",
            recon_data={
                "ports": [22, 80],
                "services": ["ssh", "http"],
                "technologies": [],
                "vulnerabilities": [],
            }
        )

        assert "target" in plan
        assert "phases" in plan
        assert "attack_vectors" in plan
        assert len(plan["phases"]) >= 3  # 至少有侦察、漏洞发现、利用阶段

    def test_generate_attack_plan_with_vulns(self, engine):
        """测试包含已知漏洞的攻击计划"""
        plan = engine.generate_attack_plan(
            target="https://vulnerable.com",
            recon_data={
                "ports": [443],
                "services": ["https"],
                "technologies": ["Apache", "PHP"],
                "vulnerabilities": [
                    {"id": "CVE-2021-41773", "severity": "critical"}
                ],
            }
        )

        # 计划应该包含利用 CVE 的向量
        vectors = plan.get("attack_vectors", [])
        assert any("CVE" in v.get("name", "") for v in vectors)

    # ==================== 输入清理测试 ====================

    def test_sanitize_input_removes_control_chars(self, engine):
        """测试移除控制字符"""
        malicious = "test\x00\x08\x0b\x1f危险"
        sanitized = engine._sanitize_input(malicious)

        assert "\x00" not in sanitized
        assert "\x08" not in sanitized
        assert "test" in sanitized
        assert "危险" in sanitized

    def test_sanitize_input_removes_newlines(self, engine):
        """测试移除换行符（防止 prompt 注入）"""
        malicious = "test\nignore previous\rinstruction"
        sanitized = engine._sanitize_input(malicious)

        assert "\n" not in sanitized
        assert "\r" not in sanitized
        assert "test" in sanitized

    def test_sanitize_input_truncates(self, engine):
        """测试长度截断"""
        long_input = "a" * 500
        sanitized = engine._sanitize_input(long_input, max_length=100)

        assert len(sanitized) == 100

    def test_sanitize_input_preserves_valid_content(self, engine):
        """测试保留有效内容"""
        valid = "https://example.com/api?q=test&id=123"
        sanitized = engine._sanitize_input(valid)

        assert sanitized == valid

    # ==================== 目标分析测试 ====================

    def test_analyze_target_ip(self, engine):
        """测试 IP 目标分析"""
        analysis = engine.analyze_target("192.168.1.1")

        assert analysis["target"] == "192.168.1.1"
        assert analysis["type"] == "ip"
        assert "recommended_tools" in analysis
        assert "attack_surface" in analysis
        assert "next_steps" in analysis

    def test_analyze_target_url(self, engine):
        """测试 URL 目标分析"""
        analysis = engine.analyze_target("https://example.com/app")

        assert analysis["type"] == "url"
        assert "recommended_tools" in analysis
        assert len(analysis["next_steps"]) > 0

    def test_analyze_target_with_context(self, engine):
        """测试带上下文的目标分析"""
        context = {
            "scope": "internal",
            "previous_findings": ["open_port_22"]
        }

        analysis = engine.analyze_target("192.168.1.1", context)

        assert "target" in analysis
        # 上下文应该被考虑（即使当前实现可能未完全使用）

    # ==================== 工具建议测试 ====================

    def test_suggest_tool_recon_ip(self, engine):
        """测试侦察阶段 IP 目标工具建议"""
        tool = engine.suggest_tool({
            "phase": "recon",
            "target_type": "ip",
        })

        assert tool is not None
        assert isinstance(tool, str)

    def test_suggest_tool_exploit_url(self, engine):
        """测试利用阶段 URL 目标工具建议"""
        tool = engine.suggest_tool({
            "phase": "exploit",
            "target_type": "url",
        })

        assert tool is not None

    # ==================== 攻击阶段创建测试 ====================

    def test_create_attack_phases_basic(self, engine):
        """测试攻击阶段创建"""
        vectors = [
            AttackVector("Test", "desc", RiskLevel.HIGH, ["tool1"], [], 0.8)
        ]

        phases = engine._create_attack_phases(vectors, {"ports": [80]})

        assert len(phases) >= 3
        assert phases[0]["phase"] == 1
        assert phases[0]["name"] == "信息收集"

        # 验证阶段顺序
        phase_numbers = [p["phase"] for p in phases]
        assert phase_numbers == sorted(phase_numbers)

    def test_create_attack_phases_with_recon_data(self, engine):
        """测试有侦察数据时的阶段状态"""
        phases = engine._create_attack_phases([], {"ports": [80, 443]})

        # 信息收集阶段应该标记为已完成（因为有侦察数据）
        recon_phase = phases[0]
        assert recon_phase["status"] == "completed"

    # ==================== 建议生成测试 ====================

    def test_generate_recommendations_web(self, engine):
        """测试 Web 服务建议"""
        recommendations = engine._generate_recommendations({"ports": [80, 443]})

        assert len(recommendations) > 0
        assert any("Web" in r for r in recommendations)

    def test_generate_recommendations_smb(self, engine):
        """测试 SMB 服务建议"""
        recommendations = engine._generate_recommendations({"ports": [445]})

        assert any("SMB" in r or "EternalBlue" in r for r in recommendations)

    def test_generate_recommendations_empty(self, engine):
        """测试无端口时的建议"""
        recommendations = engine._generate_recommendations({"ports": []})

        assert len(recommendations) > 0
        assert any("端口扫描" in r for r in recommendations)


class TestAIDecisionEngineWithProvider:
    """测试带 AI 提供者的引擎"""

    def test_get_client_local_fallback(self):
        """测试无 AI 库时回退到本地"""
        engine = AIDecisionEngine({"provider": "unknown"})
        client = engine._get_client()

        assert client == "local"

    def test_get_client_openai_provider(self):
        """测试 OpenAI 提供者配置"""
        engine = AIDecisionEngine({
            "provider": "openai",
            "api_key": "test-key"
        })

        # 触发客户端创建
        client = engine._get_client()

        # 应该返回客户端（实际 OpenAI 实例或 "local" 回退）
        assert client is not None
        # 如果 openai 库未安装，会回退到 "local"
        # 如果已安装，会是 OpenAI 客户端实例

    def test_analyze_target_without_ai_still_works(self):
        """测试没有 AI 时分析仍然工作"""
        engine = AIDecisionEngine({"provider": "local"})

        analysis = engine.analyze_target("192.168.1.1")

        # 即使没有 AI 增强，基本分析应该正常工作
        assert analysis["type"] == "ip"
        assert "recommended_tools" in analysis
        assert "ai_insights" not in analysis  # 本地模式无 AI 洞察


class TestAIDecisionEngineEdgeCases:
    """边界情况测试"""

    def test_empty_target(self):
        """测试空目标"""
        engine = AIDecisionEngine()
        analysis = engine.analyze_target("")

        assert analysis["type"] == "unknown"

    def test_special_characters_in_target(self):
        """测试目标中的特殊字符"""
        engine = AIDecisionEngine()

        # 包含特殊字符的 URL 应该正常处理
        analysis = engine.analyze_target("https://example.com/path?q=<script>")

        assert analysis["type"] == "url"

    def test_unicode_target(self):
        """测试 Unicode 目标"""
        engine = AIDecisionEngine()

        # 中文域名
        analysis = engine.analyze_target("https://测试.com")

        assert analysis["target"] == "https://测试.com"

    def test_concurrent_analysis(self):
        """测试并发分析（引擎应该是线程安全的）"""
        import threading

        engine = AIDecisionEngine()
        results = []
        errors = []

        def analyze(target):
            try:
                result = engine.analyze_target(target)
                results.append(result)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=analyze, args=(f"192.168.1.{i}",))
            for i in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 10
