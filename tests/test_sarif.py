"""SARIF 输出格式测试

测试 core.reporting.sarif 模块的 SARIF 2.1.0 输出格式生成。
"""

import json

import pytest

from core.reporting.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    SEVERITY_ORDER,
    findings_to_sarif,
    severity_meets_threshold,
    write_sarif,
)


# ==================== Fixtures ====================


@pytest.fixture
def sample_findings():
    """模拟 Scanner.detect_vulns 返回的结果"""
    return [
        {
            "type": "sqli",
            "severity": "high",
            "url": "http://target.com/login",
            "description": "SQL Injection in login form",
            "evidence": "Error: SQL syntax near 'OR 1=1'",
            "confidence": 85,
            "verified": True,
            "param": "username",
            "payload": "' OR 1=1 --",
        },
        {
            "type": "xss",
            "severity": "medium",
            "url": "http://target.com/search",
            "description": "Reflected XSS in search parameter",
            "evidence": "<script>alert(1)</script> reflected",
            "confidence": 70,
            "verified": False,
            "param": "q",
            "payload": "<script>alert(1)</script>",
        },
        {
            "type": "sqli",
            "severity": "critical",
            "url": "http://target.com/api/users",
            "description": "Blind SQL Injection in API",
            "evidence": "Time-based blind SQLi confirmed",
            "confidence": 95,
            "verified": True,
            "param": "id",
            "payload": "1 AND SLEEP(5)",
        },
    ]


@pytest.fixture
def empty_findings():
    return []


@pytest.fixture
def minimal_finding():
    """字段缺失的最小 finding"""
    return [{"type": "unknown-vuln"}]


# ==================== findings_to_sarif ====================


class TestFindingsToSarif:
    """SARIF 格式转换测试"""

    def test_sarif_basic_structure(self, sample_findings):
        """验证 SARIF 基础结构"""
        sarif = findings_to_sarif(sample_findings)

        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert run["tool"]["driver"]["name"] == "AutoRedTeam"

    def test_sarif_results_count(self, sample_findings):
        """验证结果数量匹配"""
        sarif = findings_to_sarif(sample_findings)
        results = sarif["runs"][0]["results"]
        assert len(results) == len(sample_findings)

    def test_sarif_rules_deduplicated(self, sample_findings):
        """验证规则去重 — 两个 sqli 只生成一条规则"""
        sarif = findings_to_sarif(sample_findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        # sqli 出现两次但只生成一条规则
        assert rule_ids.count("sqli") == 1
        assert "xss" in rule_ids
        assert len(rules) == 2  # sqli + xss

    def test_sarif_custom_tool_name(self, sample_findings):
        """验证自定义工具名称"""
        sarif = findings_to_sarif(sample_findings, tool_name="MyScanner", tool_version="1.0.0")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "MyScanner"
        assert driver["version"] == "1.0.0"

    def test_sarif_empty_findings(self, empty_findings):
        """空结果生成有效 SARIF"""
        sarif = findings_to_sarif(empty_findings)
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0

    def test_sarif_minimal_finding(self, minimal_finding):
        """字段缺失时使用默认值"""
        sarif = findings_to_sarif(minimal_finding)
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "unknown-vuln"
        assert result["level"] == "warning"  # medium 默认
        assert result["message"]["text"] == "Vulnerability detected"
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "unknown"

    def test_sarif_json_serializable(self, sample_findings):
        """验证输出可序列化为 JSON"""
        sarif = findings_to_sarif(sample_findings)
        text = json.dumps(sarif, ensure_ascii=False)
        assert isinstance(text, str)
        parsed = json.loads(text)
        assert parsed["version"] == SARIF_VERSION


# ==================== severity mapping ====================


class TestSeverityMapping:
    """severity -> SARIF level 映射测试"""

    @pytest.mark.parametrize(
        "severity, expected_level",
        [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("info", "note"),
        ],
    )
    def test_severity_to_level(self, severity, expected_level):
        """验证每个 severity 映射到正确的 SARIF level"""
        finding = [{"type": "test", "severity": severity, "description": "test"}]
        sarif = findings_to_sarif(finding)
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == expected_level

    def test_unknown_severity_defaults_to_warning(self):
        """未知 severity 降级为 warning"""
        finding = [{"type": "test", "severity": "unknown_level"}]
        sarif = findings_to_sarif(finding)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"


# ==================== severity_meets_threshold ====================


class TestSeverityThreshold:
    """severity 阈值判断测试"""

    @pytest.mark.parametrize(
        "severity, threshold, expected",
        [
            ("critical", "high", True),
            ("high", "high", True),
            ("medium", "high", False),
            ("low", "high", False),
            ("info", "high", False),
            ("critical", "info", True),
            ("info", "info", True),
            ("low", "medium", False),
            ("medium", "medium", True),
            ("high", "critical", False),
            ("critical", "critical", True),
        ],
    )
    def test_threshold_comparison(self, severity, threshold, expected):
        assert severity_meets_threshold(severity, threshold) is expected

    def test_threshold_case_insensitive(self):
        assert severity_meets_threshold("HIGH", "high") is True
        assert severity_meets_threshold("Critical", "HIGH") is True


# ==================== write_sarif ====================


class TestWriteSarif:
    """SARIF 文件写入测试"""

    def test_write_sarif_creates_file(self, tmp_path, sample_findings):
        """验证写入文件"""
        output_path = str(tmp_path / "output.sarif")
        sarif = findings_to_sarif(sample_findings)
        write_sarif(sarif, output_path)

        with open(output_path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["version"] == SARIF_VERSION
        assert len(loaded["runs"][0]["results"]) == 3

    def test_write_sarif_creates_parent_dirs(self, tmp_path, sample_findings):
        """验证自动创建父目录"""
        output_path = str(tmp_path / "nested" / "dir" / "output.sarif")
        sarif = findings_to_sarif(sample_findings)
        write_sarif(sarif, output_path)

        with open(output_path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["version"] == SARIF_VERSION
