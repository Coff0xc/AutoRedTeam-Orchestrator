"""
core/tools/tool_manager.py 模块测试

测试目标:
- ToolManager: 实例化、工具发现、命令构建、可用性检查
- ExternalToolResult: 创建、序列化、状态
- ResultParser: nmap XML / nuclei JSONL / sqlmap / ffuf / masscan 解析
- 便捷函数: get_tool_manager 单例、run_nmap / run_nuclei 集成测试（全 mock）
- validate_extra_args: 参数白名单过滤
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.tools.tool_manager import (
    ExternalToolResult,
    ResultParser,
    ToolInfo,
    ToolManager,
    ToolStatus,
    _match_arg_prefix,
    validate_extra_args,
)


# ==================== ExternalToolResult 测试 ====================


@pytest.mark.unit
class TestExternalToolResult:
    """外部工具执行结果测试"""

    def test_create_success_result(self):
        """创建成功结果"""
        result = ExternalToolResult(
            tool="nmap", success=True, target="192.168.1.1",
            raw_output="PORT STATE SERVICE\n80/tcp open http",
        )
        assert result.tool == "nmap"
        assert result.success is True
        assert result.target == "192.168.1.1"
        assert result.error is None

    def test_create_failure_result(self):
        """创建失败结果"""
        result = ExternalToolResult(
            tool="nmap", success=False, target="10.0.0.1",
            error="Connection refused",
        )
        assert result.success is False
        assert result.error == "Connection refused"

    def test_to_dict(self):
        """to_dict 序列化"""
        result = ExternalToolResult(
            tool="nuclei", success=True, target="http://example.com",
            parsed_data={"findings": []}, execution_time=5.2,
        )
        d = result.to_dict()
        assert d["tool"] == "nuclei"
        assert d["success"] is True
        assert d["target"] == "http://example.com"
        assert d["parsed_data"] == {"findings": []}
        assert d["execution_time"] == 5.2
        assert "timestamp" in d
        # raw_output 不在 to_dict 中
        assert "raw_output" not in d

    def test_default_timestamp(self):
        """默认时间戳自动生成"""
        result = ExternalToolResult(tool="test", success=True, target="t")
        assert result.timestamp is not None
        assert len(result.timestamp) > 0


# ==================== ToolManager 测试 ====================


@pytest.mark.unit
class TestToolManager:
    """工具管理器测试"""

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_instantiation(self, mock_exists, mock_which):
        """实例化测试（无 YAML 配置、无系统工具）"""
        mock_which.return_value = None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        assert isinstance(manager.tools, dict)
        # 默认配置中有 5 个工具
        assert len(manager.tools) >= 5

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_is_tool_available_found(self, mock_exists, mock_which):
        """工具可用检查 - 工具存在"""
        mock_which.side_effect = lambda name: "/usr/bin/nmap" if name == "nmap" else None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        assert manager.is_tool_available("nmap") is True
        assert manager.is_available("nmap") is True

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_is_tool_available_not_found(self, mock_exists, mock_which):
        """工具可用检查 - 工具不存在"""
        mock_which.return_value = None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        assert manager.is_tool_available("nmap") is False

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_is_tool_available_unknown(self, mock_exists, mock_which):
        """未知工具返回 False"""
        mock_which.return_value = None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        assert manager.is_tool_available("unknown_tool_xyz") is False

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_get_status(self, mock_exists, mock_which):
        """获取所有工具状态"""
        mock_which.return_value = None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        status = manager.get_status()
        assert isinstance(status, dict)
        assert "nmap" in status
        assert "status" in status["nmap"]
        assert "description" in status["nmap"]

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_get_all_tools_status(self, mock_exists, mock_which):
        """get_all_tools_status 别名"""
        mock_which.return_value = None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        status = manager.get_all_tools_status()
        assert "nmap" in status
        assert "available" in status["nmap"]

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_build_command_nmap(self, mock_exists, mock_which):
        """nmap 命令构建"""
        mock_which.side_effect = lambda name: f"/usr/bin/{name}" if name == "nmap" else None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        info = manager.tools.get("nmap")
        if info and info.status == ToolStatus.AVAILABLE:
            cmd, metadata = manager._build_command(info, "192.168.1.1", "quick", None)
            # 包含工具路径
            assert cmd[0] == info.path
            # 包含目标
            assert "192.168.1.1" in cmd
            # nmap 使用 -oX 输出 XML
            assert "-oX" in cmd
            # 元数据包含 XML 输出路径
            assert "nmap_xml_output" in metadata

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_build_command_nuclei(self, mock_exists, mock_which):
        """nuclei 命令构建"""
        mock_which.side_effect = lambda name: f"/usr/bin/{name}" if name == "nuclei" else None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        info = manager.tools.get("nuclei")
        if info and info.status == ToolStatus.AVAILABLE:
            cmd, _ = manager._build_command(info, "http://example.com", "quick", None)
            assert "-u" in cmd
            assert "http://example.com" in cmd

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_build_command_with_extra_args(self, mock_exists, mock_which):
        """命令构建附加额外参数（白名单过滤）"""
        mock_which.side_effect = lambda name: f"/usr/bin/{name}" if name == "nmap" else None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        info = manager.tools.get("nmap")
        if info and info.status == ToolStatus.AVAILABLE:
            cmd, _ = manager._build_command(info, "10.0.0.1", "quick", ["-p80", "--open"])
            assert "-p80" in cmd
            assert "--open" in cmd

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    async def test_run_unavailable_tool(self, mock_exists, mock_which):
        """运行不可用工具返回错误"""
        mock_which.return_value = None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        result = await manager.run("nmap", "192.168.1.1")
        assert result.success is False
        assert "不可用" in result.error

    @patch("core.tools.tool_manager.shutil.which")
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    async def test_run_unknown_tool(self, mock_exists, mock_which):
        """运行未知工具返回错误"""
        mock_which.return_value = None
        manager = ToolManager(config_path="/nonexistent/config.yaml")
        result = await manager.run("nonexistent_tool", "target")
        assert result.success is False
        assert "未知工具" in result.error


# ==================== ResultParser 测试 ====================


@pytest.mark.unit
class TestResultParser:
    """工具输出解析器测试"""

    def test_parse_nmap_xml(self):
        """解析 nmap XML 输出"""
        xml = """<?xml version="1.0"?>
<nmaprun>
  <scaninfo type="syn" protocol="tcp" services="80"/>
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="test.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        result = ResultParser.parse_nmap_xml(xml)
        assert "hosts" in result
        assert len(result["hosts"]) == 1
        host = result["hosts"][0]
        assert host["status"] == "up"
        assert host["addresses"][0]["addr"] == "192.168.1.1"
        assert host["hostnames"] == ["test.local"]
        assert host["ports"][0]["port"] == 80
        assert host["ports"][0]["state"] == "open"
        assert host["ports"][0]["service"] == "http"

    def test_parse_nmap_xml_invalid(self):
        """解析无效 XML 不抛异常"""
        result = ResultParser.parse_nmap_xml("not valid xml <><>")
        assert "hosts" in result
        assert len(result["hosts"]) == 0

    def test_parse_nuclei_jsonl(self):
        """解析 nuclei JSONL 输出"""
        line1 = json.dumps({
            "template-id": "cve-2021-1234",
            "info": {"name": "Test CVE", "severity": "critical"},
            "type": "http",
            "host": "http://example.com",
            "matched-at": "http://example.com/path",
        })
        line2 = json.dumps({
            "template-id": "exposed-panel",
            "info": {"name": "Admin Panel", "severity": "medium"},
            "type": "http",
            "host": "http://example.com",
        })
        output = f"{line1}\n{line2}"
        result = ResultParser.parse_nuclei_jsonl(output)
        assert len(result) == 2
        assert result[0]["template_id"] == "cve-2021-1234"
        assert result[0]["severity"] == "critical"
        assert result[1]["template_name"] == "Admin Panel"

    def test_parse_nuclei_jsonl_with_raw_line(self):
        """nuclei 输出包含非 JSON 行"""
        output = "[INF] nuclei started\n{not valid json"
        result = ResultParser.parse_nuclei_jsonl(output)
        # 非 JSON 行作为 raw 保留
        assert any("raw" in r for r in result)

    def test_parse_sqlmap_output(self):
        """解析 sqlmap 输出"""
        output = """
[INFO] testing 'AND boolean-based blind'
[INFO] GET parameter 'id' is vulnerable
sqlmap identified the following injection points
Type: boolean-based blind
Payload: id=1 AND 1=1
back-end DBMS: MySQL
[*] information_schema
[*] testdb
"""
        result = ResultParser.parse_sqlmap_output(output)
        assert result["vulnerable"] is True
        assert result["dbms"] == "MySQL"
        assert "testdb" in result["databases"]
        assert len(result["payloads"]) > 0

    def test_parse_sqlmap_output_not_vulnerable(self):
        """sqlmap 未发现注入"""
        output = "[INFO] testing completed\n[WARNING] no injection found"
        result = ResultParser.parse_sqlmap_output(output)
        assert result["vulnerable"] is False

    def test_parse_ffuf_json(self):
        """解析 ffuf JSON 输出"""
        data = {
            "config": {"url": "http://example.com/FUZZ"},
            "results": [
                {"input": {"FUZZ": "admin"}, "status": 200, "length": 1234, "url": "http://example.com/admin"},
                {"input": {"FUZZ": "login"}, "status": 301, "length": 0, "url": "http://example.com/login"},
            ],
        }
        result = ResultParser.parse_ffuf_json(json.dumps(data))
        assert len(result["results"]) == 2
        assert result["results"][0]["status"] == 200
        assert result["results"][0]["url"] == "http://example.com/admin"

    def test_parse_masscan_json(self):
        """解析 masscan JSON 输出"""
        data = [
            {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
            {"ip": "10.0.0.1", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]},
        ]
        result = ResultParser.parse_masscan_json(json.dumps(data))
        assert "10.0.0.1" in result["hosts"]
        assert len(result["hosts"]["10.0.0.1"]["ports"]) == 2


# ==================== validate_extra_args 测试 ====================


@pytest.mark.unit
class TestValidateExtraArgs:
    """参数白名单过滤测试"""

    def test_allowed_nmap_args(self):
        """nmap 白名单参数通过"""
        safe = validate_extra_args("nmap", ["-p80", "-sV", "--open", "-T4"])
        assert "-p80" in safe
        assert "-sV" in safe
        assert "--open" in safe
        assert "-T4" in safe

    def test_denied_nmap_args(self):
        """nmap 高危参数被拒绝"""
        safe = validate_extra_args("nmap", ["--script=exploit", "-iL", "/tmp/list"])
        assert "--script=exploit" not in safe
        assert "-iL" not in safe

    def test_unknown_tool_rejects_all(self):
        """未知工具拒绝所有额外参数"""
        safe = validate_extra_args("unknown_tool", ["-p", "80"])
        assert safe == []

    def test_match_arg_prefix_short(self):
        """短前缀匹配规则"""
        assert _match_arg_prefix("-p80", "-p") is True
        assert _match_arg_prefix("-p", "-p") is True
        assert _match_arg_prefix("-px", "-p") is False  # x 不是数字或 =

    def test_match_arg_prefix_long(self):
        """长前缀匹配规则"""
        assert _match_arg_prefix("--open", "--open") is True
        assert _match_arg_prefix("--open-extra", "--open") is True


# ==================== 便捷函数测试 ====================


@pytest.mark.unit
class TestConvenienceFunctions:
    """便捷函数测试"""

    @patch("core.tools.tool_manager._manager", None)
    @patch("core.tools.tool_manager.shutil.which", return_value=None)
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    def test_get_tool_manager_singleton(self, mock_exists, mock_which):
        """get_tool_manager 单例"""
        from core.tools.tool_manager import get_tool_manager
        m1 = get_tool_manager()
        m2 = get_tool_manager()
        assert m1 is m2

    @patch("core.tools.tool_manager.shutil.which", return_value=None)
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    async def test_run_nmap_unavailable(self, mock_exists, mock_which):
        """run_nmap 工具不可用时返回失败"""
        from core.tools.tool_manager import run_nmap

        # 重置单例
        import core.tools.tool_manager as tm
        tm._manager = None

        result = await run_nmap("192.168.1.1")
        assert result["success"] is False

    @patch("core.tools.tool_manager.shutil.which", return_value=None)
    @patch("core.tools.tool_manager.Path.exists", return_value=False)
    async def test_run_nuclei_unavailable(self, mock_exists, mock_which):
        """run_nuclei 工具不可用时返回失败"""
        from core.tools.tool_manager import run_nuclei

        import core.tools.tool_manager as tm
        tm._manager = None

        result = await run_nuclei("http://example.com")
        assert result["success"] is False
