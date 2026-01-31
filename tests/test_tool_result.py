"""
ToolResult 单元测试

测试统一工具返回值 Schema 的各种功能。
"""

import pytest
from datetime import datetime

from core.result import (
    ToolResult,
    ResultStatus,
    ensure_tool_result,
)


class TestToolResult:
    """ToolResult 数据类测试"""

    def test_ok_basic(self):
        """测试基本成功返回"""
        result = ToolResult.ok(data={'port': 80, 'open': True})
        assert result.success is True
        assert result.status == ResultStatus.SUCCESS
        assert result.data == {'port': 80, 'open': True}
        assert result.error is None

    def test_ok_with_metadata(self):
        """测试带元数据的成功返回"""
        result = ToolResult.ok(
            data={'count': 5},
            duration=1.5,
            target='example.com'
        )
        assert result.success is True
        assert result.metadata['duration'] == 1.5
        assert result.metadata['target'] == 'example.com'
        assert 'timestamp' in result.metadata

    def test_fail_basic(self):
        """测试基本失败返回"""
        result = ToolResult.fail("Connection refused", error_type="ConnectionError")
        assert result.success is False
        assert result.status == ResultStatus.FAILED
        assert result.error == "Connection refused"
        assert result.error_type == "ConnectionError"

    def test_fail_with_partial_data(self):
        """测试失败但包含部分数据"""
        result = ToolResult.fail(
            "3 of 5 targets failed",
            data={'completed': ['a.com', 'b.com'], 'failed': ['c.com', 'd.com', 'e.com']}
        )
        assert result.success is False
        assert result.data is not None
        assert len(result.data['completed']) == 2

    def test_partial(self):
        """测试部分成功返回"""
        result = ToolResult.partial(
            data={'scanned': 8, 'total': 10},
            error="2 hosts unreachable"
        )
        assert result.success is True  # 部分成功仍视为成功
        assert result.status == ResultStatus.PARTIAL
        assert result.error == "2 hosts unreachable"

    def test_timeout(self):
        """测试超时返回"""
        result = ToolResult.timeout(
            error="Scan exceeded 60s limit",
            data={'partial_results': [1, 2, 3]}
        )
        assert result.success is False
        assert result.status == ResultStatus.TIMEOUT
        assert result.error_type == "TimeoutError"

    def test_error(self):
        """测试内部错误返回"""
        result = ToolResult.internal_error(
            "Unexpected null pointer",
            error_type="InternalError"
        )
        assert result.success is False
        assert result.status == ResultStatus.ERROR

    def test_skipped(self):
        """测试跳过执行返回"""
        result = ToolResult.skipped("Target already scanned in this session")
        assert result.success is True  # 跳过不视为失败
        assert result.status == ResultStatus.SKIPPED
        assert result.error == "Target already scanned in this session"

    def test_pending(self):
        """测试异步任务待执行返回"""
        result = ToolResult.pending(task_id="task-12345")
        assert result.success is True
        assert result.status == ResultStatus.PENDING
        assert result.data['task_id'] == "task-12345"

    def test_from_exception(self):
        """测试从异常创建结果"""
        try:
            raise ValueError("Invalid port number: -1")
        except Exception as e:
            result = ToolResult.from_exception(e)

        assert result.success is False
        assert result.status == ResultStatus.ERROR
        assert "Invalid port number" in result.error
        assert result.error_type == "ValueError"

    def test_to_dict(self):
        """测试转换为字典"""
        result = ToolResult.ok(data={'test': 123})
        d = result.to_dict()

        assert isinstance(d, dict)
        assert d['success'] is True
        assert d['status'] == 'success'  # 枚举转字符串
        assert d['data'] == {'test': 123}
        # 空值字段应被移除
        assert 'error' not in d or d['error'] is None

    def test_to_json_safe(self):
        """测试 JSON 安全转换"""
        result = ToolResult.ok(data={'time': 'now'})
        result.metadata['created'] = datetime.now()

        d = result.to_json_safe()
        # datetime 应该被转换为 ISO 字符串
        assert isinstance(d['metadata']['created'], str)

    def test_bool_conversion(self):
        """测试布尔值转换"""
        success_result = ToolResult.ok()
        fail_result = ToolResult.fail("error")

        assert bool(success_result) is True
        assert bool(fail_result) is False

        # 支持 if result: 语法
        if success_result:
            passed = True
        else:
            passed = False
        assert passed is True

    def test_with_metadata(self):
        """测试添加元数据"""
        result = ToolResult.ok(data={'x': 1})
        result2 = result.with_metadata(extra='value', count=5)

        # 原结果不变
        assert 'extra' not in result.metadata
        # 新结果包含新元数据
        assert result2.metadata['extra'] == 'value'
        assert result2.metadata['count'] == 5

    def test_timestamp_auto_added(self):
        """测试自动添加时间戳"""
        result = ToolResult.ok()
        assert 'timestamp' in result.metadata
        # 时间戳应该是 ISO 格式字符串
        assert isinstance(result.metadata['timestamp'], str)


class TestEnsureToolResult:
    """ensure_tool_result 函数测试"""

    def test_pass_through_tool_result(self):
        """测试 ToolResult 直接传递"""
        original = ToolResult.ok(data={'test': True})
        result = ensure_tool_result(original)
        assert result is original

    def test_convert_success_dict(self):
        """测试转换成功字典"""
        d = {'success': True, 'data': {'port': 80}}
        result = ensure_tool_result(d)

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data == {'port': 80}

    def test_convert_success_dict_without_data(self):
        """测试转换无 data 字段的成功字典"""
        d = {'success': True, 'url': 'https://example.com', 'open_ports': [80, 443]}
        result = ensure_tool_result(d)

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data == {'url': 'https://example.com', 'open_ports': [80, 443]}

    def test_convert_fail_dict(self):
        """测试转换失败字典"""
        d = {
            'success': False,
            'status': 'failed',
            'error': 'Not found',
            'error_type': 'NotFoundError'
        }
        result = ensure_tool_result(d)

        assert isinstance(result, ToolResult)
        assert result.success is False
        assert result.status == ResultStatus.FAILED
        assert result.error == 'Not found'

    def test_convert_dict_with_invalid_status(self):
        """测试转换无效状态的字典"""
        d = {'success': True, 'status': 'unknown_status'}
        result = ensure_tool_result(d)

        # 无效状态应回退到基于 success 的默认状态
        assert result.status == ResultStatus.SUCCESS

    def test_convert_other_types(self):
        """测试转换其他类型"""
        result = ensure_tool_result("raw string value")
        assert result.success is True
        assert result.data == {'value': "raw string value"}

        result2 = ensure_tool_result(12345)
        assert result2.data == {'value': 12345}


class TestResultStatusEnum:
    """ResultStatus 枚举测试"""

    def test_all_statuses(self):
        """测试所有状态值"""
        statuses = [
            ResultStatus.SUCCESS,
            ResultStatus.FAILED,
            ResultStatus.PARTIAL,
            ResultStatus.TIMEOUT,
            ResultStatus.ERROR,
            ResultStatus.SKIPPED,
            ResultStatus.PENDING,
        ]
        assert len(statuses) == 7

    def test_status_values(self):
        """测试状态字符串值"""
        assert ResultStatus.SUCCESS.value == "success"
        assert ResultStatus.FAILED.value == "failed"
        assert ResultStatus.PARTIAL.value == "partial"
        assert ResultStatus.TIMEOUT.value == "timeout"
        assert ResultStatus.ERROR.value == "error"
        assert ResultStatus.SKIPPED.value == "skipped"
        assert ResultStatus.PENDING.value == "pending"


class TestToolResultUsageExamples:
    """ToolResult 使用示例测试（文档验证）"""

    def test_mcp_tool_pattern(self):
        """测试 MCP 工具典型使用模式"""
        # 模拟 MCP 工具函数
        async def port_scan(target: str, ports: list) -> dict:
            try:
                # 模拟扫描逻辑
                open_ports = [80, 443]
                return ToolResult.ok(
                    data={
                        'target': target,
                        'open_ports': open_ports,
                        'total_scanned': len(ports)
                    },
                    duration=2.5
                ).to_dict()
            except TimeoutError:
                return ToolResult.timeout(
                    error=f"Scan of {target} timed out"
                ).to_dict()
            except Exception as e:
                return ToolResult.from_exception(e).to_dict()

        # 验证返回格式
        import asyncio
        result = asyncio.run(port_scan("example.com", [80, 443, 8080]))

        assert result['success'] is True
        assert result['status'] == 'success'
        assert 'open_ports' in result['data']

    def test_chained_operations(self):
        """测试链式操作"""
        result = (
            ToolResult.ok(data={'step1': 'done'})
            .with_metadata(step=1)
            .with_metadata(step=2, version='1.0')
        )

        assert result.metadata['step'] == 2  # 后面的覆盖前面的
        assert result.metadata['version'] == '1.0'
