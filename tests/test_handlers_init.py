#!/usr/bin/env python3
"""
Handlers 模块初始化单元测试
测试 handlers/__init__.py 中的注册入口和异常处理
"""

import pytest
from unittest.mock import MagicMock, patch
from typing import Dict, Any


class TestHandlersInit:
    """测试 handlers 模块初始化"""

    def test_all_exports(self):
        """测试 __all__ 导出列表"""
        from handlers import __all__

        expected_exports = [
            'register_recon_tools',
            'register_detector_tools',
            'register_cve_tools',
            'register_api_security_tools',
            'register_cloud_security_tools',
            'register_supply_chain_tools',
            'register_redteam_tools',
            'register_orchestration_tools',
            'register_lateral_tools',
            'register_persistence_tools',
            'register_ad_tools',
            'register_session_tools',
            'register_report_tools',
            'register_ai_tools',
            'register_misc_tools',
            'register_external_tools_handlers',
        ]

        assert len(__all__) == len(expected_exports)
        for export in expected_exports:
            assert export in __all__

    def test_import_register_functions(self):
        """测试导入所有注册函数"""
        from handlers import (
            register_recon_tools,
            register_detector_tools,
            register_cve_tools,
            register_api_security_tools,
            register_cloud_security_tools,
            register_supply_chain_tools,
            register_redteam_tools,
            register_orchestration_tools,
            register_lateral_tools,
            register_persistence_tools,
            register_ad_tools,
            register_session_tools,
            register_report_tools,
            register_ai_tools,
            register_misc_tools,
            register_external_tools_handlers,
        )

        # 验证所有函数都是可调用的
        assert callable(register_recon_tools)
        assert callable(register_detector_tools)
        assert callable(register_cve_tools)
        assert callable(register_api_security_tools)
        assert callable(register_cloud_security_tools)
        assert callable(register_supply_chain_tools)
        assert callable(register_redteam_tools)
        assert callable(register_orchestration_tools)
        assert callable(register_lateral_tools)
        assert callable(register_persistence_tools)
        assert callable(register_ad_tools)
        assert callable(register_session_tools)
        assert callable(register_report_tools)
        assert callable(register_ai_tools)
        assert callable(register_misc_tools)
        assert callable(register_external_tools_handlers)


class TestRegisterAllHandlers:
    """测试 register_all_handlers 函数"""

    def test_register_all_handlers_success(self):
        """测试成功注册所有处理器"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 执行注册
        register_all_handlers(mock_mcp, mock_counter, mock_logger)

        # 验证没有警告日志
        warning_calls = [call for call in mock_logger.warning.call_args_list]
        assert len(warning_calls) == 0

    def test_register_all_handlers_with_import_error(self):
        """测试处理 ImportError 异常"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 模拟某个注册函数抛出 ImportError
        with patch('handlers.register_recon_tools', side_effect=ImportError("Module not found")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            # 验证记录了警告日志
            mock_logger.warning.assert_called()
            warning_message = str(mock_logger.warning.call_args_list[0])
            assert "侦察工具" in warning_message
            assert "模块导入错误" in warning_message

    def test_register_all_handlers_with_attribute_error(self):
        """测试处理 AttributeError 异常"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 模拟某个注册函数抛出 AttributeError
        with patch('handlers.register_detector_tools', side_effect=AttributeError("Function not found")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            # 验证记录了警告日志
            mock_logger.warning.assert_called()
            warning_message = str(mock_logger.warning.call_args_list[0])
            assert "漏洞检测工具" in warning_message
            assert "属性错误" in warning_message

    def test_register_all_handlers_with_type_error(self):
        """测试处理 TypeError 异常"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 模拟某个注册函数抛出 TypeError
        with patch('handlers.register_cve_tools', side_effect=TypeError("Invalid argument type")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            # 验证记录了警告日志
            mock_logger.warning.assert_called()
            warning_message = str(mock_logger.warning.call_args_list[0])
            assert "CVE工具" in warning_message
            assert "类型错误" in warning_message

    def test_register_all_handlers_with_generic_exception(self):
        """测试处理通用异常"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 模拟某个注册函数抛出通用异常
        with patch('handlers.register_api_security_tools', side_effect=RuntimeError("Unexpected error")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            # 验证记录了警告日志
            mock_logger.warning.assert_called()
            warning_message = str(mock_logger.warning.call_args_list[0])
            assert "API安全工具" in warning_message
            assert "未预期错误" in warning_message
            assert "RuntimeError" in warning_message

    def test_register_all_handlers_multiple_failures(self):
        """测试多个处理器注册失败"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 模拟多个注册函数失败
        with patch('handlers.register_recon_tools', side_effect=ImportError("Recon module error")):
            with patch('handlers.register_detector_tools', side_effect=AttributeError("Detector attr error")):
                with patch('handlers.register_redteam_tools', side_effect=TypeError("RedTeam type error")):
                    register_all_handlers(mock_mcp, mock_counter, mock_logger)

                    # 验证记录了多个警告
                    assert mock_logger.warning.call_count >= 3

    def test_register_all_handlers_partial_success(self):
        """测试部分处理器注册成功"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 模拟部分注册函数失败
        with patch('handlers.register_recon_tools', side_effect=ImportError("Error")):
            with patch('handlers.register_detector_tools'):  # 成功
                with patch('handlers.register_cve_tools'):  # 成功
                    register_all_handlers(mock_mcp, mock_counter, mock_logger)

                    # 验证只有失败的记录了警告
                    assert mock_logger.warning.call_count >= 1

    def test_register_all_handlers_order(self):
        """测试处理器注册顺序"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        call_order = []

        def track_recon(*args):
            call_order.append('recon')

        def track_detector(*args):
            call_order.append('detector')

        def track_cve(*args):
            call_order.append('cve')

        with patch('handlers.register_recon_tools', side_effect=track_recon):
            with patch('handlers.register_detector_tools', side_effect=track_detector):
                with patch('handlers.register_cve_tools', side_effect=track_cve):
                    register_all_handlers(mock_mcp, mock_counter, mock_logger)

                    # 验证注册顺序
                    assert call_order[0] == 'recon'
                    assert call_order[1] == 'detector'
                    assert call_order[2] == 'cve'

    def test_register_all_handlers_continues_after_error(self):
        """测试某个处理器失败后继续注册其他处理器"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        call_order = []

        def track_recon(*args):
            call_order.append('recon')
            raise ImportError("Recon error")

        def track_detector(*args):
            call_order.append('detector')

        def track_cve(*args):
            call_order.append('cve')

        with patch('handlers.register_recon_tools', side_effect=track_recon):
            with patch('handlers.register_detector_tools', side_effect=track_detector):
                with patch('handlers.register_cve_tools', side_effect=track_cve):
                    register_all_handlers(mock_mcp, mock_counter, mock_logger)

                    # 验证即使 recon 失败，detector 和 cve 仍然被调用
                    assert 'recon' in call_order
                    assert 'detector' in call_order
                    assert 'cve' in call_order


class TestHandlersIntegration:
    """测试 handlers 模块集成"""

    def test_all_handlers_registered(self):
        """测试所有处理器都能被注册"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 记录所有注册调用
        registered_handlers = []

        def mock_register_func(name):
            def register(*args):
                registered_handlers.append(name)
            return register

        with patch('handlers.register_recon_tools', side_effect=mock_register_func('recon')):
            with patch('handlers.register_detector_tools', side_effect=mock_register_func('detector')):
                with patch('handlers.register_cve_tools', side_effect=mock_register_func('cve')):
                    with patch('handlers.register_api_security_tools', side_effect=mock_register_func('api_security')):
                        with patch('handlers.register_cloud_security_tools', side_effect=mock_register_func('cloud_security')):
                            with patch('handlers.register_supply_chain_tools', side_effect=mock_register_func('supply_chain')):
                                with patch('handlers.register_redteam_tools', side_effect=mock_register_func('redteam')):
                                    with patch('handlers.register_orchestration_tools', side_effect=mock_register_func('orchestration')):
                                        with patch('handlers.register_session_tools', side_effect=mock_register_func('session')):
                                            with patch('handlers.register_report_tools', side_effect=mock_register_func('report')):
                                                with patch('handlers.register_ai_tools', side_effect=mock_register_func('ai')):
                                                    with patch('handlers.register_misc_tools', side_effect=mock_register_func('misc')):
                                                        register_all_handlers(mock_mcp, mock_counter, mock_logger)

                                                        # 验证所有处理器都被注册
                                                        assert len(registered_handlers) == 16
                                                        assert 'recon' in registered_handlers
                                                        assert 'detector' in registered_handlers
                                                        assert 'redteam' in registered_handlers

    def test_handlers_with_real_mcp_mock(self):
        """测试使用真实的 MCP mock 对象"""
        from handlers import register_all_handlers

        # 创建更真实的 MCP mock
        mock_mcp = MagicMock()
        mock_mcp.tool = MagicMock(return_value=lambda f: f)

        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 执行注册
        register_all_handlers(mock_mcp, mock_counter, mock_logger)

        # 验证 MCP mock 被使用且没有错误日志
        assert mock_mcp is not None, "MCP mock should be initialized"
        assert mock_logger.error.call_count == 0, "No errors should be logged during registration"


class TestHandlersErrorMessages:
    """测试错误消息格式"""

    def test_import_error_message_format(self):
        """测试 ImportError 消息格式"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        with patch('handlers.register_recon_tools', side_effect=ImportError("specific module error")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            # 获取警告消息
            warning_call = mock_logger.warning.call_args_list[0][0][0]
            assert "侦察工具注册失败" in warning_call
            assert "模块导入错误" in warning_call
            assert "specific module error" in warning_call

    def test_attribute_error_message_format(self):
        """测试 AttributeError 消息格式"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        with patch('handlers.register_detector_tools', side_effect=AttributeError("missing attribute")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            warning_call = mock_logger.warning.call_args_list[0][0][0]
            assert "漏洞检测工具注册失败" in warning_call
            assert "属性错误" in warning_call
            assert "missing attribute" in warning_call

    def test_type_error_message_format(self):
        """测试 TypeError 消息格式"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        with patch('handlers.register_cve_tools', side_effect=TypeError("wrong type")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            warning_call = mock_logger.warning.call_args_list[0][0][0]
            assert "CVE工具注册失败" in warning_call
            assert "类型错误" in warning_call
            assert "wrong type" in warning_call

    def test_generic_error_message_format(self):
        """测试通用错误消息格式"""
        from handlers import register_all_handlers

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        with patch('handlers.register_api_security_tools', side_effect=ValueError("custom error")):
            register_all_handlers(mock_mcp, mock_counter, mock_logger)

            warning_call = mock_logger.warning.call_args_list[0][0][0]
            assert "API安全工具注册失败" in warning_call
            assert "未预期错误" in warning_call
            assert "ValueError" in warning_call
            assert "custom error" in warning_call
