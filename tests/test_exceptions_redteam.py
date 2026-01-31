#!/usr/bin/env python3
"""
异常类测试 - 权限提升和数据外泄异常
"""

import pytest
from core.exceptions import (
    # 权限提升异常
    PrivilegeEscalationError,
    EscalationVectorNotFound,
    InsufficientPrivilege,
    UACBypassFailed,
    TokenManipulationError,
    # 数据外泄异常
    ExfiltrationError,
    ChannelBlocked,
    DataTooLarge,
    ChannelConnectionError,
    EncryptionRequired,
)


class TestPrivilegeEscalationExceptions:
    """测试权限提升异常类"""

    def test_privilege_escalation_error(self):
        """测试基础权限提升异常"""
        exc = PrivilegeEscalationError(
            "提权失败",
            method="uac_bypass",
            current_level="medium",
            target_level="high"
        )

        assert exc.message == "提权失败"
        assert exc.method == "uac_bypass"
        assert exc.current_level == "medium"
        assert exc.target_level == "high"
        assert exc.details['method'] == "uac_bypass"

    def test_escalation_vector_not_found(self):
        """测试未找到提权向量异常"""
        exc = EscalationVectorNotFound(
            "未找到可用的SUID二进制文件",
            method="suid"
        )

        assert "SUID" in exc.message
        assert exc.method == "suid"
        assert isinstance(exc, PrivilegeEscalationError)

    def test_insufficient_privilege(self):
        """测试权限不足异常"""
        exc = InsufficientPrivilege(
            "需要管理员权限",
            current_level="user",
            target_level="admin"
        )

        assert exc.current_level == "user"
        assert exc.target_level == "admin"
        assert isinstance(exc, PrivilegeEscalationError)

    def test_uac_bypass_failed(self):
        """测试UAC绕过失败异常"""
        exc = UACBypassFailed(
            "fodhelper绕过失败",
            method="fodhelper",
            details={"registry_key": "HKCU\\Software\\Classes"}
        )

        assert exc.method == "fodhelper"
        assert "registry_key" in exc.details
        assert isinstance(exc, PrivilegeEscalationError)

    def test_token_manipulation_error(self):
        """测试Token操纵错误"""
        exc = TokenManipulationError(
            "无法复制Token",
            method="token_impersonation",
            details={"pid": 4, "error_code": 5}
        )

        assert exc.method == "token_impersonation"
        assert exc.details['pid'] == 4
        assert isinstance(exc, PrivilegeEscalationError)

    def test_exception_to_dict(self):
        """测试异常序列化为字典"""
        exc = PrivilegeEscalationError(
            "提权测试",
            method="test_method"
        )

        d = exc.to_dict()

        assert d['message'] == "提权测试"
        assert d['type'] == 'PrivilegeEscalationError'
        assert 'method' in d['details']


class TestExfiltrationExceptions:
    """测试数据外泄异常类"""

    def test_exfiltration_error(self):
        """测试基础数据外泄异常"""
        exc = ExfiltrationError(
            "外泄失败",
            channel="dns",
            destination="exfil.example.com"
        )

        assert exc.message == "外泄失败"
        assert exc.channel == "dns"
        assert exc.destination == "exfil.example.com"
        assert exc.details['channel'] == "dns"

    def test_channel_blocked(self):
        """测试通道被阻断异常"""
        exc = ChannelBlocked(
            "DNS出站被防火墙拦截",
            channel="dns"
        )

        assert "DNS" in exc.message
        assert exc.channel == "dns"
        assert isinstance(exc, ExfiltrationError)

    def test_data_too_large(self):
        """测试数据过大异常"""
        exc = DataTooLarge(
            "数据超出DNS通道容量",
            channel="dns",
            data_size=1000000,
            max_size=65535
        )

        assert exc.data_size == 1000000
        assert exc.max_size == 65535
        assert exc.details['data_size'] == 1000000
        assert isinstance(exc, ExfiltrationError)

    def test_channel_connection_error(self):
        """测试通道连接错误"""
        exc = ChannelConnectionError(
            "SMB连接被拒绝",
            channel="smb",
            destination="\\\\target\\share"
        )

        assert exc.channel == "smb"
        assert exc.destination == "\\\\target\\share"
        assert isinstance(exc, ExfiltrationError)

    def test_encryption_required(self):
        """测试需要加密异常"""
        exc = EncryptionRequired(
            "该通道要求数据加密",
            channel="https"
        )

        assert exc.channel == "https"
        assert isinstance(exc, ExfiltrationError)

    def test_exception_to_dict(self):
        """测试异常序列化为字典"""
        exc = ExfiltrationError(
            "外泄测试",
            channel="https"
        )

        d = exc.to_dict()

        assert d['message'] == "外泄测试"
        assert d['type'] == 'ExfiltrationError'
        assert 'channel' in d['details']


class TestExceptionChaining:
    """测试异常链"""

    def test_exception_with_cause(self):
        """测试带原因的异常"""
        original = ConnectionError("网络连接失败")
        exc = ChannelBlocked(
            "外泄通道被阻断",
            channel="https",
            cause=original
        )

        assert exc.__cause__ is original
        d = exc.to_dict()
        assert 'cause' in d
        assert d['cause']['type'] == 'ConnectionError'

    def test_privilege_exception_chain(self):
        """测试权限提升异常链"""
        original = PermissionError("访问被拒绝")
        exc = InsufficientPrivilege(
            "无法访问目标进程",
            cause=original
        )

        assert exc.__cause__ is original


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
