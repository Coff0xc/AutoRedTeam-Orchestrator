"""
core.lateral 模块单元测试

测试横向移动模块的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

# 模块级别标记 - 标识为单元测试和安全测试
pytestmark = [pytest.mark.unit, pytest.mark.security]


class TestCredentials:
    """测试凭证类"""

    def test_password_credentials(self):
        """测试密码凭证"""
        from core.lateral.base import Credentials, AuthMethod

        creds = Credentials(
            username="admin",
            password="password123",
            domain="WORKGROUP"
        )

        assert creds.username == "admin"
        assert creds.password == "password123"
        assert creds.domain == "WORKGROUP"
        assert creds.method == AuthMethod.PASSWORD

    def test_hash_credentials(self):
        """测试 Hash 凭证"""
        from core.lateral.base import Credentials, AuthMethod

        creds = Credentials(
            username="admin",
            ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        )

        assert creds.method == AuthMethod.HASH
        assert creds.lm_hash == "aad3b435b51404eeaad3b435b51404ee"
        assert creds.nt_hash == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_ssh_key_credentials(self):
        """测试 SSH 密钥凭证"""
        from core.lateral.base import Credentials, AuthMethod

        creds = Credentials(
            username="root",
            ssh_key="/path/to/key"
        )

        assert creds.method == AuthMethod.KEY
        assert creds.ssh_key == "/path/to/key"

    def test_full_username(self):
        """测试完整用户名"""
        from core.lateral.base import Credentials

        creds = Credentials(
            username="admin",
            domain="CORP"
        )

        assert creds.full_username == "CORP\\admin"

    def test_credentials_to_dict(self):
        """测试凭证转字典"""
        from core.lateral.base import Credentials

        creds = Credentials(
            username="admin",
            password="password123"
        )

        creds_dict = creds.to_dict()

        assert isinstance(creds_dict, dict)
        assert creds_dict["username"] == "admin"
        assert creds_dict["has_password"] is True


class TestExecutionResult:
    """测试执行结果类"""

    def test_success_result(self):
        """测试成功结果"""
        from core.lateral.base import ExecutionResult

        result = ExecutionResult(
            success=True,
            output="NT AUTHORITY\\SYSTEM",
            exit_code=0,
            duration=0.5
        )

        assert result.success is True
        assert result.output == "NT AUTHORITY\\SYSTEM"
        assert result.exit_code == 0
        assert bool(result) is True

    def test_failure_result(self):
        """测试失败结果"""
        from core.lateral.base import ExecutionResult

        result = ExecutionResult(
            success=False,
            error="Access denied",
            exit_code=1
        )

        assert result.success is False
        assert result.error == "Access denied"
        assert bool(result) is False

    def test_result_to_dict(self):
        """测试结果转字典"""
        from core.lateral.base import ExecutionResult

        result = ExecutionResult(
            success=True,
            output="test",
            duration=1.0
        )

        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["success"] is True


class TestFileTransferResult:
    """测试文件传输结果类"""

    def test_upload_result(self):
        """测试上传结果"""
        from core.lateral.base import FileTransferResult

        result = FileTransferResult(
            success=True,
            source="/local/file.txt",
            destination="C:\\remote\\file.txt",
            size=1024,
            duration=2.0
        )

        assert result.success is True
        assert result.size == 1024

    def test_download_result(self):
        """测试下载结果"""
        from core.lateral.base import FileTransferResult

        result = FileTransferResult(
            success=False,
            source="C:\\remote\\file.txt",
            destination="/local/file.txt",
            error="File not found"
        )

        assert result.success is False
        assert result.error == "File not found"


class TestLateralConfig:
    """测试横向移动配置"""

    def test_default_config(self):
        """测试默认配置"""
        from core.lateral.base import LateralConfig

        config = LateralConfig()

        assert config.timeout == 30.0
        assert config.smb_port == 445
        assert config.ssh_port == 22
        assert config.winrm_port == 5985

    def test_custom_config(self):
        """测试自定义配置"""
        from core.lateral.base import LateralConfig

        config = LateralConfig(
            timeout=60.0,
            smb_port=4445,
            ssh_port=2222
        )

        assert config.timeout == 60.0
        assert config.smb_port == 4445
        assert config.ssh_port == 2222

    def test_ssh_host_key_policy(self):
        """测试 SSH 主机密钥策略配置"""
        from core.lateral.base import LateralConfig

        config = LateralConfig(ssh_host_key_policy='reject')

        assert config.ssh_host_key_policy == 'reject'

    def test_winrm_ssl_config(self):
        """测试 WinRM SSL 配置"""
        from core.lateral.base import LateralConfig

        config = LateralConfig(
            winrm_use_ssl=True,
            winrm_cert_validation='validate'
        )

        assert config.winrm_use_ssl is True
        assert config.winrm_cert_validation == 'validate'


class TestLateralStatus:
    """测试横向移动状态枚举"""

    def test_status_values(self):
        """测试状态值"""
        from core.lateral.base import LateralStatus

        assert LateralStatus.IDLE.value == 'idle'
        assert LateralStatus.CONNECTED.value == 'connected'
        assert LateralStatus.EXECUTING.value == 'executing'
        assert LateralStatus.FAILED.value == 'failed'


class TestAuthMethod:
    """测试认证方式枚举"""

    def test_auth_methods(self):
        """测试认证方式"""
        from core.lateral.base import AuthMethod

        assert AuthMethod.PASSWORD.value == 'password'
        assert AuthMethod.HASH.value == 'hash'
        assert AuthMethod.KEY.value == 'key'
        assert AuthMethod.TICKET.value == 'ticket'


class TestExecutionMethod:
    """测试执行方式枚举"""

    def test_execution_methods(self):
        """测试执行方式"""
        from core.lateral.base import ExecutionMethod

        assert ExecutionMethod.SMBEXEC.value == 'smbexec'
        assert ExecutionMethod.PSEXEC.value == 'psexec'
        assert ExecutionMethod.WMIEXEC.value == 'wmiexec'
        assert ExecutionMethod.WINRM.value == 'winrm'
        assert ExecutionMethod.SSH.value == 'ssh'


class TestEnsureCredentials:
    """测试凭证转换函数"""

    def test_credentials_passthrough(self):
        """测试 Credentials 对象直接传递"""
        from core.lateral.base import Credentials, ensure_credentials

        creds = Credentials(username="admin", password="pass")
        result = ensure_credentials(creds)

        assert result is creds

    def test_dict_to_credentials(self):
        """测试字典转 Credentials"""
        from core.lateral.base import Credentials, ensure_credentials

        creds_dict = {
            "username": "admin",
            "password": "pass123"
        }

        result = ensure_credentials(creds_dict)

        assert isinstance(result, Credentials)
        assert result.username == "admin"

    def test_invalid_credentials(self):
        """测试无效凭证"""
        from core.lateral.base import ensure_credentials

        with pytest.raises(ValueError):
            ensure_credentials("invalid")


class TestLateralExceptions:
    """测试横向移动异常"""

    def test_lateral_module_error(self):
        """测试模块错误"""
        from core.lateral.base import LateralModuleError

        error = LateralModuleError("Test error")
        assert str(error) == "Test error"

    def test_connection_error(self):
        """测试连接错误"""
        from core.lateral.base import ConnectionError

        error = ConnectionError("Connection failed")
        assert "failed" in str(error).lower()

    def test_authentication_error(self):
        """测试认证错误"""
        from core.lateral.base import AuthenticationError

        error = AuthenticationError("Auth failed")
        assert "failed" in str(error).lower()

    def test_execution_error(self):
        """测试执行错误"""
        from core.lateral.base import ExecutionError

        error = ExecutionError("Execution failed")
        assert "failed" in str(error).lower()

    def test_transfer_error(self):
        """测试传输错误"""
        from core.lateral.base import TransferError

        error = TransferError("Transfer failed")
        assert "failed" in str(error).lower()


class TestSMBLateral:
    """测试 SMB 横向移动"""

    def test_smb_module_exists(self):
        """测试 SMB 模块存在"""
        from core.lateral import smb
        assert smb is not None

    def test_smb_lateral_class(self):
        """测试 SMBLateral 类"""
        try:
            from core.lateral.smb import SMBLateral
            assert SMBLateral is not None
        except ImportError:
            pytest.skip("SMBLateral not available")


class TestSSHLateral:
    """测试 SSH 横向移动"""

    def test_ssh_module_exists(self):
        """测试 SSH 模块存在"""
        from core.lateral import ssh
        assert ssh is not None

    def test_ssh_lateral_class(self):
        """测试 SSHLateral 类"""
        try:
            from core.lateral.ssh import SSHLateral
            assert SSHLateral is not None
            assert SSHLateral.name == 'ssh'
            assert SSHLateral.default_port == 22
        except ImportError:
            pytest.skip("SSHLateral not available")


class TestWinRMLateral:
    """测试 WinRM 横向移动"""

    def test_winrm_module_exists(self):
        """测试 WinRM 模块存在"""
        from core.lateral import winrm
        assert winrm is not None

    def test_winrm_lateral_class(self):
        """测试 WinRMLateral 类"""
        try:
            from core.lateral.winrm import WinRMLateral
            assert WinRMLateral is not None
            assert WinRMLateral.name == 'winrm'
        except ImportError:
            pytest.skip("WinRMLateral not available")


class TestPsExecLateral:
    """测试 PsExec 横向移动"""

    def test_psexec_module_exists(self):
        """测试 PsExec 模块存在"""
        from core.lateral import psexec
        assert psexec is not None

    def test_psexec_lateral_class(self):
        """测试 PsExecLateral 类"""
        try:
            from core.lateral.psexec import PsExecLateral
            assert PsExecLateral is not None
            assert PsExecLateral.name == 'psexec'
            assert PsExecLateral.default_port == 445
            assert PsExecLateral.supports_file_transfer is True
        except ImportError:
            pytest.skip("PsExecLateral not available")


class TestWMILateral:
    """测试 WMI 横向移动"""

    def test_wmi_module_exists(self):
        """测试 WMI 模块存在"""
        from core.lateral import wmi
        assert wmi is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
