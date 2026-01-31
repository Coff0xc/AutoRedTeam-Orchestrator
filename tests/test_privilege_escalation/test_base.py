#!/usr/bin/env python3
"""
权限提升基类测试
"""

import pytest
from core.privilege_escalation.base import (
    PrivilegeLevel,
    EscalationMethod,
    EscalationStatus,
    EscalationResult,
    EscalationConfig,
    EscalationVector,
)


class TestPrivilegeLevel:
    """测试权限级别枚举"""

    def test_privilege_levels_exist(self):
        """测试所有权限级别都存在"""
        assert PrivilegeLevel.LOW.value == 'low'
        assert PrivilegeLevel.MEDIUM.value == 'medium'
        assert PrivilegeLevel.HIGH.value == 'high'
        assert PrivilegeLevel.SYSTEM.value == 'system'

    def test_privilege_level_comparison(self):
        """测试权限级别可以通过值比较"""
        levels = [PrivilegeLevel.LOW, PrivilegeLevel.MEDIUM, PrivilegeLevel.HIGH, PrivilegeLevel.SYSTEM]
        values = [l.value for l in levels]
        assert 'low' in values
        assert 'system' in values


class TestEscalationMethod:
    """测试提权方法枚举"""

    def test_escalation_methods_exist(self):
        """测试所有提权方法都存在"""
        assert EscalationMethod.UAC_BYPASS.value == 'uac_bypass'
        assert EscalationMethod.TOKEN_IMPERSONATION.value == 'token_impersonation'
        assert EscalationMethod.SUID.value == 'suid'
        assert EscalationMethod.SUDO.value == 'sudo'

    def test_all_methods_have_values(self):
        """测试所有方法都有值"""
        for method in EscalationMethod:
            assert method.value is not None
            assert len(method.value) > 0


class TestEscalationResult:
    """测试提权结果数据类"""

    def test_successful_result(self):
        """测试成功的提权结果"""
        result = EscalationResult(
            success=True,
            method=EscalationMethod.UAC_BYPASS,
            from_level=PrivilegeLevel.MEDIUM,
            to_level=PrivilegeLevel.HIGH,
            output="Elevated successfully"
        )

        assert result.success is True
        assert result.method == EscalationMethod.UAC_BYPASS
        assert result.from_level == PrivilegeLevel.MEDIUM
        assert result.to_level == PrivilegeLevel.HIGH
        assert result.output == "Elevated successfully"
        assert bool(result) is True

    def test_failed_result(self):
        """测试失败的提权结果"""
        result = EscalationResult(
            success=False,
            method=EscalationMethod.SUID,
            from_level=PrivilegeLevel.LOW,
            to_level=PrivilegeLevel.LOW,
            error="No SUID binary found"
        )

        assert result.success is False
        assert result.error == "No SUID binary found"
        assert bool(result) is False

    def test_to_dict(self):
        """测试转换为字典"""
        result = EscalationResult(
            success=True,
            method=EscalationMethod.UAC_BYPASS,
            from_level=PrivilegeLevel.MEDIUM,
            to_level=PrivilegeLevel.HIGH,
            output="Test output",
            duration=1.5
        )

        d = result.to_dict()

        assert d['success'] is True
        assert d['method'] == 'uac_bypass'
        assert d['from_level'] == 'medium'
        assert d['to_level'] == 'high'
        assert d['output'] == "Test output"
        assert d['duration'] == 1.5


class TestEscalationConfig:
    """测试提权配置数据类"""

    def test_default_config(self):
        """测试默认配置"""
        config = EscalationConfig()

        assert config.timeout == 60.0
        assert config.cleanup is True
        assert config.stealth is False
        assert config.methods == []

    def test_custom_config(self):
        """测试自定义配置"""
        config = EscalationConfig(
            timeout=120.0,
            cleanup=False,
            stealth=True,
            methods=[EscalationMethod.UAC_BYPASS, EscalationMethod.TOKEN_IMPERSONATION]
        )

        assert config.timeout == 120.0
        assert config.cleanup is False
        assert config.stealth is True
        assert len(config.methods) == 2


class TestEscalationVector:
    """测试提权向量数据类"""

    def test_vector_creation(self):
        """测试创建提权向量"""
        vector = EscalationVector(
            method=EscalationMethod.SUID,
            name="python3",
            description="Python SUID binary",
            success_probability=0.8,
            detected_info={'risk_level': 'medium'}
        )

        assert vector.method == EscalationMethod.SUID
        assert vector.name == "python3"
        assert vector.detected_info.get('risk_level') == "medium"
        assert vector.success_probability == 0.8

    def test_vector_to_dict(self):
        """测试向量转换为字典"""
        vector = EscalationVector(
            method=EscalationMethod.SUDO,
            name="sudo -l entry",
            description="NOPASSWD entry found",
            detected_info={'binary': '/usr/bin/vim', 'nopasswd': True}
        )

        d = vector.to_dict()

        assert d['method'] == 'sudo'
        assert d['name'] == "sudo -l entry"
        assert 'binary' in d['detected_info']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
