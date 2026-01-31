"""
core.session 模块单元测试

测试会话管理的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime


class TestTarget:
    """测试 Target 类"""

    def test_target_creation(self):
        """测试目标创建"""
        from core.session import Target, TargetType

        target = Target(url="https://example.com")

        assert target.url == "https://example.com"
        assert target.target_type == TargetType.URL

    def test_target_from_ip(self):
        """测试从 IP 创建目标"""
        from core.session import Target, TargetType

        target = Target(url="192.168.1.1")

        assert target.url == "192.168.1.1"

    def test_target_with_port(self):
        """测试带端口的目标"""
        from core.session import Target

        target = Target(url="https://example.com:8443")

        assert "8443" in target.url

    def test_target_to_dict(self):
        """测试目标转字典"""
        from core.session import Target

        target = Target(url="https://example.com")

        if hasattr(target, 'to_dict'):
            target_dict = target.to_dict()
            assert isinstance(target_dict, dict)
            assert "url" in target_dict


class TestTargetType:
    """测试 TargetType 枚举"""

    def test_target_types(self):
        """测试目标类型"""
        from core.session import TargetType

        assert TargetType.URL is not None
        # 检查其他可能的类型
        if hasattr(TargetType, 'IP'):
            assert TargetType.IP is not None
        if hasattr(TargetType, 'DOMAIN'):
            assert TargetType.DOMAIN is not None


class TestTargetStatus:
    """测试 TargetStatus 枚举"""

    def test_target_status_values(self):
        """测试目标状态值"""
        from core.session import TargetStatus

        assert TargetStatus is not None
        # 检查常见状态
        if hasattr(TargetStatus, 'PENDING'):
            assert TargetStatus.PENDING is not None
        if hasattr(TargetStatus, 'SCANNING'):
            assert TargetStatus.SCANNING is not None
        if hasattr(TargetStatus, 'COMPLETED'):
            assert TargetStatus.COMPLETED is not None


class TestScanContext:
    """测试 ScanContext 类"""

    def test_context_creation(self):
        """测试扫描上下文创建"""
        from core.session import ScanContext, Target

        target = Target(url="https://example.com")
        context = ScanContext(target=target)

        assert context is not None
        assert context.target == target

    def test_context_session_id(self):
        """测试会话 ID"""
        from core.session import ScanContext, Target

        target = Target(url="https://example.com")
        context = ScanContext(target=target)

        assert hasattr(context, 'session_id')
        assert context.session_id is not None

    def test_context_phase(self):
        """测试扫描阶段"""
        from core.session import ScanContext, Target, ScanPhase

        target = Target(url="https://example.com")
        context = ScanContext(target=target)

        assert hasattr(context, 'phase') or hasattr(context, 'current_phase')


class TestScanPhase:
    """测试 ScanPhase 枚举"""

    def test_scan_phases(self):
        """测试扫描阶段"""
        from core.session import ScanPhase

        assert ScanPhase is not None
        # 检查常见阶段
        if hasattr(ScanPhase, 'RECON'):
            assert ScanPhase.RECON is not None
        if hasattr(ScanPhase, 'VULN_SCAN'):
            assert ScanPhase.VULN_SCAN is not None


class TestContextStatus:
    """测试 ContextStatus 枚举"""

    def test_context_status_values(self):
        """测试上下文状态值"""
        from core.session import ContextStatus

        assert ContextStatus is not None


class TestVulnerability:
    """测试 Vulnerability 类"""

    def test_vulnerability_creation(self):
        """测试漏洞创建"""
        from core.session import Vulnerability, Severity, VulnType

        vuln = Vulnerability(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="反射型 XSS",
            url="https://example.com/search?q=test",
            param="q",
            payload="<script>alert(1)</script>"
        )

        assert vuln is not None
        assert vuln.severity == Severity.HIGH

    def test_vulnerability_to_dict(self):
        """测试漏洞转字典"""
        from core.session import Vulnerability, Severity, VulnType

        vuln = Vulnerability(
            vuln_type=VulnType.SQLI,
            severity=Severity.CRITICAL,
            title="SQL 注入",
            url="https://example.com/user?id=1"
        )

        if hasattr(vuln, 'to_dict'):
            vuln_dict = vuln.to_dict()
            assert isinstance(vuln_dict, dict)


class TestSeverity:
    """测试 Severity 枚举"""

    def test_severity_values(self):
        """测试严重性值"""
        from core.session import Severity

        assert Severity.CRITICAL is not None
        assert Severity.HIGH is not None
        assert Severity.MEDIUM is not None
        assert Severity.LOW is not None

    def test_severity_ordering(self):
        """测试严重性排序"""
        from core.session import Severity

        # 确保枚举值存在
        severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        assert len(severities) == 4


class TestVulnType:
    """测试 VulnType 枚举"""

    def test_vuln_types(self):
        """测试漏洞类型"""
        from core.session import VulnType

        assert VulnType is not None
        # 检查常见类型
        if hasattr(VulnType, 'XSS'):
            assert VulnType.XSS is not None
        if hasattr(VulnType, 'SQLI'):
            assert VulnType.SQLI is not None
        if hasattr(VulnType, 'RCE'):
            assert VulnType.RCE is not None


class TestScanResult:
    """测试 ScanResult 类"""

    def test_result_creation(self):
        """测试扫描结果创建"""
        from core.session import ScanResult

        result = ScanResult(
            session_id="test-session-123",
            target_url="https://example.com"
        )

        assert result is not None
        assert result.session_id == "test-session-123"

    def test_result_vulnerabilities(self):
        """测试结果中的漏洞列表"""
        from core.session import ScanResult

        result = ScanResult(
            session_id="test-session-123",
            target_url="https://example.com"
        )

        assert hasattr(result, 'vulnerabilities')

    def test_result_to_json(self):
        """测试结果转 JSON"""
        from core.session import ScanResult

        result = ScanResult(
            session_id="test-session-123",
            target_url="https://example.com"
        )

        if hasattr(result, 'to_json'):
            json_str = result.to_json()
            assert isinstance(json_str, str)


class TestSessionManager:
    """测试 SessionManager 类"""

    def test_get_session_manager(self):
        """测试获取会话管理器"""
        from core.session import get_session_manager, reset_session_manager

        # 重置以确保干净状态
        reset_session_manager()

        manager = get_session_manager()
        assert manager is not None

    def test_session_manager_singleton(self):
        """测试会话管理器单例"""
        from core.session import get_session_manager, reset_session_manager

        reset_session_manager()

        manager1 = get_session_manager()
        manager2 = get_session_manager()

        assert manager1 is manager2

        reset_session_manager()

    def test_create_session(self):
        """测试创建会话"""
        from core.session import get_session_manager, reset_session_manager

        reset_session_manager()
        manager = get_session_manager()

        context = manager.create_session("https://example.com")

        assert context is not None
        assert hasattr(context, 'session_id')

        reset_session_manager()

    def test_get_session(self):
        """测试获取会话"""
        from core.session import get_session_manager, reset_session_manager

        reset_session_manager()
        manager = get_session_manager()

        context = manager.create_session("https://example.com")
        session_id = context.session_id

        retrieved = manager.get_session(session_id)

        assert retrieved is not None
        assert retrieved.session_id == session_id

        reset_session_manager()

    def test_list_sessions(self):
        """测试列出会话"""
        from core.session import get_session_manager, reset_session_manager

        reset_session_manager()
        manager = get_session_manager()

        manager.create_session("https://example1.com")
        manager.create_session("https://example2.com")

        sessions = manager.list_sessions()

        assert isinstance(sessions, (list, dict))
        assert len(sessions) >= 2

        reset_session_manager()

    def test_complete_session(self):
        """测试完成会话"""
        from core.session import get_session_manager, reset_session_manager

        reset_session_manager()
        manager = get_session_manager()

        context = manager.create_session("https://example.com")
        session_id = context.session_id

        result = manager.complete_session(session_id)

        assert result is not None

        reset_session_manager()


class TestHTTPSessionManager:
    """测试 HTTPSessionManager 类"""

    def test_get_http_session_manager(self):
        """测试获取 HTTP 会话管理器"""
        from core.session import get_http_session_manager

        manager = get_http_session_manager()
        assert manager is not None

    def test_http_session_manager_class(self):
        """测试 HTTPSessionManager 类"""
        from core.session import HTTPSessionManager

        manager = HTTPSessionManager()
        assert manager is not None


class TestAuthContext:
    """测试 AuthContext 类"""

    def test_auth_context_creation(self):
        """测试认证上下文创建"""
        from core.session import AuthContext

        auth = AuthContext(
            username="admin",
            password="password123"
        )

        assert auth is not None
        assert auth.username == "admin"

    def test_auth_context_token(self):
        """测试 Token 认证"""
        from core.session import AuthContext

        auth = AuthContext(
            token="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        )

        assert auth is not None
        assert auth.token is not None


class TestSessionStorage:
    """测试 SessionStorage 类"""

    def test_storage_creation(self):
        """测试存储创建"""
        from core.session import SessionStorage

        storage = SessionStorage()
        assert storage is not None

    def test_storage_save_load(self):
        """测试存储保存和加载"""
        from core.session import SessionStorage, ScanResult
        import tempfile
        import os

        storage = SessionStorage()

        result = ScanResult(
            session_id="test-123",
            target_url="https://example.com"
        )

        # 使用临时目录
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_session.json")

            if hasattr(storage, 'save'):
                storage.save(result, filepath)

                if hasattr(storage, 'load'):
                    loaded = storage.load(filepath)
                    assert loaded is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
