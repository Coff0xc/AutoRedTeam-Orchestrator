"""
Pytest 配置文件

为测试设置 Python 路径，确保能正确导入项目模块
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Generator, Any, Dict, Optional

# 添加项目根目录到 Python 路径
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import asyncio
import json


# ==================== Pytest-asyncio 配置 ====================
pytest_plugins = ('pytest_asyncio',)


# ==================== Fixtures ====================

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """创建事件循环 fixture"""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()
    asyncio.set_event_loop(None)


@pytest.fixture
def sample_target() -> str:
    """提供测试目标 URL"""
    return "http://testphp.vulnweb.com"


@pytest.fixture
def sample_domain() -> str:
    """提供测试域名"""
    return "example.com"


@pytest.fixture
def sample_ip() -> str:
    """提供测试 IP"""
    return "192.168.1.100"


@pytest.fixture
def mock_http_response():
    """提供模拟 HTTP 响应工厂"""
    class MockResponse:
        def __init__(
            self,
            status_code: int = 200,
            text: str = "",
            headers: Optional[Dict[str, str]] = None,
            json_data: Optional[Dict[str, Any]] = None,
        ):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {"Content-Type": "text/html"}
            self.content = text.encode() if text else b""
            self._json_data = json_data
            self.ok = 200 <= status_code < 400
            self.url = "http://mock.test"

        def json(self) -> Dict[str, Any]:
            if self._json_data:
                return self._json_data
            return json.loads(self.text)

        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception(f"HTTP {self.status_code}")

    return MockResponse


@pytest.fixture
def mock_async_http_response():
    """提供异步 HTTP 响应工厂"""
    class AsyncMockResponse:
        def __init__(
            self,
            status: int = 200,
            text: str = "",
            headers: Optional[Dict[str, str]] = None,
            json_data: Optional[Dict[str, Any]] = None,
        ):
            self.status = status
            self._text = text
            self.headers = headers or {"Content-Type": "text/html"}
            self._json_data = json_data
            self.ok = 200 <= status < 400

        async def text(self) -> str:
            return self._text

        async def json(self) -> Dict[str, Any]:
            if self._json_data:
                return self._json_data
            return json.loads(self._text)

        async def read(self) -> bytes:
            return self._text.encode()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    return AsyncMockResponse


@pytest.fixture
def mock_session():
    """提供模拟 HTTP Session"""
    session = MagicMock()
    session.get = MagicMock()
    session.post = MagicMock()
    session.request = MagicMock()
    session.close = MagicMock()
    return session


@pytest.fixture
def mock_async_session():
    """提供异步模拟 HTTP Session"""
    session = AsyncMock()
    session.get = AsyncMock()
    session.post = AsyncMock()
    session.request = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def temp_file(tmp_path):
    """提供临时文件"""
    file = tmp_path / "test_file.txt"
    file.write_text("test content", encoding="utf-8")
    return file


@pytest.fixture
def temp_json_file(tmp_path):
    """提供临时 JSON 文件"""
    file = tmp_path / "test_data.json"
    data = {"key": "value", "items": [1, 2, 3]}
    file.write_text(json.dumps(data), encoding="utf-8")
    return file


@pytest.fixture
def temp_dir(tmp_path):
    """提供临时目录"""
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()
    return test_dir


# ==================== 漏洞检测 Fixtures ====================

@pytest.fixture
def sqli_params() -> Dict[str, str]:
    """SQL 注入测试参数"""
    return {"id": "1", "name": "test"}


@pytest.fixture
def xss_params() -> Dict[str, str]:
    """XSS 测试参数"""
    return {"search": "test", "q": "query"}


@pytest.fixture
def vuln_detection_result():
    """漏洞检测结果工厂"""
    def _create(
        vulnerable: bool = True,
        vuln_type: str = "sqli",
        severity: str = "high",
        confidence: float = 0.9,
    ) -> Dict[str, Any]:
        return {
            "vulnerable": vulnerable,
            "vuln_type": vuln_type,
            "severity": severity,
            "confidence": confidence,
            "url": "http://test.com/api",
            "param": "id",
            "payload": "1' OR '1'='1",
            "evidence": "SQL syntax error",
        }
    return _create


# ==================== Session Fixtures ====================

@pytest.fixture
def mock_scan_session():
    """模拟扫描会话"""
    return {
        "session_id": "test-session-001",
        "target": "http://test.example.com",
        "status": "active",
        "phase": "recon",
        "findings": [],
        "start_time": "2025-01-01T00:00:00Z",
    }


# ==================== 标记注册 ====================

def pytest_configure(config):
    """注册自定义标记"""
    config.addinivalue_line("markers", "slow: 标记慢速测试")
    config.addinivalue_line("markers", "integration: 集成测试")
    config.addinivalue_line("markers", "e2e: 端到端测试")
    config.addinivalue_line("markers", "network: 需要网络的测试")
    config.addinivalue_line("markers", "unit: 单元测试")
    config.addinivalue_line("markers", "security: 安全相关测试")


# ==================== Pytest Hooks ====================

def pytest_collection_modifyitems(config, items):
    """自动标记测试"""
    for item in items:
        # 自动为包含 'integration' 的测试添加标记
        if "integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)

        # 自动为需要网络的测试添加标记
        if any(kw in item.name for kw in ["http", "request", "fetch", "scan"]):
            if not item.get_closest_marker("network"):
                # 只有没有显式标记的才添加
                pass  # 由测试作者手动标记


def pytest_runtest_setup(item):
    """测试运行前检查"""
    # 检查是否有 network 标记但环境变量禁用网络测试
    import os
    if item.get_closest_marker("network"):
        if os.environ.get("SKIP_NETWORK_TESTS", "").lower() == "true":
            pytest.skip("Network tests are disabled")
