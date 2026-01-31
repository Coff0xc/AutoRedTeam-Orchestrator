"""
utils 模块单元测试

测试工具函数的核心功能
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os


class TestLogger:
    """测试日志模块"""

    def test_get_logger(self):
        """测试获取日志器"""
        from utils.logger import get_logger

        logger = get_logger("test")

        assert logger is not None

    def test_logger_levels(self):
        """测试日志级别"""
        from utils.logger import get_logger

        logger = get_logger("test")

        # 测试各级别日志
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")


class TestValidators:
    """测试验证器"""

    def test_validate_url(self):
        """测试 URL 验证"""
        from utils.validators import validate_url

        assert validate_url("https://example.com") is True
        assert validate_url("http://example.com:8080/path") is True
        assert validate_url("not-a-url") is False

    def test_validate_ip(self):
        """测试 IP 验证"""
        from utils.validators import validate_ip

        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True
        assert validate_ip("999.999.999.999") is False
        assert validate_ip("not-an-ip") is False

    def test_validate_domain(self):
        """测试域名验证"""
        from utils.validators import validate_domain

        assert validate_domain("example.com") is True
        assert validate_domain("sub.example.com") is True
        assert validate_domain("invalid..domain") is False

    def test_validate_port(self):
        """测试端口验证"""
        from utils.validators import validate_port

        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(65535) is True
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False

    def test_sanitize_input(self):
        """测试输入清理"""
        from utils.validators import sanitize_input

        # 测试 XSS 清理
        result = sanitize_input("<script>alert(1)</script>")
        assert "<script>" not in result

    def test_validate_cve_id(self):
        """测试 CVE ID 验证"""
        from utils.validators import validate_cve_id

        assert validate_cve_id("CVE-2021-44228") is True
        assert validate_cve_id("CVE-2023-12345") is True
        assert validate_cve_id("invalid") is False


class TestAsyncUtils:
    """测试异步工具"""

    @pytest.mark.asyncio
    async def test_async_retry(self):
        """测试异步重试"""
        from utils.async_utils import async_retry

        call_count = 0

        @async_retry(max_retries=3)
        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary error")
            return "success"

        result = await flaky_function()
        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_async_timeout(self):
        """测试异步超时"""
        from utils.async_utils import async_timeout
        import asyncio

        @async_timeout(timeout=1.0)
        async def slow_function():
            await asyncio.sleep(0.1)
            return "done"

        result = await slow_function()
        assert result == "done"

    @pytest.mark.asyncio
    async def test_gather_with_concurrency(self):
        """测试并发收集"""
        from utils.async_utils import gather_with_concurrency
        import asyncio

        async def task(n):
            await asyncio.sleep(0.01)
            return n * 2

        coros = [task(i) for i in range(5)]
        results = await gather_with_concurrency(3, coros)

        assert len(results) == 5


class TestReportGenerator:
    """测试报告生成器"""

    def test_generator_creation(self):
        """测试生成器创建"""
        from utils.report_generator import ReportGenerator

        generator = ReportGenerator()

        assert generator is not None

    def test_generate_json_report(self):
        """测试生成 JSON 报告"""
        from utils.report_generator import ReportGenerator

        generator = ReportGenerator()

        data = {
            "target": "https://example.com",
            "vulnerabilities": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.json")

            if hasattr(generator, 'generate_json'):
                generator.generate_json(data, filepath)
                assert os.path.exists(filepath)

    def test_generate_html_report(self):
        """测试生成 HTML 报告"""
        from utils.report_generator import ReportGenerator

        generator = ReportGenerator()

        data = {
            "target": "https://example.com",
            "vulnerabilities": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.html")

            if hasattr(generator, 'generate_html'):
                generator.generate_html(data, filepath)
                assert os.path.exists(filepath)

    def test_generate_markdown_report(self):
        """测试生成 Markdown 报告"""
        from utils.report_generator import ReportGenerator

        generator = ReportGenerator()

        data = {
            "target": "https://example.com",
            "vulnerabilities": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.md")

            if hasattr(generator, 'generate_markdown'):
                generator.generate_markdown(data, filepath)
                assert os.path.exists(filepath)


class TestCrypto:
    """测试加密工具"""

    def test_generate_random_bytes(self):
        """测试生成随机字节"""
        from utils.crypto import generate_random_bytes

        data = generate_random_bytes(32)

        assert len(data) == 32
        assert isinstance(data, bytes)

    def test_hash_data(self):
        """测试数据哈希"""
        from utils.crypto import hash_data

        result = hash_data(b"test data")

        assert result is not None
        assert len(result) > 0

    def test_encrypt_decrypt(self):
        """测试加密解密"""
        from utils.crypto import encrypt_data, decrypt_data

        plaintext = b"secret message"
        key = b"0123456789abcdef"  # 16 bytes for AES-128

        encrypted = encrypt_data(plaintext, key)
        assert encrypted != plaintext

        decrypted = decrypt_data(encrypted, key)
        assert decrypted == plaintext


class TestEncoding:
    """测试编码工具"""

    def test_base64_encode_decode(self):
        """测试 Base64 编解码"""
        from utils.encoding import base64_encode, base64_decode

        data = b"test data"

        encoded = base64_encode(data)
        decoded = base64_decode(encoded)

        assert decoded == data

    def test_url_encode_decode(self):
        """测试 URL 编解码"""
        from utils.encoding import url_encode, url_decode

        data = "test data with spaces & special chars"

        encoded = url_encode(data)
        decoded = url_decode(encoded)

        assert decoded == data

    def test_hex_encode_decode(self):
        """测试十六进制编解码"""
        from utils.encoding import hex_encode, hex_decode

        data = b"test data"

        encoded = hex_encode(data)
        decoded = hex_decode(encoded)

        assert decoded == data


class TestConfig:
    """测试配置管理"""

    def test_config_loading(self):
        """测试配置加载"""
        from utils.config import load_config

        config = load_config()

        assert config is not None

    def test_config_get(self):
        """测试获取配置项"""
        from utils.config import get_config

        value = get_config("timeout", default=30)

        assert value is not None

    def test_config_set(self):
        """测试设置配置项"""
        from utils.config import set_config, get_config

        set_config("test_key", "test_value")
        value = get_config("test_key")

        assert value == "test_value"


class TestFileUtils:
    """测试文件工具"""

    def test_read_file(self):
        """测试读取文件"""
        from utils.file_utils import read_file

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("test content")
            filepath = f.name

        try:
            content = read_file(filepath)
            assert content == "test content"
        finally:
            os.unlink(filepath)

    def test_write_file(self):
        """测试写入文件"""
        from utils.file_utils import write_file

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.txt")

            write_file(filepath, "test content")

            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            assert content == "test content"

    def test_ensure_directory(self):
        """测试确保目录存在"""
        from utils.file_utils import ensure_directory

        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "new", "nested", "dir")

            ensure_directory(new_dir)

            assert os.path.isdir(new_dir)


class TestNetUtils:
    """测试网络工具"""

    def test_parse_url(self):
        """测试解析 URL"""
        from utils.net_utils import parse_url

        result = parse_url("https://example.com:8443/path?query=1")

        assert result['scheme'] == 'https'
        assert result['host'] == 'example.com'
        assert result['port'] == 8443
        assert result['path'] == '/path'

    def test_build_url(self):
        """测试构建 URL"""
        from utils.net_utils import build_url

        url = build_url(
            scheme="https",
            host="example.com",
            port=443,
            path="/api/v1"
        )

        assert "https://example.com" in url
        assert "/api/v1" in url

    def test_is_private_ip(self):
        """测试私有 IP 检测"""
        from utils.net_utils import is_private_ip

        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("8.8.8.8") is False


class TestDecorators:
    """测试装饰器"""

    def test_retry_decorator(self):
        """测试重试装饰器"""
        from utils.decorators import retry

        call_count = 0

        @retry(max_retries=3, delay=0.01)
        def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary error")
            return "success"

        result = flaky_function()
        assert result == "success"

    def test_timeout_decorator(self):
        """测试超时装饰器"""
        from utils.decorators import timeout
        import time

        @timeout(seconds=2)
        def slow_function():
            time.sleep(0.1)
            return "done"

        result = slow_function()
        assert result == "done"

    def test_cache_decorator(self):
        """测试缓存装饰器"""
        from utils.decorators import cache

        call_count = 0

        @cache(ttl=60)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        result1 = expensive_function(5)
        result2 = expensive_function(5)

        assert result1 == result2 == 10
        assert call_count == 1  # 只调用一次


class TestTerminalOutput:
    """测试终端输出"""

    def test_print_table(self):
        """测试打印表格"""
        from utils.terminal_output import print_table

        data = [
            {"name": "Test1", "value": 100},
            {"name": "Test2", "value": 200}
        ]

        # 不应该抛出异常
        print_table(data)

    def test_print_progress(self):
        """测试打印进度"""
        from utils.terminal_output import print_progress

        # 不应该抛出异常
        print_progress(50, 100)


class TestScanMonitor:
    """测试扫描监控"""

    def test_monitor_creation(self):
        """测试监控器创建"""
        from utils.scan_monitor import ScanMonitor

        monitor = ScanMonitor()

        assert monitor is not None

    def test_monitor_start_stop(self):
        """测试监控器启动停止"""
        from utils.scan_monitor import ScanMonitor

        monitor = ScanMonitor()

        if hasattr(monitor, 'start') and hasattr(monitor, 'stop'):
            monitor.start()
            monitor.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
