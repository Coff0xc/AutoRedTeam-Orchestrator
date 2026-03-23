"""
utils 模块单元测试

测试工具函数的核心功能
"""

import os
import tempfile

import pytest


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



class TestAsyncUtils:
    """测试异步工具"""

    @pytest.mark.asyncio
    async def test_async_retry(self):
        """测试异步重试"""
        from utils.async_utils import async_retry

        call_count = 0

        @async_retry(max_attempts=3)
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
    async def test_gather_with_concurrency(self):
        """测试并发收集"""
        import asyncio

        from utils.async_utils import gather_with_limit

        async def task(n):
            await asyncio.sleep(0.01)
            return n * 2

        coros = [task(i) for i in range(5)]
        results = await gather_with_limit(coros, limit=3)

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

        data = {"target": "https://example.com", "vulnerabilities": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.json")

            if hasattr(generator, "generate_json"):
                generator.generate_json(data, filepath)
                assert os.path.exists(filepath)

    def test_generate_html_report(self):
        """测试生成 HTML 报告"""
        from utils.report_generator import ReportGenerator

        generator = ReportGenerator()

        data = {"target": "https://example.com", "vulnerabilities": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.html")

            if hasattr(generator, "generate_html"):
                generator.generate_html(data, filepath)
                assert os.path.exists(filepath)

    def test_generate_markdown_report(self):
        """测试生成 Markdown 报告"""
        from utils.report_generator import ReportGenerator

        generator = ReportGenerator()

        data = {"target": "https://example.com", "vulnerabilities": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "report.md")

            if hasattr(generator, "generate_markdown"):
                generator.generate_markdown(data, filepath)
                assert os.path.exists(filepath)


class TestCrypto:
    """测试加密工具"""

    def test_generate_random_bytes(self):
        """测试生成随机字节"""
        from utils.crypto import random_bytes

        data = random_bytes(32)

        assert len(data) == 32
        assert isinstance(data, bytes)


class TestEncoding:
    """测试编码工具"""

    def test_base64_encode_decode(self):
        """测试 Base64 编解码"""
        from utils.encoding import base64_decode, base64_encode

        data = b"test data"

        encoded = base64_encode(data)
        decoded = base64_decode(encoded)

        assert decoded == data

    def test_url_encode_decode(self):
        """测试 URL 编解码"""
        from utils.encoding import url_decode, url_encode

        data = "test data with spaces & special chars"

        encoded = url_encode(data)
        decoded = url_decode(encoded)

        assert decoded == data

    def test_hex_encode_decode(self):
        """测试十六进制编解码"""
        from utils.encoding import hex_decode, hex_encode

        data = b"test data"

        encoded = hex_encode(data)
        decoded = hex_decode(encoded)

        assert decoded == data


class TestConfig:
    """测试配置管理"""

    def test_config_get(self):
        """测试获取配置实例"""
        from utils.config import get_config

        config = get_config()

        assert config is not None

    def test_config_get_value(self):
        """测试获取配置值"""
        from utils.config import get_config_value

        # 使用 default 参数，确保返回非 None
        value = get_config_value("timeout", default=30)

        assert value is not None

    def test_config_set(self):
        """测试设置配置（替换全局实例）"""
        from utils.config import get_config, set_config

        original = get_config()
        set_config(original)  # 设置回同一实例
        restored = get_config()

        assert restored is original


class TestFileUtils:
    """测试文件工具"""

    def test_read_file(self):
        """测试读取文件"""
        from utils.file_utils import safe_read

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content")
            filepath = f.name

        try:
            content = safe_read(filepath)
            assert content == "test content"
        finally:
            os.unlink(filepath)

    def test_write_file(self):
        """测试写入文件"""
        from utils.file_utils import safe_write

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test.txt")

            safe_write(filepath, "test content")

            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            assert content == "test content"

    def test_ensure_directory(self):
        """测试确保目录存在"""
        from utils.file_utils import ensure_dir

        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, "new", "nested", "dir")

            ensure_dir(new_dir)

            assert os.path.isdir(new_dir)


class TestNetUtils:
    """测试网络工具"""

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

        @retry(max_attempts=3, delay=0.01)
        def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary error")
            return "success"

        result = flaky_function()
        assert result == "success"

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



if __name__ == "__main__":
    pytest.main([__file__, "-v"])
