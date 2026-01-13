#!/usr/bin/env python3
"""
安全加固模块测试套件
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

import unittest
from pathlib import Path
import tempfile
import shutil

from core.security import (
    InputValidator,
    ValidationError,
    SafeExecutor,
    SecurityError,
    ExecutionPolicy,
    AuthManager,
    Permission,
    ToolLevel,
    SecretsManager,
)


class TestInputValidator(unittest.TestCase):
    """输入验证器测试"""

    def setUp(self):
        self.validator = InputValidator()

    def test_validate_url_success(self):
        """测试URL验证 - 成功"""
        url = self.validator.validate_url("http://example.com")
        self.assertEqual(url, "http://example.com")

        url = self.validator.validate_url("https://example.com:8080/path")
        self.assertEqual(url, "https://example.com:8080/path")

    def test_validate_url_failure(self):
        """测试URL验证 - 失败"""
        with self.assertRaises(ValidationError):
            self.validator.validate_url("javascript:alert(1)")

        with self.assertRaises(ValidationError):
            self.validator.validate_url("file:///etc/passwd")

    def test_validate_ip_success(self):
        """测试IP验证 - 成功"""
        ip = self.validator.validate_ip("192.168.1.1")
        self.assertEqual(ip, "192.168.1.1")

        ip = self.validator.validate_ip("8.8.8.8")
        self.assertEqual(ip, "8.8.8.8")

    def test_validate_ip_failure(self):
        """测试IP验证 - 失败"""
        with self.assertRaises(ValidationError):
            self.validator.validate_ip("127.0.0.1")  # 回环地址

        with self.assertRaises(ValidationError):
            self.validator.validate_ip("invalid")

    def test_validate_port_success(self):
        """测试端口验证 - 成功"""
        port = self.validator.validate_port(80)
        self.assertEqual(port, 80)

        port = self.validator.validate_port("8080")
        self.assertEqual(port, 8080)

    def test_validate_port_failure(self):
        """测试端口验证 - 失败"""
        with self.assertRaises(ValidationError):
            self.validator.validate_port(0)

        with self.assertRaises(ValidationError):
            self.validator.validate_port(70000)

    def test_validate_path_traversal(self):
        """测试路径遍历防护"""
        temp_dir = tempfile.mkdtemp()

        try:
            # 正常路径
            safe_path = self.validator.validate_path(
                "test.txt",
                base_dir=temp_dir,
                allow_create=True
            )
            self.assertTrue(safe_path.startswith(temp_dir))

            # 路径遍历攻击
            with self.assertRaises(ValidationError):
                self.validator.validate_path(
                    "../etc/passwd",
                    base_dir=temp_dir
                )

            with self.assertRaises(ValidationError):
                self.validator.validate_path(
                    "../../etc/passwd",
                    base_dir=temp_dir
                )

        finally:
            shutil.rmtree(temp_dir)

    def test_validate_command_args(self):
        """测试命令参数验证"""
        # 正常参数
        args = self.validator.validate_command_args(["nmap", "-sV", "127.0.0.1"])
        self.assertEqual(args, ["nmap", "-sV", "127.0.0.1"])

        # 命令注入
        with self.assertRaises(ValidationError):
            self.validator.validate_command_args(["nmap", "-sV; rm -rf /"])

        with self.assertRaises(ValidationError):
            self.validator.validate_command_args(["nmap", "-sV | cat /etc/passwd"])


class TestSafeExecutor(unittest.TestCase):
    """安全执行器测试"""

    def setUp(self):
        self.executor = SafeExecutor(policy=ExecutionPolicy.STRICT)

    def test_execute_safe_command(self):
        """测试执行安全命令"""
        # 使用 python 命令（在白名单中）
        result = self.executor.execute(["python", "--version"], timeout=5)
        self.assertTrue(result["success"])

    def test_execute_blacklisted_command(self):
        """测试执行黑名单命令"""
        with self.assertRaises(SecurityError):
            self.executor.execute(["rm", "-rf", "/"])

    def test_command_injection_prevention(self):
        """测试命令注入防护"""
        with self.assertRaises(SecurityError):
            self.executor.execute(["python", "-c; rm -rf /"])

    def test_command_not_found(self):
        """测试命令不存在"""
        result = self.executor.execute(["nonexistent_command_12345"], timeout=5)
        self.assertFalse(result["success"])
        self.assertIn("命令未找到", result["error"])


class TestAuthManager(unittest.TestCase):
    """认证管理器测试"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.auth = AuthManager(storage_path=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_generate_key(self):
        """测试生成密钥"""
        key_info = self.auth.generate_key(
            name="测试密钥",
            permissions=[Permission.SCAN],
            max_tool_level=ToolLevel.MODERATE
        )

        self.assertIn("key_id", key_info)
        self.assertIn("secret", key_info)
        self.assertIn("full_key", key_info)

    def test_verify_key(self):
        """测试验证密钥"""
        key_info = self.auth.generate_key(
            name="测试密钥",
            permissions=[Permission.SCAN],
            max_tool_level=ToolLevel.MODERATE
        )

        # 验证正确的密钥
        api_key = self.auth.verify_key(key_info["full_key"])
        self.assertIsNotNone(api_key)
        self.assertEqual(api_key.name, "测试密钥")

        # 验证错误的密钥
        api_key = self.auth.verify_key("invalid.key")
        self.assertIsNone(api_key)

    def test_check_permission(self):
        """测试权限检查"""
        key_info = self.auth.generate_key(
            name="测试密钥",
            permissions=[Permission.SCAN],
            max_tool_level=ToolLevel.MODERATE
        )

        api_key = self.auth.verify_key(key_info["full_key"])

        # 允许的工具
        self.assertTrue(self.auth.check_permission(api_key, "sqli_detect"))

        # 不允许的工具（等级过高）
        self.assertFalse(self.auth.check_permission(api_key, "lateral_smb_exec"))

    def test_admin_permission(self):
        """测试管理员权限"""
        key_info = self.auth.generate_key(
            name="管理员",
            permissions=[Permission.ADMIN],
            max_tool_level=ToolLevel.CRITICAL
        )

        api_key = self.auth.verify_key(key_info["full_key"])

        # 管理员可以访问所有工具
        self.assertTrue(self.auth.check_permission(api_key, "port_scan"))
        self.assertTrue(self.auth.check_permission(api_key, "sqli_detect"))
        self.assertTrue(self.auth.check_permission(api_key, "lateral_smb_exec"))

    def test_revoke_key(self):
        """测试撤销密钥"""
        key_info = self.auth.generate_key(
            name="测试密钥",
            permissions=[Permission.SCAN],
            max_tool_level=ToolLevel.MODERATE
        )

        # 撤销前可以验证
        api_key = self.auth.verify_key(key_info["full_key"])
        self.assertIsNotNone(api_key)

        # 撤销密钥
        self.auth.revoke_key(key_info["key_id"])

        # 撤销后无法验证
        api_key = self.auth.verify_key(key_info["full_key"])
        self.assertIsNone(api_key)


class TestSecretsManager(unittest.TestCase):
    """敏感信息管理器测试"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.manager = SecretsManager(
            master_key="test_master_key_12345678",
            storage_path=self.temp_dir
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_set_and_get_secret(self):
        """测试设置和获取密钥"""
        self.manager.set_secret("TEST_KEY", "test_value")
        value = self.manager.get_secret("TEST_KEY")
        self.assertEqual(value, "test_value")

    def test_delete_secret(self):
        """测试删除密钥"""
        self.manager.set_secret("TEST_KEY", "test_value")
        self.manager.delete_secret("TEST_KEY")
        value = self.manager.get_secret("TEST_KEY")
        self.assertIsNone(value)

    def test_list_secrets(self):
        """测试列出密钥"""
        self.manager.set_secret("KEY1", "value1")
        self.manager.set_secret("KEY2", "value2")

        keys = self.manager.list_secrets()
        self.assertIn("KEY1", keys)
        self.assertIn("KEY2", keys)

    def test_persistence(self):
        """测试持久化"""
        self.manager.set_secret("PERSIST_KEY", "persist_value")

        # 创建新实例（模拟重启）
        new_manager = SecretsManager(
            master_key="test_master_key_12345678",
            storage_path=self.temp_dir
        )

        value = new_manager.get_secret("PERSIST_KEY")
        self.assertEqual(value, "persist_value")


def run_tests():
    """运行所有测试"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestInputValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestSafeExecutor))
    suite.addTests(loader.loadTestsFromTestCase(TestAuthManager))
    suite.addTests(loader.loadTestsFromTestCase(TestSecretsManager))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
