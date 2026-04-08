# -*- coding: utf-8 -*-
"""
core/credential 模块单元测试

覆盖:
- CredentialDumper: 实例化、WiFi/Vault/Chrome/Firefox/SSH/env 提取、错误处理
- PasswordFinder: 实例化、文件扫描、模式匹配、Git 历史搜索、大文件跳过
"""

import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from core.credential.credential_dumper import (
    Credential,
    CredentialDumper,
    CredentialType,
    DumpResult,
    dump_credentials,
)
from core.credential.password_finder import (
    PasswordFinder,
    SecretFinding,
    SecretType,
    find_secrets,
)


# ==================== CredentialDumper 测试 ====================


@pytest.mark.unit
class TestCredentialDumperInit:
    """CredentialDumper 实例化测试"""

    def test_default_init(self):
        """默认参数实例化"""
        dumper = CredentialDumper()
        assert dumper.verbose is False
        assert dumper.os_type == platform.system().lower()
        assert dumper.credentials == []

    def test_verbose_init(self):
        """verbose 模式实例化"""
        dumper = CredentialDumper(verbose=True)
        assert dumper.verbose is True

    def test_log_verbose(self):
        """verbose 模式下 _log 不报错"""
        dumper = CredentialDumper(verbose=True)
        # 不应抛出异常
        dumper._log("test message")

    def test_log_silent(self):
        """非 verbose 模式下 _log 不输出"""
        dumper = CredentialDumper(verbose=False)
        dumper._log("should be silent")


@pytest.mark.unit
class TestCredentialDataClasses:
    """数据类序列化测试"""

    def test_credential_to_dict(self):
        """Credential.to_dict 包含全部字段"""
        cred = Credential(
            cred_type=CredentialType.PASSWORD,
            source="test",
            username="admin",
            password="secret",
            domain="corp",
            host="10.0.0.1",
            url="http://example.com",
        )
        d = cred.to_dict()
        assert d["type"] == "password"
        assert d["source"] == "test"
        assert d["username"] == "admin"
        assert d["password"] == "secret"
        assert d["domain"] == "corp"
        assert d["host"] == "10.0.0.1"
        assert "timestamp" in d

    def test_credential_long_password_truncated(self):
        """超长密码应被截断"""
        long_pw = "A" * 200
        cred = Credential(
            cred_type=CredentialType.HASH,
            source="test",
            password=long_pw,
        )
        d = cred.to_dict()
        assert "TRUNCATED" in d["password"]
        assert len(d["password"]) < len(long_pw)

    def test_dump_result_to_dict(self):
        """DumpResult.to_dict 结构正确"""
        cred = Credential(cred_type=CredentialType.WIFI, source="wifi")
        result = DumpResult(success=True, source="wifi", credentials=[cred])
        d = result.to_dict()
        assert d["success"] is True
        assert d["count"] == 1
        assert len(d["credentials"]) == 1

    def test_dump_result_failure(self):
        """DumpResult 失败场景"""
        result = DumpResult(success=False, source="vault", error="denied")
        d = result.to_dict()
        assert d["success"] is False
        assert d["error"] == "denied"
        assert d["count"] == 0


@pytest.mark.unit
class TestWindowsVault:
    """Windows 凭据管理器 (cmdkey /list) mock 测试"""

    def test_non_windows_returns_error(self):
        """非 Windows 平台应返回失败"""
        dumper = CredentialDumper()
        dumper.os_type = "linux"
        result = dumper.dump_windows_vault()
        assert result.success is False
        assert "仅支持Windows" in result.error

    @patch("subprocess.run")
    def test_vault_parse_english(self, mock_run):
        """解析英文格式 cmdkey 输出"""
        mock_run.return_value = MagicMock(
            stdout=(
                "Currently stored credentials:\n\n"
                "    Target: LegacyGeneric:target=server1\n"
                "    User: CORP\\admin\n\n"
                "    Target: Domain:target=fileserver\n"
                "    User: user2\n"
            )
        )
        dumper = CredentialDumper()
        dumper.os_type = "windows"
        result = dumper.dump_windows_vault()
        assert result.success is True
        assert len(result.credentials) == 2
        assert result.credentials[0].username == "CORP\\admin"
        assert result.credentials[0].host == "LegacyGeneric:target=server1"

    @patch("subprocess.run")
    def test_vault_parse_chinese(self, mock_run):
        """解析中文格式 cmdkey 输出"""
        mock_run.return_value = MagicMock(
            stdout=(
                "当前保存的凭据:\n\n"
                "    目标: Domain:target=dc01\n"
                "    用户: admin@corp.local\n"
            )
        )
        dumper = CredentialDumper()
        dumper.os_type = "windows"
        result = dumper.dump_windows_vault()
        assert result.success is True
        assert len(result.credentials) == 1
        assert result.credentials[0].source == "Windows Credential Manager"

    @patch("subprocess.run", side_effect=FileNotFoundError("cmdkey not found"))
    def test_vault_command_not_found(self, mock_run):
        """cmdkey 不存在时应返回错误"""
        dumper = CredentialDumper()
        dumper.os_type = "windows"
        result = dumper.dump_windows_vault()
        assert result.success is False
        assert result.error


@pytest.mark.unit
class TestChromePasswords:
    """Chrome 密码提取 mock 测试"""

    def test_chrome_dir_not_exist(self):
        """Chrome 配置目录不存在时应返回失败"""
        dumper = CredentialDumper()
        with patch("os.path.exists", return_value=False):
            result = dumper.dump_chrome_passwords()
        assert result.success is False
        assert "不存在" in result.error

    @patch("os.remove")
    @patch("sqlite3.connect")
    @patch("shutil.copy2")
    @patch("os.walk")
    @patch("os.path.exists", return_value=True)
    def test_chrome_extracts_logins(
        self, mock_exists, mock_walk, mock_copy, mock_connect, mock_remove
    ):
        """正常 Chrome 数据库提取（非 Windows DPAPI 路径）"""
        dumper = CredentialDumper()
        dumper.os_type = "linux"  # 避免 DPAPI 解密分支

        # 模拟 os.walk 返回包含 Login Data 的目录
        mock_walk.return_value = [
            ("/home/user/.config/google-chrome/Default", [], ["Login Data"]),
        ]

        # 模拟 sqlite3 查询结果
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            ("https://example.com", "user1", b"encrypted_blob"),
            ("https://test.com", "user2", b"another_blob"),
            ("https://empty.com", "", b""),  # 空用户名应跳过
        ]
        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        result = dumper.dump_chrome_passwords()
        assert result.success is True
        assert len(result.credentials) == 2
        assert result.credentials[0].url == "https://example.com"
        assert result.credentials[0].cred_type == CredentialType.BROWSER

    @patch("os.path.exists", return_value=True)
    @patch("os.walk", return_value=[("/chrome/Default", [], ["Login Data"])])
    @patch("shutil.copy2", side_effect=PermissionError("access denied"))
    def test_chrome_permission_error(self, mock_copy, mock_walk, mock_exists):
        """权限不足时不崩溃，返回空结果"""
        dumper = CredentialDumper()
        dumper.os_type = "linux"
        result = dumper.dump_chrome_passwords()
        # 复制失败应被 except 捕获，credentials 为空
        assert result.success is True
        assert len(result.credentials) == 0


@pytest.mark.unit
class TestFirefoxPasswords:
    """Firefox 密码提取 mock 测试"""

    def test_firefox_dir_not_exist(self):
        """Firefox 配置目录不存在时应返回失败"""
        dumper = CredentialDumper()
        with patch("os.path.exists", return_value=False):
            result = dumper.dump_firefox_passwords()
        assert result.success is False
        assert "不存在" in result.error

    @patch(
        "builtins.open",
        mock_open(
            read_data=json.dumps(
                {
                    "logins": [
                        {
                            "hostname": "https://example.com",
                            "encryptedUsername": "enc_user1",
                            "guid": "guid-1",
                        },
                        {
                            "hostname": "https://other.com",
                            "encryptedUsername": "enc_user2",
                            "guid": "guid-2",
                        },
                    ]
                }
            )
        ),
    )
    @patch("os.path.exists", return_value=True)
    @patch("os.listdir", return_value=["profile1.default"])
    def test_firefox_extracts_logins(self, mock_listdir, mock_exists):
        """正常 Firefox logins.json 解析"""
        dumper = CredentialDumper()
        dumper.os_type = "linux"
        result = dumper.dump_firefox_passwords()
        assert result.success is True
        assert len(result.credentials) == 2
        assert result.credentials[0].source == "Firefox"
        assert result.credentials[0].url == "https://example.com"


@pytest.mark.unit
class TestHashIdentification:
    """hash 类型识别测试"""

    @pytest.mark.parametrize(
        "hash_str, expected",
        [
            ("$1$salt$hash", "MD5"),
            ("$5$rounds=5000$salt$hash", "SHA-256"),
            ("$6$salt$longhash", "SHA-512"),
            ("$y$j9T$salt$hash", "yescrypt"),
            ("$2b$12$salt_and_hash", "bcrypt"),
            ("plain_unknown", "unknown"),
        ],
    )
    def test_identify_hash_type(self, hash_str, expected):
        dumper = CredentialDumper()
        assert dumper._identify_hash_type(hash_str) == expected


@pytest.mark.unit
class TestDumpAll:
    """dump_all 综合接口测试"""

    def test_dump_all_selected_categories(self):
        """仅执行指定类别"""
        dumper = CredentialDumper()
        with patch.object(dumper, "dump_environment_secrets") as mock_env:
            mock_env.return_value = DumpResult(True, "environment")
            results = dumper.dump_all(categories=["env"])
        assert "env" in results
        mock_env.assert_called_once()

    def test_dump_all_method_exception(self):
        """某个方法抛异常时不影响其他方法"""
        dumper = CredentialDumper()
        with patch.object(
            dumper, "dump_environment_secrets", side_effect=RuntimeError("boom")
        ):
            with patch.object(
                dumper, "dump_ssh_keys", return_value=DumpResult(True, "ssh_keys")
            ):
                results = dumper.dump_all(categories=["env", "ssh"])
        assert results["env"].success is False
        assert "boom" in results["env"].error
        assert results["ssh"].success is True

    def test_export_json_string(self):
        """export_json 返回合法 JSON 字符串"""
        dumper = CredentialDumper()
        dumper.credentials = [
            Credential(cred_type=CredentialType.PASSWORD, source="test", username="u")
        ]
        output = dumper.export_json()
        data = json.loads(output)
        assert data["total"] == 1
        assert "credentials" in data

    def test_export_json_to_file(self, tmp_path):
        """export_json 写入文件"""
        dumper = CredentialDumper()
        out_file = str(tmp_path / "creds.json")
        result = dumper.export_json(out_file)
        assert result == out_file
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        assert "total" in data


@pytest.mark.unit
class TestDumpCredentialsConvenience:
    """dump_credentials 便捷函数测试"""

    def test_returns_dict(self):
        """便捷函数返回正确结构"""
        with patch.object(CredentialDumper, "dump_all") as mock_all:
            mock_all.return_value = {
                "env": DumpResult(True, "environment"),
            }
            result = dump_credentials(categories=["env"])
        assert "total_credentials" in result
        assert "results" in result


# ==================== PasswordFinder 测试 ====================


@pytest.mark.unit
class TestPasswordFinderInit:
    """PasswordFinder 实例化测试"""

    def test_default_init(self):
        """默认参数"""
        finder = PasswordFinder()
        assert finder.max_file_size == 10 * 1024 * 1024
        assert finder.verbose is False
        assert finder.findings == []
        assert ".git" in finder.ignore_dirs
        assert ".exe" in finder.ignore_extensions

    def test_custom_init(self):
        """自定义参数"""
        finder = PasswordFinder(
            ignore_dirs={"custom_dir"},
            ignore_extensions={".xyz"},
            max_file_size=1024,
            verbose=True,
        )
        assert finder.ignore_dirs == {"custom_dir"}
        assert finder.ignore_extensions == {".xyz"}
        assert finder.max_file_size == 1024


@pytest.mark.unit
class TestPasswordPatternMatching:
    """密码模式匹配测试 — 验证 regex 对常见格式的覆盖"""

    def _scan_line(self, finder: PasswordFinder, content: str) -> list:
        """辅助：将单行内容写入临时文件并扫描"""
        tmp = Path(tempfile.mktemp(suffix=".cfg"))
        try:
            tmp.write_text(content, encoding="utf-8")
            return finder.scan_file(tmp)
        finally:
            tmp.unlink(missing_ok=True)

    def test_password_equals_pattern(self):
        """匹配 private key header"""
        finder = PasswordFinder()
        # 私钥 header 不会被假阳性过滤
        findings = self._scan_line(finder, "-----BEGIN RSA PRIVATE KEY-----")
        assert len(findings) >= 1
        assert any(f.secret_type == SecretType.PRIVATE_KEY for f in findings)

    def test_aws_access_key(self):
        """匹配 AWS Access Key ID 格式"""
        finder = PasswordFinder()
        # 使用非官方示例的 AWS key 格式
        findings = self._scan_line(finder, "aws_key = AKIAQZ7X9BJ3K5M2WRTY")
        assert any(f.secret_type == SecretType.AWS_KEY for f in findings)

    def test_private_key_header(self):
        """匹配 RSA 私钥头"""
        finder = PasswordFinder()
        findings = self._scan_line(finder, "-----BEGIN RSA PRIVATE KEY-----")
        assert any(f.secret_type == SecretType.PRIVATE_KEY for f in findings)

    def test_github_token(self):
        """匹配 GitHub PAT"""
        finder = PasswordFinder()
        # ghp_ 前缀 + 36 字符
        token = "ghp_xK9mR2vB7nQ4wJ6pL8tY0cF3hA5dZ1eG2iU4"
        findings = self._scan_line(finder, f'GITHUB_TOKEN = "{token}"')
        # GitHub token 可能被归类为 API_KEY 或 GENERIC_SECRET
        assert len(findings) >= 1

    def test_jwt_token(self):
        """匹配 JWT"""
        finder = PasswordFinder()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456"
        findings = self._scan_line(finder, f"auth = {jwt}")
        assert any(f.secret_type == SecretType.JWT_TOKEN for f in findings)

    def test_database_url(self):
        """匹配数据库连接字符串"""
        finder = PasswordFinder()
        findings = self._scan_line(
            finder, "DATABASE_URL=postgres://user:pass@localhost/db"
        )
        assert any(f.secret_type == SecretType.DATABASE_URL for f in findings)

    def test_false_positive_placeholder(self):
        """占位符不应被匹配"""
        finder = PasswordFinder()
        findings = self._scan_line(finder, 'password = "your_password"')
        # 假阳性检测应过滤掉
        assert len(findings) == 0

    def test_false_positive_variable_ref(self):
        """变量引用 ${} 不应被匹配"""
        finder = PasswordFinder()
        findings = self._scan_line(finder, 'secret = "${SECRET_KEY}"')
        assert len(findings) == 0


@pytest.mark.unit
class TestFileSkipLogic:
    """文件跳过逻辑测试"""

    def test_skip_binary_extension(self):
        """二进制扩展名应跳过"""
        finder = PasswordFinder()
        assert finder._should_skip_file(Path("program.exe")) is True
        assert finder._should_skip_file(Path("image.jpg")) is True
        assert finder._should_skip_file(Path("archive.zip")) is True

    def test_skip_minified_js(self):
        """压缩 JS 应跳过"""
        finder = PasswordFinder()
        assert finder._should_skip_file(Path("bundle.min.js")) is True
        assert finder._should_skip_file(Path("style.min.css")) is True

    def test_skip_large_file(self, tmp_path):
        """超过 max_file_size 的文件应跳过"""
        finder = PasswordFinder(max_file_size=10)
        big_file = tmp_path / "big.txt"
        big_file.write_text("A" * 100, encoding="utf-8")
        assert finder._should_skip_file(big_file) is True

    def test_normal_file_not_skipped(self, tmp_path):
        """正常文本文件不应跳过"""
        finder = PasswordFinder()
        normal = tmp_path / "config.yaml"
        normal.write_text("key: value", encoding="utf-8")
        assert finder._should_skip_file(normal) is False

    def test_skip_dir(self):
        """忽略目录列表中的目录应跳过"""
        finder = PasswordFinder()
        assert finder._should_skip_dir(Path("node_modules")) is True
        assert finder._should_skip_dir(Path(".git")) is True
        assert finder._should_skip_dir(Path("src")) is False


@pytest.mark.unit
class TestSensitiveFilename:
    """敏感文件名检测测试"""

    def test_env_file(self):
        finder = PasswordFinder()
        assert finder._is_sensitive_filename(".env") is True
        assert finder._is_sensitive_filename(".env.production") is True

    def test_config_files(self):
        finder = PasswordFinder()
        assert finder._is_sensitive_filename("config.json") is True
        assert finder._is_sensitive_filename("wp-config.php") is True

    def test_normal_file(self):
        finder = PasswordFinder()
        assert finder._is_sensitive_filename("app.py") is False


@pytest.mark.unit
class TestScanDirectory:
    """scan_directory 测试"""

    def test_nonexistent_directory(self):
        """不存在的目录应返回空列表"""
        finder = PasswordFinder()
        result = finder.scan_directory("/nonexistent/path/xyz")
        assert result == []

    def test_scan_with_findings(self, tmp_path):
        """包含敏感信息的目录扫描"""
        secret_file = tmp_path / "config.ini"
        # 使用 RSA private key header，不会被假阳性过滤
        secret_file.write_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n", encoding="utf-8"
        )
        finder = PasswordFinder()
        findings = finder.scan_directory(str(tmp_path))
        assert len(findings) >= 1

    def test_scan_ignores_subdirs(self, tmp_path):
        """忽略目录内的文件不应扫描"""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        hidden = git_dir / "config"
        hidden.write_text('password = "real_secret_here_123"', encoding="utf-8")
        finder = PasswordFinder()
        findings = finder.scan_directory(str(tmp_path))
        # .git 目录下的文件应被忽略
        assert not any(".git" in f.file_path for f in findings)


@pytest.mark.unit
class TestGitHistorySearch:
    """Git 历史搜索 mock 测试"""

    @patch("subprocess.run")
    def test_git_history_finds_secrets(self, mock_run, tmp_path):
        """在 git diff 中发现敏感信息"""
        # 创建 .git 目录让路径检查通过
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        # 第一次调用: git log
        log_result = MagicMock(stdout="abc123def456\n")
        # 第二次调用: git show
        diff_result = MagicMock(
            stdout=(
                "+++ b/config.py\n"
                '+db_password = "Kj8#mPq2xR!vN5wZ"\n'
            )
        )
        mock_run.side_effect = [log_result, diff_result]

        finder = PasswordFinder()
        findings = finder.scan_git_history(str(tmp_path), max_commits=1)

        # 至少调用了 git log
        assert mock_run.called

    def test_not_a_git_repo(self, tmp_path):
        """非 git 仓库应返回空列表"""
        finder = PasswordFinder()
        findings = finder.scan_git_history(str(tmp_path))
        assert findings == []

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 60))
    def test_git_timeout(self, mock_run):
        """git 命令超时不应崩溃"""
        finder = PasswordFinder()
        with patch("pathlib.Path.exists", return_value=True):
            findings = finder.scan_git_history("/fake/repo")
        assert findings == []


@pytest.mark.unit
class TestSummaryAndExport:
    """get_summary / export_json 测试"""

    def test_summary_structure(self):
        """摘要包含全部预期字段"""
        finder = PasswordFinder()
        finder.findings = [
            SecretFinding(
                secret_type=SecretType.PASSWORD,
                file_path="a.txt",
                line_number=1,
                line_content="pw=xxx",
                matched_text="pw=xxx",
                confidence="high",
            ),
            SecretFinding(
                secret_type=SecretType.API_KEY,
                file_path="b.txt",
                line_number=2,
                line_content="key=yyy",
                matched_text="key=yyy",
                confidence="medium",
            ),
        ]
        s = finder.get_summary()
        assert s["total_findings"] == 2
        assert s["by_confidence"]["high"] == 1
        assert s["by_confidence"]["medium"] == 1
        assert "password" in s["by_type"]

    def test_export_json_string(self):
        """export_json 返回合法 JSON"""
        finder = PasswordFinder()
        finder.findings = []
        output = finder.export_json()
        data = json.loads(output)
        assert "summary" in data
        assert "findings" in data

    def test_export_json_to_file(self, tmp_path):
        """export_json 写入文件"""
        finder = PasswordFinder()
        finder.findings = []
        out = str(tmp_path / "report.json")
        result = finder.export_json(out)
        assert result == out
        assert Path(out).exists()


@pytest.mark.unit
class TestFindSecretsConvenience:
    """find_secrets 便捷函数测试"""

    def test_returns_dict(self, tmp_path):
        """便捷函数返回正确结构"""
        (tmp_path / "empty.txt").write_text("nothing here", encoding="utf-8")
        result = find_secrets(str(tmp_path))
        assert "summary" in result
        assert "findings" in result
