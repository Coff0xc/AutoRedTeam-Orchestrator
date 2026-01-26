#!/usr/bin/env python3
"""
漏洞检测工具 - 通用工具函数和配置
"""
import logging
import time
import re
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List

from .._common import (
    GLOBAL_CONFIG, HAS_REQUESTS, get_verify_ssl, validate_target_host
)

if HAS_REQUESTS:
    import requests

logger = logging.getLogger(__name__)


def vuln_check(url: str) -> dict:
    """综合漏洞检测 - 快速检测常见Web漏洞"""
    if not HAS_REQUESTS:
        return {"success": False, "error": "需要安装 requests: pip install requests"}

    vulns = []

    # 1. 检测目录遍历
    try:
        test_url = url.rstrip('/') + "/../../../etc/passwd"
        resp = requests.get(test_url, timeout=5, verify=get_verify_ssl())
        if "root:" in resp.text:
            vulns.append({"type": "Path Traversal", "severity": "HIGH", "url": test_url})
    except (requests.RequestException, OSError):
        logger.warning("Suppressed exception", exc_info=True)

    # 2. 检测信息泄露
    info_paths = [".git/config", ".env", "phpinfo.php", "server-status", "actuator/env"]
    for path in info_paths:
        try:
            test_url = url.rstrip('/') + "/" + path
            resp = requests.get(test_url, timeout=5, verify=get_verify_ssl())
            if resp.status_code == 200 and len(resp.content) > 100:
                vulns.append({"type": "Information Disclosure", "severity": "MEDIUM", "url": test_url, "path": path})
        except (requests.RequestException, OSError):
            logger.warning("Suppressed exception", exc_info=True)

    # 3. 检测CORS配置
    try:
        resp = requests.get(url, headers={"Origin": "https://evil.com"}, timeout=5, verify=get_verify_ssl())
        if "access-control-allow-origin" in resp.headers:
            origin = resp.headers.get("access-control-allow-origin")
            if origin == "*" or origin == "https://evil.com":
                vulns.append({"type": "CORS Misconfiguration", "severity": "MEDIUM", "detail": f"ACAO: {origin}"})
    except (requests.RequestException, OSError):
        logger.warning("Suppressed exception", exc_info=True)

    # 4. 检测安全头缺失
    try:
        resp = requests.get(url, timeout=5, verify=get_verify_ssl())
        missing_headers = []
        if "x-frame-options" not in resp.headers:
            missing_headers.append("X-Frame-Options")
        if "x-content-type-options" not in resp.headers:
            missing_headers.append("X-Content-Type-Options")
        if "x-xss-protection" not in resp.headers:
            missing_headers.append("X-XSS-Protection")
        if missing_headers:
            vulns.append({"type": "Missing Security Headers", "severity": "LOW", "headers": missing_headers})
    except (requests.RequestException, OSError):
        logger.warning("Suppressed exception", exc_info=True)

    # 5. 检测HTTP方法
    try:
        resp = requests.options(url, timeout=5, verify=get_verify_ssl())
        if "allow" in resp.headers:
            methods = resp.headers["allow"]
            dangerous = [m for m in ["PUT", "DELETE", "TRACE"] if m in methods.upper()]
            if dangerous:
                vulns.append({"type": "Dangerous HTTP Methods", "severity": "MEDIUM", "methods": dangerous})
    except (requests.RequestException, OSError):
        logger.warning("Suppressed exception", exc_info=True)

    return {"success": True, "url": url, "vulnerabilities": vulns, "total": len(vulns)}


def get_baseline_response(url: str, num_samples: int = 3) -> tuple:
    """获取基线响应用于对比
    
    Returns:
        tuple: (baseline_length, baseline_time, baseline_std)
    """
    baseline_lengths = []
    baseline_times = []
    
    for _ in range(num_samples):
        try:
            start = time.time()
            resp = requests.get(url, timeout=GLOBAL_CONFIG["request_timeout"], verify=get_verify_ssl())
            elapsed = time.time() - start
            baseline_lengths.append(len(resp.text))
            baseline_times.append(elapsed)
        except (requests.RequestException, OSError):
            logger.warning("Suppressed exception", exc_info=True)
    
    if not baseline_lengths:
        return 0, 0, 0
    
    avg_length = sum(baseline_lengths) / len(baseline_lengths)
    avg_time = sum(baseline_times) / len(baseline_times)
    
    # 计算时间标准差
    variance = sum((t - avg_time) ** 2 for t in baseline_times) / len(baseline_times)
    std = variance ** 0.5
    
    return avg_length, avg_time, std


def parse_url_params(url: str, default_params: List[str] = None) -> List[str]:
    """从URL解析参数名，如果没有则返回默认参数列表"""
    parsed = urlparse(url)
    params = []
    
    if parsed.query:
        params = [p.split('=')[0] for p in parsed.query.split('&') if '=' in p]
    
    if not params and default_params:
        params = default_params
    
    return params


def check_response_for_patterns(response_text: str, patterns: List[str], case_sensitive: bool = False) -> Optional[str]:
    """检查响应文本中是否包含指定模式
    
    Returns:
        匹配的模式，或 None
    """
    text = response_text if case_sensitive else response_text.lower()
    
    for pattern in patterns:
        check_pattern = pattern if case_sensitive else pattern.lower()
        if re.search(check_pattern, text, re.IGNORECASE if not case_sensitive else 0):
            return pattern
    
    return None


def build_test_url(base_url: str, param: str, payload: str) -> str:
    """构建测试URL"""
    if HAS_REQUESTS:
        encoded_payload = requests.utils.quote(payload)
    else:
        from urllib.parse import quote
        encoded_payload = quote(payload)
    
    if "?" in base_url:
        return f"{base_url}&{param}={encoded_payload}"
    else:
        return f"{base_url}?{param}={encoded_payload}"


def safe_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    """安全执行HTTP请求，捕获所有异常"""
    if not HAS_REQUESTS:
        return None
    
    try:
        kwargs.setdefault("timeout", GLOBAL_CONFIG.get("request_timeout", 10))
        kwargs.setdefault("verify", get_verify_ssl())
        return requests.request(method, url, **kwargs)
    except (requests.RequestException, OSError):
        logger.warning("Suppressed exception", exc_info=True)
        return None


# 导出
__all__ = [
    "vuln_check",
    "get_baseline_response",
    "parse_url_params", 
    "check_response_for_patterns",
    "build_test_url",
    "safe_request",
    "GLOBAL_CONFIG",
    "HAS_REQUESTS",
    "get_verify_ssl",
    "logger",
]