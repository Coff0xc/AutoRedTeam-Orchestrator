#!/usr/bin/env python3
"""
漏洞验证器基础类

包含:
- VulnerabilityVerifier: 核心验证器，整合所有 Mixin
- HTTP 请求工具方法
"""
import json
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .models import VerificationResult

logger = logging.getLogger(__name__)


class BaseVerifier:
    """验证器基类 - 提供HTTP请求工具方法"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def _request(
        self,
        url: str,
        method: str = "GET",
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[Optional[str], int, float, int]:
        """发送HTTP请求"""
        start = time.time()

        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", self.user_agent)

            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)

            if data is not None:
                if isinstance(data, (bytes, bytearray)):
                    req.data = bytes(data)
                else:
                    req.data = str(data).encode()

            resp = urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_ctx)
            body = resp.read().decode("utf-8", errors="ignore")
            elapsed = time.time() - start

            return body, resp.status, elapsed, len(body)

        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return body, e.code, elapsed, len(body)
        except Exception:
            logger.warning("HTTP request failed", exc_info=True)
            return None, 0, time.time() - start, 0

    def _merge_url_params(self, url: str, params: Dict[str, Any]) -> str:
        """合并URL参数"""
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, value in params.items():
            if isinstance(value, (list, tuple)):
                query[key] = [str(v) for v in value]
            else:
                query[key] = [str(value)]
        new_query = urllib.parse.urlencode(query, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _prepare_base_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> Tuple[str, Optional[str], Dict[str, str]]:
        """准备基础请求"""
        method = (method or "GET").upper()
        headers = dict(headers or {})
        params = dict(params or {})

        if method == "GET":
            if params:
                url = self._merge_url_params(url, params)
            return url, None, headers

        if json_data is not None and isinstance(json_data, dict):
            headers.setdefault("Content-Type", "application/json")
            return url, json.dumps(json_data, ensure_ascii=True), headers

        if isinstance(data, dict):
            return url, urllib.parse.urlencode(data, doseq=True), headers

        if data is None and params:
            return url, urllib.parse.urlencode(params, doseq=True), headers

        if data is None:
            return url, None, headers

        if isinstance(data, (bytes, bytearray)):
            return url, data.decode("utf-8", errors="ignore"), headers

        return url, str(data), headers

    def _prepare_request(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
    ) -> Tuple[str, Optional[str], Dict[str, str]]:
        """准备带payload的请求"""
        base_url, body, request_headers = self._prepare_base_request(
            url=url,
            method=method,
            headers=headers,
            params=params,
            data=data,
            json_data=json_data,
        )
        method = (method or "GET").upper()

        if method == "GET":
            merged_params = dict(params or {})
            if param:
                merged_params[param] = payload
            target_url = self._merge_url_params(base_url, merged_params)
            return target_url, None, request_headers

        if json_data is not None and isinstance(json_data, dict):
            body_dict = dict(json_data)
            if param:
                body_dict[param] = payload
            request_headers.setdefault("Content-Type", "application/json")
            return base_url, json.dumps(body_dict, ensure_ascii=True), request_headers

        if isinstance(data, dict):
            body_dict = dict(data)
            if param:
                body_dict[param] = payload
            return base_url, urllib.parse.urlencode(body_dict, doseq=True), request_headers

        if body is None:
            body_str = ""
        else:
            body_str = str(body)

        if param:
            pattern = rf"({re.escape(param)}=)[^&]*"
            if re.search(pattern, body_str):
                body_str = re.sub(
                    pattern, rf"\\1{urllib.parse.quote_plus(payload)}", body_str
                )
            else:
                sep = "&" if body_str else ""
                body_str = f"{body_str}{sep}{param}={urllib.parse.quote_plus(payload)}"

        return base_url, body_str, request_headers


# 导入 Mixin 类（延迟导入避免循环依赖）
def _create_vulnerability_verifier():
    """动态创建完整的 VulnerabilityVerifier 类"""
    from .lfi_rce import LFIRCEVerifierMixin
    from .sqli import SQLiVerifierMixin
    from .ssrf import SSRFVerifierMixin
    from .xss import XSSVerifierMixin

    class VulnerabilityVerifier(
        SQLiVerifierMixin,
        XSSVerifierMixin,
        LFIRCEVerifierMixin,
        SSRFVerifierMixin,
        BaseVerifier,
    ):
        """
        漏洞验证器

        整合所有验证功能:
        - SQLi: 时间盲注、布尔盲注、报错注入
        - XSS: 反射型XSS验证
        - LFI: 本地文件包含验证
        - RCE: 远程命令执行验证
        - SSRF: 服务端请求伪造验证
        """

        def __init__(self, timeout: int = 10):
            super().__init__(timeout)

        def batch_verify(self, findings: List[Dict[str, Any]]) -> List[VerificationResult]:
            """批量验证漏洞"""
            results = []

            for finding in findings:
                url = finding.get("url", "")
                param = finding.get("param", "")
                vuln_type = finding.get("type", "").lower()
                payload = finding.get("payload", "")

                if "sqli" in vuln_type or "sql" in vuln_type:
                    result = self.verify_sqli_error(url, param)
                    if not result.is_vulnerable:
                        result = self.verify_sqli_boolean(url, param)
                    if not result.is_vulnerable:
                        result = self.verify_sqli_time_based(url, param)

                elif "xss" in vuln_type:
                    result = self.verify_xss_reflected(url, param, payload)

                elif "lfi" in vuln_type or "file" in vuln_type:
                    result = self.verify_lfi(url, param, payload)

                elif "rce" in vuln_type or "command" in vuln_type:
                    result = self.verify_rce_time_based(url, param)

                elif "ssrf" in vuln_type:
                    result = self.verify_ssrf(url, param)

                else:
                    continue

                results.append(result)

            return results

    return VulnerabilityVerifier


# 延迟创建类
_VulnerabilityVerifier = None


def get_vulnerability_verifier_class():
    """获取 VulnerabilityVerifier 类（延迟初始化）"""
    global _VulnerabilityVerifier
    if _VulnerabilityVerifier is None:
        _VulnerabilityVerifier = _create_vulnerability_verifier()
    return _VulnerabilityVerifier


# 导出时使用代理
class VulnerabilityVerifier:
    """漏洞验证器代理类"""

    _real_class = None

    def __new__(cls, *args, **kwargs):
        if cls._real_class is None:
            cls._real_class = get_vulnerability_verifier_class()
        return cls._real_class(*args, **kwargs)