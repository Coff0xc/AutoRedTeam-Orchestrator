#!/usr/bin/env python3
"""
基础漏洞检测器 - 提取公共逻辑，消除代码重复

所有检测器的基类，提供：
- 统一的 Vulnerability 数据类
- 统一的 HTTP 请求处理
- 统一的 Payload 测试逻辑
- 统一的异常处理
- 统一的参数遍历
- 二次验证机制
"""
import logging

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
import re
import time
import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools._common import (
    get_verify_ssl, get_proxies, make_request, get_user_agent,
    GLOBAL_CONFIG, rate_limited, safe_json_response,
    record_failure, reset_failure_counter, should_abort_scan
)

# 尝试导入 requests
try:
    import requests
    from core.http.client_factory import HTTPClientFactory
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class Vulnerability:
    """漏洞数据类 - 统一的漏洞信息结构"""
    type: str                           # 漏洞类型 (如 "Error-based SQLi")
    severity: str                       # 严重程度 (CRITICAL/HIGH/MEDIUM/LOW/INFO)
    param: Optional[str] = None         # 漏洞参数
    payload: Optional[str] = None       # 触发漏洞的 Payload
    evidence: Optional[str] = None      # 漏洞证据
    url: Optional[str] = None           # 漏洞 URL
    verified: bool = False              # 是否经过二次验证
    confidence: float = 0.0             # 置信度 (0.0-1.0)
    details: Dict[str, Any] = field(default_factory=dict)  # 额外详情

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "type": self.type,
            "severity": self.severity,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence,
            "url": self.url,
            "verified": self.verified,
            "confidence": self.confidence,
            "details": self.details
        }


class BaseDetector(ABC):
    """
    漏洞检测器基类

    所有检测器必须继承此类并实现:
    - get_payloads(): 返回 Payload 字典
    - validate_response(): 验证响应是否表明存在漏洞
    """

    # 默认测试参数列表
    DEFAULT_PARAMS = [
        "id", "page", "cat", "search", "q", "query",
        "user", "name", "item", "product", "file", "path",
        "url", "redirect", "next", "return", "callback"
    ]

    def __init__(
        self,
        timeout: int = None,
        verify_ssl: bool = None,
        max_retries: int = 2,
        user_agent: str = None
    ):
        """
        初始化检测器

        Args:
            timeout: 请求超时时间 (秒)
            verify_ssl: 是否验证 SSL 证书
            max_retries: 最大重试次数
            user_agent: 自定义 User-Agent
        """
        self.timeout = timeout or GLOBAL_CONFIG.get("request_timeout", 10)
        self.verify_ssl = verify_ssl if verify_ssl is not None else get_verify_ssl()
        self.max_retries = max_retries
        self.user_agent = user_agent or get_user_agent()

        # 创建 Session 用于连接复用
        if HAS_REQUESTS:
            self.session = HTTPClientFactory.get_sync_client(
                verify_ssl=self.verify_ssl,
                headers={"User-Agent": self.user_agent},
                max_retries=max_retries,
                force_new=True
            )
        else:
            self.session = None

        # 基线响应缓存
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}

    @abstractmethod
    def get_payloads(self) -> Dict[str, List[str]]:
        """
        获取 Payload 库

        Returns:
            字典，键为 payload 类型，值为 payload 列表
            例如: {"error_based": ["'", "\""], "time_based": [...]}
        """
        pass

    @abstractmethod
    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """
        验证响应是否表明存在漏洞

        Args:
            response: 响应数据字典
            payload: 使用的 payload
            baseline: 基线响应 (用于对比)

        Returns:
            True 表示可能存在漏洞
        """
        pass

    def get_test_params(self, param: Optional[str] = None) -> List[str]:
        """获取测试参数列表"""
        if param:
            return [param]
        return self.DEFAULT_PARAMS.copy()

    @rate_limited
    def send_request(
        self,
        url: str,
        payload: str = None,
        param: str = None,
        method: str = "GET",
        data: str = None,
        headers: dict = None
    ) -> Optional[Dict[str, Any]]:
        """
        发送 HTTP 请求 - 统一的请求处理

        Args:
            url: 目标 URL
            payload: 要注入的 payload
            param: 参数名
            method: HTTP 方法
            data: POST 数据
            headers: 额外请求头

        Returns:
            响应数据字典，失败返回 None
        """
        try:
            # 构建测试 URL
            test_url = url
            if payload and param:
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{param}={payload}"

            start_time = time.time()

            # 使用 make_request 或 session
            if self.session and HAS_REQUESTS:
                proxies = get_proxies()
                req_headers = {"User-Agent": self.user_agent}
                if headers:
                    req_headers.update(headers)

                if method.upper() == "GET":
                    resp = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        proxies=proxies,
                        headers=req_headers
                    )
                elif method.upper() == "POST":
                    resp = self.session.post(
                        test_url,
                        data=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        proxies=proxies,
                        headers=req_headers
                    )
                else:
                    resp = self.session.request(
                        method,
                        test_url,
                        data=data,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        proxies=proxies,
                        headers=req_headers
                    )

                elapsed = time.time() - start_time

                return {
                    "url": test_url,
                    "status_code": resp.status_code,
                    "response_length": len(resp.text),
                    "response_time": elapsed,
                    "response_text": resp.text[:GLOBAL_CONFIG.get("max_response_size", 100000)],
                    "headers": dict(resp.headers),
                    "success": True
                }
            else:
                # 降级到 make_request
                result = make_request(test_url, method=method, headers=headers, data=data)
                if result.get("success"):
                    result["response_length"] = len(result.get("text", ""))
                    result["response_text"] = result.get("text", "")
                    result["response_time"] = 0
                return result

        except Exception as e:
            record_failure(is_network_error=True)
            return {"success": False, "error": str(e), "url": url}

    def get_baseline(self, url: str) -> Dict[str, Any]:
        """
        获取基线响应 (用于对比检测)

        Args:
            url: 目标 URL

        Returns:
            基线响应数据
        """
        if url in self._baseline_cache:
            return self._baseline_cache[url]

        baseline = self.send_request(url)
        if baseline and baseline.get("success"):
            self._baseline_cache[url] = baseline
        return baseline or {}

    def test_payload(
        self,
        url: str,
        payload: str,
        param: str,
        baseline: Dict[str, Any] = None
    ) -> Optional[Vulnerability]:
        """
        测试单个 Payload

        Args:
            url: 目标 URL
            payload: 要测试的 payload
            param: 参数名
            baseline: 基线响应 (可选)

        Returns:
            如果发现漏洞返回 Vulnerability 对象，否则返回 None
        """
        # 检查是否应该中止扫描
        if should_abort_scan():
            return None

        response = self.send_request(url, payload, param)
        if not response or not response.get("success"):
            record_failure(is_network_error=True)
            return None

        # 重置失败计数器（成功请求）
        reset_failure_counter()

        # 验证响应
        if self.validate_response(response, payload, baseline):
            return Vulnerability(
                type=self.__class__.__name__.replace("Detector", ""),
                severity="MEDIUM",  # 子类可覆盖
                param=param,
                payload=payload,
                url=response.get("url", url),
                evidence=self._extract_evidence(response),
                verified=False,
                confidence=0.6
            )
        return None

    def _extract_evidence(self, response: Dict[str, Any]) -> str:
        """从响应中提取证据"""
        evidence_parts = []
        if response.get("status_code"):
            evidence_parts.append(f"Status: {response['status_code']}")
        if response.get("response_length"):
            evidence_parts.append(f"Length: {response['response_length']}")
        if response.get("response_time"):
            evidence_parts.append(f"Time: {response['response_time']:.2f}s")
        return " | ".join(evidence_parts) if evidence_parts else "N/A"

    def test_payloads(
        self,
        url: str,
        param: Optional[str] = None,
        stop_on_first: bool = True
    ) -> List[Vulnerability]:
        """
        批量测试所有 Payloads

        Args:
            url: 目标 URL
            param: 指定参数 (可选，不指定则测试所有默认参数)
            stop_on_first: 发现第一个漏洞后是否停止

        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        payloads = self.get_payloads()
        test_params = self.get_test_params(param)
        baseline = self.get_baseline(url)

        for test_param in test_params:
            if should_abort_scan():
                break

            for payload_type, payload_list in payloads.items():
                for payload in payload_list:
                    vuln = self.test_payload(url, payload, test_param, baseline)

                    if vuln:
                        vuln.type = payload_type
                        vuln.details["payload_type"] = payload_type
                        vulnerabilities.append(vuln)

                        if stop_on_first:
                            return vulnerabilities

        return vulnerabilities

    def detect(
        self,
        url: str,
        param: Optional[str] = None,
        deep_scan: bool = False
    ) -> Dict[str, Any]:
        """
        检测入口 - 执行漏洞检测

        Args:
            url: 目标 URL
            param: 指定参数 (可选)
            deep_scan: 是否深度扫描

        Returns:
            检测结果字典
        """
        # 重置失败计数器
        reset_failure_counter()

        try:
            vulnerabilities = self.test_payloads(url, param, stop_on_first=not deep_scan)

            # 二次验证
            verified_vulns = []
            for vuln in vulnerabilities:
                if self.verify_vulnerability(vuln):
                    vuln.verified = True
                    vuln.confidence = min(1.0, vuln.confidence + 0.3)
                verified_vulns.append(vuln)

            return {
                "success": True,
                "url": url,
                "detector": self.__class__.__name__,
                "vulnerabilities": [v.to_dict() for v in verified_vulns],
                "total": len(verified_vulns),
                "verified_count": sum(1 for v in verified_vulns if v.verified)
            }

        except Exception as e:
            return {
                "success": False,
                "url": url,
                "detector": self.__class__.__name__,
                "error": str(e),
                "vulnerabilities": [],
                "total": 0
            }

    def verify_vulnerability(self, vuln: Vulnerability) -> bool:
        """
        二次验证漏洞 - 降低误报率

        Args:
            vuln: 待验证的漏洞

        Returns:
            True 表示验证通过
        """
        if not vuln.url or not vuln.payload or not vuln.param:
            return False

        # 重新发送请求验证
        response = self.send_request(vuln.url)
        if not response or not response.get("success"):
            return False

        # 使用相同 payload 再次测试
        test_response = self.send_request(
            vuln.url.split("?")[0],  # 基础 URL
            vuln.payload,
            vuln.param
        )

        if not test_response or not test_response.get("success"):
            return False

        # 验证响应是否仍然表明存在漏洞
        return self.validate_response(test_response, vuln.payload, response)

    def cleanup(self):
        """清理资源"""
        if self.session:
            try:
                self.session.close()
            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            self.session = None
        self._baseline_cache.clear()

    def __enter__(self):
        """上下文管理器入口"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.cleanup()
        return False
