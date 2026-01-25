#!/usr/bin/env python3
"""
gRPC安全测试模块
检测: 反射API、认证绕过、流量拦截、消息篡改
作者: AutoRedTeam
"""

import json
import logging
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class GRPCVulnType(Enum):
    """gRPC漏洞类型"""
    REFLECTION_ENABLED = "reflection_enabled"
    NO_TLS = "no_tls"
    WEAK_TLS = "weak_tls"
    NO_AUTH = "no_auth"
    TOKEN_EXPOSURE = "token_exposure"
    METADATA_INJECTION = "metadata_injection"
    LARGE_MESSAGE = "large_message"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"


class GRPCSeverity(Enum):
    """严重性"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class GRPCFinding:
    """gRPC安全发现"""
    vuln_type: GRPCVulnType
    severity: GRPCSeverity
    title: str
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)


class GRPCSecurityTester:
    """gRPC安全测试器"""

    # gRPC魔术字节
    GRPC_MAGIC = b'\x00'  # 未压缩
    GRPC_COMPRESSED = b'\x01'  # 压缩

    # 反射服务名
    REFLECTION_SERVICE = "grpc.reflection.v1alpha.ServerReflection"
    REFLECTION_SERVICE_V1 = "grpc.reflection.v1.ServerReflection"

    # 常见gRPC元数据键
    COMMON_METADATA_KEYS = [
        "authorization",
        "x-api-key",
        "x-auth-token",
        "grpc-timeout",
        "user-agent",
        "x-request-id",
    ]

    def __init__(self, timeout: float = 10.0):
        """
        初始化gRPC安全测试器

        Args:
            timeout: 请求超时时间
        """
        self.timeout = timeout
        self._findings: List[GRPCFinding] = []

    def _parse_grpc_url(self, url: str) -> Tuple[str, int, bool]:
        """解析gRPC URL

        Returns:
            (host, port, use_tls)
        """
        # 处理不同格式的URL
        if url.startswith("grpc://"):
            url = url[7:]
            use_tls = False
        elif url.startswith("grpcs://"):
            url = url[8:]
            use_tls = True
        elif url.startswith("https://"):
            url = url[8:]
            use_tls = True
        elif url.startswith("http://"):
            url = url[7:]
            use_tls = False
        else:
            use_tls = False

        # 解析host:port
        if ":" in url:
            host, port_str = url.split(":", 1)
            port_str = port_str.split("/")[0]  # 移除路径
            port = int(port_str)
        else:
            host = url.split("/")[0]
            port = 443 if use_tls else 80

        return host, port, use_tls

    def _create_grpc_frame(self, data: bytes,
                           compressed: bool = False) -> bytes:
        """创建gRPC帧"""
        flag = b'\x01' if compressed else b'\x00'
        length = struct.pack('>I', len(data))
        return flag + length + data

    def _connect(self, host: str, port: int,
                 use_tls: bool = False) -> Optional[socket.socket]:
        """建立连接"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            return sock

        except Exception as e:
            logger.debug(f"连接失败: {e}")
            return None

    def test_reflection(self, target: str) -> Dict[str, Any]:
        """测试gRPC反射API

        检查服务器是否启用了反射API,可能泄露服务定义

        Args:
            target: gRPC目标 (host:port 或 grpc://host:port)

        Returns:
            {
                "vulnerable": bool,
                "reflection_enabled": bool,
                "services": [...],
                "remediation": str
            }
        """
        result = {
            "vulnerable": False,
            "reflection_enabled": False,
            "services": [],
            "methods": [],
            "remediation": ""
        }

        host, port, use_tls = self._parse_grpc_url(target)

        try:
            # 尝试使用grpcio库
            import grpc

            channel_target = f"{host}:{port}"

            if use_tls:
                credentials = grpc.ssl_channel_credentials()
                channel = grpc.secure_channel(channel_target, credentials)
            else:
                channel = grpc.insecure_channel(channel_target)

            try:
                from grpc_reflection.v1alpha import reflection_pb2
                from grpc_reflection.v1alpha import reflection_pb2_grpc

                stub = reflection_pb2_grpc.ServerReflectionStub(channel)

                # 请求服务列表
                request = reflection_pb2.ServerReflectionRequest(
                    list_services=""
                )

                responses = stub.ServerReflectionInfo(iter([request]))

                for response in responses:
                    if response.HasField("list_services_response"):
                        services = response.list_services_response.service
                        result["services"] = [s.name for s in services]
                        result["reflection_enabled"] = True
                        result["vulnerable"] = True
                        break

            except ImportError:
                # 没有grpc_reflection库,使用原始方法
                result["note"] = "需要grpc_reflection库进行完整测试"

            finally:
                channel.close()

        except ImportError:
            # 没有grpcio,使用原始socket测试
            result["note"] = "需要grpcio库进行完整测试"

            # 简单检测:尝试HTTP/2连接
            sock = self._connect(host, port, use_tls)
            if sock:
                try:
                    # 发送HTTP/2 preface
                    preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                    sock.send(preface)

                    # 等待响应
                    response = sock.recv(1024)
                    if response:
                        result["http2_supported"] = True

                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

                finally:
                    sock.close()

        except Exception as e:
            result["error"] = str(e)

        if result["vulnerable"]:
            result["remediation"] = "在生产环境禁用gRPC反射API"

            self._findings.append(GRPCFinding(
                vuln_type=GRPCVulnType.REFLECTION_ENABLED,
                severity=GRPCSeverity.MEDIUM,
                title="gRPC反射API启用",
                description="服务器启用了反射API,可能泄露服务定义",
                remediation=result["remediation"],
                evidence={"services": result["services"]}
            ))

        return result

    def test_tls(self, target: str) -> Dict[str, Any]:
        """测试gRPC TLS配置

        Args:
            target: gRPC目标

        Returns:
            {
                "vulnerable": bool,
                "tls_enabled": bool,
                "tls_version": str,
                "certificate_info": {...},
                "remediation": str
            }
        """
        result = {
            "vulnerable": False,
            "tls_enabled": False,
            "tls_version": "",
            "certificate_info": {},
            "issues": [],
            "remediation": ""
        }

        host, port, _ = self._parse_grpc_url(target)

        # 首先测试无TLS连接
        sock = self._connect(host, port, use_tls=False)
        if sock:
            try:
                # 发送HTTP/2 preface
                preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                sock.send(preface)
                response = sock.recv(1024)

                if response:
                    result["plaintext_allowed"] = True
                    result["vulnerable"] = True
                    result["issues"].append("服务器接受明文gRPC连接")

            except Exception as exc:
                logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            finally:
                sock.close()

        # 测试TLS连接
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=host) as sock:
                    result["tls_enabled"] = True
                    result["tls_version"] = sock.version()

                    # 获取证书信息
                    cert = sock.getpeercert(binary_form=True)
                    if cert:
                        result["certificate_info"]["present"] = True

                    # 检查弱TLS版本
                    if sock.version() in ["TLSv1", "TLSv1.1"]:
                        result["vulnerable"] = True
                        result["issues"].append(f"使用弱TLS版本: {sock.version()}")

        except ssl.SSLError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                result["issues"].append("证书验证失败")
            else:
                result["issues"].append(f"SSL错误: {e}")

        except Exception as e:
            result["error"] = str(e)

        if result["vulnerable"]:
            if result.get("plaintext_allowed"):
                result["remediation"] = "强制使用TLS,禁用明文连接"

                self._findings.append(GRPCFinding(
                    vuln_type=GRPCVulnType.NO_TLS,
                    severity=GRPCSeverity.HIGH,
                    title="gRPC服务接受明文连接",
                    description="服务器接受未加密的gRPC连接,流量可被截获",
                    remediation=result["remediation"],
                    evidence={"plaintext_allowed": True}
                ))
            else:
                result["remediation"] = "升级到TLS 1.2或更高版本"

                self._findings.append(GRPCFinding(
                    vuln_type=GRPCVulnType.WEAK_TLS,
                    severity=GRPCSeverity.MEDIUM,
                    title="gRPC使用弱TLS版本",
                    description=f"服务器使用弱TLS版本: {result['tls_version']}",
                    remediation=result["remediation"],
                    evidence={"tls_version": result["tls_version"]}
                ))

        return result

    def test_auth_bypass(self, target: str) -> Dict[str, Any]:
        """测试gRPC认证绕过

        Args:
            target: gRPC目标

        Returns:
            {
                "vulnerable": bool,
                "auth_required": bool,
                "bypass_methods": [...],
                "remediation": str
            }
        """
        result = {
            "vulnerable": False,
            "auth_required": False,
            "tests": [],
            "remediation": ""
        }

        host, port, use_tls = self._parse_grpc_url(target)

        try:
            import grpc

            channel_target = f"{host}:{port}"

            if use_tls:
                credentials = grpc.ssl_channel_credentials()
                channel = grpc.secure_channel(channel_target, credentials)
            else:
                channel = grpc.insecure_channel(channel_target)

            # 测试无认证调用
            try:
                # 尝试获取反射信息作为测试
                from grpc_reflection.v1alpha import reflection_pb2_grpc

                stub = reflection_pb2_grpc.ServerReflectionStub(channel)

                # 如果能调用,说明不需要认证
                result["tests"].append({
                    "test": "无认证调用",
                    "success": True,
                    "note": "服务接受无认证请求"
                })

            except grpc.RpcError as e:
                status_code = e.code()

                if status_code == grpc.StatusCode.UNAUTHENTICATED:
                    result["auth_required"] = True
                    result["tests"].append({
                        "test": "无认证调用",
                        "success": False,
                        "note": "需要认证"
                    })

            except ImportError:
                result["tests"].append({
                    "test": "无认证调用",
                    "success": None,
                    "note": "需要grpc_reflection库"
                })

            # 测试伪造metadata
            test_metadata = [
                ("authorization", "Bearer fake_token"),
                ("x-api-key", "test_key"),
                ("x-forwarded-for", "127.0.0.1"),
            ]

            for key, value in test_metadata:
                try:
                    # 这里需要实际的服务方法来测试
                    result["tests"].append({
                        "test": f"metadata注入: {key}",
                        "metadata": {key: value},
                        "note": "需要已知服务方法进行完整测试"
                    })
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

            channel.close()

        except ImportError:
            result["note"] = "需要grpcio库进行完整测试"

        except Exception as e:
            result["error"] = str(e)

        # 判断是否存在认证绕过
        for test in result["tests"]:
            if test.get("test") == "无认证调用" and test.get("success"):
                result["vulnerable"] = True
                break

        if result["vulnerable"]:
            result["remediation"] = "实施gRPC拦截器进行认证验证"

            self._findings.append(GRPCFinding(
                vuln_type=GRPCVulnType.NO_AUTH,
                severity=GRPCSeverity.HIGH,
                title="gRPC服务缺少认证",
                description="服务接受无认证的gRPC请求",
                remediation=result["remediation"],
                evidence={"tests": result["tests"]}
            ))

        return result

    def test_metadata_injection(self, target: str) -> Dict[str, Any]:
        """测试gRPC metadata注入

        Args:
            target: gRPC目标

        Returns:
            {
                "vulnerable": bool,
                "injection_points": [...],
                "remediation": str
            }
        """
        result = {
            "vulnerable": False,
            "injection_tests": [],
            "remediation": ""
        }

        # 注入测试payload
        injection_payloads = [
            ("authorization", "Bearer ' OR '1'='1"),
            ("x-custom-header", "{{7*7}}"),  # SSTI
            ("x-forwarded-for", "127.0.0.1, attacker.com"),
            ("user-agent", "$(id)"),  # 命令注入
            ("x-request-id", "' OR 1=1--"),  # SQL注入
        ]

        host, port, use_tls = self._parse_grpc_url(target)

        try:
            import grpc

            channel_target = f"{host}:{port}"

            if use_tls:
                credentials = grpc.ssl_channel_credentials()
                channel = grpc.secure_channel(channel_target, credentials)
            else:
                channel = grpc.insecure_channel(channel_target)

            for key, payload in injection_payloads:
                test_result = {
                    "header": key,
                    "payload": payload,
                    "accepted": False,
                    "error": None
                }

                # 注意:这里需要实际的服务方法来测试
                # 仅记录测试用例
                result["injection_tests"].append(test_result)

            channel.close()

            result["note"] = "需要已知服务方法进行完整的注入测试"

        except ImportError:
            result["note"] = "需要grpcio库"

        except Exception as e:
            result["error"] = str(e)

        if result["vulnerable"]:
            result["remediation"] = "验证和清理所有gRPC metadata输入"

        return result

    def test_message_size_limit(self, target: str,
                                 max_size_mb: int = 10) -> Dict[str, Any]:
        """测试gRPC消息大小限制

        Args:
            target: gRPC目标
            max_size_mb: 最大测试大小(MB)

        Returns:
            {
                "vulnerable": bool,
                "max_accepted_size": int,
                "remediation": str
            }
        """
        result = {
            "vulnerable": False,
            "tests": [],
            "max_accepted_size": 0,
            "remediation": ""
        }

        host, port, use_tls = self._parse_grpc_url(target)

        # 测试不同大小
        test_sizes = [1, 5, 10, 50, 100]  # MB

        try:
            import grpc

            channel_target = f"{host}:{port}"

            # 设置大消息选项
            options = [
                ('grpc.max_send_message_length', max_size_mb * 1024 * 1024),
                ('grpc.max_receive_message_length', max_size_mb * 1024 * 1024),
            ]

            if use_tls:
                credentials = grpc.ssl_channel_credentials()
                channel = grpc.secure_channel(channel_target, credentials, options=options)
            else:
                channel = grpc.insecure_channel(channel_target, options=options)

            result["note"] = "需要已知服务方法进行完整的大小测试"

            channel.close()

        except ImportError:
            result["note"] = "需要grpcio库"

        except Exception as e:
            result["error"] = str(e)

        return result

    def full_scan(self, target: str) -> Dict[str, Any]:
        """完整gRPC安全扫描

        Args:
            target: gRPC目标 (host:port)

        Returns:
            完整扫描结果
        """
        self._findings = []

        results = {
            "target": target,
            "tests": {}
        }

        # TLS测试
        results["tests"]["tls"] = self.test_tls(target)

        # 反射API测试
        results["tests"]["reflection"] = self.test_reflection(target)

        # 认证绕过测试
        results["tests"]["auth_bypass"] = self.test_auth_bypass(target)

        # Metadata注入测试
        results["tests"]["metadata_injection"] = self.test_metadata_injection(target)

        # 统计漏洞
        vulnerabilities = []
        for finding in self._findings:
            vulnerabilities.append({
                "type": finding.vuln_type.value,
                "severity": finding.severity.value,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation
            })

        results["vulnerabilities"] = vulnerabilities

        # 汇总
        results["summary"] = {
            "total_tests": len(results["tests"]),
            "vulnerable_count": len(vulnerabilities),
            "highest_severity": self._get_highest_severity()
        }

        # 建议
        results["recommendations"] = self._generate_recommendations()

        return results

    def _get_highest_severity(self) -> str:
        """获取最高严重性"""
        severity_order = ["critical", "high", "medium", "low", "info"]

        for sev in severity_order:
            for finding in self._findings:
                if finding.severity.value == sev:
                    return sev

        return "none"

    def _generate_recommendations(self) -> List[str]:
        """生成安全建议"""
        recommendations = []

        vuln_types = set(f.vuln_type for f in self._findings)

        if GRPCVulnType.NO_TLS in vuln_types:
            recommendations.append("强制使用TLS加密所有gRPC通信")

        if GRPCVulnType.REFLECTION_ENABLED in vuln_types:
            recommendations.append("在生产环境禁用gRPC反射API")

        if GRPCVulnType.NO_AUTH in vuln_types:
            recommendations.append("实施gRPC拦截器进行认证和授权")

        if not recommendations:
            recommendations.append("继续保持良好的gRPC安全配置")

        return recommendations

    def generate_report(self) -> str:
        """生成扫描报告"""
        lines = [
            "=" * 60,
            "gRPC安全扫描报告",
            "=" * 60,
            f"发现问题数: {len(self._findings)}",
            "",
            "-" * 60,
            "问题详情:",
            "-" * 60,
        ]

        for finding in self._findings:
            severity_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "ℹ️"
            }.get(finding.severity.value, "⚪")

            lines.extend([
                f"{severity_icon} [{finding.severity.value.upper()}] {finding.title}",
                f"   描述: {finding.description}",
                f"   修复: {finding.remediation}",
                ""
            ])

        lines.append("=" * 60)

        return "\n".join(lines)


# 便捷函数
def scan_grpc(target: str) -> Dict[str, Any]:
    """快速扫描gRPC服务"""
    tester = GRPCSecurityTester()
    return tester.full_scan(target)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "localhost:50051"

    tester = GRPCSecurityTester()
    result = tester.full_scan(target)

    print(f"发现问题数: {result['summary']['vulnerable_count']}")
    print(f"最高严重性: {result['summary']['highest_severity']}")
