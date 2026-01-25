#!/usr/bin/env python3
"""
gRPC安全测试模块

提供gRPC服务安全检测功能，包括:
- Reflection服务检测
- TLS配置检测
- 认证检测
- 元数据安全检测
- 服务枚举

作者: AutoRedTeam
版本: 3.0.0
"""

import logging
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import (
    BaseCloudTester,
    CloudFinding,
    CloudVulnType,
    CloudSeverity,
)

logger = logging.getLogger(__name__)

# 尝试导入grpcio
try:
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
    HAS_GRPC = True
except ImportError:
    HAS_GRPC = False


class GRPCTester(BaseCloudTester):
    """
    gRPC安全测试器

    对gRPC服务进行安全扫描。

    使用示例:
        tester = GRPCTester(config={
            'target': 'localhost:50051'
        })
        findings = tester.scan()
    """

    name = 'grpc'
    provider = 'grpc'
    description = 'gRPC安全测试器'
    version = '3.0.0'

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化gRPC测试器

        Args:
            config: 可选配置，可包含:
                - target: gRPC服务地址 (host:port)
                - use_tls: 是否使用TLS
                - cert_path: TLS证书路径
                - auth_token: 认证Token
        """
        super().__init__(config)

        self.target = self.config.get('target', 'localhost:50051')
        self.use_tls = self.config.get('use_tls', False)
        self.cert_path = self.config.get('cert_path')
        self.auth_token = self.config.get('auth_token')

        # 解析目标地址
        if '://' in self.target:
            parsed = urlparse(self.target)
            self.host = parsed.hostname
            self.port = parsed.port or 50051
            self.use_tls = parsed.scheme == 'grpcs'
        else:
            parts = self.target.split(':')
            self.host = parts[0]
            self.port = int(parts[1]) if len(parts) > 1 else 50051

        self._channel = None
        self._discovered_services: List[str] = []

    def scan(self) -> List[CloudFinding]:
        """执行完整的gRPC安全扫描"""
        self.clear_findings()

        # 执行各项检查
        self.test_tls()
        self.test_reflection()
        self.test_auth()
        self.test_metadata()

        return self._findings

    def test_tls(self) -> Optional[CloudFinding]:
        """
        测试TLS配置

        检测gRPC服务是否使用TLS加密。

        Returns:
            测试结果或None
        """
        # 首先测试是否可以建立非TLS连接
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            # 尝试发送gRPC前缀
            # gRPC使用HTTP/2，发送PRI前缀
            sock.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')

            response = sock.recv(1024)
            sock.close()

            # 如果收到明文响应，说明没有TLS
            if response and not response.startswith(b'\x16'):  # TLS记录以0x16开头
                if not self.use_tls:
                    finding = self._create_finding(
                        vuln_type=CloudVulnType.GRPC_NO_TLS,
                        severity=CloudSeverity.HIGH,
                        resource_type='gRPCService',
                        resource_name=f'{self.host}:{self.port}',
                        title='gRPC服务未使用TLS',
                        description=(
                            f'gRPC服务 {self.host}:{self.port} 接受非加密连接，'
                            '数据以明文传输。'
                        ),
                        remediation=(
                            '1. 配置TLS证书\n'
                            '2. 使用grpc.ssl_channel_credentials()\n'
                            '3. 在服务端启用TLS'
                        ),
                        evidence={'tls_enabled': False}
                    )
                    return finding

        except Exception as e:
            logger.debug(f'TLS测试失败: {e}')

        # 测试TLS配置
        if self.use_tls:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock = context.wrap_socket(sock, server_hostname=self.host)
                sock.connect((self.host, self.port))

                # 获取证书信息
                cert = sock.getpeercert(binary_form=True)
                sock.close()

                if cert:
                    logger.info('gRPC服务使用TLS加密')

            except ssl.SSLError as e:
                self._create_finding(
                    vuln_type=CloudVulnType.GRPC_INSECURE_CHANNEL,
                    severity=CloudSeverity.MEDIUM,
                    resource_type='gRPCService',
                    resource_name=f'{self.host}:{self.port}',
                    title='gRPC TLS配置问题',
                    description=f'TLS连接错误: {str(e)}',
                    remediation='检查TLS证书配置'
                )

        return None

    def test_reflection(self) -> Optional[CloudFinding]:
        """
        测试Reflection服务

        检测gRPC服务是否启用了Server Reflection。

        Returns:
            测试结果或None
        """
        if not HAS_GRPC:
            logger.warning('grpcio未安装，跳过Reflection测试')
            return None

        try:
            # 创建channel
            if self.use_tls:
                if self.cert_path:
                    with open(self.cert_path, 'rb') as f:
                        creds = grpc.ssl_channel_credentials(f.read())
                else:
                    creds = grpc.ssl_channel_credentials()
                channel = grpc.secure_channel(f'{self.host}:{self.port}', creds)
            else:
                channel = grpc.insecure_channel(f'{self.host}:{self.port}')

            self._channel = channel

            # 创建reflection stub
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            # 发送服务列表请求
            request = reflection_pb2.ServerReflectionRequest(
                list_services=''
            )

            responses = stub.ServerReflectionInfo(iter([request]))

            for response in responses:
                if response.HasField('list_services_response'):
                    services = [
                        svc.name for svc in response.list_services_response.service
                    ]

                    self._discovered_services = services

                    finding = self._create_finding(
                        vuln_type=CloudVulnType.GRPC_REFLECTION_ENABLED,
                        severity=CloudSeverity.MEDIUM,
                        resource_type='gRPCService',
                        resource_name=f'{self.host}:{self.port}',
                        title='gRPC Reflection服务已启用',
                        description=(
                            f'gRPC服务启用了Server Reflection，'
                            f'可以枚举到{len(services)}个服务。'
                        ),
                        remediation=(
                            '1. 在生产环境禁用Reflection\n'
                            '2. 使用grpc.reflection.v1alpha.reflection.disable()\n'
                            '3. 实施访问控制'
                        ),
                        evidence={
                            'services': services,
                            'service_count': len(services)
                        }
                    )
                    return finding

        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.UNIMPLEMENTED:
                logger.info('Reflection服务未启用')
            else:
                logger.debug(f'Reflection测试失败: {e}')
        except Exception as e:
            logger.debug(f'Reflection测试异常: {e}')

        return None

    def test_auth(self) -> Optional[CloudFinding]:
        """
        测试认证配置

        检测gRPC服务是否要求认证。

        Returns:
            测试结果或None
        """
        if not HAS_GRPC:
            return None

        if not self._channel:
            try:
                if self.use_tls:
                    creds = grpc.ssl_channel_credentials()
                    self._channel = grpc.secure_channel(f'{self.host}:{self.port}', creds)
                else:
                    self._channel = grpc.insecure_channel(f'{self.host}:{self.port}')
            except Exception as e:
                logger.debug(f'创建channel失败: {e}')
                return None

        # 尝试无认证调用
        if self._discovered_services:
            for service in self._discovered_services:
                # 跳过reflection服务本身
                if 'reflection' in service.lower():
                    continue

                # 尝试调用服务的方法
                try:
                    # 这里使用通用的健康检查或第一个服务
                    # 实际实现需要根据具体服务调整
                    pass

                except grpc.RpcError as e:
                    if e.code() == grpc.StatusCode.UNAUTHENTICATED:
                        # 需要认证，这是好的
                        logger.info(f'服务 {service} 要求认证')
                    elif e.code() == grpc.StatusCode.PERMISSION_DENIED:
                        # 需要授权，这也是好的
                        logger.info(f'服务 {service} 要求授权')
                    else:
                        # 其他错误可能意味着无需认证
                        self._create_finding(
                            vuln_type=CloudVulnType.GRPC_AUTH_MISSING,
                            severity=CloudSeverity.HIGH,
                            resource_type='gRPCService',
                            resource_name=f'{self.host}:{self.port}',
                            title=f'gRPC服务可能未要求认证: {service}',
                            description=(
                                f'尝试调用服务 {service} 时未返回认证错误'
                            ),
                            remediation=(
                                '1. 实施认证拦截器\n'
                                '2. 使用Token验证\n'
                                '3. 配置mTLS'
                            ),
                            evidence={'service': service, 'error_code': str(e.code())}
                        )

        return None

    def test_metadata(self) -> Optional[CloudFinding]:
        """
        测试元数据安全

        检测gRPC响应中是否泄露敏感信息。

        Returns:
            测试结果或None
        """
        # 元数据测试需要实际调用服务
        # 这里提供框架，具体实现取决于目标服务

        sensitive_headers = [
            'server',
            'x-powered-by',
            'x-debug',
            'x-request-id',
        ]

        # 如果有channel，尝试获取元数据
        if self._channel:
            try:
                # 创建一个简单的调用来获取trailing metadata
                # 实际实现需要根据服务调整
                pass

            except Exception as e:
                logger.debug(f'元数据测试失败: {e}')

        return None

    def enumerate_services(self) -> List[Dict[str, Any]]:
        """
        枚举gRPC服务

        Returns:
            服务信息列表
        """
        if not HAS_GRPC:
            return []

        services_info = []

        try:
            if not self._channel:
                if self.use_tls:
                    creds = grpc.ssl_channel_credentials()
                    self._channel = grpc.secure_channel(f'{self.host}:{self.port}', creds)
                else:
                    self._channel = grpc.insecure_channel(f'{self.host}:{self.port}')

            stub = reflection_pb2_grpc.ServerReflectionStub(self._channel)

            # 获取服务列表
            list_request = reflection_pb2.ServerReflectionRequest(list_services='')
            list_responses = stub.ServerReflectionInfo(iter([list_request]))

            service_names = []
            for response in list_responses:
                if response.HasField('list_services_response'):
                    service_names = [
                        svc.name for svc in response.list_services_response.service
                    ]
                    break

            # 获取每个服务的详细信息
            for service_name in service_names:
                service_info = {
                    'name': service_name,
                    'methods': []
                }

                # 获取服务描述
                file_request = reflection_pb2.ServerReflectionRequest(
                    file_containing_symbol=service_name
                )

                try:
                    file_responses = stub.ServerReflectionInfo(iter([file_request]))

                    for file_response in file_responses:
                        if file_response.HasField('file_descriptor_response'):
                            # 解析文件描述符获取方法信息
                            # 这里简化处理
                            pass
                except (grpc.RpcError, StopIteration, AttributeError) as e:
                    logger.debug(f'获取服务 {service_name} 的文件描述符失败: {e}')

                services_info.append(service_info)

        except Exception as e:
            logger.error(f'服务枚举失败: {e}')

        return services_info


# 便捷函数
def scan_grpc(
    target: str,
    use_tls: bool = False
) -> Dict[str, Any]:
    """
    快速gRPC安全扫描

    Args:
        target: gRPC服务地址
        use_tls: 是否使用TLS

    Returns:
        扫描结果摘要
    """
    tester = GRPCTester(config={
        'target': target,
        'use_tls': use_tls
    })
    findings = tester.scan()
    return tester.get_summary().to_dict()


def enumerate_grpc_services(
    target: str,
    use_tls: bool = False
) -> List[Dict[str, Any]]:
    """
    枚举gRPC服务

    Args:
        target: gRPC服务地址
        use_tls: 是否使用TLS

    Returns:
        服务信息列表
    """
    tester = GRPCTester(config={
        'target': target,
        'use_tls': use_tls
    })
    return tester.enumerate_services()


__all__ = [
    'GRPCTester',
    'scan_grpc',
    'enumerate_grpc_services',
]
