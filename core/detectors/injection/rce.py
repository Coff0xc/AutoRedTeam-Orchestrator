"""
RCE (远程命令执行) 检测器

检测操作系统命令注入漏洞
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


@register_detector('rce')
class RCEDetector(BaseDetector):
    """RCE (远程命令执行) 检测器

    支持的检测技术:
    - 命令分隔符注入 (; | || & &&)
    - 命令替换 (` ` $( ))
    - 时间盲注 (sleep/ping)
    - 输出回显检测

    使用示例:
        detector = RCEDetector()
        results = detector.detect("https://example.com/ping", params={"host": "127.0.0.1"})
    """

    name = 'rce'
    description = '远程命令执行漏洞检测器'
    vuln_type = 'rce'
    severity = Severity.CRITICAL
    detector_type = DetectorType.INJECTION
    version = '2.0.0'

    # 命令执行成功的标志模式
    SUCCESS_PATTERNS = {
        'unix': [
            # id 命令输出
            r'uid=\d+\([a-z_][a-z0-9_-]*\)\s+gid=\d+\([a-z_][a-z0-9_-]*\)',
            # whoami 输出
            r'^(root|www-data|apache|nginx|nobody|daemon)$',
            # /etc/passwd 内容
            r'root:x?:0:0:',
            r'[a-z_][a-z0-9_-]*:[x*]:[\d]+:[\d]+:',
            # cat /etc/passwd
            r'bin:x?:\d+:\d+:',
            r'/bin/bash',
            r'/bin/sh',
            # ls 输出
            r'drwx[r-][w-][x-]',
            r'-rw[r-][w-][r-]',
            # uname 输出
            r'Linux\s+\S+\s+\d+\.\d+',
            # pwd 输出
            r'^/[a-z]+(/[a-z0-9_-]+)*$',
        ],
        'windows': [
            # Windows 路径
            r'[A-Z]:\\(Windows|Users|Program Files)',
            r'C:\\Windows\\System32',
            # dir 输出
            r'Directory of [A-Z]:\\',
            r'\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}',
            # systeminfo 输出
            r'OS Name:\s+Microsoft Windows',
            r'System Type:\s+[xX]64',
            # whoami 输出
            r'[a-z0-9]+\\[a-z0-9]+',
            # type 输出
            r'\[extensions\]',  # win.ini
            r'for 16-bit app support',
        ]
    }

    # 时间盲注 payload 和预期延迟
    TIME_PAYLOADS = {
        'unix': [
            ('; sleep 5', 5),
            ('| sleep 5', 5),
            ('|| sleep 5', 5),
            ('& sleep 5', 5),
            ('&& sleep 5', 5),
            ('`sleep 5`', 5),
            ('$(sleep 5)', 5),
            ('; ping -c 5 127.0.0.1', 5),
        ],
        'windows': [
            ('& ping -n 5 127.0.0.1', 5),
            ('| ping -n 5 127.0.0.1', 5),
            ('& timeout /t 5', 5),
            ('| timeout /t 5', 5),
        ]
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - max_payloads: 最大 payload 数量
                - check_time_based: 是否检测时间盲注
                - time_threshold: 时间判定阈值
                - os_target: 目标系统 ('unix', 'windows', 'both')
        """
        super().__init__(config)

        # 加载 payload
        max_payloads = self.config.get('max_payloads', 30)
        self.payloads = self._enhance_payloads(
            get_payloads(PayloadCategory.RCE, limit=max_payloads)
        )

        # 编译成功模式
        self._success_patterns: Dict[str, List[re.Pattern]] = {}
        for os_type, patterns in self.SUCCESS_PATTERNS.items():
            self._success_patterns[os_type] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in patterns
            ]

        # 配置
        self.check_time_based = self.config.get('check_time_based', True)
        self.time_threshold = self.config.get('time_threshold', 4)
        self.os_target = self.config.get('os_target', 'both')

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测命令注入漏洞

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

        # 获取参数
        params = kwargs.get('params', {})
        data = kwargs.get('data', {})
        method = kwargs.get('method', 'GET').upper()
        headers = kwargs.get('headers', {})

        # 如果没有提供参数，尝试从 URL 解析
        if not params:
            parsed = urlparse(url)
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # 测试 GET 参数
        if params:
            param_results = self._test_parameters(url, params, 'GET', headers)
            results.extend(param_results)

        # 测试 POST 数据
        if data and method == 'POST':
            data_results = self._test_parameters(url, data, 'POST', headers)
            results.extend(data_results)

        self._log_detection_end(url, results)
        return results

    def _test_parameters(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """测试参数中的命令注入

        Args:
            url: 目标 URL
            params: 参数字典
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果列表
        """
        results = []

        for param_name, original_value in params.items():
            # 回显型检测
            echo_result = self._check_echo_based(
                url, params, param_name, original_value, method, headers
            )
            if echo_result:
                results.append(echo_result)
                continue

            # 时间盲注检测
            if self.check_time_based:
                time_result = self._check_time_based(
                    url, params, param_name, original_value, method, headers
                )
                if time_result:
                    results.append(time_result)

        return results

    def _check_echo_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        original_value: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """检测回显型命令注入

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            original_value: 原始值
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        for payload in self.payloads:
            test_value = str(original_value) + payload
            test_params = params.copy()
            test_params[param_name] = test_value

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                # 检查响应中是否有命令执行成功的标志
                os_type, evidence = self._check_command_output(response.text)
                if os_type:
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
                        evidence=evidence,
                        confidence=0.95,
                        verified=True,
                        request=request_info,
                        response=response_info,
                        remediation="避免将用户输入直接传递给系统命令，使用白名单验证或安全的 API",
                        references=[
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                        ],
                        extra={
                            'os_type': os_type,
                            'injection_type': 'echo-based'
                        }
                    )

            except (ConnectionError, TimeoutError, OSError) as e:
                logger.debug(f"回显型命令注入检测失败: {e}")

        return None

    def _check_time_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        original_value: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """检测时间盲注型命令注入

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            original_value: 原始值
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 获取基线响应时间
        try:
            start = time.time()
            if method == 'GET':
                self.http_client.get(url, params=params, headers=headers)
            else:
                self.http_client.post(url, data=params, headers=headers)
            baseline_time = time.time() - start
        except (ConnectionError, TimeoutError, OSError):
            baseline_time = 1.0

        # 根据目标系统选择 payload
        time_payloads = []
        if self.os_target in ('unix', 'both'):
            time_payloads.extend(self.TIME_PAYLOADS['unix'])
        if self.os_target in ('windows', 'both'):
            time_payloads.extend(self.TIME_PAYLOADS['windows'])

        for payload, expected_delay in time_payloads:
            test_value = str(original_value) + payload
            test_params = params.copy()
            test_params[param_name] = test_value

            try:
                start = time.time()

                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                elapsed = time.time() - start

                # 如果响应时间显著增加
                if elapsed >= expected_delay - 1 and elapsed > baseline_time + self.time_threshold:
                    # 验证：再次测试确认
                    start2 = time.time()
                    if method == 'GET':
                        response_second = self.http_client.get(url, params=test_params, headers=headers)
                    else:
                        response_second = self.http_client.post(url, data=test_params, headers=headers)
                    elapsed2 = time.time() - start2

                    if elapsed2 >= expected_delay - 1:
                        request_info = self._build_request_info(
                            method=method,
                            url=url,
                            headers=headers,
                            params=test_params if method == 'GET' else None,
                            data=test_params if method != 'GET' else None
                        )
                        response_info = self._build_response_info(response_second or response)
                        return self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=payload,
                            evidence=f"响应延迟 {elapsed:.2f}s / {elapsed2:.2f}s（预期 {expected_delay}s）",
                            confidence=0.85,
                            verified=True,
                            request=request_info,
                            response=response_info,
                            remediation="避免将用户输入直接传递给系统命令，使用白名单验证或安全的 API",
                            extra={
                                'injection_type': 'time-based',
                                'delay': elapsed,
                                'os_type': 'windows' if 'ping -n' in payload else 'unix'
                            }
                        )

            except (ConnectionError, TimeoutError, OSError) as e:
                logger.debug(f"时间盲注检测失败: {e}")

        return None

    def _check_command_output(self, response_text: str) -> tuple:
        """检查响应中是否包含命令执行成功的输出

        Args:
            response_text: 响应文本

        Returns:
            (OS类型, 证据) 或 (None, None)
        """
        for os_type in ['unix', 'windows']:
            if self.os_target not in ('both', os_type):
                continue

            for pattern in self._success_patterns.get(os_type, []):
                match = pattern.search(response_text)
                if match:
                    # 提取上下文
                    start = max(0, match.start() - 30)
                    end = min(len(response_text), match.end() + 30)
                    context = response_text[start:end]
                    return (os_type, context.strip())

        return (None, None)

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads
