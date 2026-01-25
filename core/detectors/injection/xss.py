"""
XSS (跨站脚本) 检测器

检测反射型、存储型、DOM 型 XSS 漏洞
"""

from typing import List, Optional, Dict, Any, Set
import re
import html
import logging
from urllib.parse import urljoin, urlparse, parse_qs, quote

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType, RequestInfo, ResponseInfo
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

# 导入项目统一异常类型
from core.exceptions import (
    DetectorError,
    HTTPError,
    TimeoutError as DetectorTimeoutError,
    ConnectionError as DetectorConnectionError,
)

logger = logging.getLogger(__name__)


@register_detector('xss')
class XSSDetector(BaseDetector):
    """XSS (跨站脚本) 检测器

    支持的检测类型:
    - 反射型 XSS (Reflected)
    - 存储型 XSS (Stored) - 需要配合回显检测
    - DOM 型 XSS (DOM-based) - 基于特征检测

    使用示例:
        detector = XSSDetector()
        results = detector.detect("https://example.com/search", params={"q": "test"})
    """

    name = 'xss'
    description = 'XSS 跨站脚本漏洞检测器'
    vuln_type = 'xss'
    severity = Severity.HIGH
    detector_type = DetectorType.INJECTION
    version = '2.0.0'

    # XSS 执行成功的标志模式
    REFLECTION_PATTERNS = [
        # 脚本标签
        r'<script[^>]*>.*?alert\s*\(\s*[\'"]?1[\'"]?\s*\).*?</script>',
        r'<script[^>]*>.*?alert\s*\(\s*[\'"]?XSS[\'"]?\s*\).*?</script>',
        r'<script[^>]*>.*?alert\s*\(\s*document\.domain\s*\).*?</script>',

        # 事件处理器
        r'<img[^>]*\sonerror\s*=\s*[\'"]?alert\s*\([^)]*\)[\'"]?[^>]*>',
        r'<svg[^>]*\sonload\s*=\s*[\'"]?alert\s*\([^)]*\)[\'"]?[^>]*>',
        r'<body[^>]*\sonload\s*=\s*[\'"]?alert\s*\([^)]*\)[\'"]?[^>]*>',
        r'<input[^>]*\sonfocus\s*=\s*[\'"]?alert\s*\([^)]*\)[\'"]?[^>]*>',
        r'<iframe[^>]*\sonload\s*=\s*[\'"]?alert\s*\([^)]*\)[\'"]?[^>]*>',
        r'<details[^>]*\sontoggle\s*=\s*[\'"]?alert\s*\([^)]*\)[\'"]?[^>]*>',
        r'<marquee[^>]*\sonstart\s*=\s*[\'"]?alert\s*\([^)]*\)[\'"]?[^>]*>',

        # JavaScript 协议
        r'javascript\s*:\s*alert\s*\([^)]*\)',

        # 完整 payload 反射
        r"<script>alert\(1\)</script>",
        r"<img src=x onerror=alert\(1\)>",
        r"<svg onload=alert\(1\)>",
    ]

    # 危险的 DOM 属性和方法
    DOM_SINKS = [
        'innerHTML', 'outerHTML', 'insertAdjacentHTML',
        'document.write', 'document.writeln',
        'eval', 'setTimeout', 'setInterval',
        'Function', 'execScript',
        'location.href', 'location.assign', 'location.replace',
        'src', 'href', 'action', 'formaction',
    ]

    # 危险的 DOM 源
    DOM_SOURCES = [
        'location.search', 'location.hash', 'location.href',
        'document.URL', 'document.documentURI', 'document.referrer',
        'window.name', 'postMessage',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - max_payloads: 最大 payload 数量
                - check_reflected: 是否检测反射型
                - check_dom: 是否检测 DOM 型
                - encoding_bypass: 是否尝试编码绕过
        """
        super().__init__(config)

        # 加载 payload
        max_payloads = self.config.get('max_payloads', 30)
        self.payloads = self._enhance_payloads(
            get_payloads(PayloadCategory.XSS, limit=max_payloads)
        )

        # 编译反射模式
        self._reflection_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.REFLECTION_PATTERNS
        ]

        # 检测选项
        self.check_reflected = self.config.get('check_reflected', True)
        self.check_dom = self.config.get('check_dom', True)
        self.encoding_bypass = self.config.get('encoding_bypass', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 XSS 漏洞

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

        # 反射型 XSS 检测
        if self.check_reflected:
            # 测试 GET 参数
            if params:
                reflected_results = self._test_reflected_xss(
                    url, params, 'GET', headers
                )
                results.extend(reflected_results)

            # 测试 POST 数据
            if data and method == 'POST':
                reflected_results = self._test_reflected_xss(
                    url, data, 'POST', headers
                )
                results.extend(reflected_results)

        # DOM 型 XSS 检测
        if self.check_dom:
            dom_results = self._test_dom_xss(url, headers)
            results.extend(dom_results)

        self._log_detection_end(url, results)
        return results

    def _test_reflected_xss(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """测试反射型 XSS

        Args:
            url: 目标 URL
            params: 参数字典
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果列表
        """
        results = []
        tested_payloads: Set[str] = set()

        for param_name, original_value in params.items():
            # 跳过安全相关参数
            if self._should_skip_param(param_name):
                continue

            for payload in self.payloads:
                # 生成测试变体
                test_variants = self._generate_payload_variants(payload)

                for test_payload in test_variants:
                    # 避免重复测试
                    payload_key = f"{param_name}:{test_payload}"
                    if payload_key in tested_payloads:
                        continue
                    tested_payloads.add(payload_key)

                    # 构造测试参数
                    test_params = params.copy()
                    test_params[param_name] = test_payload

                    try:
                        if method == 'GET':
                            response = self.http_client.get(url, params=test_params, headers=headers)
                        else:
                            response = self.http_client.post(url, data=test_params, headers=headers)

                        # 检查响应中是否有 XSS 反射
                        xss_type, evidence = self._check_xss_reflection(
                            response.text, test_payload
                        )

                        if xss_type:
                            request_info = self._build_request_info(
                                method=method,
                                url=url,
                                headers=headers,
                                params=test_params if method == 'GET' else None,
                                data=test_params if method != 'GET' else None
                            )
                            response_info = self._build_response_info(response)
                            results.append(self._create_result(
                                url=url,
                                vulnerable=True,
                                param=param_name,
                                payload=test_payload,
                                evidence=evidence,
                                confidence=0.9 if xss_type == 'full' else 0.7,
                                verified=True if xss_type == 'full' else False,
                                request=request_info,
                                response=response_info,
                                remediation="对用户输入进行 HTML 实体编码，使用 CSP 策略",
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                ],
                                extra={
                                    'xss_type': 'reflected',
                                    'reflection_type': xss_type,
                                    'context': self._detect_context(response.text, test_payload)
                                }
                            ))
                            # 发现漏洞后跳过该参数的其他 payload
                            break

                    except DetectorTimeoutError as e:
                        # 请求超时 - 常见情况
                        logger.debug(f"反射型 XSS 检测超时 {url}: {e}")
                    except DetectorConnectionError as e:
                        # 连接失败 - 目标可能不可达
                        logger.debug(f"反射型 XSS 检测连接失败 {url}: {e}")
                    except HTTPError as e:
                        # 其他 HTTP 错误
                        logger.debug(f"反射型 XSS 检测 HTTP 错误 {url}: {e}")
                    except (AttributeError, TypeError) as e:
                        # 响应对象属性访问错误（如 response.text 不存在）
                        logger.debug(f"反射型 XSS 检测响应解析失败: {e}")
                    except Exception as e:
                        # 捕获其他未预期异常，保证检测流程继续
                        # 注意：这里使用宽泛捕获是为了单个 payload 测试失败不影响整体检测
                        logger.warning(f"反射型 XSS 检测未预期错误: {type(e).__name__}: {e}")

                # 如果已发现该参数存在漏洞，跳出
                if any(r.param == param_name for r in results):
                    break

        return results

    def _test_dom_xss(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """测试 DOM 型 XSS

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果列表
        """
        results = []

        try:
            response = self.http_client.get(url, headers=headers)

            # 查找 DOM XSS 漏洞特征
            dom_vulns = self._find_dom_xss_patterns(response.text)

            for vuln in dom_vulns:
                request_info = self._build_request_info(
                    method="GET",
                    url=url,
                    headers=headers
                )
                response_info = self._build_response_info(response)
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    param=None,
                    payload=None,
                    evidence=vuln['evidence'],
                    confidence=0.6,  # DOM XSS 需要手动验证
                    verified=False,
                    request=request_info,
                    response=response_info,
                    remediation="避免使用危险的 DOM 操作，使用安全的 API 如 textContent",
                    references=[
                        "https://owasp.org/www-community/attacks/DOM_Based_XSS"
                    ],
                    extra={
                        'xss_type': 'dom',
                        'sink': vuln.get('sink'),
                        'source': vuln.get('source')
                    }
                ))

        except DetectorTimeoutError as e:
            # 请求超时
            logger.debug(f"DOM XSS 检测超时 {url}: {e}")
        except DetectorConnectionError as e:
            # 连接失败
            logger.debug(f"DOM XSS 检测连接失败 {url}: {e}")
        except HTTPError as e:
            # HTTP 错误
            logger.debug(f"DOM XSS 检测 HTTP 错误 {url}: {e}")
        except (AttributeError, TypeError) as e:
            # 响应对象属性访问错误
            logger.debug(f"DOM XSS 检测响应解析失败: {e}")
        except re.error as e:
            # 正则表达式错误（在 _find_dom_xss_patterns 中可能发生）
            logger.warning(f"DOM XSS 检测正则表达式错误: {e}")
        except Exception as e:
            # 捕获其他未预期异常
            # 注意：DOM XSS 检测失败不应影响其他检测
            logger.warning(f"DOM XSS 检测未预期错误: {type(e).__name__}: {e}")

        return results

    def _check_xss_reflection(
        self,
        response_text: str,
        payload: str
    ) -> tuple:
        """检查 XSS 是否被反射

        Args:
            response_text: 响应文本
            payload: 测试 payload

        Returns:
            (反射类型, 证据) 或 (None, None)
        """
        # 检查完整 payload 是否被反射
        if payload in response_text:
            # 提取上下文
            idx = response_text.find(payload)
            start = max(0, idx - 50)
            end = min(len(response_text), idx + len(payload) + 50)
            context = response_text[start:end]
            return ('full', context)

        # 检查是否匹配危险模式
        for pattern in self._reflection_patterns:
            match = pattern.search(response_text)
            if match:
                return ('pattern', match.group(0)[:200])

        # 检查部分反射（payload 特征字符）
        dangerous_chars = ['<script', '<img', '<svg', 'onerror=', 'onload=', 'javascript:']
        for char in dangerous_chars:
            if char in payload.lower() and char in response_text.lower():
                idx = response_text.lower().find(char)
                start = max(0, idx - 30)
                end = min(len(response_text), idx + 80)
                return ('partial', response_text[start:end])

        return (None, None)

    def _generate_payload_variants(self, payload: str) -> List[str]:
        """生成 payload 变体

        Args:
            payload: 原始 payload

        Returns:
            payload 变体列表
        """
        variants = [payload]

        if self.encoding_bypass:
            # HTML 实体编码
            html_encoded = html.escape(payload)
            if html_encoded != payload:
                variants.append(html_encoded)

            # URL 编码
            url_encoded = quote(payload, safe='')
            if url_encoded != payload:
                variants.append(url_encoded)

            # 大小写混淆
            if '<script>' in payload.lower():
                variants.append(payload.replace('<script>', '<ScRiPt>').replace('</script>', '</sCrIpT>'))

        return variants[:5]  # 限制变体数量

    def _find_dom_xss_patterns(self, html_content: str) -> List[Dict[str, Any]]:
        """查找 DOM XSS 漏洞模式

        Args:
            html_content: HTML 内容

        Returns:
            漏洞信息列表
        """
        vulns = []

        # 查找 source 到 sink 的危险模式
        for source in self.DOM_SOURCES:
            for sink in self.DOM_SINKS:
                # 简单的模式匹配
                pattern = rf'{sink}\s*[=\(]\s*.*?{source.replace(".", r"\.")}'
                matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    vulns.append({
                        'source': source,
                        'sink': sink,
                        'evidence': match[:200]
                    })

        # 查找危险的 innerHTML 赋值
        innerHTML_patterns = [
            r'\.innerHTML\s*=\s*[^;]+location\.',
            r'\.innerHTML\s*=\s*[^;]+document\.URL',
            r'\.innerHTML\s*=\s*[^;]+document\.referrer',
            r'document\.write\s*\([^)]*location\.',
            r'eval\s*\([^)]*location\.',
        ]

        for pattern in innerHTML_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                vulns.append({
                    'source': 'location/document',
                    'sink': 'innerHTML/write/eval',
                    'evidence': match[:200]
                })

        return vulns

    def _detect_context(self, response_text: str, payload: str) -> str:
        """检测 payload 在响应中的上下文

        Args:
            response_text: 响应文本
            payload: payload

        Returns:
            上下文类型
        """
        if payload not in response_text:
            return 'none'

        idx = response_text.find(payload)
        before = response_text[max(0, idx - 50):idx]
        after = response_text[idx + len(payload):idx + len(payload) + 50]

        # 检测上下文
        if re.search(r'<script[^>]*>$', before, re.IGNORECASE):
            return 'script'
        elif re.search(r'["\']$', before):
            return 'attribute_value'
        elif re.search(r'<[a-z]+[^>]*$', before, re.IGNORECASE):
            return 'tag_attribute'
        elif re.search(r'<!--$', before):
            return 'comment'
        elif re.search(r'<style[^>]*>$', before, re.IGNORECASE):
            return 'style'
        else:
            return 'html_body'

    def _should_skip_param(self, param_name: str) -> bool:
        """判断是否应跳过某个参数

        Args:
            param_name: 参数名

        Returns:
            是否跳过
        """
        skip_patterns = [
            'token', 'csrf', 'nonce', 'hash', 'sig', 'signature',
            'timestamp', 'time', '_t', 'callback', 'jsonp', '_'
        ]
        param_lower = param_name.lower()
        return any(p in param_lower for p in skip_patterns)

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads
