"""
IDOR (不安全的直接对象引用) 检测器

检测 Insecure Direct Object Reference 漏洞
"""

from typing import List, Optional, Dict, Any, Set
import re
import logging
from urllib.parse import urlparse, parse_qs

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector

logger = logging.getLogger(__name__)


@register_detector('idor')
class IDORDetector(BaseDetector):
    """IDOR (不安全的直接对象引用) 检测器

    检测通过修改对象标识符访问未授权资源的漏洞

    使用示例:
        detector = IDORDetector()
        results = detector.detect("https://example.com/user/123", params={"id": "123"})
    """

    name = 'idor'
    description = 'IDOR 不安全直接对象引用检测器'
    vuln_type = 'idor'
    severity = Severity.HIGH
    detector_type = DetectorType.ACCESS
    version = '1.0.0'

    # 常见的 ID 参数名
    ID_PARAMS = [
        'id', 'user_id', 'userid', 'uid', 'user',
        'account_id', 'account', 'acc',
        'doc_id', 'docid', 'document_id', 'document',
        'file_id', 'fileid', 'file',
        'order_id', 'orderid', 'order',
        'item_id', 'itemid', 'item',
        'record_id', 'recordid', 'record',
        'profile_id', 'profileid', 'profile',
        'msg_id', 'msgid', 'message_id',
    ]

    # ID 值测试变体
    ID_VARIANTS = [
        lambda x: str(int(x) + 1) if x.isdigit() else None,
        lambda x: str(int(x) - 1) if x.isdigit() and int(x) > 0 else None,
        lambda x: str(int(x) + 100) if x.isdigit() else None,
        lambda x: '1',
        lambda x: '0',
        lambda x: '999999',
        lambda x: '-1',
        lambda x: x.replace('a', 'b') if not x.isdigit() else None,
    ]

    # 敏感数据模式
    SENSITIVE_PATTERNS = [
        r'"email"\s*:\s*"[^"]+@[^"]+"',
        r'"phone"\s*:\s*"[\d\-\+]+"',
        r'"password"\s*:',
        r'"ssn"\s*:',
        r'"credit_card"\s*:',
        r'"address"\s*:',
        r'"name"\s*:\s*"[^"]+"',
        r'"balance"\s*:\s*[\d\.]+',
        r'"account_number"\s*:',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - custom_id_params: 自定义 ID 参数名列表
                - check_path: 是否检测 URL 路径中的 ID
        """
        super().__init__(config)

        # 合并自定义 ID 参数
        custom_params = self.config.get('custom_id_params', [])
        self.id_params = list(set(self.ID_PARAMS + custom_params))

        # 编译敏感模式
        self._sensitive_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_PATTERNS
        ]

        # 配置
        self.check_path = self.config.get('check_path', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 IDOR 漏洞

        Args:
            url: 目标 URL
            **kwargs:
                params: GET 参数字典
                data: POST 数据字典
                method: HTTP 方法
                headers: 请求头
                auth_token: 认证令牌（用于已认证用户）

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

        # 获取基线响应
        baseline = self._get_baseline(url, params, method, headers)
        if not baseline:
            logger.warning("无法获取基线响应，跳过 IDOR 检测")
            self._log_detection_end(url, results)
            return results

        # 检测参数中的 IDOR
        param_results = self._test_params_idor(
            url, params, method, headers, baseline
        )
        results.extend(param_results)

        # 检测 URL 路径中的 IDOR
        if self.check_path:
            path_results = self._test_path_idor(url, headers, baseline)
            results.extend(path_results)

        self._log_detection_end(url, results)
        return results

    def _test_params_idor(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        headers: Dict[str, str],
        baseline: Any
    ) -> List[DetectionResult]:
        """测试参数中的 IDOR

        Args:
            url: 目标 URL
            params: 参数字典
            method: HTTP 方法
            headers: 请求头
            baseline: 基线响应

        Returns:
            检测结果列表
        """
        results = []

        for param_name, original_value in params.items():
            # 检查是否是 ID 类参数
            if not self._is_id_param(param_name, original_value):
                continue

            # 生成测试变体
            variants = self._generate_id_variants(original_value)

            for variant in variants:
                if variant is None or variant == original_value:
                    continue

                test_params = params.copy()
                test_params[param_name] = variant

                try:
                    if method == 'GET':
                        response = self.http_client.get(url, params=test_params, headers=headers)
                    else:
                        response = self.http_client.post(url, data=test_params, headers=headers)

                    # 分析响应
                    is_vulnerable, evidence = self._analyze_idor_response(
                        baseline, response, variant
                    )

                    if is_vulnerable:
                        results.append(self._create_result(
                            url=url,
                            vulnerable=True,
                            param=param_name,
                            payload=f"原值: {original_value} -> 测试值: {variant}",
                            evidence=evidence,
                            confidence=0.75,
                            verified=False,
                            remediation="实施基于权限的访问控制，不要仅依赖客户端提交的标识符",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"
                            ],
                            extra={
                                'original_value': original_value,
                                'test_value': variant
                            }
                        ))
                        break

                except Exception as e:
                    logger.debug(f"IDOR 检测失败: {e}")

        return results

    def _test_path_idor(
        self,
        url: str,
        headers: Dict[str, str],
        baseline: Any
    ) -> List[DetectionResult]:
        """测试 URL 路径中的 IDOR

        Args:
            url: 目标 URL
            headers: 请求头
            baseline: 基线响应

        Returns:
            检测结果列表
        """
        results = []
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')

        for i, part in enumerate(path_parts):
            if not part:
                continue

            # 检查是否是 ID
            if not self._looks_like_id(part):
                continue

            # 生成变体
            variants = self._generate_id_variants(part)

            for variant in variants:
                if variant is None or variant == part:
                    continue

                # 构造新 URL
                new_parts = path_parts.copy()
                new_parts[i] = variant
                new_path = '/'.join(new_parts)
                new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"

                if parsed.query:
                    new_url += f"?{parsed.query}"

                try:
                    response = self.http_client.get(new_url, headers=headers)

                    is_vulnerable, evidence = self._analyze_idor_response(
                        baseline, response, variant
                    )

                    if is_vulnerable:
                        results.append(self._create_result(
                            url=url,
                            vulnerable=True,
                            param=f"路径参数[{i}]",
                            payload=f"原值: {part} -> 测试值: {variant}",
                            evidence=evidence,
                            confidence=0.70,
                            verified=False,
                            remediation="实施基于权限的访问控制，不要仅依赖 URL 路径中的标识符",
                            extra={
                                'path_position': i,
                                'original_value': part,
                                'test_value': variant,
                                'test_url': new_url
                            }
                        ))
                        break

                except Exception as e:
                    logger.debug(f"路径 IDOR 检测失败: {e}")

        return results

    def _is_id_param(self, param_name: str, value: str) -> bool:
        """判断参数是否是 ID 类型"""
        # 检查参数名
        param_lower = param_name.lower()
        if any(id_param in param_lower for id_param in self.id_params):
            return True

        # 检查值是否像 ID
        return self._looks_like_id(value)

    def _looks_like_id(self, value: str) -> bool:
        """判断值是否像 ID"""
        if not value:
            return False

        # 纯数字
        if value.isdigit():
            return True

        # UUID
        if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', value.lower()):
            return True

        # 短 hash
        if re.match(r'^[a-f0-9]{8,32}$', value.lower()):
            return True

        return False

    def _generate_id_variants(self, value: str) -> List[Optional[str]]:
        """生成 ID 值变体"""
        variants = []
        for variant_func in self.ID_VARIANTS:
            try:
                variant = variant_func(value)
                if variant and variant not in variants:
                    variants.append(variant)
            except Exception:
                continue
        return variants

    def _analyze_idor_response(
        self,
        baseline: Any,
        response: Any,
        test_value: str
    ) -> tuple:
        """分析 IDOR 响应

        Args:
            baseline: 基线响应
            response: 测试响应
            test_value: 测试值

        Returns:
            (是否存在漏洞, 证据)
        """
        # 检查状态码
        if response.status_code == 200 and baseline.status_code == 200:
            # 响应内容不同可能表示访问了不同的资源
            if response.text != baseline.text:
                # 检查是否包含敏感数据
                sensitive_data = self._find_sensitive_data(response.text)
                if sensitive_data:
                    return (True, f"发现敏感数据: {', '.join(sensitive_data[:3])}")

                # 检查响应长度变化
                if len(response.text) > 100 and abs(len(response.text) - len(baseline.text)) > 50:
                    return (True, f"响应内容不同（长度: {len(baseline.text)} vs {len(response.text)}）")

        # 检查是否返回了不应该访问的资源
        if response.status_code == 200 and baseline.status_code != 200:
            return (True, f"使用 ID {test_value} 成功访问了资源")

        return (False, None)

    def _find_sensitive_data(self, text: str) -> List[str]:
        """查找敏感数据"""
        found = []
        for pattern in self._sensitive_patterns:
            if pattern.search(text):
                found.append(pattern.pattern.split('"')[1])
        return found

    def _get_baseline(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        headers: Dict[str, str]
    ) -> Optional[Any]:
        """获取基线响应"""
        try:
            if method == 'GET':
                return self.http_client.get(url, params=params, headers=headers)
            else:
                return self.http_client.post(url, data=params, headers=headers)
        except Exception as e:
            logger.debug(f"获取基线失败: {e}")
            return None

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return ['ID 变体测试']
