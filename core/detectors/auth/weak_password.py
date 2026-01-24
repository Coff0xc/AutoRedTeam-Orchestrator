"""
弱密码检测器

检测常见的弱密码和默认凭证
"""

from typing import List, Optional, Dict, Any, Tuple
import re
import logging
from urllib.parse import urlparse

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector

logger = logging.getLogger(__name__)


@register_detector('weak_password')
class WeakPasswordDetector(BaseDetector):
    """弱密码检测器

    检测登录接口的弱密码和默认凭证

    使用示例:
        detector = WeakPasswordDetector()
        results = detector.detect("https://example.com/login", data={"username": "admin", "password": "admin"})
    """

    name = 'weak_password'
    description = '弱密码检测器'
    vuln_type = 'weak_password'
    severity = Severity.HIGH
    detector_type = DetectorType.AUTH
    version = '1.0.0'

    # 常见弱密码
    WEAK_PASSWORDS = [
        'password', 'Password', 'PASSWORD',
        '123456', '12345678', '123456789', '1234567890',
        'admin', 'Admin', 'ADMIN', 'admin123', 'admin@123',
        'root', 'Root', 'root123', 'toor',
        'test', 'Test', 'test123', 'testing',
        'guest', 'Guest', 'guest123',
        'user', 'User', 'user123',
        'demo', 'Demo', 'demo123',
        'qwerty', 'QWERTY', 'qwerty123',
        'abc123', 'abcd1234', '1q2w3e4r',
        'password1', 'password123', 'p@ssw0rd', 'P@ssw0rd',
        'letmein', 'welcome', 'monkey', 'dragon',
        'master', 'login', 'passw0rd',
        '111111', '000000', '666666', '888888',
        'changeme', 'secret', 'pass', 'pass123',
    ]

    # 默认凭证 (用户名, 密码)
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('admin', 'admin123'),
        ('admin', ''),
        ('administrator', 'administrator'),
        ('administrator', 'password'),
        ('root', 'root'),
        ('root', 'password'),
        ('root', 'toor'),
        ('root', '123456'),
        ('user', 'user'),
        ('user', 'password'),
        ('test', 'test'),
        ('test', 'password'),
        ('guest', 'guest'),
        ('demo', 'demo'),
        ('operator', 'operator'),
        ('manager', 'manager'),
        ('support', 'support'),
        ('service', 'service'),
        ('info', 'info'),
        ('web', 'web'),
        ('mysql', 'mysql'),
        ('postgres', 'postgres'),
        ('oracle', 'oracle'),
        ('ftp', 'ftp'),
        ('anonymous', ''),
        ('anonymous', 'anonymous'),
    ]

    # 登录成功的标志
    SUCCESS_PATTERNS = [
        r'welcome',
        r'dashboard',
        r'logout',
        r'sign\s*out',
        r'log\s*out',
        r'my\s*account',
        r'profile',
        r'settings',
        r'authenticated',
        r'successfully\s*logged',
        r'login\s*successful',
        r'authentication\s*successful',
    ]

    # 登录失败的标志
    FAILURE_PATTERNS = [
        r'invalid\s*(username|password|credentials)',
        r'incorrect\s*(username|password|credentials)',
        r'wrong\s*(username|password|credentials)',
        r'authentication\s*failed',
        r'login\s*failed',
        r'access\s*denied',
        r'bad\s*credentials',
        r'user\s*not\s*found',
        r'account\s*locked',
        r'too\s*many\s*attempts',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - max_attempts: 最大尝试次数
                - username_field: 用户名字段名
                - password_field: 密码字段名
                - custom_credentials: 自定义凭证列表
        """
        super().__init__(config)

        # 配置
        self.max_attempts = self.config.get('max_attempts', 20)
        self.username_field = self.config.get('username_field', None)
        self.password_field = self.config.get('password_field', None)

        # 合并自定义凭证
        custom_creds = self.config.get('custom_credentials', [])
        self.credentials = list(self.DEFAULT_CREDENTIALS) + custom_creds

        # 编译模式
        self._success_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.SUCCESS_PATTERNS
        ]
        self._failure_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.FAILURE_PATTERNS
        ]

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测弱密码

        Args:
            url: 登录接口 URL
            **kwargs:
                data: POST 数据（包含表单字段）
                headers: 请求头
                method: HTTP 方法

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        data = kwargs.get('data', {})
        headers = kwargs.get('headers', {})
        method = kwargs.get('method', 'POST').upper()

        # 识别用户名和密码字段
        username_field, password_field = self._identify_login_fields(data)

        if not username_field or not password_field:
            logger.warning("无法识别用户名/密码字段")
            self._log_detection_end(url, results)
            return results

        # 获取基线响应（正常失败响应）
        baseline = self._get_baseline_response(
            url, data, username_field, password_field, method, headers
        )

        # 测试默认凭证
        attempts = 0
        for username, password in self.credentials:
            if attempts >= self.max_attempts:
                break

            attempts += 1

            result = self._test_credential(
                url, data, username_field, password_field,
                username, password, method, headers, baseline
            )

            if result:
                results.append(result)
                # 发现有效凭证后可以选择继续或停止
                if not self.config.get('find_all', False):
                    break

        self._log_detection_end(url, results)
        return results

    def _test_credential(
        self,
        url: str,
        original_data: Dict[str, str],
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        method: str,
        headers: Dict[str, str],
        baseline: Optional[Any]
    ) -> Optional[DetectionResult]:
        """测试单个凭证

        Args:
            url: 登录 URL
            original_data: 原始表单数据
            username_field: 用户名字段名
            password_field: 密码字段名
            username: 测试用户名
            password: 测试密码
            method: HTTP 方法
            headers: 请求头
            baseline: 基线响应

        Returns:
            检测结果或 None
        """
        test_data = original_data.copy()
        test_data[username_field] = username
        test_data[password_field] = password

        try:
            if method == 'POST':
                response = self.http_client.post(url, data=test_data, headers=headers)
            else:
                response = self.http_client.get(url, params=test_data, headers=headers)

            # 检查登录是否成功
            is_success, evidence = self._check_login_success(response, baseline)

            if is_success:
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    param=f"{username_field}/{password_field}",
                    payload=f"{username}:{password}",
                    evidence=evidence,
                    confidence=0.90,
                    verified=True,
                    remediation="强制使用强密码策略，禁用默认凭证",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy"
                    ],
                    extra={
                        'username': username,
                        'password': password,
                        'username_field': username_field,
                        'password_field': password_field
                    }
                )

        except Exception as e:
            logger.debug(f"凭证测试失败: {e}")

        return None

    def _check_login_success(
        self,
        response: Any,
        baseline: Optional[Any]
    ) -> Tuple[bool, str]:
        """检查登录是否成功

        Args:
            response: 登录响应
            baseline: 基线响应

        Returns:
            (是否成功, 证据)
        """
        # 检查重定向
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get('Location', '')
            # 重定向到非登录页面通常表示成功
            if location and 'login' not in location.lower():
                return (True, f"重定向到: {location}")

        # 检查成功标志
        for pattern in self._success_patterns:
            if pattern.search(response.text):
                return (True, f"检测到登录成功标志: {pattern.pattern}")

        # 检查 Set-Cookie（会话创建）
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.get('Set-Cookie', '')
            if any(marker in cookies.lower() for marker in ['session', 'token', 'auth', 'user']):
                # 还需要确认没有失败标志
                for pattern in self._failure_patterns:
                    if pattern.search(response.text):
                        return (False, None)
                return (True, "检测到认证会话 Cookie")

        # 与基线比较
        if baseline:
            # 状态码变化
            if response.status_code != baseline.status_code:
                if response.status_code == 200 and baseline.status_code != 200:
                    return (True, f"状态码变化: {baseline.status_code} -> {response.status_code}")

            # 响应长度显著变化
            len_diff = abs(len(response.text) - len(baseline.text))
            if len_diff > 500:
                # 确认没有失败标志
                for pattern in self._failure_patterns:
                    if pattern.search(response.text):
                        return (False, None)
                return (True, f"响应长度变化: {len(baseline.text)} -> {len(response.text)}")

        return (False, None)

    def _identify_login_fields(
        self,
        data: Dict[str, str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """识别用户名和密码字段

        Args:
            data: 表单数据

        Returns:
            (用户名字段, 密码字段)
        """
        # 使用配置的字段名
        if self.username_field and self.password_field:
            return (self.username_field, self.password_field)

        username_field = None
        password_field = None

        username_patterns = ['user', 'username', 'email', 'login', 'account', 'name']
        password_patterns = ['pass', 'password', 'pwd', 'secret', 'credential']

        for field_name in data.keys():
            field_lower = field_name.lower()

            if not username_field:
                if any(p in field_lower for p in username_patterns):
                    username_field = field_name

            if not password_field:
                if any(p in field_lower for p in password_patterns):
                    password_field = field_name

        return (username_field, password_field)

    def _get_baseline_response(
        self,
        url: str,
        data: Dict[str, str],
        username_field: str,
        password_field: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[Any]:
        """获取基线响应（使用无效凭证）

        Args:
            url: 登录 URL
            data: 表单数据
            username_field: 用户名字段
            password_field: 密码字段
            method: HTTP 方法
            headers: 请求头

        Returns:
            基线响应
        """
        try:
            baseline_data = data.copy()
            baseline_data[username_field] = 'nonexistent_user_xyz123'
            baseline_data[password_field] = 'invalid_password_xyz123'

            if method == 'POST':
                return self.http_client.post(url, data=baseline_data, headers=headers)
            else:
                return self.http_client.get(url, params=baseline_data, headers=headers)

        except Exception as e:
            logger.debug(f"获取基线响应失败: {e}")
            return None

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return [f"{u}:{p}" for u, p in self.credentials]
