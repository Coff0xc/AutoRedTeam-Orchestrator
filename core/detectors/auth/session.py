"""
会话安全检测器

检测会话管理相关的安全漏洞
"""

from typing import List, Optional, Dict, Any, Set
import re
import logging
import hashlib
from urllib.parse import urlparse

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector

logger = logging.getLogger(__name__)


@register_detector('session')
class SessionDetector(BaseDetector):
    """会话安全检测器

    检测会话管理漏洞:
    - 会话固定 (Session Fixation)
    - 会话预测 (Session Prediction)
    - 不安全的会话 Cookie 配置
    - 会话超时问题

    使用示例:
        detector = SessionDetector()
        results = detector.detect("https://example.com/login")
    """

    name = 'session'
    description = '会话安全漏洞检测器'
    vuln_type = 'session_vulnerability'
    severity = Severity.HIGH
    detector_type = DetectorType.AUTH
    version = '1.0.0'

    # 会话 Cookie 名称
    SESSION_COOKIE_NAMES = [
        'sessionid', 'session_id', 'sessid', 'sess',
        'phpsessid', 'jsessionid', 'aspsessionid',
        'asp.net_sessionid', 'cfid', 'cftoken',
        'sid', 'session', 'token', 'auth', 'authtoken',
        'access_token', 'jwt', 'bearer',
    ]

    # 安全 Cookie 属性
    REQUIRED_COOKIE_FLAGS = [
        'HttpOnly',
        'Secure',
        'SameSite',
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - check_fixation: 是否检测会话固定
                - check_prediction: 是否检测会话预测
                - check_cookie_flags: 是否检测 Cookie 配置
                - sample_count: 会话预测采样数量
        """
        super().__init__(config)

        self.check_fixation = self.config.get('check_fixation', True)
        self.check_prediction = self.config.get('check_prediction', True)
        self.check_cookie_flags = self.config.get('check_cookie_flags', True)
        self.sample_count = self.config.get('sample_count', 5)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测会话安全漏洞

        Args:
            url: 目标 URL
            **kwargs:
                headers: 请求头
                login_data: 登录数据（用于会话固定测试）

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        headers = kwargs.get('headers', {})

        # 获取初始响应以分析 Cookie
        try:
            response = self.http_client.get(url, headers=headers)
        except Exception as e:
            logger.warning(f"无法获取响应: {e}")
            self._log_detection_end(url, results)
            return results

        # 检测 Cookie 配置问题
        if self.check_cookie_flags:
            cookie_results = self._check_cookie_security(url, response)
            results.extend(cookie_results)

        # 检测会话预测
        if self.check_prediction:
            prediction_results = self._check_session_prediction(url, headers)
            results.extend(prediction_results)

        # 检测会话固定
        if self.check_fixation:
            fixation_results = self._check_session_fixation(url, headers, kwargs.get('login_data'))
            results.extend(fixation_results)

        self._log_detection_end(url, results)
        return results

    def _check_cookie_security(
        self,
        url: str,
        response: Any
    ) -> List[DetectionResult]:
        """检测 Cookie 安全配置

        Args:
            url: 目标 URL
            response: HTTP 响应

        Returns:
            检测结果列表
        """
        results = []
        parsed = urlparse(url)
        is_https = parsed.scheme == 'https'

        # 获取 Set-Cookie 头
        set_cookies = response.headers.get('Set-Cookie', '')
        if not set_cookies:
            # 尝试获取多个 Set-Cookie
            if hasattr(response.headers, 'get_all'):
                set_cookies = response.headers.get_all('Set-Cookie')
            elif hasattr(response, 'cookies'):
                set_cookies = str(response.cookies)

        if not set_cookies:
            return results

        # 转换为列表
        if isinstance(set_cookies, str):
            set_cookies = [set_cookies]

        for cookie_str in set_cookies:
            cookie_lower = cookie_str.lower()

            # 查找会话 Cookie
            is_session_cookie = any(
                name in cookie_lower
                for name in self.SESSION_COOKIE_NAMES
            )

            if not is_session_cookie:
                continue

            # 提取 Cookie 名称
            cookie_name = cookie_str.split('=')[0].strip()

            missing_flags = []

            # 检查 HttpOnly
            if 'httponly' not in cookie_lower:
                missing_flags.append('HttpOnly')

            # 检查 Secure（仅 HTTPS）
            if is_https and 'secure' not in cookie_lower:
                missing_flags.append('Secure')

            # 检查 SameSite
            if 'samesite' not in cookie_lower:
                missing_flags.append('SameSite')

            if missing_flags:
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    param=cookie_name,
                    payload=None,
                    evidence=f"会话 Cookie 缺少安全属性: {', '.join(missing_flags)}",
                    confidence=0.90,
                    verified=True,
                    remediation=f"为会话 Cookie 添加 {', '.join(missing_flags)} 属性",
                    references=[
                        "https://owasp.org/www-community/controls/SecureCookieAttribute"
                    ],
                    extra={
                        'cookie_name': cookie_name,
                        'missing_flags': missing_flags,
                        'cookie_value': cookie_str[:100]
                    }
                ))

        return results

    def _check_session_prediction(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """检测会话 ID 可预测性

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果列表
        """
        results = []
        session_ids: List[str] = []

        # 收集多个会话 ID
        for _ in range(self.sample_count):
            try:
                response = self.http_client.get(url, headers=headers)
                session_id = self._extract_session_id(response)
                if session_id:
                    session_ids.append(session_id)
            except Exception as e:
                logger.debug(f"获取会话 ID 失败: {e}")

        if len(session_ids) < 2:
            return results

        # 分析会话 ID 的可预测性
        analysis = self._analyze_session_ids(session_ids)

        if analysis['is_predictable']:
            results.append(self._create_result(
                url=url,
                vulnerable=True,
                payload=None,
                evidence=f"会话 ID 可能可预测: {analysis['reason']}",
                confidence=analysis['confidence'],
                verified=False,
                remediation="使用加密安全的随机数生成器创建会话 ID",
                references=[
                    "https://owasp.org/www-community/attacks/Session_Prediction"
                ],
                extra={
                    'sample_count': len(session_ids),
                    'analysis': analysis
                }
            ))

        return results

    def _check_session_fixation(
        self,
        url: str,
        headers: Dict[str, str],
        login_data: Optional[Dict[str, str]]
    ) -> List[DetectionResult]:
        """检测会话固定漏洞

        Args:
            url: 目标 URL
            headers: 请求头
            login_data: 登录数据

        Returns:
            检测结果列表
        """
        results = []

        if not login_data:
            return results

        try:
            # 获取登录前的会话 ID
            pre_login_response = self.http_client.get(url, headers=headers)
            pre_login_session = self._extract_session_id(pre_login_response)

            if not pre_login_session:
                return results

            # 使用固定的会话 ID 进行登录
            login_headers = headers.copy()
            login_headers['Cookie'] = f"session={pre_login_session}"

            # 尝试登录
            login_response = self.http_client.post(url, data=login_data, headers=login_headers)
            post_login_session = self._extract_session_id(login_response)

            # 如果登录后会话 ID 没有变化，可能存在会话固定
            if post_login_session and post_login_session == pre_login_session:
                results.append(self._create_result(
                    url=url,
                    vulnerable=True,
                    payload=None,
                    evidence="登录后会话 ID 未更新，可能存在会话固定漏洞",
                    confidence=0.85,
                    verified=False,
                    remediation="在用户认证后重新生成会话 ID",
                    references=[
                        "https://owasp.org/www-community/attacks/Session_fixation"
                    ],
                    extra={
                        'pre_login_session': pre_login_session[:20] + '...',
                        'post_login_session': post_login_session[:20] + '...'
                    }
                ))

        except Exception as e:
            logger.debug(f"会话固定检测失败: {e}")

        return results

    def _extract_session_id(self, response: Any) -> Optional[str]:
        """从响应中提取会话 ID

        Args:
            response: HTTP 响应

        Returns:
            会话 ID 或 None
        """
        set_cookie = response.headers.get('Set-Cookie', '')

        for cookie_name in self.SESSION_COOKIE_NAMES:
            pattern = rf'{cookie_name}=([^;]+)'
            match = re.search(pattern, set_cookie, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _analyze_session_ids(self, session_ids: List[str]) -> Dict[str, Any]:
        """分析会话 ID 的可预测性

        Args:
            session_ids: 会话 ID 列表

        Returns:
            分析结果
        """
        result = {
            'is_predictable': False,
            'confidence': 0.0,
            'reason': ''
        }

        if len(session_ids) < 2:
            return result

        # 检查长度
        lengths = [len(sid) for sid in session_ids]
        if len(set(lengths)) == 1 and lengths[0] < 16:
            result['is_predictable'] = True
            result['confidence'] = 0.7
            result['reason'] = f"会话 ID 长度过短 ({lengths[0]} 字符)"
            return result

        # 检查是否为纯数字
        if all(sid.isdigit() for sid in session_ids):
            result['is_predictable'] = True
            result['confidence'] = 0.8
            result['reason'] = "会话 ID 为纯数字"
            return result

        # 检查是否为递增
        try:
            int_ids = [int(sid) for sid in session_ids if sid.isdigit()]
            if len(int_ids) >= 2:
                diffs = [int_ids[i+1] - int_ids[i] for i in range(len(int_ids)-1)]
                if len(set(diffs)) == 1:
                    result['is_predictable'] = True
                    result['confidence'] = 0.9
                    result['reason'] = f"会话 ID 递增（步长: {diffs[0]}）"
                    return result
        except ValueError:
            pass

        # 检查熵
        combined = ''.join(session_ids)
        unique_chars = len(set(combined))
        if unique_chars < 16:
            result['is_predictable'] = True
            result['confidence'] = 0.6
            result['reason'] = f"会话 ID 字符集较小 ({unique_chars} 个唯一字符)"
            return result

        return result

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return []
