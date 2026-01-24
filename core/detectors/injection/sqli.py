"""
SQL 注入检测器

检测 SQL 注入漏洞，支持错误型、时间盲注、UNION 注入等多种技术
"""

from typing import List, Optional, Dict, Any, Tuple
import re
import time
import logging
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from ..base import BaseDetector, ContextAwareDetector
from ..result import DetectionResult, Severity, DetectorType, RequestInfo, ResponseInfo
from ..factory import register_detector
from ..payloads import get_payloads, PayloadCategory

logger = logging.getLogger(__name__)


@register_detector('sqli')
class SQLiDetector(BaseDetector):
    """SQL 注入检测器

    支持的检测技术:
    - 错误型注入 (Error-based)
    - 时间盲注 (Time-based Blind)
    - 布尔盲注 (Boolean-based Blind)
    - UNION 注入
    - 堆叠查询 (Stacked Queries)

    使用示例:
        detector = SQLiDetector()
        results = detector.detect("https://example.com/search", params={"q": "test"})
    """

    name = 'sqli'
    description = 'SQL 注入漏洞检测器'
    vuln_type = 'sqli'
    severity = Severity.CRITICAL
    detector_type = DetectorType.INJECTION
    version = '2.0.0'

    # 数据库错误特征模式
    ERROR_PATTERNS = {
        'mysql': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"Warning.*mysqli_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"Syntax error or access violation",
            r"You have an error in your SQL syntax",
            r"MySQL server version for the right syntax",
            r"mysqli_fetch",
            r"mysql_fetch",
            r"Unknown column '.*' in",
        ],
        'postgresql': [
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
            r"unterminated quoted string at or near",
        ],
        'mssql': [
            r"Driver.* SQL[-_ ]*Server",
            r"OLE DB.* SQL Server",
            r"Microsoft SQL Native Client",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"Unclosed quotation mark after the character string",
            r"Incorrect syntax near",
            r"SQL Server.*Driver",
            r"mssql_query\(\)",
        ],
        'oracle': [
            r"Oracle error",
            r"ORA-\d{4,5}",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"Warning.*ora_",
            r"quoted string not properly terminated",
            r"oracle\.jdbc\.driver",
        ],
        'sqlite': [
            r"SQLite.*error",
            r"sqlite3\.OperationalError",
            r"SQLite3::SQLException",
            r"SQLITE_ERROR",
            r"near \".*\": syntax error",
            r"unrecognized token:",
        ],
        'generic': [
            r"SQLSTATE\[[0-9A-Z]+\]",
            r"SQL command not properly ended",
            r"syntax error at end of input",
            r"Unexpected end of command in statement",
            r"Invalid query",
            r"Database error",
            r"SQL Error",
        ]
    }

    # 时间盲注检测的延迟时间（秒）
    TIME_DELAY = 5
    TIME_THRESHOLD = 4  # 判定阈值

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - max_payloads: 最大 payload 数量
                - time_delay: 时间盲注延迟时间
                - check_time_based: 是否检测时间盲注
                - check_error_based: 是否检测错误型注入
                - check_boolean_based: 是否检测布尔盲注
        """
        super().__init__(config)

        # 加载 payload
        max_payloads = self.config.get('max_payloads', 30)
        self.payloads = get_payloads(PayloadCategory.SQLI, limit=max_payloads)

        # 编译错误模式正则
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for db_type, patterns in self.ERROR_PATTERNS.items():
            self._compiled_patterns[db_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # 检测选项
        self.check_error_based = self.config.get('check_error_based', True)
        self.check_time_based = self.config.get('check_time_based', True)
        self.check_boolean_based = self.config.get('check_boolean_based', True)

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测 SQL 注入漏洞

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
            param_results = self._test_parameters(
                url, params, 'GET', headers
            )
            results.extend(param_results)

        # 测试 POST 数据
        if data and method == 'POST':
            data_results = self._test_parameters(
                url, data, 'POST', headers
            )
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
        """测试参数中的 SQL 注入

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
            # 跳过某些参数
            if self._should_skip_param(param_name):
                continue

            # 获取基线响应
            baseline = self._get_baseline_response(url, params, method, headers)
            if baseline is None:
                continue

            # 测试每个 payload
            for payload in self.payloads:
                # 构造测试值
                test_value = str(original_value) + payload

                # 错误型注入检测
                if self.check_error_based:
                    error_result = self._check_error_based(
                        url, params, param_name, test_value, method, headers
                    )
                    if error_result:
                        results.append(error_result)
                        break  # 发现漏洞后跳过该参数

                # 时间盲注检测
                if self.check_time_based and 'SLEEP' in payload.upper():
                    time_result = self._check_time_based(
                        url, params, param_name, payload, method, headers
                    )
                    if time_result:
                        results.append(time_result)
                        break

            # 布尔盲注检测（需要更复杂的逻辑）
            if self.check_boolean_based and not results:
                boolean_result = self._check_boolean_based(
                    url, params, param_name, baseline, method, headers
                )
                if boolean_result:
                    results.append(boolean_result)

        return results

    def _check_error_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        test_value: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """检测错误型 SQL 注入

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            test_value: 测试值
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        test_params = params.copy()
        test_params[param_name] = test_value

        try:
            if method == 'GET':
                response = self.http_client.get(url, params=test_params, headers=headers)
            else:
                response = self.http_client.post(url, data=test_params, headers=headers)

            # 检查响应中的数据库错误
            db_type, match_text = self._find_db_error(response.text)
            if db_type:
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    param=param_name,
                    payload=test_value,
                    evidence=match_text,
                    confidence=0.95,
                    verified=True,
                    remediation="使用参数化查询（Prepared Statements）或 ORM 框架",
                    references=[
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ],
                    extra={'db_type': db_type, 'injection_type': 'error-based'}
                )
        except Exception as e:
            logger.debug(f"错误型注入检测失败: {e}")

        return None

    def _check_time_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        payload: str,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """检测时间盲注

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            payload: 时间盲注 payload
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        test_params = params.copy()
        test_params[param_name] = payload

        try:
            start_time = time.time()

            if method == 'GET':
                self.http_client.get(url, params=test_params, headers=headers)
            else:
                self.http_client.post(url, data=test_params, headers=headers)

            elapsed = time.time() - start_time

            # 如果响应时间超过阈值，可能存在时间盲注
            if elapsed >= self.TIME_THRESHOLD:
                return self._create_result(
                    url=url,
                    vulnerable=True,
                    param=param_name,
                    payload=payload,
                    evidence=f"响应延迟 {elapsed:.2f} 秒（阈值 {self.TIME_THRESHOLD} 秒）",
                    confidence=0.85,
                    verified=True,
                    remediation="使用参数化查询（Prepared Statements）或 ORM 框架",
                    references=[
                        "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
                    ],
                    extra={'injection_type': 'time-based', 'delay': elapsed}
                )
        except Exception as e:
            logger.debug(f"时间盲注检测失败: {e}")

        return None

    def _check_boolean_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        baseline: Any,
        method: str,
        headers: Dict[str, str]
    ) -> Optional[DetectionResult]:
        """检测布尔盲注

        Args:
            url: 目标 URL
            params: 参数字典
            param_name: 测试参数名
            baseline: 基线响应
            method: HTTP 方法
            headers: 请求头

        Returns:
            检测结果或 None
        """
        # 真条件 payload
        true_payloads = [
            "' AND '1'='1",
            "' AND 1=1--",
            '" AND "1"="1',
            "' OR '1'='1",
        ]

        # 假条件 payload
        false_payloads = [
            "' AND '1'='2",
            "' AND 1=2--",
            '" AND "1"="2',
            "' AND 1=0--",
        ]

        baseline_length = len(baseline.text) if baseline else 0

        for true_payload, false_payload in zip(true_payloads, false_payloads):
            try:
                # 测试真条件
                true_params = params.copy()
                true_params[param_name] = str(params.get(param_name, '')) + true_payload

                if method == 'GET':
                    true_response = self.http_client.get(url, params=true_params, headers=headers)
                else:
                    true_response = self.http_client.post(url, data=true_params, headers=headers)

                # 测试假条件
                false_params = params.copy()
                false_params[param_name] = str(params.get(param_name, '')) + false_payload

                if method == 'GET':
                    false_response = self.http_client.get(url, params=false_params, headers=headers)
                else:
                    false_response = self.http_client.post(url, data=false_params, headers=headers)

                # 比较响应差异
                true_len = len(true_response.text)
                false_len = len(false_response.text)

                # 如果真假条件响应明显不同，可能存在布尔盲注
                if abs(true_len - false_len) > 50 and abs(true_len - baseline_length) < 50:
                    return self._create_result(
                        url=url,
                        vulnerable=True,
                        param=param_name,
                        payload=f"TRUE: {true_payload}, FALSE: {false_payload}",
                        evidence=f"真条件响应长度: {true_len}, 假条件响应长度: {false_len}",
                        confidence=0.75,
                        verified=False,
                        remediation="使用参数化查询（Prepared Statements）或 ORM 框架",
                        extra={'injection_type': 'boolean-based'}
                    )

            except Exception as e:
                logger.debug(f"布尔盲注检测失败: {e}")

        return None

    def _find_db_error(self, response_text: str) -> Tuple[Optional[str], Optional[str]]:
        """在响应中查找数据库错误

        Args:
            response_text: 响应文本

        Returns:
            (数据库类型, 匹配文本) 或 (None, None)
        """
        for db_type, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(response_text)
                if match:
                    # 提取上下文
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 50)
                    context = response_text[start:end]
                    return db_type, context.strip()
        return None, None

    def _get_baseline_response(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        headers: Dict[str, str]
    ) -> Optional[Any]:
        """获取基线响应

        Args:
            url: 目标 URL
            params: 参数字典
            method: HTTP 方法
            headers: 请求头

        Returns:
            响应对象或 None
        """
        try:
            if method == 'GET':
                return self.http_client.get(url, params=params, headers=headers)
            else:
                return self.http_client.post(url, data=params, headers=headers)
        except Exception as e:
            logger.debug(f"获取基线响应失败: {e}")
            return None

    def _should_skip_param(self, param_name: str) -> bool:
        """判断是否应跳过某个参数

        Args:
            param_name: 参数名

        Returns:
            是否跳过
        """
        skip_patterns = [
            'token', 'csrf', 'nonce', 'hash', 'sig', 'signature',
            'timestamp', 'time', '_t', 'callback', 'jsonp'
        ]
        param_lower = param_name.lower()
        return any(p in param_lower for p in skip_patterns)

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.payloads

    def verify(self, result: DetectionResult) -> bool:
        """验证 SQL 注入漏洞

        Args:
            result: 检测结果

        Returns:
            是否确认存在漏洞
        """
        if not result.vulnerable or not result.payload:
            return False

        # 已验证的结果直接返回
        if result.verified:
            return True

        # 尝试使用不同的 payload 验证
        try:
            # 使用时间盲注验证
            verify_payload = f"' AND SLEEP(3)--"
            # TODO: 实现验证逻辑
            return False
        except Exception:
            return False
