"""
信息泄露检测器

检测敏感信息泄露漏洞
"""

from typing import List, Optional, Dict, Any, Set
import re
import logging
from urllib.parse import urlparse, urljoin

from ..base import BaseDetector
from ..result import DetectionResult, Severity, DetectorType
from ..factory import register_detector

logger = logging.getLogger(__name__)


@register_detector('info_disclosure')
class InfoDisclosureDetector(BaseDetector):
    """信息泄露检测器

    检测敏感信息泄露:
    - 源代码泄露
    - 配置文件泄露
    - 备份文件泄露
    - 调试信息泄露
    - 敏感数据泄露

    使用示例:
        detector = InfoDisclosureDetector()
        results = detector.detect("https://example.com")
    """

    name = 'info_disclosure'
    description = '信息泄露漏洞检测器'
    vuln_type = 'information_disclosure'
    severity = Severity.MEDIUM
    detector_type = DetectorType.MISC
    version = '1.0.0'

    # 敏感文件路径
    SENSITIVE_PATHS = [
        # 配置文件
        '/.env',
        '/.env.local',
        '/.env.production',
        '/.env.development',
        '/config.php',
        '/config.inc.php',
        '/configuration.php',
        '/settings.php',
        '/wp-config.php',
        '/web.config',
        '/appsettings.json',
        '/application.yml',
        '/application.properties',

        # Git/SVN
        '/.git/config',
        '/.git/HEAD',
        '/.gitignore',
        '/.svn/entries',
        '/.svn/wc.db',

        # 备份文件
        '/backup.sql',
        '/backup.zip',
        '/backup.tar.gz',
        '/database.sql',
        '/db.sql',
        '/.bak',
        '/index.php.bak',
        '/index.php~',

        # 日志文件
        '/error.log',
        '/access.log',
        '/debug.log',
        '/logs/error.log',
        '/var/log/apache2/error.log',

        # 调试文件
        '/phpinfo.php',
        '/info.php',
        '/test.php',
        '/debug.php',
        '/.DS_Store',
        '/Thumbs.db',

        # API 文档
        '/swagger.json',
        '/swagger.yaml',
        '/openapi.json',
        '/api-docs',
        '/graphql',

        # 其他敏感文件
        '/robots.txt',
        '/sitemap.xml',
        '/crossdomain.xml',
        '/clientaccesspolicy.xml',
        '/.htaccess',
        '/.htpasswd',
        '/server-status',
        '/server-info',
    ]

    # 敏感信息模式
    SENSITIVE_PATTERNS = {
        'api_key': [
            r'api[_-]?key[\'":\s]*[=:]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
            r'apikey[\'":\s]*[=:]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?',
        ],
        'aws_key': [
            r'AKIA[0-9A-Z]{16}',
            r'aws[_-]?access[_-]?key[_-]?id[\'":\s]*[=:]\s*[\'"]?([A-Z0-9]{20})[\'"]?',
            r'aws[_-]?secret[_-]?access[_-]?key[\'":\s]*[=:]\s*[\'"]?([a-zA-Z0-9/+=]{40})[\'"]?',
        ],
        'private_key': [
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ],
        'password': [
            r'password[\'":\s]*[=:]\s*[\'"]?([^\s\'"]{4,})[\'"]?',
            r'passwd[\'":\s]*[=:]\s*[\'"]?([^\s\'"]{4,})[\'"]?',
            r'pwd[\'":\s]*[=:]\s*[\'"]?([^\s\'"]{4,})[\'"]?',
        ],
        'database': [
            r'mysql://[^@]+:[^@]+@[^\s]+',
            r'postgres://[^@]+:[^@]+@[^\s]+',
            r'mongodb://[^@]+:[^@]+@[^\s]+',
            r'redis://[^@]+:[^@]+@[^\s]+',
        ],
        'token': [
            r'bearer\s+([a-zA-Z0-9_\-\.]+)',
            r'token[\'":\s]*[=:]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?',
            r'jwt[\'":\s]*[=:]\s*[\'"]?(eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)[\'"]?',
        ],
        'email': [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
        'internal_ip': [
            r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            r'\b(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b',
            r'\b(?:192\.168\.\d{1,3}\.\d{1,3})\b',
        ],
        'debug_info': [
            r'(?:stack\s*trace|traceback|exception|error\s*in)',
            r'(?:at\s+[\w\.]+\([\w\.]+:\d+\))',
            r'File ".*", line \d+',
        ]
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 配置选项
                - check_paths: 是否检测敏感路径
                - check_response: 是否检测响应中的敏感信息
                - custom_paths: 自定义敏感路径
        """
        super().__init__(config)

        self.check_paths = self.config.get('check_paths', True)
        self.check_response = self.config.get('check_response', True)

        # 合并自定义路径
        custom_paths = self.config.get('custom_paths', [])
        self.sensitive_paths = list(self.SENSITIVE_PATHS) + custom_paths

        # 编译敏感模式
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for category, patterns in self.SENSITIVE_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """检测信息泄露

        Args:
            url: 目标 URL
            **kwargs:
                headers: 请求头
                response_text: 响应文本（可选，用于检测响应中的敏感信息）

        Returns:
            检测结果列表
        """
        self._log_detection_start(url)
        results: List[DetectionResult] = []

        headers = kwargs.get('headers', {})
        response_text = kwargs.get('response_text', None)

        # 检测敏感路径
        if self.check_paths:
            path_results = self._check_sensitive_paths(url, headers)
            results.extend(path_results)

        # 检测响应中的敏感信息
        if self.check_response:
            if response_text:
                response_results = self._check_response_content(url, response_text)
                results.extend(response_results)
            else:
                # 获取主页响应进行检测
                try:
                    response = self.http_client.get(url, headers=headers)
                    response_results = self._check_response_content(url, response.text)
                    results.extend(response_results)
                except Exception as e:
                    logger.debug(f"获取响应失败: {e}")

        self._log_detection_end(url, results)
        return results

    def _check_sensitive_paths(
        self,
        url: str,
        headers: Dict[str, str]
    ) -> List[DetectionResult]:
        """检测敏感路径

        Args:
            url: 目标 URL
            headers: 请求头

        Returns:
            检测结果列表
        """
        results = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.sensitive_paths:
            test_url = urljoin(base_url, path)

            try:
                response = self.http_client.get(test_url, headers=headers)

                # 检查是否可访问
                if response.status_code == 200:
                    # 验证内容是否有意义
                    content_type = self._classify_content(path, response.text)

                    if content_type:
                        severity = self._get_severity_for_path(path)
                        results.append(self._create_result(
                            url=test_url,
                            vulnerable=True,
                            payload=path,
                            evidence=f"发现敏感文件: {path}",
                            confidence=0.90,
                            verified=True,
                            remediation=f"删除或限制访问 {path}",
                            extra={
                                'disclosure_type': 'sensitive_path',
                                'path': path,
                                'content_type': content_type,
                                'content_preview': response.text[:200]
                            }
                        ))
                        results[-1].severity = severity

            except Exception as e:
                logger.debug(f"敏感路径检测失败 ({path}): {e}")

        return results

    def _check_response_content(
        self,
        url: str,
        response_text: str
    ) -> List[DetectionResult]:
        """检测响应中的敏感信息

        Args:
            url: 目标 URL
            response_text: 响应文本

        Returns:
            检测结果列表
        """
        results = []
        found_categories: Set[str] = set()

        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(response_text)
                if matches and category not in found_categories:
                    found_categories.add(category)

                    # 提取证据（脱敏处理）
                    evidence = self._sanitize_evidence(category, matches[0] if matches else '')

                    severity = self._get_severity_for_category(category)
                    results.append(self._create_result(
                        url=url,
                        vulnerable=True,
                        payload=None,
                        evidence=f"发现敏感信息 ({category}): {evidence}",
                        confidence=0.80,
                        verified=True,
                        remediation=f"移除响应中的 {category} 信息",
                        extra={
                            'disclosure_type': 'response_content',
                            'category': category,
                            'match_count': len(matches)
                        }
                    ))
                    results[-1].severity = severity
                    break

        return results

    def _classify_content(self, path: str, content: str) -> Optional[str]:
        """分类内容类型

        Args:
            path: 文件路径
            content: 文件内容

        Returns:
            内容类型或 None
        """
        if not content or len(content) < 10:
            return None

        # Git 配置
        if '.git' in path:
            if '[core]' in content or 'ref:' in content:
                return 'git_config'

        # 环境变量
        if '.env' in path:
            if '=' in content and any(k in content.upper() for k in ['KEY', 'SECRET', 'PASSWORD', 'TOKEN']):
                return 'env_file'

        # PHP 配置
        if path.endswith('.php') and '<?php' not in content:
            if any(k in content for k in ['DB_', 'DATABASE', 'mysql']):
                return 'config_file'

        # SQL 备份
        if path.endswith('.sql'):
            if 'CREATE TABLE' in content.upper() or 'INSERT INTO' in content.upper():
                return 'sql_backup'

        # 日志文件
        if 'log' in path.lower():
            if any(level in content for level in ['ERROR', 'WARNING', 'INFO', 'DEBUG']):
                return 'log_file'

        # Swagger/OpenAPI
        if 'swagger' in path.lower() or 'openapi' in path.lower():
            if '"swagger"' in content or '"openapi"' in content:
                return 'api_doc'

        # 通用检测
        if len(content) > 100:
            return 'unknown'

        return None

    def _get_severity_for_path(self, path: str) -> Severity:
        """根据路径获取严重程度"""
        high_severity_patterns = ['.env', 'config', 'password', '.git', 'backup', '.sql']
        medium_severity_patterns = ['log', 'debug', 'test', 'swagger', 'api-docs']

        path_lower = path.lower()

        if any(p in path_lower for p in high_severity_patterns):
            return Severity.HIGH

        if any(p in path_lower for p in medium_severity_patterns):
            return Severity.MEDIUM

        return Severity.LOW

    def _get_severity_for_category(self, category: str) -> Severity:
        """根据类别获取严重程度"""
        severity_map = {
            'private_key': Severity.CRITICAL,
            'aws_key': Severity.CRITICAL,
            'database': Severity.HIGH,
            'password': Severity.HIGH,
            'api_key': Severity.HIGH,
            'token': Severity.HIGH,
            'internal_ip': Severity.MEDIUM,
            'debug_info': Severity.MEDIUM,
            'email': Severity.LOW,
        }
        return severity_map.get(category, Severity.MEDIUM)

    def _sanitize_evidence(self, category: str, match: str) -> str:
        """脱敏处理证据

        Args:
            category: 类别
            match: 匹配内容

        Returns:
            脱敏后的内容
        """
        if not match:
            return "[检测到但内容已隐藏]"

        if category in ('password', 'api_key', 'aws_key', 'token', 'private_key'):
            if len(match) > 8:
                return match[:4] + '*' * (len(match) - 8) + match[-4:]
            else:
                return '*' * len(match)

        if category == 'database':
            # 隐藏密码部分
            return re.sub(r':([^@]+)@', ':****@', match)

        # 其他类型显示部分内容
        if len(match) > 50:
            return match[:50] + '...'

        return match

    def get_payloads(self) -> List[str]:
        """获取检测器使用的 payload 列表"""
        return self.sensitive_paths
