#!/usr/bin/env python3
"""
API安全测试基类模块

提供统一的API测试接口、结果数据结构和漏洞类型定义。
所有API安全测试器都应继承自BaseAPITester。

作者: AutoRedTeam
版本: 3.0.0
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import asyncio
import logging

logger = logging.getLogger(__name__)


class APIVulnType(Enum):
    """API漏洞类型枚举"""

    # JWT相关漏洞
    JWT_NONE_ALG = 'jwt_none_algorithm'
    JWT_WEAK_SECRET = 'jwt_weak_secret'
    JWT_ALG_CONFUSION = 'jwt_algorithm_confusion'
    JWT_KID_INJECTION = 'jwt_kid_injection'
    JWT_JKU_INJECTION = 'jwt_jku_injection'
    JWT_EXPIRED_ACCEPTED = 'jwt_expired_accepted'
    JWT_SIGNATURE_NOT_VERIFIED = 'jwt_signature_not_verified'

    # CORS相关漏洞
    CORS_MISCONFIGURATION = 'cors_misconfiguration'
    CORS_NULL_ORIGIN = 'cors_null_origin'
    CORS_WILDCARD = 'cors_wildcard'
    CORS_ORIGIN_REFLECTION = 'cors_origin_reflection'
    CORS_CREDENTIALS_WITH_WILDCARD = 'cors_credentials_with_wildcard'
    CORS_SUBDOMAIN_BYPASS = 'cors_subdomain_bypass'

    # GraphQL相关漏洞
    GRAPHQL_INTROSPECTION = 'graphql_introspection'
    GRAPHQL_DOS = 'graphql_dos'
    GRAPHQL_BATCH_DOS = 'graphql_batch_dos'
    GRAPHQL_DEEP_NESTING = 'graphql_deep_nesting'
    GRAPHQL_FIELD_SUGGESTION = 'graphql_field_suggestion'
    GRAPHQL_ALIAS_OVERLOAD = 'graphql_alias_overload'
    GRAPHQL_DIRECTIVE_OVERLOAD = 'graphql_directive_overload'
    GRAPHQL_INJECTION = 'graphql_injection'

    # WebSocket相关漏洞
    WEBSOCKET_CSWSH = 'websocket_cswsh'
    WEBSOCKET_ORIGIN_BYPASS = 'websocket_origin_bypass'
    WEBSOCKET_AUTH_BYPASS = 'websocket_auth_bypass'
    WEBSOCKET_NO_TLS = 'websocket_no_tls'
    WEBSOCKET_TOKEN_LEAK = 'websocket_token_leak'
    WEBSOCKET_COMPRESSION_ORACLE = 'websocket_compression_oracle'

    # OAuth相关漏洞
    OAUTH_REDIRECT = 'oauth_redirect'
    OAUTH_OPEN_REDIRECT = 'oauth_open_redirect'
    OAUTH_CSRF = 'oauth_csrf'
    OAUTH_TOKEN_LEAK = 'oauth_token_leak'
    OAUTH_PKCE_MISSING = 'oauth_pkce_missing'
    OAUTH_SCOPE_MANIPULATION = 'oauth_scope_manipulation'

    # 安全头相关
    HEADERS_MISSING_CSP = 'headers_missing_csp'
    HEADERS_MISSING_HSTS = 'headers_missing_hsts'
    HEADERS_MISSING_X_FRAME = 'headers_missing_x_frame_options'
    HEADERS_MISSING_X_CONTENT_TYPE = 'headers_missing_x_content_type'
    HEADERS_INSECURE_CSP = 'headers_insecure_csp'
    HEADERS_WEAK_HSTS = 'headers_weak_hsts'

    # 通用API漏洞
    API_RATE_LIMIT_MISSING = 'api_rate_limit_missing'
    API_BROKEN_AUTH = 'api_broken_auth'
    API_EXCESSIVE_DATA = 'api_excessive_data'
    API_MASS_ASSIGNMENT = 'api_mass_assignment'


class Severity(Enum):
    """漏洞严重性等级"""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

    @property
    def score(self) -> int:
        """获取严重性分数"""
        scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        return scores.get(self.value, 0)

    def __lt__(self, other: 'Severity') -> bool:
        return self.score < other.score

    def __gt__(self, other: 'Severity') -> bool:
        return self.score > other.score


@dataclass
class APITestResult:
    """API测试结果数据类"""

    vulnerable: bool
    vuln_type: Optional[APIVulnType] = None
    severity: Severity = Severity.MEDIUM
    title: str = ''
    description: str = ''
    evidence: Optional[Dict[str, Any]] = None
    remediation: str = ''
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'vulnerable': self.vulnerable,
            'vuln_type': self.vuln_type.value if self.vuln_type else None,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'evidence': self.evidence or {},
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'references': self.references
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'APITestResult':
        """从字典创建实例"""
        vuln_type = None
        if data.get('vuln_type'):
            try:
                vuln_type = APIVulnType(data['vuln_type'])
            except ValueError:
                pass

        severity = Severity.MEDIUM
        if data.get('severity'):
            try:
                severity = Severity(data['severity'])
            except ValueError:
                pass

        return cls(
            vulnerable=data.get('vulnerable', False),
            vuln_type=vuln_type,
            severity=severity,
            title=data.get('title', ''),
            description=data.get('description', ''),
            evidence=data.get('evidence'),
            remediation=data.get('remediation', ''),
            cvss_score=data.get('cvss_score', 0.0),
            cwe_id=data.get('cwe_id'),
            references=data.get('references', [])
        )

    def __repr__(self) -> str:
        status = "VULNERABLE" if self.vulnerable else "SAFE"
        return f"<APITestResult {status} {self.vuln_type.value if self.vuln_type else 'N/A'} [{self.severity.value}]>"


@dataclass
class APIScanSummary:
    """API扫描摘要"""

    target: str
    total_tests: int = 0
    vulnerable_count: int = 0
    highest_severity: Severity = Severity.INFO
    results: List[APITestResult] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    scan_duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'target': self.target,
            'total_tests': self.total_tests,
            'vulnerable_count': self.vulnerable_count,
            'highest_severity': self.highest_severity.value,
            'results': [r.to_dict() for r in self.results],
            'recommendations': self.recommendations,
            'scan_duration': self.scan_duration,
            'vulnerabilities_by_severity': self._count_by_severity()
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """按严重性统计漏洞数量"""
        counts: Dict[str, int] = {}
        for result in self.results:
            if result.vulnerable:
                sev = result.severity.value
                counts[sev] = counts.get(sev, 0) + 1
        return counts


class BaseAPITester(ABC):
    """
    API测试基类

    所有API安全测试器都应继承此类并实现test()方法。

    使用示例:
        class MyTester(BaseAPITester):
            name = 'my_tester'
            description = '自定义API测试'

            def test(self) -> List[APITestResult]:
                # 实现测试逻辑
                return self._results
    """

    # 子类应覆盖这些属性
    name: str = 'base'
    description: str = 'Base API Security Tester'
    version: str = '1.0.0'

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化测试器

        Args:
            target: 目标URL或端点
            config: 可选配置字典，可包含:
                - timeout: 请求超时时间
                - proxy: 代理地址
                - headers: 额外HTTP头
                - verify_ssl: 是否验证SSL
        """
        self.target = target
        self.config = config or {}
        self._results: List[APITestResult] = []
        self._http_client = None
        self._owns_client = False  # 标记是否拥有客户端（需要关闭）

        # 从配置中提取常用选项
        self.timeout = self.config.get('timeout', 10.0)
        self.proxy = self.config.get('proxy')
        self.extra_headers = self.config.get('headers', {})
        self.verify_ssl = self.config.get('verify_ssl', True)

    def __del__(self):
        """析构时关闭HTTP客户端"""
        self.close()

    def close(self):
        """关闭HTTP客户端，释放资源"""
        if self._http_client is not None and self._owns_client:
            try:
                self._http_client.close()
            except (AttributeError, OSError):
                pass  # 客户端可能没有close方法或已关闭
            self._http_client = None
            self._owns_client = False

    def __enter__(self):
        """支持上下文管理器"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出时关闭资源"""
        self.close()
        return False

    @abstractmethod
    def test(self) -> List[APITestResult]:
        """
        执行测试（子类必须实现）

        Returns:
            测试结果列表
        """
        pass

    async def async_test(self) -> List[APITestResult]:
        """
        异步执行测试

        默认实现使用线程池运行同步test()方法。
        子类可以覆盖此方法提供真正的异步实现。

        Returns:
            测试结果列表
        """
        return await asyncio.to_thread(self.test)

    def _add_result(self, result: APITestResult) -> None:
        """添加测试结果"""
        self._results.append(result)
        if result.vulnerable:
            logger.info(
                f"[{self.name}] 发现漏洞: {result.vuln_type.value if result.vuln_type else 'unknown'} "
                f"- {result.severity.value}"
            )

    def _create_result(
        self,
        vulnerable: bool,
        vuln_type: Optional[APIVulnType] = None,
        severity: Severity = Severity.MEDIUM,
        title: str = '',
        description: str = '',
        evidence: Optional[Dict[str, Any]] = None,
        remediation: str = ''
    ) -> APITestResult:
        """创建并添加测试结果的便捷方法"""
        result = APITestResult(
            vulnerable=vulnerable,
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation
        )
        self._add_result(result)
        return result

    @property
    def results(self) -> List[APITestResult]:
        """获取测试结果"""
        return self._results

    def clear_results(self) -> None:
        """清空测试结果"""
        self._results = []

    def get_summary(self) -> APIScanSummary:
        """获取扫描摘要"""
        vulnerable_results = [r for r in self._results if r.vulnerable]

        highest_severity = Severity.INFO
        recommendations = []

        for result in vulnerable_results:
            if result.severity > highest_severity:
                highest_severity = result.severity
            if result.remediation:
                recommendations.append(result.remediation)

        return APIScanSummary(
            target=self.target,
            total_tests=len(self._results),
            vulnerable_count=len(vulnerable_results),
            highest_severity=highest_severity,
            results=self._results,
            recommendations=list(set(recommendations))
        )

    def _get_http_client(self):
        """获取HTTP客户端（延迟加载）"""
        if self._http_client is None:
            try:
                from core.http import get_client, HTTPConfig

                config = HTTPConfig()
                config.timeout = self.timeout
                config.verify_ssl = self.verify_ssl

                self._http_client = get_client()
                self._owns_client = False  # 共享客户端，不需要关闭
            except ImportError:
                # 回退到requests
                import requests
                self._http_client = requests.Session()
                self._http_client.verify = self.verify_ssl
                self._owns_client = True  # 自己创建的，需要关闭

        return self._http_client

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} target='{self.target}'>"


class CompositeTester(BaseAPITester):
    """
    组合测试器

    用于组合多个测试器进行批量测试。

    使用示例:
        composite = CompositeTester(target)
        composite.add_tester(JWTTester(target, token))
        composite.add_tester(CORSTester(target))
        results = composite.test()
    """

    name = 'composite'
    description = '组合API安全测试器'

    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self._testers: List[BaseAPITester] = []

    def add_tester(self, tester: BaseAPITester) -> 'CompositeTester':
        """添加子测试器"""
        self._testers.append(tester)
        return self

    def test(self) -> List[APITestResult]:
        """执行所有子测试器的测试"""
        self.clear_results()

        for tester in self._testers:
            try:
                results = tester.test()
                self._results.extend(results)
            except Exception as e:
                logger.error(f"测试器 {tester.name} 执行失败: {e}")
                self._create_result(
                    vulnerable=False,
                    title=f"测试失败: {tester.name}",
                    description=f"测试执行出错: {str(e)}"
                )

        return self._results

    async def async_test(self) -> List[APITestResult]:
        """异步执行所有子测试器"""
        self.clear_results()

        tasks = [tester.async_test() for tester in self._testers]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        for i, results in enumerate(results_list):
            if isinstance(results, Exception):
                logger.error(f"测试器 {self._testers[i].name} 执行失败: {results}")
            else:
                self._results.extend(results)

        return self._results


# 导出
__all__ = [
    'APIVulnType',
    'Severity',
    'APITestResult',
    'APIScanSummary',
    'BaseAPITester',
    'CompositeTester',
]
