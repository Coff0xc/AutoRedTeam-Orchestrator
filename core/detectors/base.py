"""
检测器基类

定义所有漏洞检测器的基础接口和通用功能
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, AsyncIterator, Type
import asyncio
import logging
import time

from .result import DetectionResult, Severity, DetectorType, RequestInfo, ResponseInfo

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """检测器基类

    所有漏洞检测器必须继承此类并实现detect方法

    类属性:
        name: 检测器名称
        description: 检测器描述
        vuln_type: 漏洞类型标识
        severity: 默认严重程度
        detector_type: 检测器类型
        version: 检测器版本

    使用示例:
        class MyDetector(BaseDetector):
            name = 'my_detector'
            vuln_type = 'my_vuln'

            def detect(self, url: str, **kwargs) -> List[DetectionResult]:
                # 实现检测逻辑
                pass
    """

    # 子类必须定义的属性
    name: str = 'base'
    description: str = '基础检测器'
    vuln_type: str = ''
    severity: Severity = Severity.MEDIUM
    detector_type: DetectorType = DetectorType.MISC
    version: str = '1.0.0'

    # 默认配置
    default_config: Dict[str, Any] = {
        'timeout': 30,
        'max_payloads': 50,
        'verify_ssl': False,
        'follow_redirects': True,
        'max_redirects': 5,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """初始化检测器

        Args:
            config: 检测器配置，会与默认配置合并
        """
        self.config = {**self.default_config, **(config or {})}
        self.results: List[DetectionResult] = []
        self._http_client = None
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None

    @property
    def http_client(self):
        """懒加载HTTP客户端"""
        if self._http_client is None:
            try:
                from core.http import get_client, HTTPConfig

                http_config = HTTPConfig()
                http_config.timeout = self.config.get('timeout', 30)
                http_config.verify_ssl = self.config.get('verify_ssl', False)
                http_config.follow_redirects = self.config.get('follow_redirects', True)
                http_config.max_redirects = self.config.get('max_redirects', 5)

                from core.http import HTTPClient
                self._http_client = HTTPClient(config=http_config)
            except ImportError:
                # 回退到基础HTTP客户端
                from utils.http_client import SecureHTTPClient
                self._http_client = SecureHTTPClient(
                    verify_ssl=self.config.get('verify_ssl', False),
                    timeout=self.config.get('timeout', 30)
                )
        return self._http_client

    @abstractmethod
    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """同步检测方法

        Args:
            url: 目标URL
            **kwargs: 额外参数 (params, headers, data等)

        Returns:
            检测结果列表
        """
        pass

    async def async_detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """异步检测方法

        默认实现：在线程中运行同步方法
        子类可以覆盖此方法实现真正的异步检测

        Args:
            url: 目标URL
            **kwargs: 额外参数

        Returns:
            检测结果列表
        """
        return await asyncio.to_thread(self.detect, url, **kwargs)

    def verify(self, result: DetectionResult) -> bool:
        """验证漏洞是否真实存在

        Args:
            result: 待验证的检测结果

        Returns:
            是否确认存在漏洞
        """
        # 默认不验证，子类可覆盖
        return False

    def get_payloads(self) -> List[str]:
        """获取检测器使用的payload列表

        Returns:
            payload字符串列表
        """
        return []

    def _create_result(
        self,
        url: str,
        vulnerable: bool = True,
        param: Optional[str] = None,
        payload: Optional[str] = None,
        evidence: Optional[str] = None,
        confidence: float = 0.0,
        verified: bool = False,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        request: Optional[RequestInfo] = None,
        response: Optional[ResponseInfo] = None,
        extra: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> DetectionResult:
        """创建标准化的检测结果

        Args:
            url: 目标URL
            vulnerable: 是否存在漏洞
            param: 受影响参数
            payload: 使用的payload
            evidence: 漏洞证据
            confidence: 置信度
            verified: 是否已验证
            remediation: 修复建议
            references: 参考链接
            request: 请求信息
            response: 响应信息
            extra: 额外信息
            **kwargs: 其他参数

        Returns:
            DetectionResult实例
        """
        return DetectionResult(
            vulnerable=vulnerable,
            vuln_type=self.vuln_type,
            severity=self.severity,
            url=url,
            param=param,
            payload=payload,
            evidence=evidence,
            verified=verified,
            confidence=confidence,
            detector=self.name,
            detector_version=self.version,
            request=request,
            response=response,
            remediation=remediation,
            references=references or [],
            extra=extra or {}
        )

    def _log_detection_start(self, url: str) -> None:
        """记录检测开始"""
        self._start_time = time.time()
        logger.info(f"[{self.name}] 开始检测: {url}")

    def _log_detection_end(self, url: str, results: List[DetectionResult]) -> None:
        """记录检测结束"""
        self._end_time = time.time()
        duration = self._end_time - (self._start_time or self._end_time)
        vuln_count = sum(1 for r in results if r.vulnerable)
        logger.info(
            f"[{self.name}] 检测完成: {url}, "
            f"发现 {vuln_count} 个漏洞, 耗时 {duration:.2f}s"
        )

    def _safe_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[Any]:
        """安全的HTTP请求封装

        Args:
            method: HTTP方法
            url: 目标URL
            **kwargs: 请求参数

        Returns:
            响应对象或None（请求失败时）
        """
        try:
            response = self.http_client.request(method, url, **kwargs)
            return response
        except Exception as e:
            logger.debug(f"[{self.name}] 请求失败 {url}: {e}")
            return None

    def __str__(self) -> str:
        return f"{self.name} ({self.vuln_type})"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r}, vuln_type={self.vuln_type!r})>"


class CompositeDetector(BaseDetector):
    """组合检测器

    将多个检测器组合成一个，支持并行执行

    使用示例:
        sqli = SQLiDetector()
        xss = XSSDetector()
        composite = CompositeDetector([sqli, xss])
        results = composite.detect("https://example.com")
    """

    name = 'composite'
    description = '组合检测器'
    vuln_type = 'multiple'

    def __init__(
        self,
        detectors: List[BaseDetector],
        config: Optional[Dict[str, Any]] = None
    ):
        """初始化组合检测器

        Args:
            detectors: 子检测器列表
            config: 配置
        """
        super().__init__(config)
        self.detectors = detectors

    def detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """同步执行所有子检测器

        Args:
            url: 目标URL
            **kwargs: 额外参数

        Returns:
            所有检测器的结果合集
        """
        self._log_detection_start(url)
        all_results = []

        for detector in self.detectors:
            try:
                results = detector.detect(url, **kwargs)
                all_results.extend(results)
            except Exception as e:
                logger.error(f"[{detector.name}] 检测失败: {e}")

        self._log_detection_end(url, all_results)
        return all_results

    async def async_detect(self, url: str, **kwargs) -> List[DetectionResult]:
        """异步并行执行所有子检测器

        Args:
            url: 目标URL
            **kwargs: 额外参数

        Returns:
            所有检测器的结果合集
        """
        self._log_detection_start(url)

        # 创建所有检测任务
        tasks = [
            detector.async_detect(url, **kwargs)
            for detector in self.detectors
        ]

        # 并行执行
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        # 合并结果
        all_results = []
        for idx, results in enumerate(results_list):
            if isinstance(results, Exception):
                logger.error(f"[{self.detectors[idx].name}] 检测失败: {results}")
            elif isinstance(results, list):
                all_results.extend(results)

        self._log_detection_end(url, all_results)
        return all_results

    def add_detector(self, detector: BaseDetector) -> None:
        """添加子检测器

        Args:
            detector: 要添加的检测器
        """
        self.detectors.append(detector)

    def remove_detector(self, name: str) -> bool:
        """移除子检测器

        Args:
            name: 检测器名称

        Returns:
            是否成功移除
        """
        for i, detector in enumerate(self.detectors):
            if detector.name == name:
                self.detectors.pop(i)
                return True
        return False


class StreamingDetector(BaseDetector):
    """流式检测器

    支持逐个返回检测结果，适用于大规模扫描场景
    """

    name = 'streaming'
    description = '流式检测器'
    vuln_type = 'multiple'

    async def stream_detect(
        self,
        url: str,
        **kwargs
    ) -> AsyncIterator[DetectionResult]:
        """流式检测，逐个yield结果

        Args:
            url: 目标URL
            **kwargs: 额外参数

        Yields:
            检测结果
        """
        # 默认实现：执行同步检测后逐个返回
        results = await self.async_detect(url, **kwargs)
        for result in results:
            yield result


class ContextAwareDetector(BaseDetector):
    """上下文感知检测器

    根据上下文（如技术栈、WAF检测结果）调整检测策略
    """

    name = 'context_aware'
    description = '上下文感知检测器'

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.context: Dict[str, Any] = {}

    def set_context(self, key: str, value: Any) -> None:
        """设置上下文信息

        Args:
            key: 上下文键
            value: 上下文值
        """
        self.context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        """获取上下文信息

        Args:
            key: 上下文键
            default: 默认值

        Returns:
            上下文值
        """
        return self.context.get(key, default)

    def detect_with_context(
        self,
        url: str,
        context: Dict[str, Any],
        **kwargs
    ) -> List[DetectionResult]:
        """带上下文的检测

        Args:
            url: 目标URL
            context: 上下文信息
            **kwargs: 额外参数

        Returns:
            检测结果列表
        """
        self.context.update(context)
        return self.detect(url, **kwargs)
