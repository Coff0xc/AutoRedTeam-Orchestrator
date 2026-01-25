"""
检测器基类

定义所有漏洞检测器的基础接口和通用功能
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, AsyncIterator, Type
import asyncio
import logging
import time
import json
from urllib.parse import urlencode

from .result import DetectionResult, Severity, DetectorType, RequestInfo, ResponseInfo

# 导入项目统一异常类型
from core.exceptions import (
    DetectorError,
    HTTPError,
    TimeoutError as DetectorTimeoutError,
    ConnectionError as DetectorConnectionError,
)

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
        """懒加载HTTP客户端

        Returns:
            HTTP客户端实例

        Raises:
            DetectorError: 当HTTP客户端初始化失败时
        """
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
            except ImportError as e:
                # core.http 不可用时，使用 requests 作为回退
                logger.warning(f"[{self.name}] core.http 不可用，使用 requests 回退: {e}")
                try:
                    import requests
                    # 创建简单的 requests Session 包装
                    session = requests.Session()
                    session.verify = self.config.get('verify_ssl', False)
                    session.timeout = self.config.get('timeout', 30)
                    self._http_client = session
                except ImportError as req_e:
                    logger.error(f"[{self.name}] 无法加载HTTP客户端: {req_e}")
                    raise DetectorError(
                        f"HTTP客户端初始化失败: 缺少必要的依赖 (requests)",
                        detector_name=self.name,
                        cause=req_e
                    )
            except (TypeError, ValueError) as e:
                # 配置参数类型错误
                logger.error(f"[{self.name}] HTTP客户端配置错误: {e}")
                raise DetectorError(
                    f"HTTP客户端配置无效: {e}",
                    detector_name=self.name,
                    cause=e
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

    def get_payloads(self) -> List[str]:
        """获取检测器使用的payload列表

        Returns:
            payload字符串列表
        """
        return []

    def _enhance_payloads(self, payloads: List[str]) -> List[str]:
        """根据配置扩展Payload（WAF绕过/智能变异）"""
        if not payloads or not self.config.get('enable_smart_payload', False):
            return payloads

        waf_type = self.config.get('waf_type')
        source = str(self.config.get('smart_payload_source', 'adaptive')).lower()
        max_variants = self.config.get('max_payload_variants')
        try:
            max_total = (
                int(max_variants)
                if max_variants is not None and str(max_variants).strip() != ""
                else max(len(payloads) * 2, len(payloads))
            )
        except (TypeError, ValueError):
            max_total = max(len(payloads) * 2, len(payloads))

        mutated: List[str] = []
        try:
            if source == 'smart':
                from modules.smart_payload_engine import PayloadMutator as SmartMutator
                for payload in payloads:
                    mutated.extend(SmartMutator.mutate(payload, waf_type))
            else:
                from modules.adaptive_payload_engine import AdaptivePayloadEngine
                engine = AdaptivePayloadEngine()
                for payload in payloads:
                    mutated.extend(engine.mutate_payload(payload, waf_type))
        except Exception as e:
            logger.debug(f"[{self.name}] 智能Payload扩展失败: {e}")
            return payloads

        merged: List[str] = []
        seen = set()
        for payload in payloads + mutated:
            if payload not in seen:
                merged.append(payload)
                seen.add(payload)

        return merged[:max_total]

    def _build_request_info(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json_data: Any = None,
        cookies: Optional[Dict[str, Any]] = None
    ) -> RequestInfo:
        """构建请求上下文，便于后续验证与误报过滤"""
        method_value = (method or "GET").upper()
        headers_value = dict(headers or {})
        params_value = dict(params or {})
        cookies_value = dict(cookies or {})
        body = None

        if json_data is not None:
            try:
                body = json.dumps(json_data, ensure_ascii=True)
            except (TypeError, ValueError):
                body = str(json_data)
        elif isinstance(data, dict):
            body = urlencode(data, doseq=True)
        elif data is not None:
            if isinstance(data, (bytes, bytearray)):
                body = data.decode("utf-8", errors="ignore")
            else:
                body = str(data)

        return RequestInfo(
            method=method_value,
            url=url,
            headers=headers_value,
            params=params_value,
            body=body,
            cookies=cookies_value
        )

    def _build_response_info(self, response: Any) -> Optional[ResponseInfo]:
        """构建响应上下文"""
        if response is None:
            return None
        try:
            elapsed = getattr(response, "elapsed", 0.0)
            if hasattr(elapsed, "total_seconds"):
                elapsed = elapsed.total_seconds()
            elapsed_ms = float(elapsed) * 1000.0
        except (TypeError, ValueError):
            elapsed_ms = 0.0

        return ResponseInfo(
            status_code=getattr(response, "status_code", 0),
            headers=getattr(response, "headers", {}) or {},
            body=getattr(response, "text", "") or "",
            elapsed_ms=elapsed_ms
        )

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
        except DetectorTimeoutError as e:
            # 请求超时 - 常见情况，使用 debug 级别
            logger.debug(f"[{self.name}] 请求超时 {url}: {e}")
            return None
        except DetectorConnectionError as e:
            # 连接失败 - 目标可能不可达
            logger.debug(f"[{self.name}] 连接失败 {url}: {e}")
            return None
        except HTTPError as e:
            # 其他 HTTP 错误
            logger.debug(f"[{self.name}] HTTP 错误 {url}: {e}")
            return None
        except (OSError, IOError) as e:
            # 网络层错误（socket 错误等）
            logger.debug(f"[{self.name}] 网络错误 {url}: {e}")
            return None
        except Exception as e:
            # 捕获所有其他异常以保证检测器稳定性
            # 注意：这里使用宽泛捕获是为了防止单个请求失败导致整个检测中断
            logger.warning(f"[{self.name}] 未预期的请求错误 {url}: {type(e).__name__}: {e}")
            return None

    # ==================== 上下文管理器支持 ====================

    def __enter__(self) -> 'BaseDetector':
        """上下文管理器入口

        使用示例:
            with SQLiDetector() as detector:
                results = detector.detect(url)
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """上下文管理器出口，自动清理资源"""
        self.cleanup()
        return False  # 不抑制异常

    def cleanup(self) -> None:
        """清理资源

        关闭HTTP客户端连接，清理缓存等
        子类可以覆盖此方法添加额外清理逻辑
        """
        if self._http_client is not None:
            try:
                # 尝试关闭HTTP客户端
                if hasattr(self._http_client, 'close'):
                    self._http_client.close()
                elif hasattr(self._http_client, 'aclose'):
                    # 异步客户端
                    import asyncio
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(self._http_client.aclose())
                    except RuntimeError:
                        # 没有运行中的事件循环，同步关闭
                        pass
            except Exception as e:
                logger.debug(f"[{self.name}] 清理HTTP客户端时出错: {e}")
            finally:
                self._http_client = None

        # 清理结果缓存
        self.results.clear()

    # ==================== 二次验证支持 ====================

    def verify(self, result: DetectionResult) -> bool:
        """验证漏洞是否真实存在 (二次验证)

        通过重新发送相同的payload来验证漏洞是否可复现，
        降低误报率。

        Args:
            result: 待验证的检测结果

        Returns:
            是否确认存在漏洞
        """
        # 基本检查
        if not result.vulnerable:
            return False
        if result.verified:
            return True  # 已经验证过
        if not result.payload or not result.url:
            return False

        # 调用子类实现的具体验证逻辑
        try:
            is_verified = self._do_verify(result)
            if is_verified:
                result.verified = True
                result.confidence = min(1.0, result.confidence + 0.3)
            return is_verified
        except Exception as e:
            logger.debug(f"[{self.name}] 二次验证失败: {e}")
            return False

    def _do_verify(self, result: DetectionResult) -> bool:
        """执行具体的二次验证逻辑

        子类应覆盖此方法实现漏洞特定的验证逻辑

        Args:
            result: 待验证的检测结果

        Returns:
            是否确认存在漏洞
        """
        # 默认实现：重新发送请求检查响应
        if not result.request:
            return False

        try:
            # 重新发送原始请求
            response = self._safe_request(
                method=result.request.method,
                url=result.url,
                params=result.request.params,
                headers=result.request.headers,
                data=result.request.body
            )

            if response is None:
                return False

            # 检查响应是否仍然包含漏洞特征
            response_text = getattr(response, 'text', '') or ''

            # 如果有证据，检查证据是否仍然存在
            if result.evidence and result.evidence in response_text:
                return True

            # 检查响应状态和长度是否一致
            if result.response:
                status_match = getattr(response, 'status_code', 0) == result.response.status_code
                # 允许10%的长度差异
                len_diff = abs(len(response_text) - len(result.response.body or ''))
                len_threshold = max(100, len(result.response.body or '') * 0.1)
                length_similar = len_diff <= len_threshold

                return status_match and length_similar

            return False

        except Exception as e:
            logger.debug(f"[{self.name}] 二次验证请求失败: {e}")
            return False

    def verify_all(self, results: List[DetectionResult]) -> List[DetectionResult]:
        """批量验证检测结果

        Args:
            results: 检测结果列表

        Returns:
            验证后的结果列表 (包含verified字段更新)
        """
        for result in results:
            if result.vulnerable and not result.verified:
                self.verify(result)
        return results

    # ==================== 字符串表示 ====================

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
            except DetectorError as e:
                # 检测器特定错误 - 记录并继续
                logger.error(f"[{detector.name}] 检测器错误: {e}")
            except HTTPError as e:
                # HTTP 相关错误 - 可能是目标问题
                logger.warning(f"[{detector.name}] HTTP 错误: {e}")
            except (ValueError, TypeError, KeyError) as e:
                # 数据处理错误 - 可能是响应格式问题
                logger.error(f"[{detector.name}] 数据处理错误: {type(e).__name__}: {e}")
            except Exception as e:
                # 捕获所有其他异常以保证组合检测器的稳定性
                # 注意：单个检测器失败不应影响其他检测器的执行
                logger.error(f"[{detector.name}] 未预期的检测失败: {type(e).__name__}: {e}")

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
            detector_name = self.detectors[idx].name
            if isinstance(results, DetectorError):
                # 检测器特定错误
                logger.error(f"[{detector_name}] 检测器错误: {results}")
            elif isinstance(results, HTTPError):
                # HTTP 相关错误
                logger.warning(f"[{detector_name}] HTTP 错误: {results}")
            elif isinstance(results, (ValueError, TypeError, KeyError)):
                # 数据处理错误
                logger.error(f"[{detector_name}] 数据处理错误: {type(results).__name__}: {results}")
            elif isinstance(results, Exception):
                # 其他未预期的异常
                logger.error(f"[{detector_name}] 未预期的检测失败: {type(results).__name__}: {results}")
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
