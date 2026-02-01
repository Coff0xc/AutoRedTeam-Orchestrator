#!/usr/bin/env python3
"""
检测策略模式 - 支持不同的检测策略
应用策略模式，解耦检测逻辑
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class DetectionContext:
    """检测上下文 - 传递给策略的数据"""

    url: str
    params: List[str]
    deep_scan: bool = False
    timeout: int = 10
    max_payloads: int = 100
    stop_on_first: bool = True
    custom_headers: Dict[str, str] = None


class DetectionStrategy(ABC):
    """
    检测策略基类

    所有检测策略必须实现 execute 方法
    """

    @abstractmethod
    def execute(self, detector, context: DetectionContext) -> Dict[str, Any]:
        """
        执行检测策略

        Args:
            detector: 检测器实例
            context: 检测上下文

        Returns:
            检测结果
        """

    @abstractmethod
    def get_name(self) -> str:
        """获取策略名称"""


class QuickScanStrategy(DetectionStrategy):
    """
    快速扫描策略 - 使用少量高效 Payload

    特点:
    - 只测试最常见的参数
    - 使用高置信度 Payload
    - 发现第一个漏洞后停止
    - 适合快速验证
    """

    def get_name(self) -> str:
        return "quick_scan"

    def execute(self, detector, context: DetectionContext) -> Dict[str, Any]:
        logger.info(f"执行快速扫描策略: {context.url}")

        # 限制参数数量
        test_params = context.params[:3] if context.params else ["id", "page", "q"]

        # 获取高优先级 Payload
        payloads = detector.get_payloads()
        limited_payloads = {}
        for category, payload_list in payloads.items():
            limited_payloads[category] = payload_list[:5]  # 每类只取前5个

        # 临时替换 Payload
        original_payloads = detector.get_payloads
        detector.get_payloads = lambda: limited_payloads

        try:
            # 执行检测
            vulnerabilities = detector.test_payloads(
                context.url, param=test_params[0] if test_params else None, stop_on_first=True
            )

            return {
                "success": True,
                "strategy": self.get_name(),
                "vulnerabilities": [v.to_dict() for v in vulnerabilities],
                "total": len(vulnerabilities),
            }
        finally:
            # 恢复原始 Payload
            detector.get_payloads = original_payloads


class DeepScanStrategy(DetectionStrategy):
    """
    深度扫描策略 - 全面测试所有 Payload

    特点:
    - 测试所有参数
    - 使用完整 Payload 库
    - 不会提前停止
    - 包含二次验证
    - 适合全面评估
    """

    def get_name(self) -> str:
        return "deep_scan"

    def execute(self, detector, context: DetectionContext) -> Dict[str, Any]:
        logger.info(f"执行深度扫描策略: {context.url}")

        # 测试所有参数
        test_params = context.params or detector.DEFAULT_PARAMS

        all_vulnerabilities = []

        for param in test_params:
            vulnerabilities = detector.test_payloads(
                context.url, param=param, stop_on_first=False  # 不提前停止
            )
            all_vulnerabilities.extend(vulnerabilities)

        # 二次验证
        verified_vulns = []
        for vuln in all_vulnerabilities:
            if detector.verify_vulnerability(vuln):
                vuln.verified = True
                vuln.confidence = min(1.0, vuln.confidence + 0.3)
            verified_vulns.append(vuln)

        return {
            "success": True,
            "strategy": self.get_name(),
            "vulnerabilities": [v.to_dict() for v in verified_vulns],
            "total": len(verified_vulns),
            "verified_count": sum(1 for v in verified_vulns if v.verified),
        }


class SmartScanStrategy(DetectionStrategy):
    """
    智能扫描策略 - 基于响应动态调整

    特点:
    - 先快速探测
    - 根据响应特征选择 Payload
    - 动态调整扫描深度
    - 平衡速度和准确性
    """

    def get_name(self) -> str:
        return "smart_scan"

    def execute(self, detector, context: DetectionContext) -> Dict[str, Any]:
        logger.info(f"执行智能扫描策略: {context.url}")

        # 阶段1: 快速探测
        baseline = detector.get_baseline(context.url)
        if not baseline or not baseline.get("success"):
            return {"success": False, "error": "无法获取基线响应", "strategy": self.get_name()}

        # 分析响应特征
        features = self._analyze_response(baseline)

        # 阶段2: 根据特征选择 Payload
        selected_payloads = self._select_payloads(detector, features)

        # 阶段3: 执行检测
        vulnerabilities = []
        test_params = context.params[:5] if context.params else ["id", "page", "q"]

        for param in test_params:
            for category, payload_list in selected_payloads.items():
                for payload in payload_list:
                    vuln = detector.test_payload(context.url, payload, param, baseline)
                    if vuln:
                        vuln.type = category
                        vulnerabilities.append(vuln)

                        # 如果发现高置信度漏洞，停止该参数的测试
                        if vuln.confidence > 0.8:
                            break

        return {
            "success": True,
            "strategy": self.get_name(),
            "features": features,
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "total": len(vulnerabilities),
        }

    def _analyze_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """分析响应特征"""
        features = {
            "has_error_page": False,
            "response_time": response.get("response_time", 0),
            "content_length": response.get("response_length", 0),
            "server": response.get("headers", {}).get("server", "unknown"),
            "technology": [],
        }

        # 检测技术栈
        text = response.get("response_text", "").lower()
        if "php" in text:
            features["technology"].append("php")
        if "asp.net" in text or "aspx" in text:
            features["technology"].append("aspnet")
        if "java" in text or "jsp" in text:
            features["technology"].append("java")

        return features

    def _select_payloads(self, detector, features: Dict[str, Any]) -> Dict[str, List[str]]:
        """根据特征选择 Payload"""
        all_payloads = detector.get_payloads()
        selected = {}

        # 根据技术栈选择
        tech = features.get("technology", [])

        for category, payload_list in all_payloads.items():
            if "php" in tech:
                # PHP 环境优先测试特定 Payload
                selected[category] = payload_list[:10]
            elif "aspnet" in tech:
                selected[category] = payload_list[:8]
            else:
                selected[category] = payload_list[:6]

        return selected


class TargetedScanStrategy(DetectionStrategy):
    """
    定向扫描策略 - 针对特定漏洞类型

    特点:
    - 只测试指定类型的 Payload
    - 适合已知漏洞验证
    - 速度快，针对性强
    """

    def __init__(self, target_categories: List[str]):
        """
        Args:
            target_categories: 目标 Payload 类别列表
        """
        self.target_categories = target_categories

    def get_name(self) -> str:
        return "targeted_scan"

    def execute(self, detector, context: DetectionContext) -> Dict[str, Any]:
        logger.info(f"执行定向扫描策略: {context.url} - {self.target_categories}")

        # 只获取目标类别的 Payload
        all_payloads = detector.get_payloads()
        targeted_payloads = {
            cat: payloads for cat, payloads in all_payloads.items() if cat in self.target_categories
        }

        if not targeted_payloads:
            return {
                "success": False,
                "error": f"未找到目标类别: {self.target_categories}",
                "strategy": self.get_name(),
            }

        # 临时替换 Payload
        original_payloads = detector.get_payloads
        detector.get_payloads = lambda: targeted_payloads

        try:
            vulnerabilities = detector.test_payloads(
                context.url,
                param=context.params[0] if context.params else None,
                stop_on_first=context.stop_on_first,
            )

            return {
                "success": True,
                "strategy": self.get_name(),
                "target_categories": self.target_categories,
                "vulnerabilities": [v.to_dict() for v in vulnerabilities],
                "total": len(vulnerabilities),
            }
        finally:
            detector.get_payloads = original_payloads


# 策略工厂
class StrategyFactory:
    """策略工厂 - 创建检测策略"""

    _strategies = {
        "quick": QuickScanStrategy,
        "deep": DeepScanStrategy,
        "smart": SmartScanStrategy,
    }

    @classmethod
    def create(cls, strategy_name: str, **kwargs) -> DetectionStrategy:
        """
        创建策略实例

        Args:
            strategy_name: 策略名称 (quick/deep/smart/targeted)
            **kwargs: 策略参数

        Returns:
            策略实例
        """
        if strategy_name == "targeted":
            target_categories = kwargs.get("target_categories", [])
            return TargetedScanStrategy(target_categories)

        strategy_class = cls._strategies.get(strategy_name)
        if not strategy_class:
            raise ValueError(f"未知策略: {strategy_name}")

        return strategy_class()

    @classmethod
    def list_strategies(cls) -> List[str]:
        """列出所有可用策略"""
        return list(cls._strategies.keys()) + ["targeted"]


# 使用示例
if __name__ == "__main__":
    from tools.detectors.factory import DetectorFactory

    # 创建检测器
    detector = DetectorFactory.create("sqli")

    # 创建检测上下文
    context = DetectionContext(url="https://example.com", params=["id", "page"], deep_scan=False)

    # 使用快速扫描策略
    strategy = StrategyFactory.create("quick")
    result = strategy.execute(detector, context)
    print(f"快速扫描结果: {result['total']} 个漏洞")

    # 使用智能扫描策略
    strategy = StrategyFactory.create("smart")
    result = strategy.execute(detector, context)
    print(f"智能扫描结果: {result['total']} 个漏洞")
