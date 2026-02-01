#!/usr/bin/env python3
"""
迁移指南 - 从旧架构迁移到新架构
提供向后兼容的适配器和迁移工具
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class LegacyAdapter:
    """
    旧架构适配器 - 提供向后兼容

    将旧的 API 调用转换为新架构的调用
    """

    @staticmethod
    def sqli_detect(url: str, param: str = None, deep_scan: bool = True) -> Dict[str, Any]:
        """
        旧版 SQLi 检测接口 (已弃用)

        迁移到:
            from tools.detectors.factory import DetectorFactory
            detector = DetectorFactory.create("sqli")
            result = detector.detect(url, param, deep_scan)
        """
        logger.warning("sqli_detect() 已弃用，请使用 DetectorFactory.create('sqli')")

        try:
            from tools.detectors.factory import DetectorFactory

            detector = DetectorFactory.create("sqli")
            result = detector.detect(url, param, deep_scan)

            # 转换为旧格式
            return {
                "success": result.get("success", False),
                "url": url,
                "vulnerabilities": result.get("vulnerabilities", []),
                "total": result.get("total", 0),
            }
        except Exception as e:
            logger.error(f"SQLi 检测失败: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def xss_detect(url: str, param: str = None, deep_scan: bool = True) -> Dict[str, Any]:
        """
        旧版 XSS 检测接口 (已弃用)

        迁移到:
            from tools.detectors.factory import DetectorFactory
            detector = DetectorFactory.create("xss")
            result = detector.detect(url, param, deep_scan)
        """
        logger.warning("xss_detect() 已弃用，请使用 DetectorFactory.create('xss')")

        try:
            from tools.detectors.factory import DetectorFactory

            detector = DetectorFactory.create("xss")
            result = detector.detect(url, param, deep_scan)

            return {
                "success": result.get("success", False),
                "url": url,
                "vulnerabilities": result.get("vulnerabilities", []),
                "total": result.get("total", 0),
            }
        except Exception as e:
            logger.error(f"XSS 检测失败: {e}")
            return {"success": False, "error": str(e)}


# 迁移映射表
MIGRATION_MAP = {
    "sqli_detect": {
        "new_api": "DetectorFactory.create('sqli').detect()",
        "module": "tools.detectors.factory",
        "example": """
# 旧代码
from tools.vuln_tools import sqli_detect
result = sqli_detect(url="https://example.com")

# 新代码
from tools.detectors.factory import DetectorFactory
detector = DetectorFactory.create("sqli")
result = detector.detect(url="https://example.com")
""",
    },
    "xss_detect": {
        "new_api": "DetectorFactory.create('xss').detect()",
        "module": "tools.detectors.factory",
        "example": """
# 旧代码
from tools.vuln_tools import xss_detect
result = xss_detect(url="https://example.com")

# 新代码
from tools.detectors.factory import DetectorFactory
detector = DetectorFactory.create("xss")
result = detector.detect(url="https://example.com")
""",
    },
}


def print_migration_guide(old_function: str):
    """打印迁移指南"""
    if old_function in MIGRATION_MAP:
        guide = MIGRATION_MAP[old_function]
        print(f"\n{'='*60}")
        print(f"迁移指南: {old_function}")
        print(f"{'='*60}")
        print(f"新 API: {guide['new_api']}")
        print(f"模块: {guide['module']}")
        print(f"\n示例:")
        print(guide["example"])
        print(f"{'='*60}\n")


# 使用示例
if __name__ == "__main__":
    # 使用适配器（向后兼容）
    result = LegacyAdapter.sqli_detect("https://example.com")
    print(f"结果: {result}")

    # 打印迁移指南
    print_migration_guide("sqli_detect")
