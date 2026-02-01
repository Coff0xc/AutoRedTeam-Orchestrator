#!/usr/bin/env python3
"""
Payload 管理器 - 统一管理所有攻击 Payload
消除 Payload 定义分散的问题
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class PayloadManager:
    """
    Payload 管理器 - 统一管理所有攻击 Payload

    特性:
    - 集中管理所有 Payload
    - 支持动态加载和更新
    - 支持 Payload 分类和标签
    - 支持自定义 Payload
    - 支持 Payload 优先级
    """

    def __init__(self, payload_dir: str = None):
        """
        初始化 Payload 管理器

        Args:
            payload_dir: Payload 文件目录
        """
        self.payload_dir = payload_dir or Path(__file__).parent
        self._cache: Dict[str, Dict[str, List[str]]] = {}
        self._custom_payloads: Dict[str, Dict[str, List[str]]] = {}
        self._tags: Dict[str, Set[str]] = {}
        self._load_all()

    def _load_all(self):
        """加载所有 Payload 文件"""
        payload_files = Path(self.payload_dir).glob("*_payloads.py")

        for file in payload_files:
            try:
                vuln_type = file.stem.replace("_payloads", "")
                payloads = self._load_module(file)
                if payloads:
                    self._cache[vuln_type] = payloads
                    logger.info(
                        f"已加载 {vuln_type} Payload: {sum(len(v) for v in payloads.values())} 条"
                    )
            except Exception as e:
                logger.error(f"加载 Payload 文件失败 {file}: {e}")

    def _load_module(self, file_path: Path) -> Dict[str, List[str]]:
        """
        从 Python 模块加载 Payload

        Args:
            file_path: 模块文件路径

        Returns:
            Payload 字典
        """
        import importlib.util

        spec = importlib.util.spec_from_file_location("payloads", file_path)
        if not spec or not spec.loader:
            return {}

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # 查找所有大写的字典变量
        payloads = {}
        for name in dir(module):
            if name.isupper() and isinstance(getattr(module, name), dict):
                payloads[name.lower()] = getattr(module, name)

        return payloads

    def get_payloads(
        self, vuln_type: str, category: str = None, tags: List[str] = None, limit: int = None
    ) -> List[str]:
        """
        获取指定类型的 Payload

        Args:
            vuln_type: 漏洞类型 (如 "sqli", "xss")
            category: Payload 类别 (如 "error_based", "time_based")
            tags: 标签过滤
            limit: 限制返回数量

        Returns:
            Payload 列表
        """
        # 从缓存获取
        payloads_dict = self._cache.get(vuln_type, {})

        # 合并自定义 Payload
        if vuln_type in self._custom_payloads:
            for cat, payloads in self._custom_payloads[vuln_type].items():
                if cat not in payloads_dict:
                    payloads_dict[cat] = []
                payloads_dict[cat].extend(payloads)

        # 按类别过滤
        if category:
            result = payloads_dict.get(category, [])
        else:
            # 返回所有类别的 Payload
            result = []
            for payload_list in payloads_dict.values():
                result.extend(payload_list)

        # 按标签过滤
        if tags:
            result = [p for p in result if self._has_tags(vuln_type, p, tags)]

        # 限制数量
        if limit:
            result = result[:limit]

        return result

    def _has_tags(self, vuln_type: str, payload: str, tags: List[str]) -> bool:
        """检查 Payload 是否包含指定标签"""
        payload_tags = self._tags.get(f"{vuln_type}:{payload}", set())
        return any(tag in payload_tags for tag in tags)

    def add_custom_payload(
        self, vuln_type: str, category: str, payload: str, tags: List[str] = None
    ):
        """
        添加自定义 Payload

        Args:
            vuln_type: 漏洞类型
            category: Payload 类别
            payload: Payload 内容
            tags: 标签列表
        """
        if vuln_type not in self._custom_payloads:
            self._custom_payloads[vuln_type] = {}

        if category not in self._custom_payloads[vuln_type]:
            self._custom_payloads[vuln_type][category] = []

        self._custom_payloads[vuln_type][category].append(payload)

        # 添加标签
        if tags:
            key = f"{vuln_type}:{payload}"
            if key not in self._tags:
                self._tags[key] = set()
            self._tags[key].update(tags)

        logger.info(f"添加自定义 Payload: {vuln_type}/{category}")

    def list_types(self) -> List[str]:
        """列出所有漏洞类型"""
        return list(self._cache.keys())

    def list_categories(self, vuln_type: str) -> List[str]:
        """列出指定漏洞类型的所有类别"""
        return list(self._cache.get(vuln_type, {}).keys())

    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        stats = {}
        for vuln_type, payloads_dict in self._cache.items():
            total = sum(len(v) for v in payloads_dict.values())
            stats[vuln_type] = total
        return stats

    def export_to_json(self, output_file: str):
        """导出 Payload 到 JSON 文件"""
        data = {"builtin": self._cache, "custom": self._custom_payloads}
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"Payload 已导出到: {output_file}")

    def import_from_json(self, input_file: str):
        """从 JSON 文件导入 Payload"""
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "custom" in data:
            self._custom_payloads.update(data["custom"])
            logger.info(f"已导入自定义 Payload: {input_file}")


# 全局单例
_payload_manager: Optional[PayloadManager] = None


def get_payload_manager() -> PayloadManager:
    """获取全局 Payload 管理器实例"""
    global _payload_manager
    if _payload_manager is None:
        _payload_manager = PayloadManager()
    return _payload_manager


# 使用示例
if __name__ == "__main__":
    manager = PayloadManager()

    # 获取 SQLi Payload
    sqli_payloads = manager.get_payloads("sqli", category="error_based", limit=10)
    print(f"SQLi Error-based Payloads: {len(sqli_payloads)}")

    # 添加自定义 Payload
    manager.add_custom_payload("sqli", "custom", "' AND 1=1--", tags=["mysql", "simple"])

    # 统计信息
    stats = manager.get_stats()
    print(f"Payload 统计: {stats}")
