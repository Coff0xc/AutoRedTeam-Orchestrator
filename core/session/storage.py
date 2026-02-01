#!/usr/bin/env python3
"""
storage.py - 会话持久化模块

提供会话数据的持久化存储功能，支持JSON格式的文件存储。
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Session ID 安全正则 - 只允许字母数字和短横线
SESSION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{6,62}[a-zA-Z0-9]$")


class SessionStorage:
    """
    会话存储类

    提供会话上下文和结果的持久化功能。

    Attributes:
        storage_dir: 存储目录路径
    """

    def __init__(self, storage_dir: Optional[Path] = None):
        """
        初始化存储

        Args:
            storage_dir: 存储目录，默认为项目 data/sessions 目录
        """
        if storage_dir is None:
            # 获取项目根目录
            project_root = Path(__file__).parent.parent.parent
            storage_dir = project_root / "data" / "sessions"

        self.storage_dir = Path(storage_dir)
        self._ensure_storage_dir()

        # 子目录
        self._contexts_dir = self.storage_dir / "contexts"
        self._results_dir = self.storage_dir / "results"
        self._contexts_dir.mkdir(parents=True, exist_ok=True)
        self._results_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"会话存储初始化完成: {self.storage_dir}")

    def _ensure_storage_dir(self) -> None:
        """确保存储目录存在"""
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _validate_session_id(self, session_id: str) -> bool:
        """
        验证 Session ID 格式

        防止路径遍历攻击

        Args:
            session_id: 会话ID

        Returns:
            bool: 是否有效
        """
        if not session_id:
            return False

        if not SESSION_ID_PATTERN.match(session_id):
            return False

        # 额外检查危险字符
        dangerous_chars = ["..", "/", "\\", "\x00", "\n", "\r"]
        for char in dangerous_chars:
            if char in session_id:
                return False

        return True

    def _get_safe_path(self, base_dir: Path, session_id: str, suffix: str = ".json") -> Path:
        """
        获取安全的文件路径

        防止路径遍历攻击

        Args:
            base_dir: 基础目录
            session_id: 会话ID
            suffix: 文件后缀

        Returns:
            Path: 安全的文件路径

        Raises:
            ValueError: 如果session_id无效
        """
        if not self._validate_session_id(session_id):
            raise ValueError(f"无效的 Session ID: {session_id}")

        # 构建路径
        filepath = base_dir / f"{session_id}{suffix}"
        resolved = filepath.resolve()
        base_resolved = base_dir.resolve()

        # 确保路径在基础目录内
        try:
            resolved.relative_to(base_resolved)
        except ValueError as e:
            raise ValueError(f"路径遍历攻击检测: {session_id}") from e

        return resolved

    def save_context(self, context: "ScanContext") -> Path:
        """
        保存扫描上下文

        Args:
            context: 扫描上下文对象

        Returns:
            Path: 保存的文件路径
        """

        filepath = self._get_safe_path(self._contexts_dir, context.session_id)

        data = context.to_dict()
        data["_saved_at"] = datetime.now().isoformat()
        data["_storage_version"] = "1.0"

        # 使用临时文件写入，然后原子性移动
        temp_path = filepath.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            # 原子性替换（Windows 需要先删除目标文件）
            if filepath.exists():
                filepath.unlink()
            temp_path.rename(filepath)

            logger.debug(f"会话上下文已保存: {filepath}")
            return filepath

        except (OSError, TypeError) as e:
            # OSError: 文件系统错误（权限、磁盘空间等）
            # TypeError: 序列化不可序列化的对象
            # 清理临时文件
            if temp_path.exists():
                temp_path.unlink()
            logger.error(f"保存会话上下文失败: {type(e).__name__}: {e}")
            raise

    def load_context(self, session_id: str) -> Optional["ScanContext"]:
        """
        加载扫描上下文

        Args:
            session_id: 会话ID

        Returns:
            ScanContext: 上下文对象，如果不存在返回None
        """
        from .context import ScanContext

        try:
            filepath = self._get_safe_path(self._contexts_dir, session_id)

            if not filepath.exists():
                logger.debug(f"会话上下文不存在: {session_id}")
                return None

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            # 移除存储元数据
            data.pop("_saved_at", None)
            data.pop("_storage_version", None)

            context = ScanContext.from_dict(data)
            logger.debug(f"会话上下文已加载: {session_id}")
            return context

        except ValueError as e:
            logger.error(f"无效的会话ID: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"会话文件格式错误: {e}")
            return None
        except (OSError, TypeError, KeyError, AttributeError) as e:
            # OSError: 文件系统错误
            # TypeError/KeyError/AttributeError: 数据结构问题
            logger.error(f"加载会话上下文失败: {type(e).__name__}: {e}")
            return None

    def save_result(self, result: "ScanResult") -> Path:
        """
        保存扫描结果

        Args:
            result: 扫描结果对象

        Returns:
            Path: 保存的文件路径
        """

        filepath = self._get_safe_path(self._results_dir, result.session_id)

        data = result.to_dict()
        data["_saved_at"] = datetime.now().isoformat()
        data["_storage_version"] = "1.0"

        # 使用临时文件写入
        temp_path = filepath.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            # 原子性替换
            if filepath.exists():
                filepath.unlink()
            temp_path.rename(filepath)

            logger.debug(f"扫描结果已保存: {filepath}")
            return filepath

        except (OSError, TypeError) as e:
            # OSError: 文件系统错误（权限、磁盘空间等）
            # TypeError: 序列化不可序列化的对象
            if temp_path.exists():
                temp_path.unlink()
            logger.error(f"保存扫描结果失败: {type(e).__name__}: {e}")
            raise

    def load_result(self, session_id: str) -> Optional["ScanResult"]:
        """
        加载扫描结果

        Args:
            session_id: 会话ID

        Returns:
            ScanResult: 结果对象，如果不存在返回None
        """
        from .result import ScanResult

        try:
            filepath = self._get_safe_path(self._results_dir, session_id)

            if not filepath.exists():
                logger.debug(f"扫描结果不存在: {session_id}")
                return None

            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)

            # 移除存储元数据
            data.pop("_saved_at", None)
            data.pop("_storage_version", None)

            result = ScanResult.from_dict(data)
            logger.debug(f"扫描结果已加载: {session_id}")
            return result

        except ValueError as e:
            logger.error(f"无效的会话ID: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"结果文件格式错误: {e}")
            return None
        except (OSError, TypeError, KeyError, AttributeError) as e:
            # OSError: 文件系统错误
            # TypeError/KeyError/AttributeError: 数据结构问题
            logger.error(f"加载扫描结果失败: {type(e).__name__}: {e}")
            return None

    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        列出所有会话

        Returns:
            List[Dict]: 会话信息列表
        """
        sessions = []

        # 列出所有上下文文件
        for filepath in self._contexts_dir.glob("*.json"):
            try:
                session_id = filepath.stem

                # 验证session_id格式
                if not self._validate_session_id(session_id):
                    continue

                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # 提取摘要信息
                sessions.append(
                    {
                        "session_id": session_id,
                        "target": (
                            data.get("target", {}).get("value") if data.get("target") else None
                        ),
                        "status": data.get("status", "unknown"),
                        "phase": data.get("phase", "unknown"),
                        "started_at": data.get("started_at"),
                        "ended_at": data.get("ended_at"),
                        "saved_at": data.get("_saved_at"),
                        "vulnerabilities_count": len(data.get("vulnerabilities", [])),
                        "has_result": self._has_result(session_id),
                    }
                )

            except (OSError, json.JSONDecodeError, KeyError, TypeError) as e:
                # OSError: 文件读取错误
                # json.JSONDecodeError: JSON解析错误
                # KeyError/TypeError: 数据结构问题
                logger.warning(f"读取会话文件失败 {filepath}: {type(e).__name__}: {e}")
                continue

        # 按保存时间排序，最新的在前
        sessions.sort(key=lambda x: x.get("saved_at", ""), reverse=True)

        return sessions

    def _has_result(self, session_id: str) -> bool:
        """检查是否有对应的结果文件"""
        try:
            filepath = self._get_safe_path(self._results_dir, session_id)
            return filepath.exists()
        except ValueError:
            return False

    def delete_session(self, session_id: str) -> bool:
        """
        删除会话

        同时删除上下文和结果文件

        Args:
            session_id: 会话ID

        Returns:
            bool: 是否成功删除
        """
        deleted = False

        try:
            # 删除上下文文件
            context_path = self._get_safe_path(self._contexts_dir, session_id)
            if context_path.exists():
                context_path.unlink()
                deleted = True
                logger.debug(f"已删除会话上下文: {session_id}")

            # 删除结果文件
            result_path = self._get_safe_path(self._results_dir, session_id)
            if result_path.exists():
                result_path.unlink()
                deleted = True
                logger.debug(f"已删除扫描结果: {session_id}")

            if deleted:
                logger.info(f"会话已删除: {session_id}")
            return deleted

        except ValueError as e:
            logger.error(f"删除失败 - 无效的会话ID: {e}")
            return False
        except OSError as e:
            # OSError: 文件删除错误（权限等）
            logger.error(f"删除会话失败: {type(e).__name__}: {e}")
            return False

    def cleanup_old_sessions(self, max_age_days: int = 30) -> int:
        """
        清理旧会话

        Args:
            max_age_days: 最大保留天数

        Returns:
            int: 清理的会话数
        """
        cleaned = 0
        cutoff_time = datetime.now().timestamp() - (max_age_days * 24 * 3600)

        for filepath in self._contexts_dir.glob("*.json"):
            try:
                # 检查文件修改时间
                if filepath.stat().st_mtime < cutoff_time:
                    session_id = filepath.stem
                    if self._validate_session_id(session_id):
                        if self.delete_session(session_id):
                            cleaned += 1

            except (OSError, ValueError) as e:
                # OSError: 文件操作错误
                # ValueError: 无效的会话ID
                logger.warning(f"清理会话失败 {filepath}: {type(e).__name__}: {e}")
                continue

        logger.info(f"清理了 {cleaned} 个过期会话")
        return cleaned

    def get_storage_stats(self) -> Dict[str, Any]:
        """
        获取存储统计

        Returns:
            Dict: 统计信息
        """
        contexts_count = len(list(self._contexts_dir.glob("*.json")))
        results_count = len(list(self._results_dir.glob("*.json")))

        # 计算总大小
        total_size = 0
        for filepath in self.storage_dir.rglob("*.json"):
            total_size += filepath.stat().st_size

        return {
            "storage_dir": str(self.storage_dir),
            "contexts_count": contexts_count,
            "results_count": results_count,
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
        }

    def export_all(self, output_path: Path) -> Path:
        """
        导出所有会话数据

        Args:
            output_path: 输出文件路径

        Returns:
            Path: 导出文件路径
        """
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "storage_version": "1.0",
            "contexts": {},
            "results": {},
        }

        # 导出所有上下文
        for filepath in self._contexts_dir.glob("*.json"):
            session_id = filepath.stem
            if self._validate_session_id(session_id):
                with open(filepath, "r", encoding="utf-8") as f:
                    export_data["contexts"][session_id] = json.load(f)

        # 导出所有结果
        for filepath in self._results_dir.glob("*.json"):
            session_id = filepath.stem
            if self._validate_session_id(session_id):
                with open(filepath, "r", encoding="utf-8") as f:
                    export_data["results"][session_id] = json.load(f)

        output_path = Path(output_path)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        logger.info(f"已导出所有会话数据到: {output_path}")
        return output_path

    def import_all(self, input_path: Path, overwrite: bool = False) -> int:
        """
        导入会话数据

        Args:
            input_path: 导入文件路径
            overwrite: 是否覆盖已存在的会话

        Returns:
            int: 导入的会话数
        """
        input_path = Path(input_path)
        with open(input_path, "r", encoding="utf-8") as f:
            import_data = json.load(f)

        imported = 0

        # 导入上下文
        for session_id, context_data in import_data.get("contexts", {}).items():
            if not self._validate_session_id(session_id):
                continue

            filepath = self._get_safe_path(self._contexts_dir, session_id)
            if filepath.exists() and not overwrite:
                continue

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(context_data, f, ensure_ascii=False, indent=2)
            imported += 1

        # 导入结果
        for session_id, result_data in import_data.get("results", {}).items():
            if not self._validate_session_id(session_id):
                continue

            filepath = self._get_safe_path(self._results_dir, session_id)
            if filepath.exists() and not overwrite:
                continue

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(result_data, f, ensure_ascii=False, indent=2)

        logger.info(f"已导入 {imported} 个会话")
        return imported
