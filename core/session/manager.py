#!/usr/bin/env python3
"""
manager.py - 会话管理器模块

提供线程安全的单例模式会话管理器，统一管理所有扫描会话。
"""

from typing import Optional, Dict, List, Any, Callable
from datetime import datetime
import threading
import logging
import uuid
from enum import Enum

from .target import Target, TargetStatus
from .context import ScanContext, ScanPhase, ContextStatus
from .result import ScanResult, Vulnerability, Severity, VulnType
from .storage import SessionStorage

logger = logging.getLogger(__name__)


class SessionManager:
    """
    会话管理器

    线程安全的单例模式，管理所有扫描会话的生命周期。

    Features:
        - 线程安全的单例模式
        - 会话创建、获取、更新、删除
        - 自动过期清理
        - 持久化支持
    """

    _instance: Optional['SessionManager'] = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs) -> 'SessionManager':
        """单例模式实现"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, storage_dir: Optional[str] = None, auto_save: bool = True):
        """
        初始化会话管理器

        Args:
            storage_dir: 存储目录路径
            auto_save: 是否自动保存会话
        """
        # 防止重复初始化
        if self._initialized:
            return

        self._sessions: Dict[str, ScanContext] = {}
        self._results: Dict[str, ScanResult] = {}
        self._session_lock = threading.RLock()  # 可重入锁

        # 存储
        self._storage = SessionStorage(storage_dir) if storage_dir else SessionStorage()
        self._auto_save = auto_save

        # 事件回调
        self._callbacks: Dict[str, List[Callable]] = {
            'session_created': [],
            'session_updated': [],
            'session_completed': [],
            'session_deleted': [],
            'vulnerability_found': [],
        }

        self._initialized = True
        logger.info("会话管理器初始化完成")

    def create_session(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None
    ) -> ScanContext:
        """
        创建新会话

        Args:
            target: 目标字符串
            config: 扫描配置
            session_id: 指定的会话ID（可选）

        Returns:
            ScanContext: 新创建的会话上下文
        """
        with self._session_lock:
            # 生成或验证会话ID
            if session_id is None:
                session_id = str(uuid.uuid4())
            elif session_id in self._sessions:
                raise ValueError(f"会话ID已存在: {session_id}")

            # 解析目标
            target_obj = Target.parse(target)

            # 创建上下文
            context = ScanContext(
                session_id=session_id,
                target=target_obj,
                config=config or {},
                started_at=datetime.now(),
            )

            self._sessions[session_id] = context

            logger.info(f"创建会话: {session_id} -> {target}")

            # 触发回调
            self._trigger_callback('session_created', context)

            # 自动保存
            if self._auto_save:
                self._storage.save_context(context)

            return context

    def get_session(self, session_id: str) -> Optional[ScanContext]:
        """
        获取会话

        Args:
            session_id: 会话ID

        Returns:
            ScanContext: 会话上下文，不存在返回None
        """
        with self._session_lock:
            context = self._sessions.get(session_id)

            # 如果内存中没有，尝试从存储加载
            if context is None:
                context = self._storage.load_context(session_id)
                if context:
                    self._sessions[session_id] = context

            return context

    def update_session(self, session_id: str, **kwargs) -> bool:
        """
        更新会话

        Args:
            session_id: 会话ID
            **kwargs: 要更新的字段

        Returns:
            bool: 是否成功更新
        """
        with self._session_lock:
            context = self._sessions.get(session_id)
            if not context:
                logger.warning(f"会话不存在: {session_id}")
                return False

            # 更新字段
            for key, value in kwargs.items():
                if hasattr(context, key):
                    setattr(context, key, value)
                else:
                    # 存入metadata
                    context.metadata[key] = value

            # 触发回调
            self._trigger_callback('session_updated', context)

            # 自动保存
            if self._auto_save:
                self._storage.save_context(context)

            return True

    def add_vulnerability(
        self,
        session_id: str,
        vuln_type: VulnType,
        severity: Severity,
        title: str,
        url: str,
        **kwargs
    ) -> bool:
        """
        向会话添加漏洞

        Args:
            session_id: 会话ID
            vuln_type: 漏洞类型
            severity: 严重程度
            title: 漏洞标题
            url: 漏洞URL
            **kwargs: 其他漏洞属性

        Returns:
            bool: 是否成功添加
        """
        with self._session_lock:
            context = self._sessions.get(session_id)
            if not context:
                return False

            vuln = Vulnerability(
                type=vuln_type,
                severity=severity,
                title=title,
                url=url,
                **kwargs
            )

            context.add_vulnerability(vuln)

            # 触发回调
            self._trigger_callback('vulnerability_found', context, vuln)

            # 自动保存
            if self._auto_save:
                self._storage.save_context(context)

            return True

    def complete_session(self, session_id: str) -> Optional[ScanResult]:
        """
        完成会话并生成结果

        Args:
            session_id: 会话ID

        Returns:
            ScanResult: 扫描结果，失败返回None
        """
        with self._session_lock:
            context = self._sessions.get(session_id)
            if not context:
                logger.warning(f"会话不存在: {session_id}")
                return None

            # 更新状态
            context.set_status(ContextStatus.COMPLETED)
            context.set_phase(ScanPhase.COMPLETED)

            # 生成结果
            result = context.to_scan_result()
            result.complete()

            self._results[session_id] = result

            logger.info(f"会话完成: {session_id}, 发现 {result.total_vulns} 个漏洞")

            # 触发回调
            self._trigger_callback('session_completed', context, result)

            # 保存
            if self._auto_save:
                self._storage.save_context(context)
                self._storage.save_result(result)

            return result

    def fail_session(self, session_id: str, error: str = None) -> Optional[ScanResult]:
        """
        标记会话失败

        Args:
            session_id: 会话ID
            error: 错误信息

        Returns:
            ScanResult: 扫描结果
        """
        with self._session_lock:
            context = self._sessions.get(session_id)
            if not context:
                return None

            # 更新状态
            context.set_status(ContextStatus.FAILED)
            context.set_phase(ScanPhase.FAILED)
            if error:
                context.log('error', error)

            # 生成结果
            result = context.to_scan_result()
            result.fail(error)

            self._results[session_id] = result

            # 保存
            if self._auto_save:
                self._storage.save_context(context)
                self._storage.save_result(result)

            return result

    def get_result(self, session_id: str) -> Optional[ScanResult]:
        """
        获取扫描结果

        Args:
            session_id: 会话ID

        Returns:
            ScanResult: 扫描结果
        """
        with self._session_lock:
            result = self._results.get(session_id)

            # 如果内存中没有，尝试从存储加载
            if result is None:
                result = self._storage.load_result(session_id)
                if result:
                    self._results[session_id] = result

            return result

    def list_sessions(
        self,
        status: Optional[str] = None,
        phase: Optional[str] = None,
        limit: int = 100
    ) -> List[ScanContext]:
        """
        列出会话

        Args:
            status: 按状态过滤
            phase: 按阶段过滤
            limit: 最大返回数量

        Returns:
            List[ScanContext]: 会话列表
        """
        with self._session_lock:
            sessions = list(self._sessions.values())

            # 过滤
            if status:
                try:
                    status_enum = ContextStatus(status)
                    sessions = [s for s in sessions if s.status == status_enum]
                except ValueError:
                    pass

            if phase:
                try:
                    phase_enum = ScanPhase(phase)
                    sessions = [s for s in sessions if s.phase == phase_enum]
                except ValueError:
                    pass

            # 按开始时间排序
            sessions.sort(key=lambda x: x.started_at, reverse=True)

            return sessions[:limit]

    def list_active_sessions(self) -> List[ScanContext]:
        """
        列出活动会话

        Returns:
            List[ScanContext]: 活动会话列表
        """
        return self.list_sessions(status='active')

    def delete_session(self, session_id: str, delete_storage: bool = True) -> bool:
        """
        删除会话

        Args:
            session_id: 会话ID
            delete_storage: 是否同时删除存储的文件

        Returns:
            bool: 是否成功删除
        """
        with self._session_lock:
            deleted = False

            # 从内存删除
            if session_id in self._sessions:
                context = self._sessions.pop(session_id)
                self._trigger_callback('session_deleted', context)
                deleted = True

            if session_id in self._results:
                self._results.pop(session_id)
                deleted = True

            # 从存储删除
            if delete_storage:
                storage_deleted = self._storage.delete_session(session_id)
                deleted = deleted or storage_deleted

            if deleted:
                logger.info(f"会话已删除: {session_id}")

            return deleted

    def cleanup_expired(self, max_age: int = 3600) -> int:
        """
        清理过期会话

        Args:
            max_age: 最大存活时间（秒）

        Returns:
            int: 清理的会话数
        """
        with self._session_lock:
            now = datetime.now()
            expired_ids = []

            for session_id, context in self._sessions.items():
                # 已完成或失败的会话才检查过期
                if context.status in (ContextStatus.COMPLETED, ContextStatus.FAILED):
                    if context.ended_at:
                        age = (now - context.ended_at).total_seconds()
                        if age > max_age:
                            expired_ids.append(session_id)

            # 删除过期会话
            for session_id in expired_ids:
                self.delete_session(session_id, delete_storage=False)

            if expired_ids:
                logger.info(f"清理了 {len(expired_ids)} 个过期会话")

            return len(expired_ids)

    def get_active_count(self) -> int:
        """
        获取活动会话数量

        Returns:
            int: 活动会话数
        """
        with self._session_lock:
            return sum(
                1 for ctx in self._sessions.values()
                if ctx.status == ContextStatus.ACTIVE
            )

    def get_stats(self) -> Dict[str, Any]:
        """
        获取统计信息

        Returns:
            Dict: 统计字典
        """
        with self._session_lock:
            status_counts = {}
            phase_counts = {}
            total_vulns = 0

            for ctx in self._sessions.values():
                # 状态统计
                status_key = ctx.status.value
                status_counts[status_key] = status_counts.get(status_key, 0) + 1

                # 阶段统计
                phase_key = ctx.phase.value
                phase_counts[phase_key] = phase_counts.get(phase_key, 0) + 1

                # 漏洞统计
                total_vulns += len(ctx.vulnerabilities)

            return {
                'total_sessions': len(self._sessions),
                'total_results': len(self._results),
                'total_vulnerabilities': total_vulns,
                'by_status': status_counts,
                'by_phase': phase_counts,
                'storage': self._storage.get_storage_stats(),
            }

    # ========== 事件回调 ==========

    def on(self, event: str, callback: Callable) -> None:
        """
        注册事件回调

        Args:
            event: 事件名称
            callback: 回调函数
        """
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def off(self, event: str, callback: Callable) -> None:
        """
        移除事件回调

        Args:
            event: 事件名称
            callback: 回调函数
        """
        if event in self._callbacks and callback in self._callbacks[event]:
            self._callbacks[event].remove(callback)

    def _trigger_callback(self, event: str, *args) -> None:
        """触发事件回调"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args)
            except Exception as e:
                logger.error(f"回调执行失败 [{event}]: {e}")

    # ========== 持久化操作 ==========

    def save_session(self, session_id: str) -> bool:
        """
        手动保存会话

        Args:
            session_id: 会话ID

        Returns:
            bool: 是否成功保存
        """
        with self._session_lock:
            context = self._sessions.get(session_id)
            if not context:
                return False

            try:
                self._storage.save_context(context)

                # 如果有结果也保存
                result = self._results.get(session_id)
                if result:
                    self._storage.save_result(result)

                return True

            except Exception as e:
                logger.error(f"保存会话失败: {e}")
                return False

    def load_session(self, session_id: str) -> Optional[ScanContext]:
        """
        从存储加载会话

        Args:
            session_id: 会话ID

        Returns:
            ScanContext: 会话上下文
        """
        with self._session_lock:
            context = self._storage.load_context(session_id)
            if context:
                self._sessions[session_id] = context

                # 尝试加载结果
                result = self._storage.load_result(session_id)
                if result:
                    self._results[session_id] = result

            return context

    def load_all_sessions(self) -> int:
        """
        从存储加载所有会话

        Returns:
            int: 加载的会话数
        """
        with self._session_lock:
            loaded = 0
            for session_info in self._storage.list_sessions():
                session_id = session_info['session_id']
                if session_id not in self._sessions:
                    context = self._storage.load_context(session_id)
                    if context:
                        self._sessions[session_id] = context
                        loaded += 1

                        # 加载结果
                        result = self._storage.load_result(session_id)
                        if result:
                            self._results[session_id] = result

            logger.info(f"从存储加载了 {loaded} 个会话")
            return loaded


# 全局单例获取函数
_session_manager: Optional[SessionManager] = None
_manager_lock = threading.Lock()


def get_session_manager(
    storage_dir: Optional[str] = None,
    auto_save: bool = True
) -> SessionManager:
    """
    获取会话管理器单例

    Args:
        storage_dir: 存储目录
        auto_save: 是否自动保存

    Returns:
        SessionManager: 会话管理器实例
    """
    global _session_manager
    with _manager_lock:
        if _session_manager is None:
            _session_manager = SessionManager(storage_dir, auto_save)
        return _session_manager


def reset_session_manager() -> None:
    """
    重置会话管理器（仅用于测试）
    """
    global _session_manager
    with _manager_lock:
        if _session_manager is not None:
            # 清理内部状态
            with _session_manager._session_lock:
                _session_manager._sessions.clear()
                _session_manager._results.clear()
            _session_manager._initialized = False
            SessionManager._instance = None
            _session_manager = None
