#!/usr/bin/env python3
"""
test_core_session_manager.py - 会话管理器单元测试

测试覆盖:
- SessionManager 单例模式
- 会话创建、获取、更新、删除
- 线程安全
- 事件回调
- 持久化存储
"""

import pytest
import threading
import time
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any
from pathlib import Path

# 导入被测试的模块
from core.session.manager import SessionManager
from core.session.context import ScanContext, ScanPhase, ContextStatus
from core.session.target import Target, TargetStatus
from core.session.result import ScanResult, Vulnerability, Severity, VulnType


# ============== 测试夹具 ==============

@pytest.fixture
def temp_storage_dir():
    """临时存储目录"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def clean_manager():
    """清理单例实例"""
    # 重置单例
    SessionManager._instance = None
    yield
    # 测试后清理
    SessionManager._instance = None


# ============== SessionManager 单例测试 ==============

class TestSessionManagerSingleton:
    """SessionManager 单例模式测试"""

    def test_singleton_same_instance(self, clean_manager):
        """测试单例返回相同实例"""
        manager1 = SessionManager()
        manager2 = SessionManager()

        assert manager1 is manager2

    def test_singleton_thread_safe(self, clean_manager):
        """测试单例的线程安全性"""
        instances = []

        def create_manager():
            manager = SessionManager()
            instances.append(manager)

        threads = [threading.Thread(target=create_manager) for _ in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 所有实例应该是同一个对象
        assert len(set(id(inst) for inst in instances)) == 1

    def test_singleton_initialization_once(self, clean_manager):
        """测试单例只初始化一次"""
        manager1 = SessionManager()
        initial_sessions = len(manager1._sessions)

        manager2 = SessionManager()
        # 第二次获取不应该重新初始化
        assert len(manager2._sessions) == initial_sessions


# ============== 会话创建测试 ==============

class TestSessionCreation:
    """会话创建测试"""

    def test_create_session_basic(self, clean_manager):
        """测试基本会话创建"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')

        assert context is not None
        assert context.target.url == 'https://example.com'
        assert context.status == ContextStatus.CREATED
        assert context.session_id is not None

    def test_create_session_with_config(self, clean_manager):
        """测试带配置的会话创建"""
        manager = SessionManager()
        config = {
            'timeout': 60,
            'max_threads': 10,
        }
        context = manager.create_session('https://example.com', config=config)

        assert context.config['timeout'] == 60
        assert context.config['max_threads'] == 10

    def test_create_session_with_custom_id(self, clean_manager):
        """测试使用自定义会话ID"""
        manager = SessionManager()
        custom_id = 'test-session-123'
        context = manager.create_session('https://example.com', session_id=custom_id)

        assert context.session_id == custom_id

    def test_create_session_duplicate_id(self, clean_manager):
        """测试重复的会话ID"""
        manager = SessionManager()
        session_id = 'duplicate-id'

        # 第一次创建成功
        context1 = manager.create_session('https://example.com', session_id=session_id)
        assert context1.session_id == session_id

        # 第二次创建应该失败或返回新ID
        context2 = manager.create_session('https://example.com', session_id=session_id)
        # 根据实现，可能抛出异常或生成新ID
        assert context2 is not None

    def test_create_multiple_sessions(self, clean_manager):
        """测试创建多个会话"""
        manager = SessionManager()

        contexts = [
            manager.create_session('https://example1.com'),
            manager.create_session('https://example2.com'),
            manager.create_session('https://example3.com'),
        ]

        assert len(contexts) == 3
        # 所有会话ID应该不同
        session_ids = [ctx.session_id for ctx in contexts]
        assert len(set(session_ids)) == 3


# ============== 会话获取测试 ==============

class TestSessionRetrieval:
    """会话获取测试"""

    def test_get_session_exists(self, clean_manager):
        """测试获取存在的会话"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')
        session_id = context.session_id

        retrieved = manager.get_session(session_id)

        assert retrieved is not None
        assert retrieved.session_id == session_id
        assert retrieved is context

    def test_get_session_not_exists(self, clean_manager):
        """测试获取不存在的会话"""
        manager = SessionManager()
        retrieved = manager.get_session('nonexistent-id')

        assert retrieved is None

    def test_list_sessions(self, clean_manager):
        """测试列出所有会话"""
        manager = SessionManager()

        # 创建多个会话
        manager.create_session('https://example1.com')
        manager.create_session('https://example2.com')
        manager.create_session('https://example3.com')

        sessions = manager.list_sessions()

        assert len(sessions) == 3

    def test_list_sessions_empty(self, clean_manager):
        """测试列出空会话列表"""
        manager = SessionManager()
        sessions = manager.list_sessions()

        assert sessions == []


# ============== 会话更新测试 ==============

class TestSessionUpdate:
    """会话更新测试"""

    def test_update_session_status(self, clean_manager):
        """测试更新会话状态"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')
        session_id = context.session_id

        # 更新状态
        success = manager.update_session(session_id, status=ContextStatus.RUNNING)

        assert success is True
        updated = manager.get_session(session_id)
        assert updated.status == ContextStatus.RUNNING

    def test_update_session_phase(self, clean_manager):
        """测试更新会话阶段"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')
        session_id = context.session_id

        # 更新阶段
        success = manager.update_session(session_id, phase=ScanPhase.RECON)

        assert success is True
        updated = manager.get_session(session_id)
        assert updated.current_phase == ScanPhase.RECON

    def test_update_session_not_exists(self, clean_manager):
        """测试更新不存在的会话"""
        manager = SessionManager()
        success = manager.update_session('nonexistent-id', status=ContextStatus.RUNNING)

        assert success is False

    def test_update_session_multiple_fields(self, clean_manager):
        """测试同时更新多个字段"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')
        session_id = context.session_id

        success = manager.update_session(
            session_id,
            status=ContextStatus.RUNNING,
            phase=ScanPhase.EXPLOIT,
        )

        assert success is True
        updated = manager.get_session(session_id)
        assert updated.status == ContextStatus.RUNNING
        assert updated.current_phase == ScanPhase.EXPLOIT


# ============== 会话删除测试 ==============

class TestSessionDeletion:
    """会话删除测试"""

    def test_delete_session_exists(self, clean_manager):
        """测试删除存在的会话"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')
        session_id = context.session_id

        success = manager.delete_session(session_id)

        assert success is True
        assert manager.get_session(session_id) is None

    def test_delete_session_not_exists(self, clean_manager):
        """测试删除不存在的会话"""
        manager = SessionManager()
        success = manager.delete_session('nonexistent-id')

        assert success is False

    def test_delete_all_sessions(self, clean_manager):
        """测试删除所有会话"""
        manager = SessionManager()

        # 创建多个会话
        manager.create_session('https://example1.com')
        manager.create_session('https://example2.com')
        manager.create_session('https://example3.com')

        count = manager.delete_all_sessions()

        assert count == 3
        assert len(manager.list_sessions()) == 0


# ============== 事件回调测试 ==============

class TestEventCallbacks:
    """事件回调测试"""

    def test_register_callback(self, clean_manager):
        """测试注册回调"""
        manager = SessionManager()
        callback = Mock()

        manager.register_callback('session_created', callback)

        # 创建会话应该触发回调
        context = manager.create_session('https://example.com')

        callback.assert_called_once()

    def test_multiple_callbacks(self, clean_manager):
        """测试多个回调"""
        manager = SessionManager()
        callback1 = Mock()
        callback2 = Mock()

        manager.register_callback('session_created', callback1)
        manager.register_callback('session_created', callback2)

        context = manager.create_session('https://example.com')

        callback1.assert_called_once()
        callback2.assert_called_once()

    def test_unregister_callback(self, clean_manager):
        """测试取消注册回调"""
        manager = SessionManager()
        callback = Mock()

        manager.register_callback('session_created', callback)
        manager.unregister_callback('session_created', callback)

        context = manager.create_session('https://example.com')

        # 回调不应该被调用
        callback.assert_not_called()

    def test_callback_exception_handled(self, clean_manager):
        """测试回调异常处理"""
        manager = SessionManager()

        def bad_callback(context):
            raise RuntimeError('Callback error')

        manager.register_callback('session_created', bad_callback)

        # 不应该因为回调异常而崩溃
        context = manager.create_session('https://example.com')
        assert context is not None


# ============== 持久化存储测试 ==============

class TestPersistence:
    """持久化存储测试"""

    def test_auto_save_enabled(self, clean_manager, temp_storage_dir):
        """测试自动保存"""
        manager = SessionManager(storage_dir=temp_storage_dir, auto_save=True)
        context = manager.create_session('https://example.com')

        # 检查文件是否创建
        session_files = list(Path(temp_storage_dir).glob('*.json'))
        assert len(session_files) > 0

    def test_auto_save_disabled(self, clean_manager, temp_storage_dir):
        """测试禁用自动保存"""
        manager = SessionManager(storage_dir=temp_storage_dir, auto_save=False)
        context = manager.create_session('https://example.com')

        # 不应该自动创建文件
        session_files = list(Path(temp_storage_dir).glob('*.json'))
        assert len(session_files) == 0

    def test_manual_save(self, clean_manager, temp_storage_dir):
        """测试手动保存"""
        manager = SessionManager(storage_dir=temp_storage_dir, auto_save=False)
        context = manager.create_session('https://example.com')

        # 手动保存
        manager.save_session(context.session_id)

        # 检查文件是否创建
        session_files = list(Path(temp_storage_dir).glob('*.json'))
        assert len(session_files) > 0

    def test_load_session(self, clean_manager, temp_storage_dir):
        """测试加载会话"""
        # 创建并保存会话
        manager1 = SessionManager(storage_dir=temp_storage_dir, auto_save=True)
        context = manager1.create_session('https://example.com')
        session_id = context.session_id

        # 重新创建管理器并加载
        SessionManager._instance = None
        manager2 = SessionManager(storage_dir=temp_storage_dir)
        loaded = manager2.load_session(session_id)

        assert loaded is not None
        assert loaded.session_id == session_id


# ============== 线程安全测试 ==============

class TestThreadSafety:
    """线程安全测试"""

    def test_concurrent_session_creation(self, clean_manager):
        """测试并发创建会话"""
        manager = SessionManager()
        contexts = []
        errors = []

        def create_session(index):
            try:
                context = manager.create_session(f'https://example{index}.com')
                contexts.append(context)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_session, args=(i,)) for i in range(20)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 所有会话都应该成功创建
        assert len(contexts) == 20
        assert len(errors) == 0

        # 所有会话ID应该不同
        session_ids = [ctx.session_id for ctx in contexts]
        assert len(set(session_ids)) == 20

    def test_concurrent_session_update(self, clean_manager):
        """测试并发更新会话"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')
        session_id = context.session_id

        results = []

        def update_session():
            success = manager.update_session(session_id, status=ContextStatus.RUNNING)
            results.append(success)

        threads = [threading.Thread(target=update_session) for _ in range(10)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 所有更新都应该成功
        assert all(results)

    def test_concurrent_read_write(self, clean_manager):
        """测试并发读写"""
        manager = SessionManager()
        context = manager.create_session('https://example.com')
        session_id = context.session_id

        read_results = []
        write_results = []

        def read_session():
            ctx = manager.get_session(session_id)
            read_results.append(ctx is not None)

        def write_session():
            success = manager.update_session(session_id, status=ContextStatus.RUNNING)
            write_results.append(success)

        # 混合读写线程
        threads = []
        for i in range(20):
            if i % 2 == 0:
                threads.append(threading.Thread(target=read_session))
            else:
                threads.append(threading.Thread(target=write_session))

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # 所有操作都应该成功
        assert all(read_results)
        assert all(write_results)


# ============== 边界条件测试 ==============

class TestEdgeCases:
    """边界条件测试"""

    def test_empty_target(self, clean_manager):
        """测试空目标"""
        manager = SessionManager()

        # 空字符串目标
        context = manager.create_session('')
        assert context is not None

    def test_invalid_target(self, clean_manager):
        """测试无效目标"""
        manager = SessionManager()

        # 无效 URL
        context = manager.create_session('not-a-url')
        assert context is not None

    def test_unicode_target(self, clean_manager):
        """测试 Unicode 目标"""
        manager = SessionManager()
        context = manager.create_session('https://例え.jp')

        assert context is not None
        assert '例え.jp' in context.target.url

    def test_very_long_target(self, clean_manager):
        """测试超长目标"""
        manager = SessionManager()
        long_url = 'https://example.com/' + 'a' * 10000
        context = manager.create_session(long_url)

        assert context is not None

    def test_none_config(self, clean_manager):
        """测试 None 配置"""
        manager = SessionManager()
        context = manager.create_session('https://example.com', config=None)

        assert context is not None
        assert context.config is not None


# ============== 集成测试 ==============

class TestIntegration:
    """集成测试"""

    def test_full_session_lifecycle(self, clean_manager):
        """测试完整会话生命周期"""
        manager = SessionManager()

        # 1. 创建会话
        context = manager.create_session('https://example.com')
        session_id = context.session_id
        assert context.status == ContextStatus.CREATED

        # 2. 启动会话
        manager.update_session(session_id, status=ContextStatus.RUNNING)
        assert manager.get_session(session_id).status == ContextStatus.RUNNING

        # 3. 更新阶段
        manager.update_session(session_id, phase=ScanPhase.RECON)
        assert manager.get_session(session_id).current_phase == ScanPhase.RECON

        # 4. 完成会话
        manager.update_session(session_id, status=ContextStatus.COMPLETED)
        assert manager.get_session(session_id).status == ContextStatus.COMPLETED

        # 5. 删除会话
        manager.delete_session(session_id)
        assert manager.get_session(session_id) is None

    def test_multiple_sessions_lifecycle(self, clean_manager):
        """测试多会话生命周期"""
        manager = SessionManager()

        # 创建多个会话
        sessions = []
        for i in range(5):
            context = manager.create_session(f'https://example{i}.com')
            sessions.append(context.session_id)

        # 验证所有会话都存在
        assert len(manager.list_sessions()) == 5

        # 更新部分会话
        for i in range(3):
            manager.update_session(sessions[i], status=ContextStatus.RUNNING)

        # 删除部分会话
        for i in range(2):
            manager.delete_session(sessions[i])

        # 验证剩余会话
        assert len(manager.list_sessions()) == 3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
