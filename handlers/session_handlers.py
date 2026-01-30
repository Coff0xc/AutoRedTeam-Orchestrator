"""
会话管理工具处理器
包含: session_create, session_status, session_list, session_complete
"""

from typing import Any, Dict
from .tooling import tool
from .error_handling import (
    handle_errors,
    ErrorCategory,
    extract_target,
    validate_inputs,
)


def register_session_tools(mcp, counter, logger):
    """注册会话管理工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @validate_inputs(target='target')
    @handle_errors(logger, category=ErrorCategory.SESSION, context_extractor=extract_target)
    async def session_create(target: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """创建扫描会话 - 创建新的渗透测试会话

        Args:
            target: 目标URL或IP
            config: 会话配置

        Returns:
            会话信息
        """
        from core.session import get_session_manager

        manager = get_session_manager()
        context = manager.create_session(target, config)

        return {
            'success': True,
            'session_id': context.session_id,
            'target': target,
            'status': context.status.value,
            'created_at': context.started_at.isoformat()
        }

    @tool(mcp)
    @validate_inputs(session_id='session_id')
    @handle_errors(logger, category=ErrorCategory.SESSION)
    async def session_status(session_id: str) -> Dict[str, Any]:
        """查询会话状态 - 获取会话的当前状态

        Args:
            session_id: 会话ID

        Returns:
            会话状态
        """
        from core.session import get_session_manager

        manager = get_session_manager()
        context = manager.get_session(session_id)

        if not context:
            return {'success': False, 'error': f'会话不存在: {session_id}'}

        return {
            'success': True,
            'session_id': session_id,
            'target': context.target.url,
            'status': context.status.value,
            'phase': context.phase.value,
            'vulns_found': len(context.vulnerabilities)
        }

    @tool(mcp)
    @handle_errors(logger, category=ErrorCategory.SESSION)
    async def session_list(status: str = None, limit: int = 20) -> Dict[str, Any]:
        """列出会话 - 获取会话列表

        Args:
            status: 按状态过滤 (active, completed, failed)
            limit: 最大返回数量

        Returns:
            会话列表
        """
        from core.session import get_session_manager

        manager = get_session_manager()
        sessions = manager.list_sessions(status=status, limit=limit)

        return {
            'success': True,
            'sessions': [
                {
                    'session_id': s.session_id,
                    'target': s.target.url,
                    'status': s.status.value,
                    'phase': s.phase.value
                }
                for s in sessions
            ],
            'count': len(sessions)
        }

    @tool(mcp)
    @validate_inputs(session_id='session_id')
    @handle_errors(logger, category=ErrorCategory.SESSION)
    async def session_complete(session_id: str) -> Dict[str, Any]:
        """完成会话 - 结束会话并生成报告

        Args:
            session_id: 会话ID

        Returns:
            扫描结果摘要
        """
        from core.session import get_session_manager

        manager = get_session_manager()
        result = manager.complete_session(session_id)

        if not result:
            return {'success': False, 'error': f'会话不存在: {session_id}'}

        return {
            'success': True,
            'session_id': session_id,
            'total_vulns': result.total_vulns,
            'critical': result.critical_count,
            'high': result.high_count,
            'medium': result.medium_count,
            'low': result.low_count,
            'duration': result.duration
        }

    counter.add('session', 4)
    logger.info("[Session] 已注册 4 个会话管理工具")
