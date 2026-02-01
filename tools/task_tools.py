"""
任务队列工具模块

包含工具:
- task_submit: 提交后台任务
- task_status: 查询任务状态
- task_cancel: 取消任务
- task_list: 列出所有任务
"""


def register_task_tools(mcp):
    """注册任务队列工具到MCP服务器"""

    # 延迟导入工具函数避免循环依赖
    # 这些函数将在 task_submit 中动态获取

    @mcp.tool()
    def task_submit(tool_name: str, target: str, kwargs: str = "{}") -> dict:
        """提交后台任务 - 异步执行耗时扫描

        Args:
            tool_name: 要执行的工具名称 (如 auto_pentest, full_recon, port_scan)
            target: 目标URL或IP
            kwargs: 工具的其他参数 (JSON格式)

        Returns:
            task_id: 任务ID，用于查询状态
        """
        import json

        from utils.task_queue import get_task_queue

        # 延迟导入需要的工具函数
        # 注意: 这些函数在 mcp_stdio_server.py 中定义，此处需要从主模块获取
        # 在实际使用时，需要确保这些函数已经被注册
        try:
            # 从当前注册的工具中获取函数
            from tools.recon_tools import (
                _dir_bruteforce_impl,
                _full_recon_impl,
                _port_scan_impl,
                _sensitive_scan_impl,
                _subdomain_bruteforce_impl,
            )
            from tools.vuln_tools import _sqli_detect_impl, _vuln_check_impl, _xss_detect_impl
        except ImportError:
            # 如果模块拆分未完成，尝试从原始位置导入
            pass

        # 工具映射表 - 使用延迟绑定
        tool_map = {}

        # 尝试获取工具实现
        try:
            from tools.recon_tools import _port_scan_impl

            tool_map["port_scan"] = _port_scan_impl
        except (ImportError, AttributeError):
            pass

        try:
            from tools.recon_tools import _full_recon_impl

            tool_map["full_recon"] = _full_recon_impl
        except (ImportError, AttributeError):
            pass

        try:
            from tools.recon_tools import _subdomain_bruteforce_impl

            tool_map["subdomain_bruteforce"] = _subdomain_bruteforce_impl
        except (ImportError, AttributeError):
            pass

        try:
            from tools.recon_tools import _dir_bruteforce_impl

            tool_map["dir_bruteforce"] = _dir_bruteforce_impl
        except (ImportError, AttributeError):
            pass

        try:
            from tools.recon_tools import _sensitive_scan_impl

            tool_map["sensitive_scan"] = _sensitive_scan_impl
        except (ImportError, AttributeError):
            pass

        try:
            from tools.vuln_tools import _vuln_check_impl

            tool_map["vuln_check"] = _vuln_check_impl
        except (ImportError, AttributeError):
            pass

        try:
            from tools.vuln_tools import _sqli_detect_impl

            tool_map["sqli_detect"] = _sqli_detect_impl
        except (ImportError, AttributeError):
            pass

        try:
            from tools.vuln_tools import _xss_detect_impl

            tool_map["xss_detect"] = _xss_detect_impl
        except (ImportError, AttributeError):
            pass

        if tool_name not in tool_map:
            return {
                "success": False,
                "error": f"不支持的工具: {tool_name}",
                "available": list(tool_map.keys()),
            }

        # 解析额外参数
        try:
            extra_kwargs = json.loads(kwargs) if kwargs else {}
        except json.JSONDecodeError:
            extra_kwargs = {}

        tq = get_task_queue()
        task_id = tq.submit(tool_map[tool_name], target, **extra_kwargs)

        return {
            "success": True,
            "task_id": task_id,
            "tool": tool_name,
            "target": target,
            "message": f"任务已提交，使用 task_status('{task_id}') 查询状态",
        }

    @mcp.tool()
    def task_status(task_id: str) -> dict:
        """查询任务状态

        Args:
            task_id: 任务ID

        Returns:
            任务状态和结果
        """
        from utils.task_queue import get_task_queue

        return get_task_queue().get_status(task_id)

    @mcp.tool()
    def task_cancel(task_id: str) -> dict:
        """取消任务 (仅限等待中的任务)

        Args:
            task_id: 任务ID

        Returns:
            操作结果
        """
        from utils.task_queue import get_task_queue

        return get_task_queue().cancel(task_id)

    @mcp.tool()
    def task_list(limit: int = 20) -> dict:
        """列出所有任务

        Args:
            limit: 返回数量限制 (默认20)

        Returns:
            任务列表和统计信息
        """
        from utils.task_queue import get_task_queue

        return get_task_queue().list_tasks(limit)

    return ["task_submit", "task_status", "task_cancel", "task_list"]
