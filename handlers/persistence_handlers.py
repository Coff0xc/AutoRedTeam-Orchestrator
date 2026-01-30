"""
持久化工具处理器
包含: persistence_windows, persistence_linux, persistence_webshell

授权级别:
- CRITICAL: 所有持久化工具

重构说明 (2026-01):
    - 修复与core/persistence模块的接口不匹配问题
    - 使用便捷函数而非枚举类型
    - 正确处理返回值类型
"""

from typing import Any, Dict, List
from .tooling import tool
from .error_handling import handle_errors, ErrorCategory

# 授权中间件
from core.security import require_critical_auth


def register_persistence_tools(mcp, counter, logger):
    """注册持久化工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @require_critical_auth
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def persistence_windows(
        method: str = "registry",
        payload: str = None,
        name: str = "WindowsUpdate",
        trigger: str = "logon"
    ) -> Dict[str, Any]:
        """Windows持久化 - 在Windows系统上建立持久化

        支持方法:
        - registry: 注册表自启动
        - task: 计划任务
        - service: Windows服务
        - wmi: WMI事件订阅
        - startup: 启动文件夹

        警告: 仅限授权渗透测试使用！

        Args:
            method: 持久化方法 (registry, task, service, wmi, startup)
            payload: 要执行的Payload (命令或文件路径)
            name: 持久化项名称
            trigger: 触发条件 (logon, startup, daily, hourly) - 仅task方法

        Returns:
            持久化结果
        """
        from core.persistence import windows_persist

        # 方法映射: handler参数 -> core函数参数
        method_map = {
            "registry": "registry",
            "registry_run": "registry",
            "registry_ps": "registry_ps",
            "scheduled_task": "task",
            "task": "task",
            "service": "service",
            "wmi": "wmi",
            "wmi_subscription": "wmi",
            "startup_folder": "startup",
            "startup": "startup",
            "screensaver": "screensaver",
            "bits": "bits",
        }

        core_method = method_map.get(method, method)

        # 调用便捷函数
        kwargs = {}
        if core_method == "task" and trigger:
            kwargs["trigger"] = trigger

        result = windows_persist(
            payload_path=payload,
            method=core_method,
            name=name,
            **kwargs
        )

        # windows_persist 返回 dict，直接使用
        if isinstance(result, dict):
            return {
                'success': result.get('success', False),
                'method': method,
                'name': name,
                'location': result.get('location'),
                'trigger': trigger if core_method == 'task' else None,
                'cleanup_command': result.get('cleanup_command'),
                'error': result.get('error')
            }

        # 兼容返回对象的情况
        return {
            'success': getattr(result, 'success', False),
            'method': method,
            'name': name,
            'location': getattr(result, 'location', None),
            'trigger': trigger if core_method == 'task' else None,
            'cleanup_command': getattr(result, 'cleanup_command', None),
            'error': getattr(result, 'error', None)
        }

    @tool(mcp)
    @require_critical_auth
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def persistence_linux(
        method: str = "crontab",
        payload: str = None,
        name: str = "system-update",
        schedule: str = "*/5 * * * *"
    ) -> Dict[str, Any]:
        """Linux持久化 - 在Linux系统上建立持久化

        支持方法:
        - crontab: 定时任务
        - systemd: Systemd服务
        - bashrc: Shell配置文件
        - ssh_keys: SSH公钥
        - ld_preload: LD_PRELOAD劫持
        - init_d: init.d脚本
        - rc_local: rc.local
        - apt_hook: APT Hook
        - motd: MOTD脚本

        警告: 仅限授权渗透测试使用！

        Args:
            method: 持久化方法
            payload: 要执行的命令或路径
            name: 持久化项名称
            schedule: crontab调度表达式 (仅crontab方法)

        Returns:
            持久化结果
        """
        from core.persistence import linux_persist

        # 方法映射
        method_map = {
            "crontab": "crontab",
            "systemd": "systemd",
            "systemd_service": "systemd",
            "bashrc": "bashrc",
            "profile": "profile",
            "ssh_key": "ssh_keys",
            "ssh_keys": "ssh_keys",
            "ssh_rc": "ssh_rc",
            "ld_preload": "ld_preload",
            "init_d": "init_d",
            "rc_local": "rc_local",
            "apt_hook": "apt_hook",
            "motd": "motd",
        }

        core_method = method_map.get(method, method)

        # 调用便捷函数
        kwargs = {}
        if core_method == "crontab" and schedule:
            kwargs["schedule"] = schedule

        result = linux_persist(
            command=payload,
            method=core_method,
            **kwargs
        )

        # linux_persist 返回 dict
        if isinstance(result, dict):
            return {
                'success': result.get('success', False),
                'method': method,
                'name': name,
                'location': result.get('location'),
                'schedule': schedule if core_method == 'crontab' else None,
                'install_command': result.get('install_command'),
                'cleanup_command': result.get('cleanup_command'),
                'error': result.get('error')
            }

        return {
            'success': getattr(result, 'success', False),
            'method': method,
            'name': name,
            'location': getattr(result, 'location', None),
            'schedule': schedule if core_method == 'crontab' else None,
            'cleanup_command': getattr(result, 'cleanup_command', None),
            'error': getattr(result, 'error', None)
        }

    @tool(mcp)
    @require_critical_auth
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def persistence_webshell(
        shell_type: str = "php",
        password: str = "pass",
        obfuscation: str = "medium",
        features: List[str] = None
    ) -> Dict[str, Any]:
        """Webshell生成 - 生成各类Webshell

        支持类型:
        - php: PHP Webshell
        - jsp: JSP Webshell
        - aspx: ASPX Webshell
        - python: Python Webshell
        - behinder: 冰蝎兼容
        - godzilla: 哥斯拉兼容
        - php_memshell: PHP内存马

        混淆级别:
        - none: 无混淆
        - low: 低度混淆
        - medium: 中度混淆
        - high: 高度混淆

        警告: 仅限授权渗透测试使用！

        Args:
            shell_type: Webshell类型
            password: 连接密码
            obfuscation: 混淆级别 (none, low, medium, high)
            features: 功能列表 (cmd, file, db, proxy) - 部分类型支持

        Returns:
            生成的Webshell代码
        """
        from core.persistence import generate_webshell

        # shell_type 映射
        type_map = {
            "php": "php",
            "jsp": "jsp",
            "aspx": "aspx",
            "python": "python",
            "memory": "php_memshell",
            "php_memshell": "php_memshell",
            "behinder": "behinder",
            "godzilla": "godzilla",
        }

        core_type = type_map.get(shell_type, shell_type)

        # 调用便捷函数 - obfuscation 是字符串，不是枚举
        result = generate_webshell(
            shell_type=core_type,
            password=password,
            obfuscation=obfuscation
        )

        # generate_webshell 返回 dict
        if isinstance(result, dict):
            # 生成文件名
            ext_map = {
                "php": "php", "php_memshell": "php",
                "jsp": "jsp", "aspx": "aspx",
                "python": "py", "behinder": "php", "godzilla": "php"
            }
            ext = ext_map.get(core_type, shell_type)

            return {
                'success': result.get('success', False),
                'type': shell_type,
                'obfuscation': obfuscation,
                'code': result.get('content'),
                'filename': result.get('filename', f"shell.{ext}"),
                'usage': result.get('usage'),
                'features': features or ['cmd', 'file'],
                'error': result.get('error')
            }

        return {
            'success': getattr(result, 'success', False),
            'type': shell_type,
            'obfuscation': obfuscation,
            'code': getattr(result, 'content', None),
            'filename': getattr(result, 'filename', f"shell.{shell_type}"),
            'usage': getattr(result, 'usage', None),
            'features': features or ['cmd', 'file'],
            'error': getattr(result, 'error', None)
        }

    counter.add('persistence', 3)
    logger.info("[Persistence] 已注册 3 个持久化工具")
