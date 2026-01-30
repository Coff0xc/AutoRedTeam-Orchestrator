"""
横向移动工具处理器
包含: lateral_ssh, lateral_wmi, lateral_winrm, lateral_psexec,
      lateral_auto, credential_spray

授权级别:
- CRITICAL: 所有横向移动工具

重构说明 (2026-01):
    - 修复与core/lateral模块的接口不匹配问题
    - 使用便捷函数而非类实例化
    - 添加资源清理保护
"""

from typing import Any, Dict, List
from .tooling import tool
from .error_handling import (
    handle_errors,
    ErrorCategory,
    extract_target,
    validate_inputs,
)

# 授权中间件
from core.security import require_critical_auth


def register_lateral_tools(mcp, counter, logger):
    """注册横向移动工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    # ==================== SSH横向移动 ====================

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_ssh(
        target: str,
        username: str,
        password: str = None,
        key_file: str = None,
        command: str = "whoami",
        port: int = 22
    ) -> Dict[str, Any]:
        """SSH横向移动 - 通过SSH执行远程命令

        支持: 密码认证、私钥文件认证
        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP或主机名
            username: 用户名
            password: 密码 (与key_file二选一)
            key_file: SSH私钥文件路径
            command: 要执行的命令
            port: SSH端口 (默认22)

        Returns:
            执行结果
        """
        from core.lateral import ssh_exec

        # 直接调用便捷函数，返回值已是正确格式
        result = ssh_exec(
            target=target,
            username=username,
            password=password or '',
            key_file=key_file or '',
            command=command,
            port=port
        )

        # ssh_exec 返回 dict，直接返回
        if isinstance(result, dict):
            return result

        # 兼容返回对象的情况
        return {
            'success': result.success,
            'target': target,
            'command': command,
            'output': result.output,
            'exit_code': getattr(result, 'exit_code', None),
            'error': getattr(result, 'error', None)
        }

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_ssh_tunnel(
        target: str,
        username: str,
        password: str = None,
        local_port: int = 8080,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        port: int = 22
    ) -> Dict[str, Any]:
        """SSH隧道 - 创建SSH端口转发隧道

        警告: 仅限授权渗透测试使用！

        Args:
            target: SSH服务器地址
            username: 用户名
            password: 密码
            local_port: 本地监听端口
            remote_host: 远程目标主机
            remote_port: 远程目标端口
            port: SSH端口

        Returns:
            隧道信息
        """
        from core.lateral import ssh_tunnel

        result = ssh_tunnel(
            target=target,
            username=username,
            password=password or '',
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            port=port
        )

        if isinstance(result, dict):
            return {
                'success': result.get('success', False),
                'target': target,
                'tunnel': {
                    'local_port': local_port,
                    'remote_host': remote_host,
                    'remote_port': remote_port
                },
                'local_bind': result.get('local_bind'),
                'error': result.get('error')
            }

        return {
            'success': result.success,
            'target': target,
            'tunnel': {
                'local_port': local_port,
                'remote_host': remote_host,
                'remote_port': remote_port
            },
            'error': getattr(result, 'error', None)
        }

    # ==================== WMI横向移动 ====================

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_wmi(
        target: str,
        username: str,
        password: str = None,
        command: str = "whoami",
        domain: str = ""
    ) -> Dict[str, Any]:
        """WMI横向移动 - 通过WMI执行远程命令

        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP
            username: 用户名
            password: 密码
            command: 要执行的命令
            domain: 域名 (可选)

        Returns:
            执行结果
        """
        from core.lateral import wmi_exec

        result = wmi_exec(
            target=target,
            username=username,
            password=password or '',
            command=command,
            domain=domain
        )

        if isinstance(result, dict):
            return result

        return {
            'success': result.success,
            'target': target,
            'command': command,
            'output': result.output,
            'error': getattr(result, 'error', None)
        }

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_wmi_query(
        target: str,
        username: str,
        password: str = None,
        query: str = "SELECT * FROM Win32_OperatingSystem",
        domain: str = ""
    ) -> Dict[str, Any]:
        """WMI查询 - 执行WQL查询获取系统信息

        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP
            username: 用户名
            password: 密码
            query: WQL查询语句
            domain: 域名

        Returns:
            查询结果
        """
        from core.lateral import wmi_query

        result = wmi_query(
            target=target,
            username=username,
            password=password or '',
            wql=query,
            domain=domain
        )

        if isinstance(result, dict):
            return {
                'success': result.get('success', False),
                'target': target,
                'query': query,
                'results': result.get('data', []),
                'error': result.get('error')
            }

        return {
            'success': result.success,
            'target': target,
            'query': query,
            'results': getattr(result, 'data', []),
            'error': getattr(result, 'error', None)
        }

    # ==================== WinRM横向移动 ====================

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_winrm(
        target: str,
        username: str,
        password: str,
        command: str = "whoami",
        domain: str = "",
        use_ssl: bool = True
    ) -> Dict[str, Any]:
        """WinRM横向移动 - 通过WinRM执行远程命令

        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP或主机名
            username: 用户名
            password: 密码
            command: 要执行的命令
            domain: 域名
            use_ssl: 是否使用SSL (HTTPS)

        Returns:
            执行结果
        """
        from core.lateral import winrm_exec

        result = winrm_exec(
            target=target,
            username=username,
            password=password,
            command=command,
            domain=domain,
            use_ssl=use_ssl
        )

        if isinstance(result, dict):
            return result

        return {
            'success': result.success,
            'target': target,
            'command': command,
            'output': result.output,
            'exit_code': getattr(result, 'exit_code', None),
            'error': getattr(result, 'error', None)
        }

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_winrm_ps(
        target: str,
        username: str,
        password: str,
        script: str,
        domain: str = "",
        use_ssl: bool = True
    ) -> Dict[str, Any]:
        """WinRM PowerShell - 通过WinRM执行PowerShell脚本

        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP或主机名
            username: 用户名
            password: 密码
            script: PowerShell脚本内容
            domain: 域名
            use_ssl: 是否使用SSL

        Returns:
            执行结果
        """
        from core.lateral import winrm_ps

        result = winrm_ps(
            target=target,
            username=username,
            password=password,
            script=script,
            domain=domain,
            use_ssl=use_ssl
        )

        if isinstance(result, dict):
            return result

        return {
            'success': result.success,
            'target': target,
            'output': result.output,
            'error': getattr(result, 'error', None)
        }

    # ==================== PsExec横向移动 ====================

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_psexec(
        target: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        command: str = "whoami",
        domain: str = ""
    ) -> Dict[str, Any]:
        """PsExec横向移动 - 通过PsExec执行远程命令

        支持: 密码认证、Pass-the-Hash
        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP
            username: 用户名
            password: 密码 (与ntlm_hash二选一)
            ntlm_hash: NTLM Hash
            command: 要执行的命令
            domain: 域名

        Returns:
            执行结果
        """
        from core.lateral import psexec

        result = psexec(
            target=target,
            username=username,
            password=password or '',
            ntlm_hash=ntlm_hash or '',
            command=command,
            domain=domain
        )

        if isinstance(result, dict):
            return result

        return {
            'success': result.success,
            'target': target,
            'command': command,
            'output': result.output,
            'error': getattr(result, 'error', None)
        }

    # ==================== 自动化横向移动 ====================

    @tool(mcp)
    @require_critical_auth
    @validate_inputs(target='target')
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_auto(
        target: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        command: str = "whoami",
        domain: str = ""
    ) -> Dict[str, Any]:
        """自动横向移动 - 自动选择最佳横向移动方法

        自动探测可用协议并选择最优方案
        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP
            username: 用户名
            password: 密码
            ntlm_hash: NTLM Hash
            command: 要执行的命令
            domain: 域名

        Returns:
            执行结果
        """
        from core.lateral import auto_lateral, Credentials

        creds = Credentials(
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain
        )

        lateral = auto_lateral(target, creds)

        if not lateral:
            return {
                'success': False,
                'target': target,
                'error': '无法找到可用的横向移动方法'
            }

        try:
            result = lateral.execute(command)
            method_used = type(lateral).__name__
            return {
                'success': result.success,
                'target': target,
                'method': method_used,
                'command': command,
                'output': result.output,
                'error': getattr(result, 'error', None)
            }
        finally:
            # 确保资源清理
            lateral.disconnect()

    @tool(mcp)
    @require_critical_auth
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def credential_spray(
        targets: List[str],
        usernames: List[str],
        passwords: List[str],
        protocol: str = "smb",
        domain: str = ""
    ) -> Dict[str, Any]:
        """凭证喷洒 - 对多个目标进行凭证测试

        警告: 仅限授权渗透测试使用！

        Args:
            targets: 目标列表
            usernames: 用户名列表
            passwords: 密码列表
            protocol: 协议 (smb, ssh, winrm)
            domain: 域名

        Returns:
            有效凭证列表
        """
        from core.lateral import spray_credentials, Credentials

        # 构建凭证列表 - 用户名和密码的笛卡尔积
        credentials_list = [
            Credentials(username=u, password=p, domain=domain)
            for u in usernames for p in passwords
        ]

        # methods 是协议列表
        methods = [protocol] if protocol else None

        results = spray_credentials(
            targets=targets,
            credentials_list=credentials_list,
            methods=methods
        )

        # spray_credentials 返回 Dict[str, Dict[str, Any]]
        # 格式: {target: {'credentials': creds, 'method': method}}
        if isinstance(results, dict):
            valid_creds = []
            for target, info in results.items():
                if info and info.get('credentials'):
                    creds = info['credentials']
                    valid_creds.append({
                        'target': target,
                        'username': creds.username if hasattr(creds, 'username') else str(creds),
                        'method': info.get('method', protocol)
                    })

            return {
                'success': len(valid_creds) > 0,
                'total_attempts': len(targets) * len(credentials_list),
                'valid_credentials': valid_creds,
                'valid_count': len(valid_creds)
            }

        # 兼容列表返回
        valid_creds = [r for r in results if getattr(r, 'success', False)]

        return {
            'success': len(valid_creds) > 0,
            'total_attempts': len(results),
            'valid_credentials': [
                {
                    'target': getattr(r, 'target', ''),
                    'username': getattr(r, 'username', ''),
                }
                for r in valid_creds
            ],
            'valid_count': len(valid_creds)
        }

    counter.add('lateral', 9)
    logger.info("[Lateral] 已注册 9 个横向移动工具")
