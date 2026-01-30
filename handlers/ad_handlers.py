"""
Active Directory攻击工具处理器
包含: ad_enumerate, ad_kerberos_attack, ad_spn_scan

授权级别:
- CRITICAL: 所有AD攻击工具

重构说明 (2026-01):
    - 修复与core/ad模块的接口不匹配问题
    - 使用便捷函数正确签名
    - enum_type是单数字符串，不是列表
    - kerberos_attack的targets参数，不是target_users
"""

from typing import Any, Dict, List
from .tooling import tool
from .error_handling import handle_errors, ErrorCategory

# 授权中间件
from core.security import require_critical_auth


def register_ad_tools(mcp, counter, logger):
    """注册Active Directory攻击工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    @require_critical_auth
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def ad_enumerate(
        domain: str,
        dc_ip: str,
        username: str = None,
        password: str = None,
        enum_type: str = "all"
    ) -> Dict[str, Any]:
        """AD枚举 - 枚举Active Directory对象

        枚举类型:
        - users: 域用户
        - groups: 域组
        - computers: 域计算机
        - spn: SPN服务
        - gpo: 组策略
        - trusts: 域信任关系
        - domain_admins: 域管理员
        - all: 全部

        警告: 仅限授权渗透测试使用！

        Args:
            domain: 域名 (如: corp.local)
            dc_ip: 域控制器IP
            username: 用户名 (可选，匿名绑定)
            password: 密码
            enum_type: 枚举类型 (默认: all)

        Returns:
            枚举结果
        """
        from core.ad import ad_enumerate as _ad_enumerate

        # 调用便捷函数
        result = _ad_enumerate(
            domain=domain,
            dc_ip=dc_ip,
            username=username or '',
            password=password or '',
            enum_type=enum_type,
            verbose=False
        )

        # ad_enumerate 返回 dict
        if isinstance(result, dict):
            # 如果是 all 类型，结果结构不同
            if enum_type == "all":
                return {
                    'success': True,
                    'domain': domain,
                    'dc_ip': dc_ip,
                    'enum_type': enum_type,
                    'results': result,
                    'statistics': {
                        'users': result.get('users', {}).get('count', 0),
                        'groups': result.get('groups', {}).get('count', 0),
                        'computers': result.get('computers', {}).get('count', 0),
                    }
                }
            else:
                return {
                    'success': result.get('success', True),
                    'domain': domain,
                    'dc_ip': dc_ip,
                    'enum_type': enum_type,
                    'count': result.get('count', 0),
                    'objects': result.get('objects', []),
                    'error': result.get('error')
                }

        # 兼容返回对象的情况
        return {
            'success': getattr(result, 'success', False),
            'domain': domain,
            'dc_ip': dc_ip,
            'enum_type': enum_type,
            'error': getattr(result, 'error', None)
        }

    @tool(mcp)
    @require_critical_auth
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def ad_kerberos_attack(
        domain: str,
        dc_ip: str,
        attack_type: str = "asrep",
        username: str = None,
        password: str = None,
        targets: List[str] = None
    ) -> Dict[str, Any]:
        """Kerberos攻击 - 执行Kerberos协议攻击

        攻击类型:
        - asrep: AS-REP Roasting (无需认证，需要目标用户列表)
        - kerberoast: Kerberoasting (需要域用户，需要SPN列表)
        - spray: 密码喷洒 (需要用户列表和密码)
        - enum: 用户枚举 (通过Kerberos错误码)

        警告: 仅限授权渗透测试使用！

        Args:
            domain: 域名
            dc_ip: 域控制器IP
            attack_type: 攻击类型 (asrep, kerberoast, spray, enum)
            username: 用户名 (kerberoast需要认证用户)
            password: 密码 (spray时为测试密码)
            targets: 目标列表 (用户名或SPN，取决于攻击类型)

        Returns:
            攻击结果
        """
        from core.ad import kerberos_attack as _kerberos_attack

        # 攻击类型映射
        attack_map = {
            "asreproast": "asrep",
            "asrep": "asrep",
            "kerberoast": "kerberoast",
            "password_spray": "spray",
            "spray": "spray",
            "enum": "enum",
            "user_enum": "enum",
        }

        core_attack = attack_map.get(attack_type, attack_type)

        # 调用便捷函数
        result = _kerberos_attack(
            domain=domain,
            dc_ip=dc_ip,
            attack_type=core_attack,
            targets=targets or [],
            password=password or '',
            verbose=False
        )

        # kerberos_attack 返回 dict
        if isinstance(result, dict):
            return {
                'success': result.get('success', False),
                'domain': domain,
                'dc_ip': dc_ip,
                'attack_type': attack_type,
                'hashes': result.get('hashes', []),
                'hash_count': result.get('hash_count', len(result.get('hashes', []))),
                'valid_users': result.get('valid_users', []),
                'error': result.get('error')
            }

        return {
            'success': getattr(result, 'success', False),
            'domain': domain,
            'dc_ip': dc_ip,
            'attack_type': attack_type,
            'hashes': getattr(result, 'hashes', []),
            'hash_count': len(getattr(result, 'hashes', [])),
            'error': getattr(result, 'error', None)
        }

    @tool(mcp)
    @require_critical_auth
    @handle_errors(logger, ErrorCategory.REDTEAM)
    async def ad_spn_scan(
        domain: str,
        dc_ip: str,
        username: str,
        password: str = None,
        service_class: str = None
    ) -> Dict[str, Any]:
        """SPN扫描 - 扫描域内SPN服务

        用于发现可Kerberoast的服务账户
        警告: 仅限授权渗透测试使用！

        Args:
            domain: 域名
            dc_ip: 域控制器IP
            username: 用户名
            password: 密码
            service_class: 服务类型过滤 (如: MSSQL, HTTP, LDAP)

        Returns:
            SPN列表
        """
        from core.ad import ADEnumerator

        enumerator = ADEnumerator(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password or ''
        )

        try:
            # 方法是 enum_spn，不是 enum_spns
            result = enumerator.enum_spn()

            # result 是 EnumResult 对象
            spns = []
            kerberoastable = []

            for obj in result.objects:
                spn_data = obj.to_dict()
                spns.append(spn_data)

                # 检查是否可Kerberoast
                attrs = spn_data.get('attributes', {})
                if attrs.get('kerberoastable', False):
                    kerberoastable.append(spn_data)

            # 如果指定了服务类型，过滤结果
            if service_class:
                spns = [
                    s for s in spns
                    if service_class.upper() in s.get('attributes', {}).get('spn', '').upper()
                ]
                kerberoastable = [
                    s for s in kerberoastable
                    if service_class.upper() in s.get('attributes', {}).get('spn', '').upper()
                ]

            # 提取服务类型
            service_classes = set()
            for spn in spns:
                spn_str = spn.get('attributes', {}).get('spn', '')
                if '/' in spn_str:
                    service_classes.add(spn_str.split('/')[0])

            return {
                'success': result.success,
                'domain': domain,
                'total_spns': len(spns),
                'spns': spns,
                'kerberoastable': kerberoastable,
                'kerberoastable_count': len(kerberoastable),
                'service_classes': list(service_classes),
                'error': result.error if hasattr(result, 'error') else None
            }

        finally:
            enumerator.close()

    counter.add('ad', 3)
    logger.info("[AD] 已注册 3 个Active Directory攻击工具")
