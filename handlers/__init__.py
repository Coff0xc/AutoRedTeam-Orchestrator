"""
AutoRedTeam MCP Handlers
模块化的MCP工具处理器

此模块将原 mcp_stdio_server.py 中的工具按功能拆分为独立模块:
- recon_handlers: 侦察工具 (8个)
- detector_handlers: 漏洞检测工具 (12个)
- cve_handlers: CVE相关工具 (5个)
- api_security_handlers: API安全工具 (7个)
- cloud_security_handlers: 云安全工具 (3个)
- supply_chain_handlers: 供应链安全工具 (3个)
- redteam_handlers: 红队工具 (8个)
- orchestration_handlers: 自动化渗透编排工具 (7个)
- session_handlers: 会话管理工具 (4个)
- report_handlers: 报告工具 (2个)
- ai_handlers: AI辅助工具 (3个)
- misc_handlers: 杂项工具 (3个)
"""

from .recon_handlers import register_recon_tools
from .detector_handlers import register_detector_tools
from .cve_handlers import register_cve_tools
from .api_security_handlers import register_api_security_tools
from .cloud_security_handlers import register_cloud_security_tools
from .supply_chain_handlers import register_supply_chain_tools
from .redteam_handlers import register_redteam_tools
from .orchestration_handlers import register_orchestration_tools
from .session_handlers import register_session_tools
from .report_handlers import register_report_tools
from .ai_handlers import register_ai_tools
from .misc_handlers import register_misc_tools

__all__ = [
    'register_recon_tools',
    'register_detector_tools',
    'register_cve_tools',
    'register_api_security_tools',
    'register_cloud_security_tools',
    'register_supply_chain_tools',
    'register_redteam_tools',
    'register_orchestration_tools',
    'register_session_tools',
    'register_report_tools',
    'register_ai_tools',
    'register_misc_tools',
]


def register_all_handlers(mcp, counter, logger):
    """注册所有处理器到MCP服务器

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """
    handlers = [
        ('侦察工具', register_recon_tools),
        ('漏洞检测工具', register_detector_tools),
        ('CVE工具', register_cve_tools),
        ('API安全工具', register_api_security_tools),
        ('云安全工具', register_cloud_security_tools),
        ('供应链安全工具', register_supply_chain_tools),
        ('红队工具', register_redteam_tools),
        ('自动化渗透编排工具', register_orchestration_tools),
        ('会话管理工具', register_session_tools),
        ('报告工具', register_report_tools),
        ('AI辅助工具', register_ai_tools),
        ('杂项工具', register_misc_tools),
    ]

    for name, register_func in handlers:
        try:
            register_func(mcp, counter, logger)
        except ImportError as e:
            # 模块依赖缺失，某些功能可能不可用
            logger.warning(f"{name}注册失败 - 模块导入错误: {e}")
        except AttributeError as e:
            # 注册函数不存在或签名不匹配
            logger.warning(f"{name}注册失败 - 属性错误: {e}")
        except TypeError as e:
            # 参数类型不匹配
            logger.warning(f"{name}注册失败 - 类型错误: {e}")
        except Exception as e:
            # 兜底: 注册过程可能涉及第三方库的各种异常，
            # 为保证其他模块正常注册，此处捕获所有异常
            logger.warning(f"{name}注册失败 - 未预期错误: {type(e).__name__}: {e}")
