"""
AI辅助工具处理器
包含: smart_analyze, attack_chain_plan, smart_payload
"""

from typing import Any, Dict
from .tooling import tool


def register_ai_tools(mcp, counter, logger):
    """注册AI辅助工具

    Args:
        mcp: FastMCP实例
        counter: ToolCounter实例
        logger: Logger实例
    """

    @tool(mcp)
    async def smart_analyze(target: str, context: str = None) -> Dict[str, Any]:
        """智能分析 - AI辅助分析目标并推荐测试策略

        Args:
            target: 目标URL
            context: 额外上下文信息

        Returns:
            分析结果和建议
        """
        try:
            from core.ai_engine import AIAnalyzer

            analyzer = AIAnalyzer()
            result = analyzer.analyze(target, context)

            return {
                'success': True,
                'target': target,
                'analysis': result
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @tool(mcp)
    async def attack_chain_plan(
        target: str,
        reconnaissance_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """攻击链规划 - 基于侦察数据规划攻击链

        Args:
            target: 目标URL
            reconnaissance_data: 侦察数据 (可选)

        Returns:
            推荐的攻击链
        """
        try:
            from core.attack_chain import AttackChainEngine
            from urllib.parse import urlparse

            # 判断目标类型
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                target_type = 'url'
                domain = parsed.netloc
            elif '.' in target and not target.replace('.', '').isdigit():
                target_type = 'domain'
                domain = target
            else:
                target_type = 'ip'
                domain = target

            # 创建攻击链引擎 (tool_registry 可为 None，引擎会使用内置工具映射)
            engine = AttackChainEngine(tool_registry=None)
            chain = engine.create_chain(target, target_type)

            # 返回攻击链信息
            return {
                'success': True,
                'target': target,
                'target_type': target_type,
                'attack_chain': {
                    'id': chain.id,
                    'name': chain.name,
                    'nodes': [
                        {
                            'id': node.id,
                            'phase': node.phase.value,
                            'technique': node.technique,
                            'tool': node.tool,
                            'params': node.params,
                            'dependencies': node.dependencies
                        }
                        for node in chain.nodes
                    ],
                    'total_nodes': len(chain.nodes)
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'target': target}

    @tool(mcp)
    async def smart_payload(
        vuln_type: str,
        context: Dict[str, Any] = None,
        waf_detected: bool = False
    ) -> Dict[str, Any]:
        """智能Payload生成 - 根据上下文生成优化的payload

        Args:
            vuln_type: 漏洞类型 (sqli, xss, rce, ssrf, etc.)
            context: 上下文信息 (WAF类型、过滤规则等)
            waf_detected: 是否检测到WAF

        Returns:
            推荐的payloads
        """
        try:
            from modules.smart_payload_engine import SmartPayloadEngine

            engine = SmartPayloadEngine()
            payloads = engine.generate(
                vuln_type=vuln_type,
                context=context,
                waf_bypass=waf_detected
            )

            return {
                'success': True,
                'vuln_type': vuln_type,
                'payloads': payloads,
                'count': len(payloads)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    counter.add('ai', 3)
    logger.info("[AI] 已注册 3 个AI辅助工具")