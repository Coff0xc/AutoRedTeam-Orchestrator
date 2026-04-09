"""
MCP Prompt 处理器

提供预设的渗透测试工作流提示模板，让 AI 编辑器可以一键调用攻击规划。

Prompts (6个):
- plan_pentest: 渗透测试规划
- analyze_findings: 分析扫描发现
- plan_attack_chain: 攻击链规划
- suggest_next_phase: 建议下一步
- write_report: 生成渗透报告
- explain_vulnerability: 漏洞解释
"""

from __future__ import annotations


def register_prompt_handlers(mcp, counter, logger):
    """注册 MCP Prompt 处理器

    Args:
        mcp: FastMCP 实例
        counter: ToolCounter 实例
        logger: Logger 实例
    """

    @mcp.prompt(
        name="plan_pentest",
        description="规划完整渗透测试流程 — 分析目标、选择策略、制定攻击计划",
    )
    def plan_pentest(target: str, scope: str = "full") -> list:
        """渗透测试规划提示"""
        return [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": f"""你是一名资深渗透测试工程师。请为以下目标制定完整的渗透测试计划：

目标: {target}
范围: {scope}

请按以下结构输出：

## 1. 信息收集阶段
- 被动侦察策略 (OSINT, DNS, WHOIS)
- 主动侦察策略 (端口扫描, 服务识别, WAF检测)
- 推荐使用的 AutoRedTeam 工具: full_recon, port_scan, subdomain_enum, waf_detect

## 2. 漏洞发现阶段
- Web 漏洞扫描策略 (OWASP Top 10)
- API 安全检测
- 推荐工具: sqli_scan, xss_scan, ssrf_scan, jwt_scan

## 3. 漏洞利用阶段
- 利用优先级排序
- PoC 验证策略
- 推荐工具: exploit_vulnerability, cve_auto_exploit

## 4. 后渗透阶段
- 权限提升路径
- 横向移动策略
- 数据收集目标
- 推荐工具: privilege_check, lateral_smb, credential_find

## 5. 报告
- 风险评级
- 修复建议优先级

请基于目标类型(Web应用/API/内网/云环境)调整策略。""",
                },
            }
        ]

    counter.add("misc", 1)

    @mcp.prompt(
        name="analyze_findings",
        description="分析扫描发现 — 解读漏洞、评估风险、建议修复",
    )
    def analyze_findings(findings_json: str) -> list:
        """分析扫描发现提示"""
        return [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": f"""你是一名安全分析师。请分析以下渗透测试发现：

```json
{findings_json}
```

请按以下结构分析：

## 漏洞概览
- 按严重程度分类统计 (Critical/High/Medium/Low)

## 关键发现详解
对每个 Critical/High 漏洞：
1. 漏洞原理
2. 影响范围
3. 利用难度
4. PoC 验证建议 (推荐 AutoRedTeam 工具)

## 攻击链分析
- 这些漏洞能否串联为攻击链？
- 最优利用顺序是什么？

## 修复建议
- 按优先级排序的修复方案
- 短期缓解 vs 长期修复""",
                },
            }
        ]

    counter.add("misc", 1)

    @mcp.prompt(
        name="plan_attack_chain",
        description="规划攻击链 — 基于已发现漏洞设计最优攻击路径",
    )
    def plan_attack_chain(
        target: str,
        vulnerabilities: str,
        access_level: str = "none",
    ) -> list:
        """攻击链规划提示"""
        return [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": f"""你是一名红队专家。基于以下信息规划攻击链：

目标: {target}
当前访问级别: {access_level}
已发现漏洞:
{vulnerabilities}

请分析：

## 攻击路径
列出所有可能的攻击路径，按成功概率排序：
1. 路径描述 → 每步使用的漏洞/工具 → 预期结果
2. ...

## 推荐攻击链
选择最优路径并详细说明：
- Step 1: [初始入口] → 使用 AutoRedTeam 的哪个工具
- Step 2: [权限提升] → 工具 + 参数
- Step 3: [横向移动] → 工具 + 参数
- Step 4: [目标达成] → 数据收集/持久化

## 风险评估
- 被检测概率
- 建议的隐蔽措施
- 回退计划""",
                },
            }
        ]

    counter.add("misc", 1)

    @mcp.prompt(
        name="suggest_next_phase",
        description="建议下一步 — 基于当前渗透进度推荐最佳行动",
    )
    def suggest_next_phase(
        current_phase: str,
        findings_summary: str,
        access_level: str = "none",
    ) -> list:
        """建议下一阶段提示"""
        return [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": f"""你是渗透测试项目经理。基于当前进度，建议下一步行动：

当前阶段: {current_phase}
当前访问级别: {access_level}
已有发现摘要:
{findings_summary}

请回答：

1. **当前阶段评估**: 本阶段是否充分？还需要哪些补充扫描？
2. **下一步建议**: 最应该进入哪个阶段？为什么？
3. **具体操作**: 列出接下来 3-5 个具体的 AutoRedTeam 工具调用，包含参数
4. **时间估算**: 预计每步耗时
5. **注意事项**: 风险点和前置条件""",
                },
            }
        ]

    counter.add("misc", 1)

    @mcp.prompt(
        name="write_report",
        description="生成渗透测试报告 — 将发现转化为专业交付物",
    )
    def write_report(
        target: str,
        findings_json: str,
        report_type: str = "executive",
    ) -> list:
        """报告生成提示"""
        return [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": f"""你是安全顾问。请基于以下渗透测试结果生成{report_type}报告：

目标: {target}
报告类型: {report_type} (executive=管理层摘要, technical=技术详情, remediation=修复方案)

发现:
```json
{findings_json}
```

{"## 管理层摘要报告格式" if report_type == "executive" else "## 技术详情报告格式" if report_type == "technical" else "## 修复方案报告格式"}

请包含：
- 测试范围和方法论
- 风险评级 (Critical/High/Medium/Low 统计)
- {"关键发现概述（非技术语言）、业务影响、优先修复建议" if report_type == "executive" else "每个漏洞的技术细节、PoC、影响分析" if report_type == "technical" else "每个漏洞的修复步骤、验证方法、实施优先级"}
- 总结和建议""",
                },
            }
        ]

    counter.add("misc", 1)

    @mcp.prompt(
        name="explain_vulnerability",
        description="解释漏洞 — 用清晰语言描述漏洞原理、影响和修复方法",
    )
    def explain_vulnerability(
        vuln_type: str,
        context: str = "",
    ) -> list:
        """漏洞解释提示"""
        return [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": f"""请详细解释以下安全漏洞：

漏洞类型: {vuln_type}
{"上下文: " + context if context else ""}

请按以下结构说明：

## 漏洞原理
- 技术原理（附代码示例）
- 常见出现场景

## 影响范围
- 攻击者能做什么
- 最坏情况 (CIA 影响)

## 检测方法
- 推荐的 AutoRedTeam 扫描工具
- 手动验证步骤

## 修复方案
- 代码层面修复（附修复代码示例）
- 架构层面防御
- WAF/IDS 规则建议

## 参考
- CWE 编号
- OWASP 分类
- 相关 CVE 示例""",
                },
            }
        ]

    counter.add("misc", 1)

    logger.info("MCP Prompts 注册完成: 6 个提示模板")
