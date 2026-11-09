# AutoRedTeam-Orchestrator 深度分析报告

- **对象**: https://github.com/Coff0xc/AutoRedTeam-Orchestrator @ 596dbca (v3.1.0)
- **日期**: 2026-11-08
- **方法**: 三轮递进——① 架构与治理链路；② 子系统深挖与测试实证；③ 元测试（自审自身）+ 盲区定量 + 受限区抽查
- **环境**: Windows 11 / Python 3.12 / 临时 venv（typer + pydantic + pyyaml），全程未运行任何针对外部目标的主动能力

---

## 1. 项目定位与规模

**一句话定位（2026-11-10 对齐）**：本地 MCP/AI 攻击面审计和证据门禁。三个入口仍是 MCP Server、Python SDK 和 Typer CLI。默认档案是 `safe`：静态分析、dry-run 和本地元数据。侦察、检测和实验引擎留在源码树里，只在显式选择 `scan`、`active-lab` 或 `full` 时注册。下文的规模和计数仍是 2026-11-08、提交 `596dbca` 的快照。

| 维度 | 数据 |
|---|---|
| 版本 / 许可 | v3.1.0（`_version.py` 单源），MIT |
| 语言 / 平台 | Python 3.10+，Windows 是一等关注点（pre-commit 有硬编码 Unix 路径检查） |
| 规模 | 456 个 .py 文件、约 17.7 万行；core/ 304 文件 12.2 万行 |
| 测试 | 94 个测试文件、**2,188 个测试函数**（约 3.5 万行） |
| 贡献 | coff0xc 218 commits 主力，1 位协作者 + copilot bot |
| MCP 面 | **142 surfaces**（132 tools / 6 prompts / 4 resources） |

分层：`core/` 是唯一引擎；`mcp_stdio_server.py`（158 行）、`autort/` SDK（约 1,100 行薄异步门面）、`cli/main.py`（788 行）都是适配层。能力只实现一次。CHANGELOG 记录了主动清理：删除 527 行未用 DI 容器、删除零调用者的 `engine_router.py`——**对死代码有主动清理意识**。

## 2. 治理机制拆解

### 2.1 Capability Manifest（`core/capability_manifest.py`，808 行）

全项目最有设计价值的部分：所有 MCP surface 的机器可读单一事实来源。AST 统计分布：

| 维度 | 分布 |
|---|---|
| 按档案 | safe 23 / scan 63 / active-lab 20 / full 36（累计继承） |
| 按执行器 | in-process 80 / **isolated-required 56** / external-process 6 |
| 按类别 | detector 29、redteam 14、misc 13、orchestration 12、ai 11、recon 9、lateral 9、cve 8…… |
| 高危控制 | 26 处 `auth_required=True` |

fail-closed 有三道真实闸门：

1. **未分类即抛错**：任何 `kind:name` 不在 manifest，注册阶段直接 `CapabilityManifestError`（`handlers/__init__.py:148`）。
2. **handler 归属校验**：`_ProfiledMCP._decorator` 校验 surface 归属的 handler 与注册者一致，防止跨模块蒙混注册。
3. **重复注册检测**：`_autort_capability_profile` 属性防同一 MCP 实例换档案二次注册（`handlers/__init__.py:211`）。

过滤干净：超出档案的函数**原样返回不注册**（`handlers/__init__.py:154`），schema 层面即不可见。

### 2.2 认证中间件（`core/security/mcp_auth_middleware.py`，367 行）

- **DISABLED 只在测试环境生效**：`set_auth_mode` 与模块级初始化都检查 `AUTOREDTEAM_ENV=test` / `PYTEST_CURRENT_TEST`，否则拒绝并回退 strict（`:55-63, :350-360`）。
- **高危工具无视 permissive**：CRITICAL/DANGEROUS 级无 Key 一律拒绝；AuthManager 不可用时宁 fail-closed 视为高危（`:116-134`）。
- **审计脱敏**：`_sanitize_params` 对 password/token/ntlm_hash 等键 REDACTED，>200 字符截断。
- 69 处 `require_*_auth` 分布在 8 个高危 handler 文件；典型装饰器栈四层（`lateral_ssh`: tool → require_critical_auth → validate_inputs → handle_errors）+ 运行时 gate。

**已知缺口（项目文档自认）**：auth 是逐工具装饰器，非注册层统一边界；resource/prompt 不在覆盖内；CLI/SDK 路径完全绕过档案门禁。

### 2.3 第二道防线：mcp_security（816 行）—— 被「点覆盖」结论低估

- **SSRF 防护是 DNS-aware 的**：`InputValidator._validate_url()`（`mcp_security.py:430`）对 **DNS 解析后的 IP** 复查 `_is_private_ip(resolved_ip)`（`:469`），可挡「公网域名解析到 169.254.169.254」绕过。
- `RateLimiter`（`:513`，带 max_keys 驱逐）+ `OperationAuthorizer`（`:623`）+ `secure_tool` 装饰器（`:760`）。
- `SafeExecutor`（882 行）：外部命令白名单 + max_args + 逐参校验（`:280-292`），非裸 subprocess。
- `.bandit` 实际仅 1 条 skip——AGENTS.md「大量 skip」是历史印象。

修正后结论：防护是**三层叠加**（manifest 档案过滤 → auth 装饰器 → mcp_security 输入/限流/白名单），每层各自不完整，叠加后纵深真实存在。

### 2.4 Orchestrator / Sandbox / agent_runtime

- **Orchestrator**（orchestrator.py ~590 行 + contracts.py 1,029 行）：8 阶段流水线，`PHASE_RISK` 映射、checkpoint/resume（executor 级亦有）、进度回调；定级 Experimental，符合实际。
- **Sandbox**：`core/sandbox/executor.py` 真调 Docker SDK（`containers.run` + `wait`）；`fallback.py`（218 行）本地回退——security-model 明文「fallback 不得称为沙箱」。
- **agent_runtime**（全部 1,441 行）：`models.py` 498 行对象模型（RunMode/RiskLevel/Action/Task/Flow/AgentRunState/TraceEvent）+ `middleware.py` 责任链 + `sandbox.py` 策略判定与容器执行分离。plan-time 治理元数据定位诚实，接口占位完整。

## 3. 引擎层规模地图（纯 Python 实现）

| 模块 | 行数 | 说明 |
|---|---|---|
| `core/recon/` | 7,669 | fingerprint 870 / directory 734 / port_scanner 724 / tech_detect 714 / engine 689 / subdomain 680 / waf_detect 600 / dns_resolver 588 / js_analyzer 400 |
| `core/exploit/` | 6,635 | pure_scanner 1,013 / pure_sqli 1,001 / rce_exploiter 587 / orchestrator 601 / engine 552 |
| `core/detectors/` | 27 个检测器 | injection 10 / access 4 / auth 4 / misc 5 / file 2 / request 2；`sqli.py` 762 行为真实实现（boolean-based 双向验证、payload 增强） |
| restricted 区 | 11,855 | c2 + persistence + lateral + post_exploit，全部 manifest 标 isolated-required/full |
| `session + config/` | 4,065 | Pydantic 配置级联（env → yaml → 默认值） |
| `ai_surface/` | 759 | AST NodeVisitor，识别 FastMCP `@mcp.tool()` 与 low-level `Tool(...)`/`list_tools`，SARIF 输出 |
| `ai_redteam/` | 1,394 | scenario→plugins→strategies→runner→scorers 标准链路骨架；runner 明确产出 `not_run`（runner.py:133），无执行闭环——刻意的 scope 控制 |

可扫描面约 2.2 万行，restricted 区约 1.2 万行，治理+安全层约 4 千行——重心在「可治理的扫描能力」而非武器库。工程质量细节：`core/http/client.py:21` 把 retry sleep 抽成可 patch 钩子（为可测试性设计 API）。

## 4. 测试与 CI

- **负路径测试真实**：`test_capability_manifest.py:108` 一次覆盖未知档案/未分类/重复注册三个 fail-closed 分支，`pytest.raises(match=...)` 精确断言。
- **ai_surface 测试是行为测试**：tmp_path 写真实源码跑 AST；含误报回归用例（`test_ai_surface.py:53`）。
- **集成稀疏**：94 个测试文件仅 3 个使用 network/e2e/integration marker；mock 偏重（conftest 全局禁 auth + HTTP retry mock）。
- **CI 缺口**：`ci.yml:38` mypy 只查 3 个文件且含已删除的 `core/container.py`；无 Windows matrix；lint/security/docker-publish/self-audit 管线本身完整。

## 5. 元测试：ai-surface 审计自身

`ai-surface scan --path . --format sarif` 跑通，产出合法 SARIF 2.1.0：**109 条 findings**（error 56 / warning 33 / note 20）。热点与人工判断一致：redteam_handlers 14 / orchestration 11 / ai_handlers 11 / lateral 9 / recon 9——error 集中在 AD/CVE 利用等高危工具。

### 5.1 缺陷一：SARIF 分诊能力弱

109 条全部挂单一 `ruleId="mcp_tool"`（driver.rules 仅 1 条）；finding properties 只有 `{confidence, param, payload, verified}`，**无 tool_name**，message 仅 docstring 文本。进 GitHub Code Scanning 后是「一条规则、109 个无结构告警」，无法按工具过滤或与 manifest 对账。

### 5.2 缺陷二：盲区 33 个 surface（精确分解）

以 manifest 为基准逐 handler 对账：

```
handler            manifest  scanned   gap
detector              28        2      26   <-- 工厂生成，AST 不可见
prompts                6        0       6   <-- scanner 不匹配 prompt kind
resources              4        0       4   <-- scanner 不匹配 resource kind
其余 19 个 handler    104      104       0   ✓ 全覆盖
```

**33 = 36 个不可见 surface − 3 个误报**。根因：① 26 个 detector surface 由 `detector_factory.py` 动态生成，AST 扫描器只认装饰器/构造两种模式；② prompt/resource kind 完全未实现；③ 误报 3 条来自 `tests/test_capability_manifest.py`（2，测试内假装饰器）与 `core/recon/js_analyzer.py`（1）。文档写了「does not execute handlers」，**没写「cannot see factory-generated surfaces」**——这个结构性盲区未披露。

### 5.3 小摩擦

README 起步命令称「只读、无网络」，但 `cli/main.py:22 → typer`、`core/__init__.py:14 → ai_engine → pydantic` 的 import 链意味着至少需要 typer + pydantic + pyyaml。

## 6. c2/beacon.py 抽查：Restricted Experimental 标得准

1,714 行真实实现，非 stub。工程细节讲究：可中断心跳（`:488,637` `_stop_event.wait` 代替 `time.sleep`）、密码学安全 jitter（`:651-652` `secrets.randbelow`）、可插拔加密（`:241-242` `C2Crypto`）、handler registry 任务分发（`:301`）。manifest 标 `full` + `isolated-required` 恰当且必要。

## 7. 总评

**治理设计（manifest/profile/auth/whitelist/runtime 模型）领先于执行能力（AI 红队闭环、端到端验证、统一 scope 强制）**，且代码、文档、自评三者高度一致——这在 17 万行的安全工具仓库中罕见。元测试判词：ai-surface 通过了「审自己」的考试——分级准确、热点正确、无高危漏报（盲区全是结构性原因且集中在低危/受限面）。

### 建议（按性价比排序）

1. **ai-surface × manifest 对账**：扫描后与 manifest 核对，输出「static coverage: 106/142 + 不可见清单」——盲区变一等公民指标，架构上是顺手的事。
2. **SARIF 结构化**：finding 补 `properties.tool_name`，按风险类别拆 rule。
3. **扫描盲区**：实现 prompt/resource kind 匹配 + `--exclude-tests`。
4. **CI 修复**：更新 mypy 文件列表（移除已删的 `core/container.py`）、逐步扩到 handlers/utils；加 windows-latest 测试 job。
5. **README 澄清**：起步命令注明依赖，或让 ai-surface 路径绕开 `core/__init__` 的 eager import（utils/ 在 3.1.0 已做 `__getattr__` 懒加载，模式现成）。

### 附录：本地环境备注

克隆时 4 个文件（`core/evasion/payload_obfuscator.py` 等）在 Git Bash 下 cat 报 Permission denied，但 git mode 100644 正常、内容完整（27KB 在）——属 Windows 文件 ACL 残留，非仓库问题；`chmod +r` 或重新 clone 即可。
