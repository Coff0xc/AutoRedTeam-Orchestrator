# Migration Guide

## v2.x → v3.0 迁移指南

本文档记录从 AutoRedTeam-Orchestrator v2.x 升级到 v3.0 的迁移路径和重要变更。

---

## 📋 目录

- [重大变更](#重大变更)
- [模块重构映射](#模块重构映射)
- [删除的模块](#删除的模块)
- [新增功能](#新增功能)
- [API 变更](#api-变更)
- [配置变更](#配置变更)
- [迁移步骤](#迁移步骤)

---

## 重大变更

### 1. 架构重构

v3.0 采用了模块化的 Handler 架构，将原来的单体 `mcp_stdio_server.py` 拆分为 16 个独立的 Handler 模块：

```
mcp_stdio_server.py (单体)
         ↓ 重构
handlers/
├── recon_handlers.py          # 侦察工具 (8个)
├── detector_handlers.py       # 漏洞检测工具 (11个)
├── cve_handlers.py            # CVE工具 (8个)
├── api_security_handlers.py   # API安全工具 (7个)
├── cloud_security_handlers.py # 云安全工具 (3个)
├── supply_chain_handlers.py   # 供应链安全工具 (3个)
├── redteam_handlers.py        # 红队工具 (14个)
├── orchestration_handlers.py  # 自动化渗透编排工具 (11个)
├── lateral_handlers.py        # 横向移动工具 (9个)
├── persistence_handlers.py    # 持久化工具 (3个)
├── ad_handlers.py             # AD攻击工具 (3个)
├── session_handlers.py        # 会话管理工具 (4个)
├── report_handlers.py         # 报告工具 (2个)
├── ai_handlers.py             # AI辅助工具 (3个)
├── misc_handlers.py           # 杂项工具 (3个)
└── external_tools_handlers.py # 外部工具集成 (8个) [新增]
```

### 2. MCP 工具数量

- **v2.x**: 74-97 个工具
- **v3.0**: 100 个工具

---

## 模块重构映射

### 横向移动模块 (core/lateral/)

| 旧模块 | 新模块 | 说明 |
|--------|--------|------|
| `core/lateral/smb_lateral.py` | `core/lateral/smb.py` | 合并，API 兼容 |
| `core/lateral/ssh_lateral.py` | `core/lateral/ssh.py` | 合并，API 兼容 |
| `core/lateral/wmi_lateral.py` | `core/lateral/wmi.py` | 合并，API 兼容 |

**迁移示例**：
```python
# v2.x
from core.lateral.smb_lateral import SMBLateral
lateral = SMBLateral(target, username, password)

# v3.0
from core.lateral.smb import SMBLateralMove
lateral = SMBLateralMove(target, credential)
```

### 会话管理模块 (core/session/)

| 旧模块 | 新模块 | 说明 |
|--------|--------|------|
| `core/session_manager.py` | `core/session/manager.py` | 移动到子目录 |

**迁移示例**：
```python
# v2.x
from core.session_manager import SessionManager

# v3.0
from core.session.manager import SessionManager
# 或使用顶层导入
from core.session import SessionManager
```

### 输入验证模块 (utils/)

| 旧模块 | 新模块 | 说明 |
|--------|--------|------|
| `core/security/input_validator.py` | `utils/validators.py` | 合并统一 |
| `utils/input_validator.py` | `utils/validators.py` | 合并统一 |

**迁移示例**：
```python
# v2.x
from core.security.input_validator import InputValidator
validator = InputValidator()

# v3.0
from utils.validators import (
    validate_url,
    validate_ip,
    validate_cidr,
    sanitize_command,
    sanitize_path
)
# 使用函数式API
is_valid = validate_url(url)
safe_cmd = sanitize_command(cmd)
```

### Payload 引擎模块 (modules/payload/)

| 旧模块 | 新模块 | 说明 |
|--------|--------|------|
| `core/mega_payload_library.py` | `modules/payload/library.py` | 移动重构 |
| `modules/adaptive_payload_engine.py` | `modules/payload/adaptive.py` | 移动重构 |
| `modules/smart_payload_engine.py` | `modules/payload/smart.py` | 移动重构 |
| `modules/smart_payload_selector.py` | `modules/payload/selector.py` | 合并 |

### Web 攻击模块 (modules/web_attack/)

**整个目录已删除**，功能合并到 `core/detectors/`：

| 旧模块 | 新模块 | 说明 |
|--------|--------|------|
| `modules/web_attack/sqli_tools.py` | `core/detectors/sqli.py` | 合并到检测器 |
| `modules/web_attack/xss_tools.py` | `core/detectors/xss.py` | 合并到检测器 |
| `modules/web_attack/xxe_tools.py` | `core/detectors/xxe.py` | 合并到检测器 |
| `modules/web_attack/advanced_xss.py` | `core/detectors/xss.py` | 合并到检测器 |
| `modules/web_attack/dir_tools.py` | `core/recon/dir_scanner.py` | 移动到侦察模块 |
| `modules/web_attack/fuzzing_tools.py` | `modules/enhanced_scanner.py` | 合并 |

### 工具注册表 (core/registry/)

| 旧模块 | 新模块 | 说明 |
|--------|--------|------|
| `core/tool_registry.py` | `core/registry/tool_registry.py` | 移动到子目录 |

---

## 删除的模块

以下模块在 v3.0 中已完全删除：

| 模块 | 原因 | 替代方案 |
|------|------|----------|
| `core/async_executor.py` | 功能重复 | 使用 `asyncio` 原生 API |
| `core/async_http_client.py` | 功能重复 | 使用 `core/http/client.py` |
| `core/concurrency_controller.py` | 重构 | 使用 `core/concurrency/` |
| `core/recon/standard.py` | 重命名 | 使用 `core/recon/engine.py` |
| `tests/test_poc_engine.py` | 测试重构 | 测试合并到其他文件 |
| `tests/test_security.py` | 测试重构 | 测试合并到其他文件 |
| `tests/test_v25_integration.py` | 过时 | 使用新的集成测试 |

---

## 新增功能

### v3.0.1 新增

1. **外部工具集成** (`core/tools/tool_manager.py`)
   - Nmap 集成
   - Nuclei 集成
   - SQLMap 集成
   - ffuf 集成
   - Masscan 集成

2. **工具链编排** (`ext_tool_chain`)
   - 支持多工具顺序执行
   - YAML 配置驱动

3. **CVE 自动利用增强** (`core/cve/auto_exploit.py`)
   - AI PoC 生成
   - 自动利用编排
   - 3 个新 MCP 工具

### v3.0 新增

1. **Handler 模块化架构**
2. **统一的错误处理装饰器** (`@handle_errors`)
3. **输入验证装饰器** (`@validate_inputs`)
4. **改进的日志系统**

---

## API 变更

### MCP 工具名称变更

| v2.x 工具名 | v3.0 工具名 | 说明 |
|-------------|-------------|------|
| `smb_exec` | `lateral_smb` | 统一前缀 |
| `ssh_exec` | `lateral_ssh` | 统一前缀 |
| `wmi_exec` | `lateral_wmi` | 统一前缀 |
| `winrm_exec` | `lateral_winrm` | 统一前缀 |
| `psexec_exec` | `lateral_psexec` | 统一前缀 |

### 返回值格式统一

v3.0 所有工具返回标准化格式：

```python
{
    "success": bool,           # 执行是否成功
    "data": Any,               # 成功时的数据
    "error": str | None,       # 失败时的错误信息
    "metadata": dict | None    # 可选的元数据
}
```

---

## 配置变更

### 新增配置文件

1. **`config/external_tools.yaml`** - 外部工具配置
   ```yaml
   base_path: "/path/to/tools"
   tools:
     nmap:
       enabled: true
       path: "${base_path}/nmap/nmap"
     nuclei:
       enabled: true
       path: "${base_path}/nuclei/nuclei"
   ```

### pyproject.toml 变更

- 版本号: `3.0.0` → `3.0.1`
- 新增 mypy 配置
- 新增 pylint 配置
- 测试覆盖率阈值: `30%` → `50%`

### CI/CD 变更

- Lint 检查现在会阻塞构建 (移除 `|| true`)
- 安全扫描使用 `continue-on-error: true`
- 覆盖率阈值提高到 50%

---

## 迁移步骤

### 1. 更新依赖

```bash
pip install -r requirements.txt --upgrade
```

### 2. 更新导入语句

使用以下脚本查找需要更新的导入：

```bash
# 查找旧的导入
grep -r "from core.lateral.smb_lateral" .
grep -r "from core.session_manager" .
grep -r "from core.security.input_validator" .
grep -r "from modules.web_attack" .
```

### 3. 更新 MCP 工具调用

如果您的代码直接调用 MCP 工具，更新工具名称：

```python
# v2.x
result = await mcp.call_tool("smb_exec", {...})

# v3.0
result = await mcp.call_tool("lateral_smb", {...})
```

### 4. 更新配置

创建 `config/external_tools.yaml` 如果需要使用外部工具集成。

### 5. 运行测试

```bash
pytest tests/ -v
```

### 6. 检查废弃警告

```bash
python -W default mcp_stdio_server.py
```

---

## 兼容性说明

### 向后兼容

- 大多数核心 API 保持兼容
- MCP 工具参数格式未变
- 会话管理 API 兼容

### 不兼容变更

- 删除的模块无法直接使用
- Web 攻击模块需要迁移到检测器
- 部分工具名称变更

---

## 常见问题

### Q: 导入错误 `ModuleNotFoundError: No module named 'core.lateral.smb_lateral'`

**A**: 模块已合并，请更新导入：
```python
from core.lateral.smb import SMBLateralMove
```

### Q: 工具调用失败 `Tool 'smb_exec' not found`

**A**: 工具已重命名，使用新名称：
```python
await mcp.call_tool("lateral_smb", {...})
```

### Q: 如何启用外部工具集成？

**A**:
1. 创建 `config/external_tools.yaml`
2. 配置工具路径
3. 重启 MCP 服务器

---

## 获取帮助

- **文档**: [README.md](README.md)
- **问题**: [GitHub Issues](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues)
- **社区**: [Discord](https://discord.gg/PtVyrMvB)

---

*最后更新: 2026-01-28*
*版本: v3.0.1*
