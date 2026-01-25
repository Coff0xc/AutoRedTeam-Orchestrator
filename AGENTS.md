# Repository Guidelines

## ⚠️ 项目状态 (2026-01)

**当前状态**: v3.0.0 - 架构重构完成，持续优化中

| 指标 | 状态 |
|------|------|
| MCP 工具数 | 由 ToolCounter 运行时统计 |
| 测试覆盖率 | <1% ⚠️ |
| 生产就绪度 | 65/100 |

**已修复缺陷**:
- ✅ `core/c2/beacon.py` 线程安全问题 (使用 Lock + Event 重构)
- ✅ `handlers/` 统一异常处理机制 (`error_handling.py`)
- ✅ 工具数量口径统一 (移除硬编码，改为运行时统计)

**待改进项**:
- 测试覆盖率需提升至 >70%
- 部分 `tools/` 和 `utils/` 仍有通用异常捕获待收敛

**已删除模块** (git status 显示 D):
- `core/async_executor.py`
- `core/async_http_client.py`
- `core/concurrency_controller.py`
- `core/recon/standard.py`
- `tests/test_poc_engine.py`, `tests/test_security.py`, `tests/test_v25_integration.py`

## 项目结构与模块组织
- `core/`：核心能力实现（如 session_manager、c2、evasion、stealth、exploit）。
- `modules/`：工具模块与聚合层（如 redteam_tools、vuln_verifier）。
- `tools/`：legacy 工具实现（兼容入口，已弃用）。
- `utils/`：通用组件（任务队列、报告生成等）。
- `mcp_stdio_server.py`：MCP server 入口；`auto_recon.py`：独立侦察引擎。
- 入口关系说明：`docs/ARCHITECTURE_ENTRYPOINTS.md`。
- `tests/`：测试用例；`config/`、`templates/`、`payloads/`、`wordlists/`、`poc-templates/` 为配置与数据。
- `scripts/`：辅助脚本；`docs/`、`examples/`：文档与示例。

## 构建、测试与本地开发命令
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
python mcp_stdio_server.py
pytest
pytest tests/test_exceptions_redteam.py
pytest tests/test_exfiltration/test_base.py
pytest tests/test_privilege_escalation/test_base.py
pytest tests/test_performance_integration.py
pre-commit install
```
以上命令依次用于安装依赖、启动 MCP 服务、执行全量与指定测试，以及启用提交前检查。

> ⚠️ **注意**: `tests/test_v25_integration.py` 已删除，请使用 `tests/test_performance_integration.py`

## 编码风格与命名规范
- Python 3.10+；4 空格缩进。
- `black`/`isort` 配置在 `pyproject.toml`，行宽 100；`pylint` 最低分 7。
- 命名：函数/变量 `snake_case`，类 `PascalCase`，常量 `UPPER_SNAKE_CASE`；MCP 工具用 `snake_case`。
- 跨平台与编码：使用 `pathlib.Path`/`os.path`，避免硬编码 `/tmp`；文件读写显式 `encoding="utf-8"`；外部工具先 `shutil.which()`。

## 测试指南
- 使用 `pytest`，测试文件 `test_*.py` 或 `*_test.py`，函数 `test_*`（见 `pyproject.toml`）。
- 支持 `slow`/`integration`/`e2e`/`network` 标记；覆盖率由 `pytest-cov` 生成 `html/xml` 报告。
- **?? 当前状态**: 已有多组单元/集成测试，但覆盖率仍 <1%。
- **优先任务**: 新功能需新增单元测试，优先覆盖 `core/`、`modules/`、`tools/`、`utils/`。
- **目标**: 测试覆盖率需达到 >70%。

## 提交与 PR 规范
- Git 历史以 Conventional Commits 为主：`feat:` `fix:` `docs:` `refactor:` `chore:` `security:`，可带范围或版本（如 `feat(v2.2.0): ...`）。
- PR 需包含清晰描述、关联 Issue、必要的测试/文档更新；建议通过 `black`/`isort`/`pylint`/`flake8` 和 `pytest`。
- 安全问题请遵循 `SECURITY.md`，不要在 PR 中泄露密钥或样本。

## 安全与配置提示
- 以 `.env.example` 为模板生成 `.env`，敏感配置不要提交。
- 运行/调试相关日志与报告默认在 `logs/`、`reports/`，避免提交大型生成文件。
