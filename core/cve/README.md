# CVE 多源同步管理器 / AI PoC 工厂

> 负责 CVE 情报同步、索引、订阅过滤与 AI PoC 生成。跨平台：Windows / Linux / macOS。

## 🎯 组成
- `update_manager.py`：多源同步（NVD API 2.0、Nuclei Templates、Exploit-DB CSV），增量更新，速率自适应，临时缓存。
- `subscription_manager.py`：订阅过滤（关键字/严重度/产品/CVSS），预留通知能力。
- `ai_poc_generator.py` / `example_ai_poc_generator.py`：基于 CVE 描述生成 PoC 模板。
- `poc_engine.py`：YAML PoC 解析与执行（兼容 Nuclei 模板格式）。
- `mcp_integration.py`：MCP 工具封装。
- 相关文档：`QUICKSTART.py`、`QUICKSTART_SUBSCRIPTION.md`、`QUICKREF.md`、`USAGE_AI_POC_GENERATOR.md`。

## ⚡ 快速开始
```bash
# 依赖已在主项目 requirements 中
pip install aiohttp httpx
```
```python
from core.cve import CVEUpdateManager
import asyncio

m = CVEUpdateManager()
asyncio.run(m.sync_all(days_back=7))
cves = m.search(keyword="Apache", severity="CRITICAL", min_cvss=9.0, poc_only=True)
print(m.get_stats())
```

### CLI
```bash
python core/cve/update_manager.py sync                 # 同步
python core/cve/update_manager.py search "SQL injection"  # 检索
python core/cve/update_manager.py stats                # 统计
python core/cve/ai_poc_generator.py --help             # AI PoC
```

## 🔗 数据源与限额
- **NVD**：5 req/30s（无 key）或 50 req/30s（有 key），建议申请 API Key。
- **Nuclei Templates**：GitHub Token 可将 60 提升至 5000 req/h。
- **Exploit-DB**：每日 CSV，本地解析。

## 🧰 API 速览
- 同步：`sync_nvd(days_back=7)`, `sync_nuclei_templates()`, `sync_exploit_db()`, `sync_all(days_back=7)`
- 查询：`search(keyword="", severity=None, min_cvss=0.0, poc_only=False)`
- 统计：`get_stats()` 返回总量/有 PoC/按严重度与来源/上次同步时间

## 🩺 常见问题
- 触发 NVD 限速：使用 API Key，减小 `days_back`，或拉长同步间隔。
- GitHub 限额：设置环境变量 `GITHUB_TOKEN`。
- `database is locked`：避免多进程并发访问，必要时串行。

## 🛤️ 路线图
- [x] 多源同步与限速
- [x] 缓存与增量优化
- [ ] 智能订阅/通知
- [ ] PoC 自动化执行
- [ ] AI 驱动 CVE 风险评估

## 📜 许可
MIT License；欢迎 Issue / PR。
```
