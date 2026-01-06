# CVE多源同步管理器 - 快速参考

## 快速开始 (30秒)

```python
from core.cve import CVEUpdateManager
import asyncio

# 初始化
manager = CVEUpdateManager()

# 同步数据 (异步)
asyncio.run(manager.sync_all(days_back=7))

# 搜索CVE
results = manager.search(keyword="Apache", severity="CRITICAL", poc_only=True)

# 查看统计
print(manager.get_stats())
```

## 核心API速查

### 同步方法

| 方法 | 说明 | 示例 |
|------|------|------|
| `sync_nvd(days_back)` | 同步NVD官方数据 | `await manager.sync_nvd(7)` |
| `sync_nuclei_templates()` | 同步Nuclei PoC | `await manager.sync_nuclei_templates()` |
| `sync_exploit_db()` | 同步Exploit-DB | `await manager.sync_exploit_db()` |
| `sync_all(days_back)` | 同步所有源 | `await manager.sync_all(7)` |

### 搜索方法

```python
# 关键词搜索
manager.search(keyword="SQL injection")

# 严重性过滤
manager.search(severity="CRITICAL")

# CVSS分数过滤
manager.search(min_cvss=9.0)

# 仅显示有PoC的CVE
manager.search(poc_only=True)

# 复合查询
manager.search(keyword="Apache", severity="HIGH", min_cvss=8.0, poc_only=True)
```

### 统计方法

```python
stats = manager.get_stats()

# 返回值:
{
    "total_cves": 1234,
    "poc_available": 567,
    "by_severity": {"CRITICAL": 100, "HIGH": 300, ...},
    "by_source": {"NVD": 800, "Nuclei": 200, ...},
    "last_sync": {"NVD": "2026-01-06T12:00:00", ...}
}
```

## 数据源配置

### NVD API Key (可选)

```bash
# 申请: https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="your_api_key_here"
```

**速率限制**:
- 无Key: 5 req/30s
- 有Key: 50 req/30s

### GitHub Token (可选)

```bash
# 申请: https://github.com/settings/tokens
export GITHUB_TOKEN="ghp_your_token_here"
```

**速率限制**:
- 无Token: 60 req/hour
- 有Token: 5000 req/hour

## CLI命令

```bash
# 同步所有数据源
python core/cve/update_manager.py sync

# 搜索CVE
python core/cve/update_manager.py search "Apache"

# 查看统计
python core/cve/update_manager.py stats

# 运行示例
python core/cve/examples.py

# 运行测试
python core/cve/test_update_manager.py
```

## 常见场景

### 场景1: 每日自动更新

```python
import asyncio
from core.cve import CVEUpdateManager

async def daily_update():
    manager = CVEUpdateManager()
    results = await manager.sync_all(days_back=1)
    print(f"更新完成: {results}")

# 定时任务 (Cron)
asyncio.run(daily_update())
```

### 场景2: 监控特定产品

```python
manager = CVEUpdateManager()

# 监控产品列表
products = ["Apache", "nginx", "MySQL", "Docker"]

for product in products:
    cves = manager.search(keyword=product, severity="CRITICAL", poc_only=True)
    if cves:
        print(f"[警告] {product} 发现 {len(cves)} 个严重漏洞!")
        for cve in cves[:5]:
            print(f"  • {cve.cve_id} [CVSS: {cve.cvss}]")
```

### 场景3: 生成威胁情报报告

```python
import json
manager = CVEUpdateManager()

# 收集最新高危CVE
critical = manager.search(severity="CRITICAL", min_cvss=9.0, poc_only=True)

# 导出JSON
report = {
    "date": datetime.now().isoformat(),
    "total": len(critical),
    "cves": [cve.to_dict() for cve in critical]
}

with open("threat_intel.json", "w") as f:
    json.dump(report, f, indent=2)
```

### 场景4: 与其他工具联动

```python
# 与Nuclei联动
manager = CVEUpdateManager()

# 找到有Nuclei模板的CVE
nuclei_cves = manager.search(poc_only=True)

for cve in nuclei_cves:
    if cve.poc_path and cve.poc_path.startswith("nuclei-templates:"):
        template_path = cve.poc_path.split(":")[1]
        # 调用Nuclei执行扫描
        print(f"nuclei -t {template_path} -u {target}")
```

## 性能优化

### 减少同步时间

```python
# 只同步最近1天 (而不是7天)
await manager.sync_nvd(days_back=1)

# 只同步特定源
await manager.sync_nuclei_templates()  # 只同步Nuclei
```

### 使用缓存

```python
# 自定义缓存目录
manager = CVEUpdateManager(cache_dir="/path/to/cache")

# 缓存会自动保存HTTP响应,下次同步更快
```

### 并发搜索

```python
import concurrent.futures

keywords = ["Apache", "nginx", "MySQL"]

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    futures = [executor.submit(manager.search, keyword=k) for k in keywords]
    results = [f.result() for f in futures]
```

## 故障排查

### 问题1: 数据库锁定

```
sqlite3.OperationalError: database is locked
```

**解决**: 避免多进程同时访问数据库

```python
# 使用独立的数据库文件
manager1 = CVEUpdateManager(db_path="db1.sqlite")
manager2 = CVEUpdateManager(db_path="db2.sqlite")
```

### 问题2: API速率限制

```
WARNING: 触发速率限制 [nvd], 等待 25.3s
```

**解决**: 设置API Key或减少同步频率

```bash
export NVD_API_KEY="your_key"
export GITHUB_TOKEN="your_token"
```

### 问题3: 网络超时

```
TimeoutError: Request timeout
```

**解决**: 增加超时时间或使用代理

```python
# 在 update_manager.py 修改超时设置
async with session.get(url, timeout=60) as resp:  # 默认30s -> 60s
```

## 数据库维护

### 清理旧数据

```python
import sqlite3

conn = sqlite3.connect("data/cve_index.db")
cursor = conn.cursor()

# 删除1年前的CVE
cursor.execute("""
    DELETE FROM cve_index
    WHERE last_updated < date('now', '-1 year')
""")

conn.commit()
conn.close()
```

### 备份数据库

```bash
# 复制数据库文件
cp data/cve_index.db data/cve_index_backup.db

# 或使用SQLite命令
sqlite3 data/cve_index.db ".backup data/cve_backup.db"
```

### 查看数据库大小

```bash
du -h data/cve_index.db
```

## 进阶用法

### 自定义数据源

```python
class CustomCVEManager(CVEUpdateManager):
    async def sync_custom_source(self):
        """同步自定义数据源"""
        # 实现你的同步逻辑
        pass
```

### 添加订阅过滤

```python
# 未来功能预览
manager.add_subscription(
    filter_type="keyword",
    filter_value="Apache",
    min_cvss=7.0
)

# 只同步订阅的CVE
await manager.sync_subscriptions()
```

### 集成到Web服务

```python
from flask import Flask, jsonify
from core.cve import CVEUpdateManager

app = Flask(__name__)
manager = CVEUpdateManager()

@app.route("/api/cve/search")
def api_search():
    keyword = request.args.get("q", "")
    results = manager.search(keyword=keyword)
    return jsonify([cve.to_dict() for cve in results[:50]])

@app.route("/api/cve/stats")
def api_stats():
    return jsonify(manager.get_stats())
```

## 最佳实践

1. **定时同步**: 每天同步一次,避免数据过时
2. **使用API Key**: 提高速率限制,加快同步速度
3. **关键词监控**: 关注关键产品的高危漏洞
4. **PoC优先**: 优先关注有PoC的CVE (可直接复现)
5. **备份数据**: 定期备份数据库文件

## 联系支持

- GitHub Issues: https://github.com/your-repo/issues
- 文档: core/cve/README.md
- 示例: core/cve/examples.py
