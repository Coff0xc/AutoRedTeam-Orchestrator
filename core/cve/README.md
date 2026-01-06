# CVE 多源同步管理器

## 功能概述

CVE多源同步管理器是一个强大的CVE情报管理工具，支持从多个权威数据源自动同步CVE信息，并提供本地索引、智能搜索和订阅管理功能。

### 核心特性

- **多数据源同步**: 支持 NVD API 2.0, Nuclei Templates, Exploit-DB
- **本地SQLite索引**: 快速搜索和过滤
- **增量更新**: 只拉取新增/更新的CVE，节省带宽
- **智能订阅**: 按关键词、产品、CVSS分数自动过滤
- **速率限制**: 自动遵守API速率限制，避免封禁
- **PoC管理**: 自动关联可用的PoC和Exploit
- **跨平台**: Windows/Linux/macOS 全平台支持

## 快速开始

### 1. 安装依赖

```bash
# 已包含在项目主依赖中
pip install aiohttp httpx
```

### 2. 基本使用

```python
from core.cve import CVEUpdateManager

# 初始化管理器
manager = CVEUpdateManager()

# 同步所有数据源 (异步)
import asyncio
results = asyncio.run(manager.sync_all(days_back=7))

# 搜索CVE
cves = manager.search(keyword="Apache", severity="CRITICAL", poc_only=True)

# 查看统计
stats = manager.get_stats()
print(f"总CVE数: {stats['total_cves']}, 有PoC: {stats['poc_available']}")
```

### 3. CLI使用

```bash
# 同步所有数据源
python core/cve/update_manager.py sync

# 搜索CVE
python core/cve/update_manager.py search "SQL injection"

# 查看统计
python core/cve/update_manager.py stats
```

## 数据源说明

### 1. NVD (National Vulnerability Database)

- **权威性**: CVE官方数据库
- **数据质量**: ★★★★★
- **更新频率**: 实时
- **速率限制**: 5 req/30s (无API key) | 50 req/30s (有API key)
- **包含信息**: CVE ID, CVSS分数, 严重性, 受影响产品, 详细描述

**获取API Key**: https://nvd.nist.gov/developers/request-an-api-key

### 2. Nuclei Templates (ProjectDiscovery)

- **权威性**: 社区驱动的漏洞验证模板
- **数据质量**: ★★★★☆
- **更新频率**: 频繁更新 (GitHub)
- **速率限制**: 60 req/hour (无Token) | 5000 req/hour (有Token)
- **包含信息**: 可执行的YAML格式PoC

**获取GitHub Token**: https://github.com/settings/tokens

### 3. Exploit-DB (Offensive Security)

- **权威性**: 业界知名Exploit数据库
- **数据质量**: ★★★★★
- **更新频率**: 每日更新
- **速率限制**: 无严格限制
- **包含信息**: 可执行的Exploit代码

## API参考

### CVEUpdateManager

```python
class CVEUpdateManager:
    def __init__(self, db_path: Optional[str] = None, cache_dir: Optional[str] = None)
```

#### 同步方法

```python
# 同步NVD数据 (最近N天)
async def sync_nvd(days_back: int = 7) -> Tuple[int, int]

# 同步Nuclei Templates
async def sync_nuclei_templates() -> Tuple[int, int]

# 同步Exploit-DB
async def sync_exploit_db() -> Tuple[int, int]

# 同步所有数据源
async def sync_all(days_back: int = 7) -> Dict[str, Tuple[int, int]]
```

#### 搜索方法

```python
def search(
    keyword: str = "",           # 关键词搜索
    severity: Optional[str] = None,  # 严重性过滤 (CRITICAL/HIGH/MEDIUM/LOW)
    min_cvss: float = 0.0,       # 最低CVSS分数
    poc_only: bool = False       # 仅显示有PoC的CVE
) -> List[CVEEntry]
```

#### 统计方法

```python
def get_stats() -> Dict
# 返回: {
#   "total_cves": 1234,
#   "poc_available": 567,
#   "by_severity": {"CRITICAL": 100, ...},
#   "by_source": {"NVD": 800, ...},
#   "last_sync": {"NVD": "2026-01-06T12:00:00", ...}
# }
```

### CVEEntry (数据模型)

```python
@dataclass
class CVEEntry:
    cve_id: str                  # CVE-2024-1234
    description: str             # 漏洞描述
    severity: str                # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    cvss: float                  # CVSS分数 (0.0 - 10.0)
    affected_products: str       # JSON数组字符串
    poc_available: bool          # 是否有PoC
    poc_path: Optional[str]      # PoC路径 (格式: source:path)
    source: str                  # 数据来源
    last_updated: str            # 最后更新时间 (ISO格式)
```

## 数据库Schema

```sql
-- CVE索引表
CREATE TABLE cve_index (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    severity TEXT,
    cvss REAL,
    affected_products TEXT,
    poc_available BOOLEAN,
    poc_path TEXT,
    source TEXT,
    last_updated TEXT
);

-- 同步历史表
CREATE TABLE sync_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    sync_time TEXT,
    new_cves INTEGER,
    updated_cves INTEGER,
    status TEXT
);

-- 订阅表 (未来功能)
CREATE TABLE subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filter_type TEXT,
    filter_value TEXT,
    enabled BOOLEAN DEFAULT 1,
    created_at TEXT
);
```

## 高级用法

### 1. 智能订阅过滤

```python
# 仅同步Apache相关的高危CVE
manager = CVEUpdateManager()

# 先同步所有数据
await manager.sync_all()

# 然后过滤
critical_apache = manager.search(
    keyword="Apache",
    severity="CRITICAL",
    min_cvss=9.0,
    poc_only=True
)

# 保存到文件
import json
with open("critical_apache.json", "w") as f:
    json.dump([cve.to_dict() for cve in critical_apache], f, indent=2)
```

### 2. 定时自动更新

```python
import asyncio
from datetime import datetime

async def auto_update_loop():
    manager = CVEUpdateManager()

    while True:
        print(f"[{datetime.now()}] 开始同步...")
        results = await manager.sync_all(days_back=1)  # 每次只同步最近1天

        for source, (new, updated) in results.items():
            print(f"  {source}: 新增{new}, 更新{updated}")

        # 每小时执行一次
        await asyncio.sleep(3600)

# 运行
asyncio.run(auto_update_loop())
```

### 3. 与MCP集成

```python
# 在 mcp_stdio_server.py 中添加工具
from core.cve import CVEUpdateManager

manager = CVEUpdateManager()

@mcp_server.tool()
async def cve_sync(days_back: int = 7) -> dict:
    """同步CVE数据库"""
    results = await manager.sync_all(days_back=days_back)
    return {"results": results, "stats": manager.get_stats()}

@mcp_server.tool()
def cve_search(keyword: str = "", severity: str = "", min_cvss: float = 0.0) -> list:
    """搜索CVE"""
    cves = manager.search(keyword=keyword, severity=severity, min_cvss=min_cvss)
    return [cve.to_dict() for cve in cves[:50]]  # 限制返回数量
```

## 性能优化

### 1. 速率限制策略

- NVD: 自动遵守 5 req/30s 限制
- GitHub: 使用Token提升到 5000 req/hour
- Exploit-DB: 单次下载CSV文件，本地解析

### 2. 缓存机制

- 使用临时目录缓存HTTP响应
- 增量更新减少重复下载
- SQLite索引优化查询性能

### 3. 并发控制

```python
# Nuclei同步使用Semaphore限制并发
semaphore = asyncio.Semaphore(10)  # 最多10个并发请求
```

## 故障排查

### 1. API速率限制

**问题**: `触发速率限制 [nvd], 等待 XX.Xs`

**解决**:
- 申请NVD API Key (提升到 50 req/30s)
- 减少 `days_back` 参数
- 增加同步间隔

### 2. GitHub API限制

**问题**: `API访问受限 [github]`

**解决**:
- 设置环境变量 `GITHUB_TOKEN`
- 使用Personal Access Token

### 3. 数据库锁定

**问题**: `database is locked`

**解决**:
- 避免多进程同时访问数据库
- 使用异步锁机制

## 测试

```bash
# 运行测试脚本
python core/cve/test_update_manager.py

# 选择测试项
1. 基本功能测试
2. 全量同步测试
3. 搜索查询测试
4. 全部运行
```

## 路线图

- [x] v2.5.0: 基础同步功能 (NVD, Nuclei, Exploit-DB)
- [x] v2.5.1: 速率限制和缓存优化
- [ ] v2.6.0: 智能订阅和通知系统
- [ ] v2.7.0: PoC自动化执行引擎
- [ ] v2.8.0: AI驱动的CVE风险评估

## 许可证

MIT License - 详见项目根目录 LICENSE 文件

## 贡献

欢迎提交Issue和Pull Request!
