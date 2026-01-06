# CVE订阅管理器使用示例

## 快速开始

```python
from core.cve.subscription_manager import (
    SubscriptionManager,
    FilterType,
    NotifyMethod
)

# 初始化订阅管理器
manager = SubscriptionManager()

# 添加订阅
sub_id = manager.add_subscription(
    filter_type=FilterType.KEYWORD.value,
    filter_value="Apache",
    min_cvss=7.0,
    notify_method=NotifyMethod.CONSOLE.value
)

# 检查新CVE
matches = manager.check_new_cves()
```

## 过滤类型

### 1. 关键词过滤 (KEYWORD)
匹配CVE ID或描述中包含关键词的CVE:

```python
# 订阅所有包含"RCE"的高危CVE
sub_id = manager.add_subscription(
    filter_type="keyword",
    filter_value="RCE",
    min_cvss=7.0,
    notify_method="console"
)
```

### 2. 产品过滤 (PRODUCT)
匹配受影响产品列表中包含特定产品的CVE:

```python
# 订阅nginx相关的所有CVE
sub_id = manager.add_subscription(
    filter_type="product",
    filter_value="nginx",
    min_cvss=0.0,
    notify_method="file",
    notify_target="/tmp/nginx_cves.log"
)
```

### 3. 严重性过滤 (SEVERITY)
匹配特定严重性等级的CVE:

```python
# 订阅所有CRITICAL级别的CVE
sub_id = manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",
    min_cvss=0.0,
    notify_method="console"
)
```

可选值: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`

### 4. CVSS范围过滤 (CVSS_RANGE)
匹配CVSS分数在特定范围内的CVE:

```python
# 订阅CVSS分数在8.0-10.0之间的CVE
sub_id = manager.add_subscription(
    filter_type="cvss_range",
    filter_value="8.0-10.0",
    min_cvss=0.0,
    notify_method="console"
)
```

## 通知方式

### 1. 控制台通知 (CONSOLE)
直接输出到控制台:

```python
sub_id = manager.add_subscription(
    filter_type="keyword",
    filter_value="SQLi",
    min_cvss=5.0,
    notify_method="console"
)
```

输出示例:
```
================================================================================
[订阅通知] ID=1 | keyword=SQLi
================================================================================
匹配到 3 个新CVE:

[HIGH] CVE-2024-1234 (CVSS: 7.5)
  描述: SQL injection vulnerability in Apache Struts...
  PoC: nuclei-templates:cves/2024/CVE-2024-1234.yaml
  更新: 2024-01-06T10:30:00

...
================================================================================
```

### 2. 文件通知 (FILE)
追加写入到文件:

```python
sub_id = manager.add_subscription(
    filter_type="product",
    filter_value="MySQL",
    min_cvss=6.0,
    notify_method="file",
    notify_target="/var/log/mysql_cves.log"
)
```

文件内容示例:
```
================================================================================
[订阅通知] 2024-01-06T10:30:00
订阅ID: 2
过滤条件: product=MySQL
================================================================================

[HIGH] CVE-2024-5678 (CVSS: 8.1)
描述: Authentication bypass in MySQL 8.0...
产品: ["mysql:mysql"]
PoC: exploit-db:exploits/50123.py
来源: Exploit-DB
更新: 2024-01-06T10:00:00

...
```

### 3. Webhook通知 (WEBHOOK)
HTTP POST回调 (异步):

```python
sub_id = manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",
    min_cvss=0.0,
    notify_method="webhook",
    notify_target="https://your-server.com/webhook/cve-alert"
)
```

Payload格式:
```json
{
  "subscription_id": 3,
  "filter_type": "severity",
  "filter_value": "CRITICAL",
  "timestamp": "2024-01-06T10:30:00",
  "cves": [
    {
      "cve_id": "CVE-2024-9999",
      "severity": "CRITICAL",
      "cvss": 9.8,
      "description": "Remote code execution...",
      "affected_products": ["apache:tomcat"],
      "poc_available": true,
      "poc_path": "nuclei-templates:cves/2024/CVE-2024-9999.yaml",
      "source": "NVD",
      "last_updated": "2024-01-06T10:00:00"
    }
  ]
}
```

## 订阅管理

### 列出所有订阅
```python
subscriptions = manager.list_subscriptions()

for sub in subscriptions:
    print(f"ID={sub.id} | {sub.filter_type}={sub.filter_value}")
    print(f"  CVSS>={sub.min_cvss} | 通知: {sub.notify_method}")
    print(f"  状态: {'启用' if sub.enabled else '禁用'}")
    if sub.last_notified:
        print(f"  最后通知: {sub.last_notified}")
```

### 启用/禁用订阅
```python
# 禁用订阅
manager.disable_subscription(subscription_id=1)

# 启用订阅
manager.enable_subscription(subscription_id=1)
```

### 删除订阅
```python
# 删除订阅及其通知历史
manager.remove_subscription(subscription_id=1)
```

## 检查新CVE

### 手动触发检查
```python
# 检查所有启用的订阅
matches = manager.check_new_cves()

# 返回: {subscription_id: [matched_cves], ...}
for sub_id, cves in matches.items():
    print(f"订阅 {sub_id} 匹配到 {len(cves)} 个新CVE")
```

### 自动化检查 (定时任务)
```python
import asyncio

async def auto_check_loop():
    """每小时检查一次"""
    manager = SubscriptionManager()

    while True:
        print("[定时检查] 开始检查新CVE...")

        # 同步CVE数据
        await manager.cve_manager.sync_all(days_back=1)

        # 检查订阅匹配
        matches = manager.check_new_cves()

        print(f"[定时检查] 完成: {len(matches)} 个订阅匹配")

        # 等待1小时
        await asyncio.sleep(3600)

# 启动定时任务
asyncio.run(auto_check_loop())
```

### 结合cron/systemd定时任务
```bash
# crontab -e
# 每小时运行一次CVE检查
0 * * * * cd /path/to/AutoRedTeam-Orchestrator && python -c "from core.cve.subscription_manager import SubscriptionManager; import asyncio; asyncio.run(SubscriptionManager().check_new_cves())"
```

## 订阅统计

```python
stats = manager.get_subscription_stats(subscription_id=1)

print(f"订阅统计:")
print(f"  总通知次数: {stats['total_notifications']}")
print(f"  最近7天通知: {stats['recent_notifications_7d']}")
print(f"  最后通知时间: {stats['last_notification']}")
```

## 高级用法

### 多条件组合订阅
虽然单个订阅只支持一种过滤类型,但可以创建多个订阅实现组合效果:

```python
# 订阅1: Apache + 高危
sub1 = manager.add_subscription(
    filter_type="keyword",
    filter_value="Apache",
    min_cvss=7.0,
    notify_method="console"
)

# 订阅2: nginx + 高危
sub2 = manager.add_subscription(
    filter_type="product",
    filter_value="nginx",
    min_cvss=7.0,
    notify_method="console"
)

# 订阅3: 所有CRITICAL级别
sub3 = manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",
    min_cvss=0.0,
    notify_method="file",
    notify_target="/var/log/critical_cves.log"
)
```

### 去重逻辑
订阅管理器会自动记录已通知的CVE,避免重复通知:

```python
# 第一次检查: 匹配5个CVE,发送通知
matches1 = manager.check_new_cves()

# 第二次检查: 如果没有新CVE,不会重复通知
matches2 = manager.check_new_cves()  # 返回空
```

### 自定义Webhook处理器
如果使用Webhook通知,需要在接收端实现处理逻辑:

```python
# Flask示例
from flask import Flask, request

app = Flask(__name__)

@app.route('/webhook/cve-alert', methods=['POST'])
def handle_cve_alert():
    payload = request.json

    subscription_id = payload['subscription_id']
    cves = payload['cves']

    # 自定义处理逻辑
    for cve in cves:
        # 发送邮件/Slack/钉钉通知
        # 触发自动化扫描
        # 记录到日志系统
        print(f"新CVE告警: {cve['cve_id']} (CVSS: {cve['cvss']})")

    return {'status': 'ok'}

if __name__ == '__main__':
    app.run(port=8000)
```

## CLI命令行工具

### 添加订阅
```bash
python core/cve/subscription_manager.py add keyword "Apache" 7.0 console
python core/cve/subscription_manager.py add product "nginx" 5.0 file /tmp/nginx.log
```

### 列出订阅
```bash
python core/cve/subscription_manager.py list
```

### 检查新CVE
```bash
python core/cve/subscription_manager.py check
```

### 查看统计
```bash
python core/cve/subscription_manager.py stats 1
```

### 删除订阅
```bash
python core/cve/subscription_manager.py remove 1
```

## 数据库结构

### subscriptions表
```sql
CREATE TABLE subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filter_type TEXT NOT NULL,          -- keyword/product/severity/cvss_range
    filter_value TEXT NOT NULL,         -- 过滤值
    min_cvss REAL DEFAULT 0.0,          -- 最低CVSS分数
    notify_method TEXT NOT NULL,        -- console/file/webhook
    notify_target TEXT,                 -- 文件路径/Webhook URL
    enabled BOOLEAN DEFAULT 1,          -- 是否启用
    created_at TEXT NOT NULL,           -- 创建时间
    last_notified TEXT                  -- 最后通知时间
);
```

### notification_history表
```sql
CREATE TABLE notification_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id INTEGER,            -- 订阅ID
    cve_id TEXT,                        -- CVE ID
    notified_at TEXT,                   -- 通知时间
    status TEXT,                        -- 通知状态 (SUCCESS/FAILED)
    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
);
```

## 注意事项

1. **CVE数据源同步**: 订阅检查前需要先同步CVE数据
   ```python
   await manager.cve_manager.sync_all(days_back=7)
   ```

2. **Webhook超时**: Webhook请求超时时间为10秒,接收端应快速响应

3. **文件路径**: 文件通知会自动创建父目录,但需要写权限

4. **并发安全**: SQLite数据库支持多进程读,但建议单进程写入

5. **内存占用**: 大量CVE匹配时,内存占用会增加,建议分批处理

## 完整示例

```python
import asyncio
from core.cve.subscription_manager import SubscriptionManager

async def main():
    # 初始化
    manager = SubscriptionManager()

    # 添加多个订阅
    subs = [
        # 订阅Apache高危漏洞
        manager.add_subscription(
            filter_type="keyword",
            filter_value="Apache",
            min_cvss=7.0,
            notify_method="console"
        ),

        # 订阅nginx漏洞到文件
        manager.add_subscription(
            filter_type="product",
            filter_value="nginx",
            min_cvss=5.0,
            notify_method="file",
            notify_target="/tmp/nginx_cves.log"
        ),

        # 订阅所有CRITICAL级别到Webhook
        manager.add_subscription(
            filter_type="severity",
            filter_value="CRITICAL",
            min_cvss=0.0,
            notify_method="webhook",
            notify_target="https://your-server.com/webhook"
        ),

        # 订阅高CVSS分数段
        manager.add_subscription(
            filter_type="cvss_range",
            filter_value="9.0-10.0",
            min_cvss=0.0,
            notify_method="console"
        ),
    ]

    print(f"成功添加 {len(subs)} 个订阅")

    # 同步CVE数据
    print("\n同步CVE数据...")
    await manager.cve_manager.sync_all(days_back=7)

    # 检查订阅匹配
    print("\n检查订阅匹配...")
    matches = manager.check_new_cves()

    # 输出结果
    for sub_id, cves in matches.items():
        print(f"\n订阅 ID={sub_id} 匹配到 {len(cves)} 个CVE")

    # 查看统计
    print("\n订阅统计:")
    for sub_id in subs:
        stats = manager.get_subscription_stats(sub_id)
        print(f"  订阅 {sub_id}: {stats['total_notifications']} 次通知")

if __name__ == "__main__":
    asyncio.run(main())
```

## 故障排查

### 问题1: 订阅没有匹配到CVE
**原因**: CVE数据库为空或过滤条件太严格
**解决**:
```python
# 检查CVE数据库统计
stats = manager.cve_manager.get_stats()
print(stats)

# 放宽过滤条件
manager.add_subscription(
    filter_type="keyword",
    filter_value="CVE",  # 使用通用关键词
    min_cvss=0.0,        # 降低CVSS限制
    notify_method="console"
)
```

### 问题2: Webhook通知失败
**原因**: 网络不可达或接收端异常
**解决**:
```python
# 检查通知历史
conn = sqlite3.connect(str(manager.db_path))
cursor = conn.cursor()
cursor.execute("SELECT * FROM notification_history WHERE status = 'FAILED'")
failed = cursor.fetchall()
conn.close()

# 切换到文件通知
manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",
    min_cvss=0.0,
    notify_method="file",
    notify_target="/tmp/critical_cves.log"
)
```

### 问题3: 重复通知
**原因**: notification_history表损坏
**解决**:
```python
# 清理通知历史
conn = sqlite3.connect(str(manager.db_path))
cursor = conn.cursor()
cursor.execute("DELETE FROM notification_history WHERE subscription_id = ?", (sub_id,))
conn.commit()
conn.close()
```

## 性能优化

### 1. 批量添加订阅
```python
filters = [
    ("keyword", "RCE", 7.0),
    ("keyword", "SQLi", 6.0),
    ("product", "nginx", 5.0),
]

for filter_type, filter_value, min_cvss in filters:
    manager.add_subscription(
        filter_type=filter_type,
        filter_value=filter_value,
        min_cvss=min_cvss,
        notify_method="console"
    )
```

### 2. 定期清理历史
```python
# 清理30天前的通知历史
conn = sqlite3.connect(str(manager.db_path))
cursor = conn.cursor()
cursor.execute("""
    DELETE FROM notification_history
    WHERE notified_at < datetime('now', '-30 days')
""")
conn.commit()
conn.close()
```

### 3. 数据库优化
```bash
# 定期执行VACUUM
sqlite3 data/cve_index.db "VACUUM;"
```
