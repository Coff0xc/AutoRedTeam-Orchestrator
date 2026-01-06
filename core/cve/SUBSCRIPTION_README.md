# CVE订阅管理器 (Subscription Manager)

## 概述

CVE订阅管理器是AutoRedTeam-Orchestrator v2.5的核心模块,提供智能化CVE情报订阅和通知功能。

### 核心特性

- **多种过滤方式**: 关键词/产品/严重性/CVSS范围
- **灵活通知**: 控制台/文件/Webhook
- **自动去重**: 避免重复通知已知CVE
- **统计分析**: 订阅匹配历史和通知记录
- **自动迁移**: 兼容旧数据库,自动升级表结构

## 快速开始

### 安装

```python
from core.cve.subscription_manager import (
    SubscriptionManager,
    FilterType,
    NotifyMethod
)

# 初始化管理器 (自动复用CVE数据库)
manager = SubscriptionManager()
```

### 基础用法

```python
# 1. 添加订阅
sub_id = manager.add_subscription(
    filter_type=FilterType.KEYWORD.value,
    filter_value="Apache",
    min_cvss=7.0,
    notify_method=NotifyMethod.CONSOLE.value
)

# 2. 检查新CVE
matches = manager.check_new_cves()

# 3. 列出订阅
subs = manager.list_subscriptions()

# 4. 禁用/启用订阅
manager.disable_subscription(sub_id)
manager.enable_subscription(sub_id)

# 5. 删除订阅
manager.remove_subscription(sub_id)
```

## 过滤类型

### 1. 关键词过滤 (KEYWORD)

匹配CVE ID或描述中包含关键词的CVE。

```python
sub_id = manager.add_subscription(
    filter_type="keyword",
    filter_value="RCE",          # 匹配所有包含"RCE"的CVE
    min_cvss=7.0,
    notify_method="console"
)
```

**适用场景**:
- 关注特定漏洞类型 (如 "SQLi", "XSS", "RCE")
- 关注特定厂商 (如 "Microsoft", "Cisco")
- 关注特定技术 (如 "Kubernetes", "Docker")

### 2. 产品过滤 (PRODUCT)

匹配受影响产品列表中包含特定产品的CVE。

```python
sub_id = manager.add_subscription(
    filter_type="product",
    filter_value="nginx",        # 匹配所有影响nginx的CVE
    min_cvss=0.0,
    notify_method="file",
    notify_target="/var/log/nginx_cves.log"
)
```

**适用场景**:
- 监控基础设施组件 (如 "nginx", "MySQL", "Redis")
- 关注业务系统 (如 "WordPress", "Joomla")

### 3. 严重性过滤 (SEVERITY)

匹配特定严重性等级的CVE。

```python
sub_id = manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",     # 仅匹配CRITICAL级别
    min_cvss=0.0,
    notify_method="webhook",
    notify_target="https://your-server.com/webhook"
)
```

**可选值**:
- `CRITICAL`: 严重 (通常CVSS >= 9.0)
- `HIGH`: 高危 (7.0 <= CVSS < 9.0)
- `MEDIUM`: 中危 (4.0 <= CVSS < 7.0)
- `LOW`: 低危 (CVSS < 4.0)

### 4. CVSS范围过滤 (CVSS_RANGE)

匹配CVSS分数在特定范围内的CVE。

```python
sub_id = manager.add_subscription(
    filter_type="cvss_range",
    filter_value="8.0-10.0",     # 匹配CVSS 8.0-10.0之间的CVE
    min_cvss=0.0,
    notify_method="console"
)
```

**适用场景**:
- 精准匹配分数范围
- 排除低危漏洞 (如 "7.0-10.0")

## 通知方式

### 1. 控制台通知 (CONSOLE)

直接输出到控制台。

```python
sub_id = manager.add_subscription(
    filter_type="keyword",
    filter_value="SQLi",
    min_cvss=5.0,
    notify_method="console"
)
```

**输出示例**:
```
================================================================================
[订阅通知] ID=1 | keyword=SQLi
================================================================================
匹配到 3 个新CVE:

[HIGH] CVE-2024-1234 (CVSS: 7.5)
  描述: SQL injection vulnerability...
  PoC: nuclei-templates:cves/2024/CVE-2024-1234.yaml
  更新: 2024-01-06T10:30:00
...
```

### 2. 文件通知 (FILE)

追加写入到文件。

```python
sub_id = manager.add_subscription(
    filter_type="product",
    filter_value="MySQL",
    min_cvss=6.0,
    notify_method="file",
    notify_target="/var/log/mysql_cves.log"
)
```

**文件格式**:
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

HTTP POST回调。

```python
sub_id = manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",
    min_cvss=0.0,
    notify_method="webhook",
    notify_target="https://your-server.com/webhook/cve-alert"
)
```

**Payload格式**:
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

### 列出订阅

```python
# 列出所有订阅
subs = manager.list_subscriptions()

# 仅列出启用的订阅
active_subs = manager.list_subscriptions(enabled_only=True)

for sub in subs:
    print(f"ID={sub.id} | {sub.filter_type}={sub.filter_value}")
    print(f"  状态: {'启用' if sub.enabled else '禁用'}")
    print(f"  CVSS>={sub.min_cvss} | 通知: {sub.notify_method}")
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
result = manager.remove_subscription(subscription_id=1)
```

### 订阅统计

```python
stats = manager.get_subscription_stats(subscription_id=1)

print(f"总通知次数: {stats['total_notifications']}")
print(f"最近7天通知: {stats['recent_notifications_7d']}")
print(f"最后通知时间: {stats['last_notification']}")
```

## CVE检查

### 手动检查

```python
# 检查所有启用的订阅
matches = manager.check_new_cves()

# 返回: {subscription_id: [matched_cves], ...}
for sub_id, cves in matches.items():
    print(f"订阅 {sub_id} 匹配到 {len(cves)} 个新CVE")
    for cve in cves:
        print(f"  {cve.cve_id} (CVSS: {cve.cvss})")
```

### 自动化检查 (定时任务)

```python
import asyncio

async def auto_check_loop():
    """每小时检查一次"""
    manager = SubscriptionManager()

    while True:
        # 同步CVE数据
        await manager.cve_manager.sync_all(days_back=1)

        # 检查订阅匹配
        matches = manager.check_new_cves()

        print(f"检查完成: {len(matches)} 个订阅匹配")

        # 等待1小时
        await asyncio.sleep(3600)

asyncio.run(auto_check_loop())
```

### 结合cron定时任务

```bash
# crontab -e
# 每小时运行一次
0 * * * * cd /path/to/AutoRedTeam-Orchestrator && python -m core.cve.subscription_manager check
```

## CLI命令行工具

### 添加订阅

```bash
python core/cve/subscription_manager.py add keyword "Apache" 7.0 console
python core/cve/subscription_manager.py add product "nginx" 5.0 file /tmp/nginx.log
python core/cve/subscription_manager.py add severity "CRITICAL" 0.0 webhook https://example.com/hook
python core/cve/subscription_manager.py add cvss_range "8.0-10.0" 0.0 console
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

## 高级用法

### 多条件组合

虽然单个订阅只支持一种过滤类型,但可以创建多个订阅实现组合效果:

```python
# 组合1: Apache高危漏洞
manager.add_subscription(
    filter_type="keyword",
    filter_value="Apache",
    min_cvss=7.0,  # 组合条件: 关键词 + CVSS
    notify_method="console"
)

# 组合2: nginx中高危漏洞
manager.add_subscription(
    filter_type="product",
    filter_value="nginx",
    min_cvss=5.0,  # 组合条件: 产品 + CVSS
    notify_method="file",
    notify_target="/tmp/nginx.log"
)
```

### 自定义Webhook处理器

```python
# Flask示例
from flask import Flask, request

app = Flask(__name__)

@app.route('/webhook/cve-alert', methods=['POST'])
def handle_cve_alert():
    payload = request.json
    cves = payload['cves']

    for cve in cves:
        # 发送邮件/Slack/钉钉通知
        send_alert(cve)

        # 触发自动化扫描
        trigger_scan(cve['cve_id'])

        # 记录到SIEM
        log_to_siem(cve)

    return {'status': 'ok'}

if __name__ == '__main__':
    app.run(port=8000)
```

### 与CVE更新管理器集成

```python
import asyncio

async def full_workflow():
    """完整工作流: 同步 -> 订阅 -> 检查 -> 通知"""
    manager = SubscriptionManager()

    # 1. 添加订阅
    manager.add_subscription(
        filter_type="severity",
        filter_value="CRITICAL",
        min_cvss=0.0,
        notify_method="console"
    )

    # 2. 同步CVE数据
    print("同步CVE数据...")
    await manager.cve_manager.sync_all(days_back=7)

    # 3. 检查订阅匹配
    print("检查订阅匹配...")
    matches = manager.check_new_cves()

    # 4. 输出结果
    for sub_id, cves in matches.items():
        print(f"订阅 {sub_id}: {len(cves)} 个匹配")

asyncio.run(full_workflow())
```

## 数据库结构

### subscriptions表

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 订阅ID (主键) |
| filter_type | TEXT | 过滤类型 |
| filter_value | TEXT | 过滤值 |
| min_cvss | REAL | 最低CVSS分数 |
| notify_method | TEXT | 通知方式 |
| notify_target | TEXT | 通知目标 |
| enabled | BOOLEAN | 是否启用 |
| created_at | TEXT | 创建时间 |
| last_notified | TEXT | 最后通知时间 |

### notification_history表

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 记录ID (主键) |
| subscription_id | INTEGER | 订阅ID (外键) |
| cve_id | TEXT | CVE ID |
| notified_at | TEXT | 通知时间 |
| status | TEXT | 通知状态 |

## 注意事项

1. **CVE数据源同步**: 订阅检查前需要先同步CVE数据
2. **去重逻辑**: 已通知的CVE不会重复通知
3. **Webhook超时**: Webhook请求超时时间为10秒
4. **文件权限**: 文件通知需要写权限
5. **数据库迁移**: 自动兼容旧表结构并迁移

## 故障排查

### 问题1: 订阅没有匹配到CVE

**原因**: CVE数据库为空或过滤条件太严格

**解决**:
```python
# 检查CVE数据库
stats = manager.cve_manager.get_stats()
print(stats)

# 放宽条件
manager.add_subscription(
    filter_type="keyword",
    filter_value="CVE",
    min_cvss=0.0,
    notify_method="console"
)
```

### 问题2: Webhook通知失败

**原因**: 网络不可达或接收端异常

**解决**:
```python
# 切换到文件通知
manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",
    min_cvss=0.0,
    notify_method="file",
    notify_target="/tmp/critical_cves.log"
)
```

### 问题3: 数据库迁移失败

**原因**: 表结构损坏

**解决**:
```bash
# 备份数据库
cp data/cve_index.db data/cve_index.db.backup

# 重建表
sqlite3 data/cve_index.db "DROP TABLE subscriptions; DROP TABLE notification_history;"

# 重新初始化
python -c "from core.cve import SubscriptionManager; SubscriptionManager()"
```

## 完整示例

详见:
- `core/cve/examples_subscription.py` - 完整示例代码
- `core/cve/SUBSCRIPTION_USAGE.md` - 详细使用文档

## 版本历史

- **v2.5.0** (2024-01-06)
  - 初始版本
  - 支持4种过滤类型
  - 支持3种通知方式
  - 自动数据库迁移
  - 去重逻辑

## 许可证

MIT License
