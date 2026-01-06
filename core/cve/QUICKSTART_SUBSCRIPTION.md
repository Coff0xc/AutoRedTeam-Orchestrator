# CVE订阅管理器 - 5分钟快速开始

## 1. 基础用法 (30秒)

```python
from core.cve.subscription_manager import SubscriptionManager, FilterType, NotifyMethod

# 初始化
manager = SubscriptionManager()

# 添加订阅: 关注Apache高危漏洞
sub_id = manager.add_subscription(
    filter_type=FilterType.KEYWORD.value,
    filter_value="Apache",
    min_cvss=7.0,
    notify_method=NotifyMethod.CONSOLE.value
)

print(f"订阅创建成功! ID={sub_id}")
```

## 2. 检查CVE (1分钟)

```python
import asyncio

async def check():
    manager = SubscriptionManager()

    # 同步CVE数据 (最近1天)
    print("同步CVE数据...")
    await manager.cve_manager.sync_nvd(days_back=1)

    # 检查订阅匹配
    print("检查订阅...")
    matches = manager.check_new_cves()

    # 显示结果
    for sub_id, cves in matches.items():
        print(f"订阅 {sub_id}: {len(cves)} 个匹配")

asyncio.run(check())
```

## 3. 文件通知 (1分钟)

```python
import tempfile
from pathlib import Path

manager = SubscriptionManager()

# 订阅nginx漏洞,写入文件
log_file = Path(tempfile.gettempdir()) / "nginx_cves.log"

sub_id = manager.add_subscription(
    filter_type=FilterType.PRODUCT.value,
    filter_value="nginx",
    min_cvss=5.0,
    notify_method=NotifyMethod.FILE.value,
    notify_target=str(log_file)
)

print(f"文件通知订阅创建成功!")
print(f"日志文件: {log_file}")
```

## 4. 高级过滤 (2分钟)

```python
manager = SubscriptionManager()

# 订阅1: 关键词过滤
manager.add_subscription(
    filter_type="keyword",
    filter_value="RCE",
    min_cvss=7.0,
    notify_method="console"
)

# 订阅2: 产品过滤
manager.add_subscription(
    filter_type="product",
    filter_value="MySQL",
    min_cvss=6.0,
    notify_method="console"
)

# 订阅3: 严重性过滤
manager.add_subscription(
    filter_type="severity",
    filter_value="CRITICAL",
    min_cvss=0.0,
    notify_method="console"
)

# 订阅4: CVSS范围过滤
manager.add_subscription(
    filter_type="cvss_range",
    filter_value="9.0-10.0",
    min_cvss=0.0,
    notify_method="console"
)

# 列出所有订阅
subs = manager.list_subscriptions()
print(f"共创建 {len(subs)} 个订阅")
```

## 5. 订阅管理 (1分钟)

```python
manager = SubscriptionManager()

# 列出所有订阅
subs = manager.list_subscriptions()
for sub in subs:
    print(f"ID={sub.id} | {sub.filter_type}={sub.filter_value}")

# 禁用订阅
manager.disable_subscription(subscription_id=1)

# 启用订阅
manager.enable_subscription(subscription_id=1)

# 删除订阅
manager.remove_subscription(subscription_id=1)
```

## CLI命令 (30秒)

```bash
# 添加订阅
python core/cve/subscription_manager.py add keyword "Apache" 7.0 console

# 列出订阅
python core/cve/subscription_manager.py list

# 检查新CVE
python core/cve/subscription_manager.py check

# 删除订阅
python core/cve/subscription_manager.py remove 1
```

## 完整示例 (5分钟)

运行完整示例:
```bash
python core/cve/examples_subscription.py
```

## 下一步

- 📖 阅读详细文档: `SUBSCRIPTION_README.md`
- 📚 查看使用指南: `SUBSCRIPTION_USAGE.md`
- 💻 运行示例代码: `examples_subscription.py`
- 🧪 运行测试脚本: `test_subscription.py`

## 常见问题

### Q: 订阅没有匹配到CVE?
**A**: 先同步CVE数据:
```python
await manager.cve_manager.sync_nvd(days_back=7)
```

### Q: 如何组合多个条件?
**A**: 创建多个订阅:
```python
# 订阅1: Apache + 高危
manager.add_subscription("keyword", "Apache", min_cvss=7.0, notify_method="console")

# 订阅2: nginx + 中危以上
manager.add_subscription("product", "nginx", min_cvss=5.0, notify_method="console")
```

### Q: Webhook如何接收通知?
**A**: 实现HTTP POST接口:
```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def handle():
    payload = request.json
    print(f"收到 {len(payload['cves'])} 个CVE")
    return {'status': 'ok'}

app.run(port=8000)
```

## 完成!

现在你已经掌握了CVE订阅管理器的基础用法,开始使用吧! 🚀
