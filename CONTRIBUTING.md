# Contributing to AutoRedTeam-Orchestrator

感谢你对 AutoRedTeam-Orchestrator 的关注！我们欢迎任何形式的贡献。

## 目录

- [开发环境搭建](#开发环境搭建)
- [代码规范](#代码规范)
- [分支策略](#分支策略)
- [提交 Pull Request](#提交-pull-request)
- [Issue 规范](#issue-规范)
- [测试要求](#测试要求)
- [代码审查标准](#代码审查标准)

---

## 开发环境搭建

### 前置要求

- Python 3.10+
- Git
- (可选) Kali Linux 或安装了安全工具的系统

### 安装步骤

```bash
# 1. Fork 并克隆仓库
git clone https://github.com/YOUR_USERNAME/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或 venv\Scripts\activate  # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 安装开发依赖
pip install flake8 black bandit pytest

# 5. 复制环境变量示例
cp .env.example .env
# 编辑 .env 填入你的 API 密钥
```

### 验证安装

```bash
# 运行 MCP 服务器
python mcp_stdio_server.py

# 运行测试
python test_server.py
```

---

## 代码规范

### Python 风格

- 遵循 [PEP 8](https://pep8.org/) 规范
- 使用 4 空格缩进
- 最大行宽 120 字符
- 使用类型注解

### 格式化工具

```bash
# 使用 Black 格式化代码
black --line-length 120 your_file.py

# 使用 flake8 检查
flake8 --max-line-length 120 your_file.py
```

### 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 函数/变量 | snake_case | `port_scan`, `target_url` |
| 类 | PascalCase | `AttackChain`, `ToolRegistry` |
| 常量 | UPPER_SNAKE_CASE | `MAX_THREADS`, `DEFAULT_TIMEOUT` |
| MCP 工具 | snake_case | `@mcp.tool() def sqli_detect()` |

### 文档字符串

```python
@mcp.tool()
def example_tool(target: str, option: bool = False) -> dict:
    """工具简短描述 - 一句话说明功能

    Args:
        target: 目标地址 (IP 或域名)
        option: 可选参数说明

    Returns:
        dict: 包含 success, data, error 等字段
    """
    pass
```

### 异常处理规范

项目使用 `core/exceptions/` 统一异常体系。请遵循以下规范：

#### 使用具体异常类型

```python
# ❌ 错误 - 泛型异常捕获
try:
    response = requests.get(url)
except Exception:
    pass

# ✅ 正确 - 捕获具体异常
from core.exceptions import HTTPError, TimeoutError, ConnectionError

try:
    response = requests.get(url)
except requests.Timeout as e:
    raise TimeoutError("请求超时", url=url, cause=e)
except requests.ConnectionError as e:
    raise ConnectionError("连接失败", url=url, cause=e)
```

#### 使用异常装饰器

```python
from core.exceptions import handle_exceptions, TimeoutError

# ✅ 推荐 - 使用装饰器处理异常
@handle_exceptions(logger=logger, reraise=True)
async def fetch_data(url: str):
    ...
```

#### 异常层次结构

| 异常基类 | 子异常 | 使用场景 |
|---------|-------|---------|
| `AutoRedTeamError` | - | 所有自定义异常的基类 |
| `HTTPError` | `TimeoutError`, `ConnectionError`, `SSLError` | 网络请求错误 |
| `AuthError` | `InvalidCredentials`, `PermissionDenied` | 认证/授权错误 |
| `ScanError` | `TargetUnreachable`, `RateLimited` | 扫描过程错误 |
| `ExploitError` | `ExploitFailed`, `ShellError` | 漏洞利用错误 |
| `LateralError` | `SMBError`, `SSHError`, `WMIError` | 横向移动错误 |

#### 何时可以使用 `except Exception`

1. **顶层错误处理器** - 如 `handlers/error_handling.py` 中的装饰器
2. **清理代码** - 确保资源释放的 finally 替代方案
3. **必须记录日志** - 捕获后必须记录异常信息

```python
# ✅ 可接受 - 顶层处理器记录所有未预期错误
except Exception as e:
    logger.exception(f"未预期的错误: {e}")
    return {'success': False, 'error': str(e)}
```

---

## 分支策略

| 分支 | 用途 |
|------|------|
| `main` | 稳定版本，只接受 PR 合并 |
| `dev` | 开发分支，新功能先合并到这里 |
| `feature/*` | 新功能分支，如 `feature/add-xxe-detect` |
| `fix/*` | Bug 修复分支，如 `fix/sqli-false-positive` |
| `docs/*` | 文档更新分支 |

### 工作流程

```bash
# 1. 从 main 创建功能分支
git checkout main
git pull origin main
git checkout -b feature/your-feature

# 2. 开发并提交
git add .
git commit -m "feat: add XXE detection tool"

# 3. 推送并创建 PR
git push origin feature/your-feature
```

---

## 提交 Pull Request

### Commit 消息规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Type 类型**:
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式 (不影响功能)
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建/工具变更

**示例**:
```
feat(tools): add SSTI detection tool

- Support Jinja2, Twig, Freemarker templates
- Add 50+ detection payloads
- Integrate with auto_pentest workflow

Closes #123
```

### PR 检查清单

- [ ] 代码通过 `flake8` 检查
- [ ] 代码通过 `black` 格式化
- [ ] 添加了必要的测试
- [ ] 更新了相关文档
- [ ] Commit 消息符合规范
- [ ] PR 描述清晰完整

---

## Issue 规范

### Bug 报告

请使用 Bug Report 模板，包含：
- 问题描述
- 复现步骤
- 期望行为
- 实际行为
- 环境信息 (OS, Python 版本)
- 错误日志

### 功能请求

请使用 Feature Request 模板，包含：
- 功能描述
- 使用场景
- 可能的实现方案

### 安全漏洞

**请勿公开报告安全漏洞！** 请参阅 [SECURITY.md](SECURITY.md)

---

## 测试要求

### 运行测试

```bash
# 运行所有测试
pytest tests/

# 运行特定测试
pytest tests/test_tools.py -v

# 生成覆盖率报告
pytest --cov=. --cov-report=html
```

### 测试规范

- 新功能必须包含单元测试
- 测试文件命名: `test_*.py`
- 测试函数命名: `test_功能描述`
- 使用 `pytest` 框架

### 示例测试

```python
def test_port_scan_open_port():
    """测试端口扫描 - 开放端口检测"""
    result = port_scan("127.0.0.1", "22,80,443")
    assert result["success"] == True
    assert "open_ports" in result["data"]

def test_sqli_detect_error_based():
    """测试 SQL 注入检测 - 错误型注入"""
    result = sqli_detect("http://testphp.vulnweb.com/listproducts.php?cat=1")
    assert result["success"] == True
```

---

## 代码审查标准

PR 将根据以下标准进行审查：

### 功能性
- [ ] 代码实现了预期功能
- [ ] 边界情况已处理
- [ ] 错误处理完善

### 安全性
- [ ] 无命令注入风险
- [ ] 无敏感信息泄露
- [ ] 输入已验证/过滤

### 可维护性
- [ ] 代码清晰易读
- [ ] 有适当的注释
- [ ] 遵循项目代码规范

### 性能
- [ ] 无明显性能问题
- [ ] 资源使用合理

---

## 获取帮助

- 📖 查看 [README.md](README.md) 了解项目概述
- 💬 在 Issue 中提问
- 📧 联系维护者

感谢你的贡献！
