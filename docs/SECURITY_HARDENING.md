# AutoRedTeam-Orchestrator 安全加固方案

## 概述

本文档提供完整的安全加固实施方案，解决项目中存在的安全问题。

## 已识别的安全问题

### 1. 命令注入风险
- **位置**: `utils/command_executor.py`, `tools/external_tools.py`, `core/persistence/webshell_manager.py`
- **问题**: 使用 `shell=True`, `os.system()` 执行命令
- **风险**: 攻击者可通过参数注入执行任意命令

### 2. 路径遍历漏洞
- **位置**: `core/session_manager.py`, 文件上传/下载功能
- **问题**: 未充分验证文件路径
- **风险**: 读取/写入任意文件

### 3. 代码执行漏洞
- **位置**: `modules/smart_payload_engine.py`, `core/evasion/payload_obfuscator.py`
- **问题**: 使用 `exec()`, `eval()` 执行动态代码
- **风险**: 远程代码执行

### 4. 无认证机制
- **位置**: MCP工具接口
- **问题**: 所有工具无需认证即可调用
- **风险**: 未授权访问敏感功能

### 5. 输入校验缺失
- **位置**: 多个工具函数
- **问题**: 未验证URL、IP、端口等参数
- **风险**: 注入攻击、SSRF

### 6. 硬编码敏感信息
- **位置**: `config/config.yaml`
- **问题**: API密钥明文存储
- **风险**: 密钥泄露

## 解决方案

### 1. 输入验证框架

**文件**: `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\input_validator.py`

**核心功能**:
- 统一的输入校验装饰器
- URL/IP/端口/路径验证
- 防止路径遍历、XSS、SQL注入
- 命令参数白名单验证

**使用示例**:
```python
from core.security import InputValidator, validate_params, ValidationError

# 方式1: 直接调用
validator = InputValidator()
url = validator.validate_url("http://example.com")
ip = validator.validate_ip("192.168.1.1")
port = validator.validate_port(8080)

# 方式2: 装饰器
@validate_params(
    url=lambda x: InputValidator.validate_url(x),
    port=lambda x: InputValidator.validate_port(x)
)
def scan_target(url: str, port: int):
    # 参数已自动验证
    pass

# 方式3: 路径验证（防止路径遍历）
safe_path = validator.validate_path(
    "uploads/file.txt",
    base_dir="/var/www/uploads",
    must_exist=False
)
```

### 2. 安全命令执行

**文件**: `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\safe_executor.py`

**核心功能**:
- 命令白名单机制
- 参数验证
- 禁止 `shell=True`
- 沙箱执行支持

**使用示例**:
```python
from core.security import SafeExecutor, ExecutionPolicy, SecurityError

# 创建执行器（严格模式）
executor = SafeExecutor(policy=ExecutionPolicy.STRICT)

# 执行安全命令
result = executor.execute(["nmap", "-sV", "192.168.1.1"], timeout=300)

if result["success"]:
    print(result["stdout"])
else:
    print(result["error"])

# 添加自定义白名单
from core.security import CommandWhitelist

executor.add_whitelist("custom_tool", CommandWhitelist(
    command="custom_tool",
    allowed_args=["-a", "-b", "-c"],
    max_args=10,
    description="自定义工具"
))
```

**迁移指南**:
```python
# 旧代码（不安全）
import subprocess
result = subprocess.run(f"nmap -sV {target}", shell=True)

# 新代码（安全）
from core.security import safe_execute
result = safe_execute(["nmap", "-sV", target], timeout=300)
```

### 3. 认证授权机制

**文件**: `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\auth_manager.py`

**核心功能**:
- API Key生成和管理
- 工具分级授权（SAFE/MODERATE/DANGEROUS/CRITICAL）
- 速率限制
- 审计日志

**使用示例**:
```python
from core.security import AuthManager, Permission, ToolLevel

# 初始化认证管理器
auth = AuthManager()

# 生成API密钥
key_info = auth.generate_key(
    name="测试密钥",
    permissions=[Permission.SCAN, Permission.EXPLOIT],
    max_tool_level=ToolLevel.DANGEROUS,
    expires_days=30,
    rate_limit=100
)

print(f"API Key: {key_info['full_key']}")

# 验证密钥
api_key = auth.verify_key(key_info['full_key'])
if api_key:
    # 检查工具权限
    if auth.check_permission(api_key, "sqli_detect"):
        # 执行工具
        pass

    # 记录审计日志
    auth.audit(
        key_id=api_key.key_id,
        tool_name="sqli_detect",
        params={"url": "http://example.com"},
        success=True
    )
```

**工具等级分类**:
- **SAFE**: 信息收集（port_scan, dns_lookup, whois_query）
- **MODERATE**: 漏洞扫描（sqli_detect, xss_detect, vuln_check）
- **DANGEROUS**: 漏洞利用（exploit_sqli_extract, brute_force）
- **CRITICAL**: 后渗透（lateral_*_exec, persistence_*, credential_dump）

### 4. 敏感信息管理

**文件**: `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\secrets_manager.py`

**核心功能**:
- 配置文件加密
- 环境变量管理
- 密钥轮换
- 主密钥保护

**使用示例**:
```python
from core.security import SecretsManager, get_secret, set_secret

# 设置敏感信息
set_secret("OPENAI_API_KEY", "sk-xxx")
set_secret("DATABASE_PASSWORD", "secret123")

# 获取敏感信息（优先从环境变量读取）
api_key = get_secret("OPENAI_API_KEY")

# 密钥轮换
manager = SecretsManager()
manager.rotate_master_key("new_master_key")

# 加密配置文件
from core.security import ConfigEncryptor

ConfigEncryptor.encrypt_config(
    config_path="config/config.yaml",
    output_path="config/config.enc",
    master_key="your_master_key"
)
```

**环境变量配置**:
```bash
# .env 文件
REDTEAM_MASTER_KEY=your_master_key_here
OPENAI_API_KEY=sk-xxx
SHODAN_API_KEY=xxx
```

## 集成到现有代码

### 步骤1: 更新 `utils/command_executor.py`

```python
# 在文件开头添加
from core.security import safe_execute, ValidationError

# 修改 execute_command 函数
def execute_command(cmd: List[str], timeout: int = 300, **kwargs) -> Dict:
    """使用安全执行器"""
    try:
        return safe_execute(cmd, timeout=timeout, **kwargs)
    except ValidationError as e:
        return {
            "success": False,
            "error": f"参数验证失败: {e}",
            "stdout": "",
            "stderr": "",
            "returncode": -1
        }
```

### 步骤2: 为MCP工具添加认证

```python
# 在 mcp_stdio_server.py 中添加
from core.security import get_auth_manager, ValidationError

auth_manager = get_auth_manager()

# 装饰器：要求认证
def require_auth_mcp(tool_name: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # 从请求中获取API Key
            api_key_str = kwargs.get("api_key") or os.getenv("REDTEAM_API_KEY")

            if not api_key_str:
                return {"error": "需要API Key认证"}

            # 验证密钥
            api_key = auth_manager.verify_key(api_key_str)
            if not api_key:
                return {"error": "无效的API Key"}

            # 检查权限
            if not auth_manager.check_permission(api_key, tool_name):
                return {"error": f"无权限访问工具: {tool_name}"}

            # 执行工具
            try:
                result = await func(*args, **kwargs)

                # 记录审计日志
                auth_manager.audit(
                    key_id=api_key.key_id,
                    tool_name=tool_name,
                    params=kwargs,
                    success=True
                )

                return result

            except Exception as e:
                auth_manager.audit(
                    key_id=api_key.key_id,
                    tool_name=tool_name,
                    params=kwargs,
                    success=False,
                    error=str(e)
                )
                raise

        return wrapper
    return decorator

# 使用示例
@mcp.tool()
@require_auth_mcp("sqli_detect")
async def sqli_detect(url: str, api_key: str = None):
    """SQL注入检测"""
    # 输入验证
    url = InputValidator.validate_url(url)

    # 执行检测
    pass
```

### 步骤3: 更新配置管理

```python
# 在 utils/config_manager.py 中
from core.security import get_secret, EnvironmentManager

class ConfigManager:
    def __init__(self):
        # 加载环境变量
        EnvironmentManager.load_env_file(".env")

        # 从加密存储读取敏感信息
        self.openai_key = get_secret("OPENAI_API_KEY")
        self.shodan_key = get_secret("SHODAN_API_KEY")
```

## 部署清单

### 1. 安装依赖
```bash
pip install cryptography
```

### 2. 生成主密钥
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. 配置环境变量
```bash
# Linux/macOS
export REDTEAM_MASTER_KEY="your_key_here"

# Windows
set REDTEAM_MASTER_KEY=your_key_here
```

### 4. 初始化认证系统
```python
from core.security import get_auth_manager, Permission, ToolLevel

auth = get_auth_manager()

# 生成管理员密钥
admin_key = auth.generate_key(
    name="管理员",
    permissions=[Permission.ADMIN],
    max_tool_level=ToolLevel.CRITICAL
)

print(f"管理员密钥: {admin_key['full_key']}")
```

### 5. 迁移敏感信息
```python
from core.security import set_secret

# 从 config.yaml 迁移到加密存储
set_secret("OPENAI_API_KEY", "sk-xxx")
set_secret("SHODAN_API_KEY", "xxx")

# 删除 config.yaml 中的明文密钥
```

## 安全最佳实践

### 1. 命令执行
- 永远不使用 `shell=True`
- 使用列表形式传递命令参数
- 验证所有用户输入
- 使用白名单限制可执行命令

### 2. 文件操作
- 使用 `Path.resolve()` 规范化路径
- 验证路径在允许的目录内
- 检查 `..` 和绝对路径
- 设置适当的文件权限

### 3. 认证授权
- 所有敏感工具必须认证
- 使用最小权限原则
- 定期轮换密钥
- 记录审计日志

### 4. 敏感信息
- 使用环境变量或加密存储
- 不在代码中硬编码密钥
- 不提交 `.env` 文件到Git
- 定期审查敏感信息访问

### 5. 输入验证
- 验证所有外部输入
- 使用白名单而非黑名单
- 对输出进行编码
- 防止注入攻击

## 测试验证

### 1. 输入验证测试
```python
from core.security import InputValidator, ValidationError

validator = InputValidator()

# 测试路径遍历
try:
    validator.validate_path("../etc/passwd", base_dir="/tmp")
    assert False, "应该抛出异常"
except ValidationError:
    print("路径遍历防护正常")

# 测试命令注入
try:
    validator.validate_command_args(["nmap", "-sV; rm -rf /"])
    assert False, "应该抛出异常"
except ValidationError:
    print("命令注入防护正常")
```

### 2. 认证测试
```python
from core.security import get_auth_manager, Permission, ToolLevel

auth = get_auth_manager()

# 生成测试密钥
key = auth.generate_key(
    name="测试",
    permissions=[Permission.SCAN],
    max_tool_level=ToolLevel.MODERATE
)

# 验证权限
api_key = auth.verify_key(key['full_key'])
assert auth.check_permission(api_key, "sqli_detect") == True
assert auth.check_permission(api_key, "lateral_smb_exec") == False
print("权限控制正常")
```

## 文件清单

已创建的安全模块文件:
1. `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\input_validator.py` - 输入验证框架
2. `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\safe_executor.py` - 安全命令执行
3. `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\auth_manager.py` - 认证授权管理
4. `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\secrets_manager.py` - 敏感信息管理
5. `E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\security\__init__.py` - 模块初始化

## 后续工作

1. **代码审计**: 使用 `bandit` 扫描现有代码
2. **集成测试**: 编写完整的安全测试套件
3. **文档更新**: 更新开发者文档和API文档
4. **培训**: 团队安全编码培训
5. **持续监控**: 设置安全告警和监控

## 参考资源

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/
- Python Security Best Practices: https://python.readthedocs.io/en/stable/library/security_warnings.html
