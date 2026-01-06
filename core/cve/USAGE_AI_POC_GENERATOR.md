# AI PoC Generator - 使用指南

## 概述

`ai_poc_generator.py` 是一个基于规则匹配的智能 PoC 模板生成器,可以根据 CVE 描述自动生成 YAML 格式的 PoC 模板,兼容 `poc_engine.py`。

## 核心特性

- **智能漏洞类型识别**: 基于关键词匹配识别 10+ 种漏洞类型
- **自动信息提取**: 从 CVE 描述中提取产品名、版本号、路径等
- **多种模板支持**: SQL注入、XSS、RCE、路径遍历、SSRF、认证绕过等
- **纯 Python 实现**: 无需外部 AI API,基于规则匹配
- **YAML 格式输出**: 兼容 poc_engine,可直接加载执行

## 快速开始

### 基础用法

```python
from core.cve.ai_poc_generator import generate_poc

# 生成 SQL 注入 PoC
poc_yaml = generate_poc(
    cve_id="CVE-2024-1234",
    cve_description="SQL injection in WordPress Plugin Contact Form 7 via id parameter",
    severity="high"
)

print(poc_yaml)
```

### 高级用法

```python
from core.cve.ai_poc_generator import AIPoCGenerator

generator = AIPoCGenerator()

# 生成 PoC
poc_yaml = generator.generate_poc(
    cve_id="CVE-2024-5678",
    cve_description="Cross-site scripting vulnerability in Joomla search functionality",
    severity="medium"
)

# 保存到文件
with open("CVE-2024-5678.yaml", "w", encoding="utf-8") as f:
    f.write(poc_yaml)
```

### 与 poc_engine 集成

```python
from core.cve.ai_poc_generator import generate_poc
from core.cve.poc_engine import PoCEngine
import tempfile

# 1. 生成 PoC
poc_yaml = generate_poc(
    cve_id="CVE-2024-9999",
    cve_description="Remote code execution in Apache Struts",
    severity="critical"
)

# 2. 保存到临时文件
with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    f.write(poc_yaml)
    temp_file = f.name

# 3. 使用 poc_engine 加载并执行
engine = PoCEngine()
template = engine.load_template(temp_file)

# 4. 执行 PoC
results = engine.run(template, "http://target.com")

for result in results:
    if result.vulnerable:
        print(f"[+] 发现漏洞: {result.template_name}")
```

## 支持的漏洞类型

| 漏洞类型 | 识别关键词 | CWE ID |
|---------|-----------|--------|
| SQL注入 | sql injection, sqli, sql query | CWE-89 |
| XSS | cross-site scripting, xss, script injection | CWE-79 |
| RCE | remote code execution, rce, code execution | CWE-94 |
| 路径遍历 | path traversal, directory traversal, lfi | CWE-22 |
| SSRF | server-side request forgery, ssrf | CWE-918 |
| 认证绕过 | authentication bypass, auth bypass | CWE-287 |
| XXE | xml external entity, xxe | CWE-611 |
| 文件上传 | file upload, unrestricted upload | CWE-434 |
| 命令注入 | command injection, os command | CWE-78 |
| IDOR | insecure direct object reference, idor | CWE-639 |

## 生成的 PoC 模板示例

### SQL 注入模板

```yaml
id: CVE-2024-1234

info:
  name: WordPress Plugin - SQL Injection
  severity: high
  description: SQL injection vulnerability in WordPress Plugin
  tags:
    - sqli
    - injection
    - cve-2024-1234
  classification:
    cve-id: CVE-2024-1234
    cwe-id: CWE-89

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?id=1' OR '1'='1"
      - "{{BaseURL}}/search?id=1' AND SLEEP(5)--"
    matchers:
      - type: word
        words:
          - "mysql_fetch"
          - "syntax error"
          - "SQL syntax"
          - "mysqli_"
          - "pg_query"
        part: body
        condition: or
      - type: status
        status:
          - 200
          - 500
    matchers-condition: and
```

### XSS 模板

```yaml
id: CVE-2024-5678

info:
  name: Joomla - Cross-Site Scripting
  severity: medium
  description: XSS vulnerability in Joomla
  tags:
    - xss
    - injection
    - cve-2024-5678
  classification:
    cve-id: CVE-2024-5678
    cwe-id: CWE-79

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?search=<script>alert(1)</script>"
      - "{{BaseURL}}/search?search=<img src=x onerror=alert(1)>"
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
          - "<img src=x onerror=alert(1)>"
          - "onerror=alert"
        part: body
        condition: or
      - type: word
        words:
          - "text/html"
        part: header
    matchers-condition: and
```

## API 参考

### generate_poc()

便捷函数,快速生成 PoC。

```python
def generate_poc(cve_id: str, cve_description: str, severity: str = "medium") -> str
```

**参数:**
- `cve_id`: CVE 编号 (如 "CVE-2024-1234")
- `cve_description`: CVE 描述文本
- `severity`: 严重性级别 ("info" | "low" | "medium" | "high" | "critical")

**返回:**
- YAML 格式的 PoC 模板字符串

### AIPoCGenerator

主生成器类。

```python
class AIPoCGenerator:
    def generate_poc(self, cve_id: str, cve_description: str, severity: str = "medium") -> str
```

### KeywordMatcher

漏洞类型识别器。

```python
class KeywordMatcher:
    @staticmethod
    def identify_vuln_type(description: str) -> VulnType
```

### CVEParser

CVE 信息提取器。

```python
class CVEParser:
    @staticmethod
    def extract_product(description: str) -> str

    @staticmethod
    def extract_version(description: str) -> str

    @staticmethod
    def extract_path(description: str) -> str

    @staticmethod
    def extract_keywords(description: str) -> List[str]
```

## 工作原理

### 1. 漏洞类型识别

基于关键词匹配,对描述文本进行分词分析:

```python
description = "SQL injection in login form"
vuln_type = KeywordMatcher.identify_vuln_type(description)
# => VulnType.SQL_INJECTION
```

### 2. 信息提取

使用正则表达式提取关键信息:

```python
description = "A vulnerability in WordPress Plugin Contact Form 7 version 5.8.1"

product = CVEParser.extract_product(description)
# => "WordPress Plugin Contact Form 7"

version = CVEParser.extract_version(description)
# => "5.8.1"
```

### 3. 模板生成

根据漏洞类型选择对应的模板生成器:

```python
template_dict = PoCTemplateGenerator.generate_sqli_template(cve_info)
```

### 4. YAML 格式化

使用 `yaml.dump` 转换为 YAML 字符串,自动处理特殊字符转义。

## 最佳实践

### 1. 提供详细的 CVE 描述

```python
# 好 - 包含产品、版本、路径等信息
description = """
SQL injection vulnerability in WordPress Plugin Contact Form 7
version 5.8.1 allows remote attackers to execute arbitrary SQL
commands via the id parameter in /admin/login.php endpoint.
"""

# 差 - 信息不足
description = "SQL injection vulnerability"
```

### 2. 验证生成的 PoC

```python
import yaml

poc_yaml = generate_poc(cve_id, description, severity)

# 验证 YAML 语法
try:
    parsed = yaml.safe_load(poc_yaml)
    assert 'id' in parsed
    assert 'info' in parsed
    assert 'requests' in parsed
    print("PoC 格式正确")
except Exception as e:
    print(f"PoC 格式错误: {e}")
```

### 3. 手动优化 Payload

生成的模板是基础版本,建议根据实际情况优化:

- 调整请求路径
- 添加自定义 Payload
- 优化 Matcher 条件
- 添加 Extractor 提取数据

## 限制与注意事项

1. **基于规则匹配**: 不使用外部 AI,识别准确度取决于关键词匹配
2. **模板通用性**: 生成的是通用模板,需根据实际情况调整
3. **路径识别**: 如果描述中没有明确路径,会使用默认路径
4. **产品名提取**: 依赖正则表达式,可能不够精确

## 故障排除

### Q: 生成的 PoC 无法加载?

A: 检查 YAML 语法:

```python
import yaml

try:
    yaml.safe_load(poc_yaml)
except yaml.YAMLError as e:
    print(f"YAML 错误: {e}")
```

### Q: 漏洞类型识别错误?

A: 在描述中添加更明确的关键词:

```python
# 改进描述
description = "SQL injection vulnerability (SQLi) in database query"
```

### Q: 提取的产品名不准确?

A: 手动指定产品信息,或者生成后手动修改 YAML。

## 测试

运行完整测试套件:

```bash
cd E:\A-2026-project\Github-project\AutoRedTeam-Orchestrator\core\cve
python test_ai_poc_generator.py
```

测试覆盖:
- 漏洞类型识别
- PoC 生成
- poc_engine 兼容性
- 所有漏洞类型生成
- CVE 信息提取
- YAML 格式化

## 文件结构

```
core/cve/
├── ai_poc_generator.py         # 主模块
├── poc_engine.py                # PoC 执行引擎
├── test_ai_poc_generator.py    # 测试套件
└── USAGE_AI_POC_GENERATOR.md   # 本文档
```

## 贡献

欢迎贡献新的漏洞类型模板或改进现有模板!

## License

MIT License - 仅供授权测试和教育使用
