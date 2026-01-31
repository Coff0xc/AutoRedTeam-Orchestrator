# Handlers 单元测试使用指南

## 快速开始

```bash
# 运行所有 handlers 测试
pytest tests/test_handlers_*.py -v

# 或使用简化配置
pytest tests/test_handlers_*.py -v -o addopts=""
```

## 测试文件说明

| 文件 | 描述 | 测试数量 |
|------|------|---------|
| `test_handlers_init.py` | 测试 handlers 模块初始化和注册机制 | 17 |
| `test_handlers_recon.py` | 测试侦察工具处理器 | 11 |
| `test_handlers_detector.py` | 测试漏洞检测工具处理器 | 15 |
| `test_handlers_redteam.py` | 测试红队工具处理器 | 18 |

## 运行特定测试

```bash
# 运行单个测试文件
pytest tests/test_handlers_init.py -v

# 运行特定测试类
pytest tests/test_handlers_recon.py::TestFullReconTool -v

# 运行特定测试方法
pytest tests/test_handlers_detector.py::TestSQLiScanTool::test_sqli_scan_vulnerable -v
```

## 测试覆盖率

```bash
# 生成覆盖率报告（需要安装 pytest-cov）
pip install pytest-cov

# 运行测试并生成覆盖率
pytest tests/test_handlers_*.py --cov=handlers --cov-report=html

# 查看 HTML 报告
open htmlcov/index.html  # macOS/Linux
start htmlcov/index.html  # Windows
```

## 测试特点

- ✅ 使用 Mock 模拟 MCP 实例，无需实际启动服务器
- ✅ 测试工具注册机制
- ✅ 测试输入验证和异常处理
- ✅ 测试成功和失败场景
- ✅ 100% 测试通过率

## 依赖要求

```bash
pip install pytest pytest-asyncio
```

## 常见问题

### Q: 测试失败提示 "unrecognized arguments: --cov-report"
A: 使用 `-o addopts=""` 覆盖 pyproject.toml 中的配置:
```bash
pytest tests/test_handlers_*.py -v -o addopts=""
```

### Q: 如何只运行异步测试?
A: 使用 pytest 标记:
```bash
pytest tests/test_handlers_*.py -v -m asyncio
```

### Q: 如何查看详细的失败信息?
A: 使用 `--tb=long` 参数:
```bash
pytest tests/test_handlers_*.py -v --tb=long
```

## 贡献指南

添加新测试时请遵循以下模式:

```python
@pytest.mark.asyncio
async def test_tool_name_scenario(self):
    """测试描述"""
    from handlers.xxx_handlers import register_xxx_tools
    
    # 1. 模拟 MCP
    mock_mcp = MagicMock()
    mock_counter = MagicMock()
    mock_logger = MagicMock()
    
    # 2. 捕获工具
    registered_tools = {}
    def capture_tool():
        def decorator(func):
            registered_tools[func.__name__] = func
            return func
        return decorator
    mock_mcp.tool = capture_tool
    
    # 3. 注册工具
    register_xxx_tools(mock_mcp, mock_counter, mock_logger)
    
    # 4. Mock 底层模块
    with patch('core.xxx.YYY') as mock_yyy:
        mock_yyy.return_value = expected_result
        
        # 5. 调用并验证
        result = await registered_tools['tool_name'](params)
        assert result['success'] is True
```

## 更多信息

查看 `HANDLERS_TEST_SUMMARY.md` 获取完整的测试总结和覆盖范围。
