#!/usr/bin/env python3
"""
PoC引擎测试脚本
演示如何使用YAML PoC引擎进行漏洞检测
"""

import sys
import os
from pathlib import Path

# 确保项目根目录在路径中（与 tests/test_v25_integration.py 保持一致）
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cve import PoCEngine, SeverityLevel

def test_variable_replacement():
    """测试变量替换功能"""
    print("\n[*] 测试1: 变量替换")
    print("="*50)

    from core.cve.poc_engine import VariableReplacer

    test_cases = [
        ("URL: {{BaseURL}}/api", "https://example.com"),
        ("Host: {{Hostname}}", "https://test.example.com:8080"),
        ("Random: {{randstr}}", "https://example.com"),
    ]

    for text, base_url in test_cases:
        result = VariableReplacer.replace_variables(text, base_url)
        print(f"  原始: {text}")
        print(f"  替换: {result}")

def test_template_parsing():
    """测试模板解析"""
    print("\n[*] 测试2: YAML模板解析")
    print("="*50)

    # 创建测试模板
    test_template = {
        "id": "test-001",
        "info": {
            "name": "Test PoC",
            "author": "test",
            "severity": "high",
            "description": "Test template",
            "tags": ["test"]
        },
        "requests": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/test"],
                "headers": {
                    "User-Agent": "Mozilla/5.0"
                },
                "matchers": [
                    {
                        "type": "status",
                        "status": [200]
                    }
                ]
            }
        ]
    }

    engine = PoCEngine()
    template = engine.load_template_from_dict(test_template)

    if template:
        print(f"  [+] 模板ID: {template.info.id}")
        print(f"  [+] 模板名称: {template.info.name}")
        print(f"  [+] 严重性: {template.info.severity.value}")
        print(f"  [+] 请求数: {len(template.requests)}")
    else:
        print("  [-] 模板解析失败")

def test_poc_execution():
    """测试PoC执行"""
    print("\n[*] 测试3: PoC执行测试")
    print("="*50)

    # 使用简单的HTTP测试
    test_template = {
        "id": "http-test",
        "info": {
            "name": "HTTP Status Test",
            "severity": "info",
            "description": "Test HTTP connectivity",
        },
        "requests": [
            {
                "method": "GET",
                "path": ["/"],
                "matchers": [
                    {
                        "type": "status",
                        "status": [200, 301, 302, 404]
                    }
                ]
            }
        ]
    }

    engine = PoCEngine(timeout=5.0, verify_ssl=False)
    template = engine.load_template_from_dict(test_template)

    # 测试公开可访问的网站
    test_target = "http://httpbin.org"

    try:
        print(f"  [*] 测试目标: {test_target}")
        results = engine.run(template, test_target)

        if results:
            for result in results:
                print(f"  [+] 匹配成功: {result.matched_at}")
                print(f"  [+] 证据: {result.evidence}")
        else:
            print("  [-] 无匹配结果")
    except Exception as e:
        print(f"  [!] 执行失败: {e}")
    finally:
        engine.close()

def test_batch_execution():
    """测试批量执行"""
    print("\n[*] 测试4: 批量执行测试")
    print("="*50)

    from core.cve import execute_poc_batch

    test_template = {
        "id": "batch-test",
        "info": {
            "name": "Batch Test",
            "severity": "info"
        },
        "requests": [
            {
                "method": "GET",
                "path": ["/"],
                "matchers": [
                    {
                        "type": "status",
                        "status": [200, 301, 302, 404]
                    }
                ]
            }
        ]
    }

    targets = [
        "http://httpbin.org",
        "http://example.com",
    ]

    engine = PoCEngine()
    template = engine.load_template_from_dict(test_template)

    try:
        print(f"  [*] 测试 {len(targets)} 个目标")
        results = execute_poc_batch(template, targets, concurrency=2, timeout=5.0)
        print(f"  [+] 完成扫描，共 {len(results)} 个结果")
    except Exception as e:
        print(f"  [!] 批量执行失败: {e}")

def main():
    print("\n" + "="*50)
    print("  YAML PoC 引擎测试套件")
    print("="*50)

    try:
        test_variable_replacement()
        test_template_parsing()
        test_poc_execution()
        test_batch_execution()

        print("\n" + "="*50)
        print("  [SUCCESS] 所有测试完成!")
        print("="*50 + "\n")

    except Exception as e:
        print(f"\n[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
