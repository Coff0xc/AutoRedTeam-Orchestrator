#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI PoC Generator 集成测试
验证生成的模板与 poc_engine 的兼容性
"""

import os
import sys
import tempfile
import yaml
from pathlib import Path

# 设置UTF-8输出 (Windows兼容)
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# 导入生成器
from ai_poc_generator import AIPoCGenerator, generate_poc, VulnType, KeywordMatcher

# 导入PoC引擎
from poc_engine import PoCEngine, YAMLPoCParser


def test_vuln_type_detection():
    """测试漏洞类型识别"""
    print("\n[Test 1] 漏洞类型识别")
    print("-" * 60)

    test_cases = [
        ("SQL injection in login form", VulnType.SQL_INJECTION),
        ("Cross-site scripting vulnerability", VulnType.XSS),
        ("Remote code execution via OGNL", VulnType.RCE),
        ("Path traversal allows reading /etc/passwd", VulnType.PATH_TRAVERSAL),
        ("Server-side request forgery in API", VulnType.SSRF),
        ("Authentication bypass using header injection", VulnType.AUTH_BYPASS),
    ]

    for description, expected_type in test_cases:
        detected = KeywordMatcher.identify_vuln_type(description)
        status = "[OK]" if detected == expected_type else "[FAIL]"
        print(f"{status} '{description[:40]}...' => {detected.value}")

    print()


def test_poc_generation():
    """测试PoC生成"""
    print("\n[Test 2] PoC生成")
    print("-" * 60)

    generator = AIPoCGenerator()

    # 测试SQL注入
    sqli_yaml = generator.generate_poc(
        cve_id="CVE-TEST-0001",
        cve_description="SQL injection in WordPress Plugin Contact Form 7 via id parameter",
        severity="high"
    )

    print("Generated SQL Injection PoC:")
    print(sqli_yaml[:300], "...\n")

    # 验证YAML语法
    try:
        yaml.safe_load(sqli_yaml)
        print("[OK] YAML语法正确\n")
    except yaml.YAMLError as e:
        print(f"[FAIL] YAML语法错误: {e}\n")


def test_poc_engine_compatibility():
    """测试与 poc_engine 的兼容性"""
    print("\n[Test 3] poc_engine 兼容性测试")
    print("-" * 60)

    # 生成PoC
    generator = AIPoCGenerator()
    poc_yaml = generator.generate_poc(
        cve_id="CVE-TEST-0002",
        cve_description="Cross-site scripting in Joomla search parameter",
        severity="medium"
    )

    # 保存到临时文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as f:
        f.write(poc_yaml)
        temp_file = f.name

    try:
        # 使用 poc_engine 加载
        engine = PoCEngine()
        template = engine.load_template(temp_file)

        if template:
            print(f"[OK] PoC引擎加载成功")
            print(f"  - Template ID: {template.info.id}")
            print(f"  - Template Name: {template.info.name}")
            print(f"  - Severity: {template.info.severity.value}")
            print(f"  - Requests: {len(template.requests)}")
            print()
        else:
            print("[FAIL] PoC引擎加载失败\n")

    finally:
        # 清理临时文件
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def test_all_vuln_types():
    """测试所有漏洞类型的生成"""
    print("\n[Test 4] 所有漏洞类型生成测试")
    print("-" * 60)

    test_cases = {
        "SQL Injection": "SQL injection vulnerability in user login",
        "XSS": "Cross-site scripting in search functionality",
        "RCE": "Remote code execution via template injection",
        "Path Traversal": "Directory traversal allows file read",
        "SSRF": "Server-side request forgery in URL fetcher",
        "Auth Bypass": "Authentication bypass using X-Forwarded-For",
    }

    generator = AIPoCGenerator()

    for name, description in test_cases.items():
        try:
            poc_yaml = generator.generate_poc(
                cve_id=f"CVE-TEST-{name.replace(' ', '-')}",
                cve_description=description,
                severity="medium"
            )

            # 验证YAML
            parsed = yaml.safe_load(poc_yaml)

            # 验证必需字段
            assert 'id' in parsed, "Missing 'id'"
            assert 'info' in parsed, "Missing 'info'"
            assert 'requests' in parsed, "Missing 'requests'"

            print(f"[OK] {name} - 生成成功")

        except Exception as e:
            print(f"[FAIL] {name} - 生成失败: {e}")

    print()


def test_cve_parsing():
    """测试CVE信息提取"""
    print("\n[Test 5] CVE信息提取测试")
    print("-" * 60)

    from ai_poc_generator import CVEParser

    # 测试产品名提取
    description = "A vulnerability in WordPress Plugin Contact Form 7 version 5.8.1 allows..."
    product = CVEParser.extract_product(description)
    print(f"Product: {product}")

    # 测试版本号提取
    version = CVEParser.extract_version(description)
    print(f"Version: {version}")

    # 测试路径提取
    description_with_path = "SQL injection in /admin/login.php endpoint"
    path = CVEParser.extract_path(description_with_path)
    print(f"Path: {path}")

    # 测试关键词提取
    keywords = CVEParser.extract_keywords(description)
    print(f"Keywords: {keywords}")

    print()


def test_yaml_formatting():
    """测试YAML格式化"""
    print("\n[Test 6] YAML格式化测试")
    print("-" * 60)

    generator = AIPoCGenerator()
    poc_yaml = generator.generate_poc(
        cve_id="CVE-2024-TEST",
        cve_description="Test vulnerability for YAML formatting",
        severity="low"
    )

    # 验证缩进
    lines = poc_yaml.split('\n')
    print(f"Total lines: {len(lines)}")

    # 检查关键行
    key_checks = [
        ("id:", lines[0].startswith("id:")),
        ("info:", "info:" in poc_yaml),
        ("requests:", "requests:" in poc_yaml),
        ("matchers:", "matchers:" in poc_yaml),
    ]

    for key, result in key_checks:
        status = "[OK]" if result else "[FAIL]"
        print(f"{status} {key} present")

    print()


def main():
    """主测试函数"""
    print("=" * 60)
    print("AI PoC Generator - 集成测试")
    print("=" * 60)

    try:
        test_vuln_type_detection()
        test_poc_generation()
        test_poc_engine_compatibility()
        test_all_vuln_types()
        test_cve_parsing()
        test_yaml_formatting()

        print("=" * 60)
        print("[SUCCESS] 所有测试完成!")
        print("=" * 60)

    except Exception as e:
        print(f"\n[ERROR] 测试失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
