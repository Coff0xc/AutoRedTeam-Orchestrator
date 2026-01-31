#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI PoC Generator - 快速示例
演示如何使用 AI PoC Generator 生成和执行 PoC
"""

import os
import tempfile

from ai_poc_generator import AIPoCGenerator, generate_poc
from poc_engine import PoCEngine


def example_1_basic_usage():
    """示例 1: 基础用法"""
    print("\n" + "=" * 60)
    print("示例 1: 基础用法 - 生成 SQL 注入 PoC")
    print("=" * 60)

    # 生成 PoC
    poc_yaml = generate_poc(
        cve_id="CVE-2024-1234",
        cve_description="SQL injection in WordPress Plugin Contact Form 7 via id parameter",
        severity="high",
    )

    print("\n生成的 PoC:")
    print("-" * 60)
    print(poc_yaml)
    print("-" * 60)


def example_2_all_vuln_types():
    """示例 2: 生成多种漏洞类型的 PoC"""
    print("\n" + "=" * 60)
    print("示例 2: 生成多种漏洞类型的 PoC")
    print("=" * 60)

    test_cases = {
        "SQL Injection": "SQL injection vulnerability in user login via username parameter",
        "XSS": "Cross-site scripting in search functionality allows script execution",
        "RCE": "Remote code execution in Apache Struts via OGNL injection",
        "SSRF": "Server-side request forgery in URL fetcher endpoint",
    }

    generator = AIPoCGenerator()

    for vuln_name, description in test_cases.items():
        print(f"\n[+] {vuln_name}")
        poc_yaml = generator.generate_poc(
            cve_id=f"CVE-2024-{vuln_name.replace(' ', '-')}",
            cve_description=description,
            severity="medium",
        )

        # 显示前3行
        lines = poc_yaml.split("\n")
        print(f"    {lines[0]}")
        print(f"    {lines[1]}")
        if len(lines) > 2:
            print(f"    {lines[2]}")


def example_3_with_poc_engine():
    """示例 3: 与 poc_engine 集成"""
    print("\n" + "=" * 60)
    print("示例 3: 与 poc_engine 集成")
    print("=" * 60)

    # 1. 生成 PoC
    print("\n[1] 生成 PoC...")
    poc_yaml = generate_poc(
        cve_id="CVE-2024-TEST",
        cve_description="Cross-site scripting in Joomla search parameter",
        severity="medium",
    )

    # 2. 保存到临时文件
    print("[2] 保存到临时文件...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(poc_yaml)
        temp_file = f.name
    print(f"    文件路径: {temp_file}")

    # 3. 使用 poc_engine 加载
    print("[3] 使用 poc_engine 加载...")
    engine = PoCEngine()
    template = engine.load_template(temp_file)

    if template:
        print(f"    [OK] 加载成功")
        print(f"    - Template ID: {template.info.id}")
        print(f"    - Template Name: {template.info.name}")
        print(f"    - Severity: {template.info.severity.value}")
        print(f"    - Requests: {len(template.requests)}")
    else:
        print("    [FAIL] 加载失败")

    # 4. 清理临时文件
    if os.path.exists(temp_file):
        os.unlink(temp_file)
        print("[4] 清理临时文件完成")


def example_4_custom_generation():
    """示例 4: 高级用法 - 自定义生成"""
    print("\n" + "=" * 60)
    print("示例 4: 高级用法 - 提取 CVE 信息")
    print("=" * 60)

    from ai_poc_generator import CVEParser, KeywordMatcher

    cve_description = """
    A SQL injection vulnerability in WordPress Plugin Contact Form 7
    version 5.8.1 allows remote attackers to execute arbitrary SQL
    commands via the id parameter in /admin/login.php endpoint.
    """

    print(f"\nCVE 描述:")
    print(cve_description.strip())

    print("\n提取的信息:")
    print(f"  - 产品名: {CVEParser.extract_product(cve_description)}")
    print(f"  - 版本号: {CVEParser.extract_version(cve_description)}")
    print(f"  - 路径: {CVEParser.extract_path(cve_description)}")
    print(f"  - 漏洞类型: {KeywordMatcher.identify_vuln_type(cve_description).value}")

    print("\n生成 PoC:")
    poc_yaml = generate_poc(
        cve_id="CVE-2024-CUSTOM", cve_description=cve_description, severity="high"
    )

    # 显示前10行
    lines = poc_yaml.split("\n")
    for i, line in enumerate(lines[:10], 1):
        print(f"    {i:2d} | {line}")


def example_5_save_to_file():
    """示例 5: 保存到文件"""
    print("\n" + "=" * 60)
    print("示例 5: 保存 PoC 到文件")
    print("=" * 60)

    # 生成 PoC
    poc_yaml = generate_poc(
        cve_id="CVE-2024-FILE-TEST",
        cve_description="Remote code execution in web application",
        severity="critical",
    )

    # 保存到文件
    filename = "CVE-2024-FILE-TEST.yaml"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(poc_yaml)

    print(f"\n[OK] PoC 已保存到: {filename}")
    print(f"[OK] 文件大小: {os.path.getsize(filename)} 字节")

    # 验证文件
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()
        print(f"[OK] 文件内容验证通过 ({len(content)} 字符)")

    # 清理
    if os.path.exists(filename):
        os.unlink(filename)
        print(f"[OK] 清理测试文件完成")


def main():
    """主函数"""
    print("AI PoC Generator - 快速示例")

    try:
        example_1_basic_usage()
        example_2_all_vuln_types()
        example_3_with_poc_engine()
        example_4_custom_generation()
        example_5_save_to_file()

        print("\n" + "=" * 60)
        print("所有示例运行完成!")
        print("=" * 60)

    except Exception as e:
        print(f"\n[ERROR] 示例运行失败: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
