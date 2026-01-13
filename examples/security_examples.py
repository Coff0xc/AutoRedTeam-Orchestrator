#!/usr/bin/env python3
"""
安全加固模块使用示例
演示如何在实际项目中使用安全模块
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def example_input_validation():
    """示例1: 输入验证"""
    print("=" * 60)
    print("示例1: 输入验证")
    print("=" * 60)

    from core.security import InputValidator, ValidationError

    validator = InputValidator()

    # 验证URL
    print("\n[*] 验证URL:")
    try:
        url = validator.validate_url("http://example.com")
        print(f"  [+] 有效URL: {url}")
    except ValidationError as e:
        print(f"  [-] 验证失败: {e}")

    try:
        url = validator.validate_url("javascript:alert(1)")
        print(f"  [+] 有效URL: {url}")
    except ValidationError as e:
        print(f"  [-] 验证失败: {e} (预期)")

    # 验证IP
    print("\n[*] 验证IP:")
    try:
        ip = validator.validate_ip("192.168.1.1")
        print(f"  [+] 有效IP: {ip}")
    except ValidationError as e:
        print(f"  [-] 验证失败: {e}")

    # 验证路径（防止路径遍历）
    print("\n[*] 验证路径:")
    try:
        path = validator.validate_path("test.txt", base_dir=".", allow_create=True)
        print(f"  [+] 安全路径: {path}")
    except ValidationError as e:
        print(f"  [-] 验证失败: {e}")

    try:
        path = validator.validate_path("../etc/passwd", base_dir=".")
        print(f"  [+] 安全路径: {path}")
    except ValidationError as e:
        print(f"  [-] 验证失败: {e} (预期)")


def example_safe_executor():
    """示例2: 安全命令执行"""
    print("\n" + "=" * 60)
    print("示例2: 安全命令执行")
    print("=" * 60)

    from core.security import SafeExecutor, ExecutionPolicy, SecurityError

    executor = SafeExecutor(policy=ExecutionPolicy.STRICT)

    # 执行安全命令
    print("\n[*] 执行安全命令:")
    result = executor.execute(["python", "--version"], timeout=5)
    if result["success"]:
        print(f"  [+] 执行成功: {result['stdout'].strip()}")
    else:
        print(f"  [-] 执行失败: {result['error']}")

    # 尝试执行危险命令
    print("\n[*] 尝试执行危险命令:")
    try:
        result = executor.execute(["rm", "-rf", "/"], timeout=5)
        print(f"  [+] 执行成功: {result}")
    except SecurityError as e:
        print(f"  [-] 安全拦截: {e} (预期)")

    # 尝试命令注入
    print("\n[*] 尝试命令注入:")
    try:
        result = executor.execute(["python", "-c; rm -rf /"], timeout=5)
        print(f"  [+] 执行成功: {result}")
    except SecurityError as e:
        print(f"  [-] 安全拦截: {e} (预期)")


def example_auth_manager():
    """示例3: 认证授权"""
    print("\n" + "=" * 60)
    print("示例3: 认证授权")
    print("=" * 60)

    from core.security import AuthManager, Permission, ToolLevel

    auth = AuthManager(storage_path="data/auth_example")

    # 生成API密钥
    print("\n[*] 生成API密钥:")
    key_info = auth.generate_key(
        name="示例密钥",
        permissions=[Permission.SCAN],
        max_tool_level=ToolLevel.MODERATE,
        rate_limit=100
    )
    print(f"  [+] Key ID: {key_info['key_id']}")
    print(f"  [+] Full Key: {key_info['full_key']}")

    # 验证密钥
    print("\n[*] 验证密钥:")
    api_key = auth.verify_key(key_info['full_key'])
    if api_key:
        print(f"  [+] 密钥有效: {api_key.name}")
        print(f"  [+] 权限: {[p.value for p in api_key.permissions]}")
        print(f"  [+] 最大工具等级: {api_key.max_tool_level.name}")
    else:
        print("  [-] 密钥无效")

    # 检查工具权限
    print("\n[*] 检查工具权限:")
    tools = [
        ("port_scan", ToolLevel.SAFE),
        ("sqli_detect", ToolLevel.MODERATE),
        ("lateral_smb_exec", ToolLevel.CRITICAL)
    ]

    for tool_name, level in tools:
        has_permission = auth.check_permission(api_key, tool_name)
        status = "[+]" if has_permission else "[-]"
        print(f"  {status} {tool_name} ({level.name}): {'允许' if has_permission else '拒绝'}")

    # 记录审计日志
    print("\n[*] 记录审计日志:")
    auth.audit(
        key_id=api_key.key_id,
        tool_name="sqli_detect",
        params={"url": "http://example.com"},
        success=True
    )
    print("  [+] 审计日志已记录")


def example_secrets_manager():
    """示例4: 敏感信息管理"""
    print("\n" + "=" * 60)
    print("示例4: 敏感信息管理")
    print("=" * 60)

    from core.security import SecretsManager

    manager = SecretsManager(
        master_key="example_master_key_12345678",
        storage_path="data/secrets_example"
    )

    # 设置敏感信息
    print("\n[*] 设置敏感信息:")
    manager.set_secret("OPENAI_API_KEY", "sk-example123456")
    manager.set_secret("DATABASE_PASSWORD", "secret_password")
    print("  [+] 敏感信息已加密存储")

    # 获取敏感信息
    print("\n[*] 获取敏感信息:")
    api_key = manager.get_secret("OPENAI_API_KEY")
    print(f"  [+] OPENAI_API_KEY: {api_key[:10]}... (已遮蔽)")

    # 列出所有密钥
    print("\n[*] 列出所有密钥名称:")
    keys = manager.list_secrets()
    for key in keys:
        print(f"  [+] {key}")


def example_decorator():
    """示例5: 使用装饰器"""
    print("\n" + "=" * 60)
    print("示例5: 使用装饰器")
    print("=" * 60)

    from core.security import InputValidator, validate_params, ValidationError

    @validate_params(
        url=lambda x: InputValidator.validate_url(x),
        port=lambda x: InputValidator.validate_port(x)
    )
    def scan_target(url: str, port: int):
        """扫描目标（参数已自动验证）"""
        return f"扫描 {url}:{port}"

    # 正常调用
    print("\n[*] 正常调用:")
    try:
        result = scan_target("http://example.com", 80)
        print(f"  [+] {result}")
    except ValidationError as e:
        print(f"  [-] 验证失败: {e}")

    # 异常调用
    print("\n[*] 异常调用:")
    try:
        result = scan_target("javascript:alert(1)", 80)
        print(f"  [+] {result}")
    except ValidationError as e:
        print(f"  [-] 验证失败: {e} (预期)")


def example_integration():
    """示例6: 完整集成示例"""
    print("\n" + "=" * 60)
    print("示例6: 完整集成示例 - 安全的SQL注入检测工具")
    print("=" * 60)

    from core.security import (
        InputValidator,
        SafeExecutor,
        AuthManager,
        ValidationError,
        SecurityError,
        Permission,
        ToolLevel
    )

    # 初始化组件
    validator = InputValidator()
    executor = SafeExecutor()
    auth = AuthManager(storage_path="data/auth_example")

    # 生成测试密钥
    key_info = auth.generate_key(
        name="集成测试",
        permissions=[Permission.SCAN],
        max_tool_level=ToolLevel.MODERATE
    )

    def sqli_detect(url: str, api_key: str):
        """
        SQL注入检测工具（集成安全模块）
        """
        print(f"\n[*] SQL注入检测: {url}")

        # 1. 验证API密钥
        print("  [1/4] 验证API密钥...")
        api_key_obj = auth.verify_key(api_key)
        if not api_key_obj:
            return {"error": "无效的API密钥"}

        # 2. 检查权限
        print("  [2/4] 检查工具权限...")
        if not auth.check_permission(api_key_obj, "sqli_detect"):
            return {"error": "无权限访问此工具"}

        # 3. 验证输入
        print("  [3/4] 验证输入参数...")
        try:
            validated_url = validator.validate_url(url)
        except ValidationError as e:
            return {"error": f"URL验证失败: {e}"}

        # 4. 执行检测（这里用curl模拟）
        print("  [4/4] 执行检测...")
        try:
            result = executor.execute(
                ["curl", "-s", "-I", validated_url],
                timeout=10
            )

            # 记录审计日志
            auth.audit(
                key_id=api_key_obj.key_id,
                tool_name="sqli_detect",
                params={"url": url},
                success=result["success"]
            )

            if result["success"]:
                return {
                    "success": True,
                    "message": "检测完成",
                    "vulnerable": False  # 简化示例
                }
            else:
                return {"error": result["error"]}

        except SecurityError as e:
            return {"error": f"安全检查失败: {e}"}

    # 调用工具
    result = sqli_detect("http://example.com", key_info['full_key'])
    print(f"\n[*] 检测结果: {result}")


def main():
    """运行所有示例"""
    print("\n" + "=" * 60)
    print("AutoRedTeam-Orchestrator 安全加固模块使用示例")
    print("=" * 60)

    examples = [
        ("输入验证", example_input_validation),
        ("安全命令执行", example_safe_executor),
        ("认证授权", example_auth_manager),
        ("敏感信息管理", example_secrets_manager),
        ("装饰器使用", example_decorator),
        ("完整集成", example_integration),
    ]

    for name, func in examples:
        try:
            func()
        except Exception as e:
            print(f"\n[-] 示例 '{name}' 执行失败: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 60)
    print("所有示例执行完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
