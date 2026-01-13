#!/usr/bin/env python3
"""
安全加固快速部署脚本
自动化部署安全模块并进行配置检查
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import List, Tuple

# 颜色输出
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_success(msg: str):
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")

def print_error(msg: str):
    print(f"{Colors.RED}[-]{Colors.END} {msg}")

def print_info(msg: str):
    print(f"{Colors.BLUE}[*]{Colors.END} {msg}")


def check_dependencies() -> bool:
    """检查依赖是否安装"""
    print_info("检查依赖...")

    required_packages = [
        "cryptography",
        "requests",
    ]

    missing = []
    for package in required_packages:
        try:
            __import__(package)
            print_success(f"  {package}: 已安装")
        except ImportError:
            print_error(f"  {package}: 未安装")
            missing.append(package)

    if missing:
        print_warning(f"\n缺少依赖: {', '.join(missing)}")
        print_info("运行以下命令安装:")
        print(f"  pip install {' '.join(missing)}")
        return False

    return True


def check_security_modules() -> bool:
    """检查安全模块是否存在"""
    print_info("\n检查安全模块...")

    required_files = [
        "core/security/__init__.py",
        "core/security/input_validator.py",
        "core/security/safe_executor.py",
        "core/security/auth_manager.py",
        "core/security/secrets_manager.py",
    ]

    all_exist = True
    for file_path in required_files:
        if Path(file_path).exists():
            print_success(f"  {file_path}: 存在")
        else:
            print_error(f"  {file_path}: 不存在")
            all_exist = False

    return all_exist


def generate_master_key() -> str:
    """生成主密钥"""
    print_info("\n生成主密钥...")

    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        print_success(f"  主密钥: {key[:20]}...")
        return key
    except Exception as e:
        print_error(f"  生成失败: {e}")
        return None


def setup_env_file(master_key: str):
    """创建.env文件"""
    print_info("\n配置环境变量...")

    env_file = Path(".env")

    if env_file.exists():
        print_warning("  .env文件已存在，跳过创建")
        return

    env_content = f"""# AutoRedTeam-Orchestrator 环境变量配置
# 生成时间: {__import__('datetime').datetime.now().isoformat()}

# 主密钥（用于加密敏感信息）
REDTEAM_MASTER_KEY={master_key}

# AI API密钥
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# 安全工具API密钥
SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
VT_API_KEY=

# 数据库配置（如果使用）
DATABASE_PASSWORD=

# JWT密钥（如果使用）
JWT_SECRET=
"""

    try:
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write(env_content)

        # 设置文件权限（Unix-like系统）
        if os.name != 'nt':
            os.chmod(env_file, 0o600)

        print_success(f"  .env文件已创建: {env_file.absolute()}")
        print_warning("  请编辑.env文件填入实际的API密钥")
    except Exception as e:
        print_error(f"  创建失败: {e}")


def generate_admin_key():
    """生成管理员API密钥"""
    print_info("\n生成管理员API密钥...")

    try:
        sys.path.insert(0, str(Path.cwd()))
        from core.security import AuthManager, Permission, ToolLevel

        auth = AuthManager()

        key_info = auth.generate_key(
            name="管理员",
            permissions=[Permission.ADMIN],
            max_tool_level=ToolLevel.CRITICAL,
            rate_limit=1000
        )

        print_success("  管理员密钥已生成:")
        print(f"    Key ID: {key_info['key_id']}")
        print(f"    Full Key: {key_info['full_key']}")
        print_warning("  请妥善保存此密钥，它将用于访问所有工具")

        # 保存到文件
        keys_file = Path("data/admin_key.txt")
        keys_file.parent.mkdir(parents=True, exist_ok=True)

        with open(keys_file, 'w', encoding='utf-8') as f:
            f.write(f"Admin API Key: {key_info['full_key']}\n")
            f.write(f"Generated: {__import__('datetime').datetime.now().isoformat()}\n")

        if os.name != 'nt':
            os.chmod(keys_file, 0o600)

        print_success(f"  密钥已保存到: {keys_file.absolute()}")

    except Exception as e:
        print_error(f"  生成失败: {e}")
        import traceback
        traceback.print_exc()


def run_security_tests():
    """运行安全测试"""
    print_info("\n运行安全测试...")

    test_file = Path("tests/test_security.py")
    if not test_file.exists():
        print_warning("  测试文件不存在，跳过测试")
        return

    try:
        result = subprocess.run(
            [sys.executable, str(test_file)],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            print_success("  所有测试通过")
        else:
            print_error("  部分测试失败")
            print(result.stdout)
            print(result.stderr)

    except subprocess.TimeoutExpired:
        print_error("  测试超时")
    except Exception as e:
        print_error(f"  测试失败: {e}")


def check_existing_vulnerabilities():
    """检查现有代码中的安全问题"""
    print_info("\n扫描现有代码安全问题...")

    issues = []

    # 检查shell=True使用
    print_info("  检查命令注入风险...")
    dangerous_patterns = [
        ("shell=True", "命令注入风险"),
        ("os.system(", "不安全的命令执行"),
        ("eval(", "代码执行风险"),
        ("exec(", "代码执行风险"),
    ]

    for root, dirs, files in os.walk("."):
        # 跳过特定目录
        if any(skip in root for skip in [".git", "__pycache__", "venv", "node_modules"]):
            continue

        for file in files:
            if not file.endswith(".py"):
                continue

            file_path = Path(root) / file
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for pattern, desc in dangerous_patterns:
                    if pattern in content:
                        issues.append((file_path, pattern, desc))
            except:
                pass

    if issues:
        print_warning(f"  发现 {len(issues)} 个潜在安全问题:")
        for file_path, pattern, desc in issues[:10]:  # 只显示前10个
            print(f"    {file_path}: {pattern} ({desc})")

        if len(issues) > 10:
            print(f"    ... 还有 {len(issues) - 10} 个问题")
    else:
        print_success("  未发现明显的安全问题")


def create_gitignore():
    """更新.gitignore"""
    print_info("\n更新.gitignore...")

    gitignore_entries = [
        "# 敏感信息",
        ".env",
        "*.enc",
        "data/secrets/",
        "data/auth/",
        "data/admin_key.txt",
        "",
        "# 密钥文件",
        ".master_key",
        "*.key",
        "*.pem",
    ]

    gitignore_file = Path(".gitignore")

    try:
        existing = []
        if gitignore_file.exists():
            with open(gitignore_file, 'r', encoding='utf-8') as f:
                existing = f.read().splitlines()

        # 添加新条目
        new_entries = [e for e in gitignore_entries if e not in existing]

        if new_entries:
            with open(gitignore_file, 'a', encoding='utf-8') as f:
                f.write("\n" + "\n".join(new_entries) + "\n")
            print_success(f"  已添加 {len(new_entries)} 个条目到.gitignore")
        else:
            print_success("  .gitignore已是最新")

    except Exception as e:
        print_error(f"  更新失败: {e}")


def print_summary():
    """打印部署摘要"""
    print("\n" + "=" * 60)
    print("部署摘要")
    print("=" * 60)

    print("\n已创建的文件:")
    print("  - core/security/input_validator.py")
    print("  - core/security/safe_executor.py")
    print("  - core/security/auth_manager.py")
    print("  - core/security/secrets_manager.py")
    print("  - docs/SECURITY_HARDENING.md")
    print("  - tests/test_security.py")
    print("  - examples/security_examples.py")

    print("\n下一步操作:")
    print("  1. 编辑.env文件，填入实际的API密钥")
    print("  2. 查看管理员密钥: cat data/admin_key.txt")
    print("  3. 运行测试: python tests/test_security.py")
    print("  4. 查看示例: python examples/security_examples.py")
    print("  5. 阅读文档: docs/SECURITY_HARDENING.md")

    print("\n集成到现有代码:")
    print("  - 参考 docs/SECURITY_HARDENING.md 中的迁移指南")
    print("  - 使用 SafeExecutor 替换 subprocess.run(shell=True)")
    print("  - 为MCP工具添加 @require_auth_mcp 装饰器")
    print("  - 使用 InputValidator 验证所有外部输入")


def main():
    """主函数"""
    print("=" * 60)
    print("AutoRedTeam-Orchestrator 安全加固部署脚本")
    print("=" * 60)

    # 1. 检查依赖
    if not check_dependencies():
        print_error("\n部署失败: 缺少必要依赖")
        return 1

    # 2. 检查安全模块
    if not check_security_modules():
        print_error("\n部署失败: 安全模块文件不完整")
        return 1

    # 3. 生成主密钥
    master_key = generate_master_key()
    if not master_key:
        print_error("\n部署失败: 无法生成主密钥")
        return 1

    # 4. 创建.env文件
    setup_env_file(master_key)

    # 5. 生成管理员密钥
    generate_admin_key()

    # 6. 更新.gitignore
    create_gitignore()

    # 7. 检查现有代码
    check_existing_vulnerabilities()

    # 8. 运行测试
    run_security_tests()

    # 9. 打印摘要
    print_summary()

    print("\n" + "=" * 60)
    print_success("安全加固部署完成!")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
