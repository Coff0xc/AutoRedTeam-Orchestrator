#!/usr/bin/env python3
"""
测试运行脚本 - 运行 tools/ 模块的单元测试

使用方法:
    python run_tools_tests.py              # 运行所有测试
    python run_tools_tests.py -v           # 详细输出
    python run_tools_tests.py --cov        # 生成覆盖率报告
"""

import sys
import subprocess
from pathlib import Path

def run_tests(verbose=False, coverage=False):
    """运行测试"""
    # 测试文件
    test_files = [
        "tests/test_tools_detectors_base.py",
        "tests/test_tools_pentest_tools.py"
    ]

    # 构建命令
    cmd = ["python", "-m", "pytest"]
    cmd.extend(test_files)

    # 添加选项
    if verbose:
        cmd.append("-v")
    else:
        cmd.append("-q")

    if coverage:
        cmd.extend([
            "--cov=tools",
            "--cov-report=term-missing",
            "--cov-report=html"
        ])

    # 禁用默认的 addopts
    cmd.extend(["-o", "addopts="])

    print(f"运行命令: {' '.join(cmd)}")
    print("-" * 60)

    # 执行测试
    result = subprocess.run(cmd, cwd=Path(__file__).parent.parent)

    if result.returncode == 0:
        print("\n" + "=" * 60)
        print("[SUCCESS] All tests passed!")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("[FAILED] Some tests failed")
        print("=" * 60)

    return result.returncode

if __name__ == "__main__":
    verbose = "-v" in sys.argv or "--verbose" in sys.argv
    coverage = "--cov" in sys.argv or "--coverage" in sys.argv

    sys.exit(run_tests(verbose, coverage))
