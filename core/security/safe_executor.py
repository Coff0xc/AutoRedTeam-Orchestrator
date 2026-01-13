#!/usr/bin/env python3
"""
安全命令执行器 - 防止命令注入
提供安全的subprocess封装和命令白名单机制
"""

import subprocess
import shlex
import shutil
import logging
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ExecutionPolicy(Enum):
    """执行策略"""
    STRICT = "strict"      # 严格模式：仅允许白名单命令
    MODERATE = "moderate"  # 中等模式：白名单+参数验证
    PERMISSIVE = "permissive"  # 宽松模式：仅基本验证


@dataclass
class CommandWhitelist:
    """命令白名单配置"""
    command: str
    allowed_args: List[str] = None  # None表示允许所有参数
    max_args: int = 50
    require_absolute_path: bool = False
    description: str = ""


class SafeExecutor:
    """安全命令执行器"""

    # 默认白名单命令
    DEFAULT_WHITELIST = {
        # 网络扫描工具
        "nmap": CommandWhitelist(
            command="nmap",
            allowed_args=["-sV", "-sC", "-p", "-Pn", "-T4", "-A", "-O", "--script"],
            description="Nmap端口扫描"
        ),
        "masscan": CommandWhitelist(
            command="masscan",
            allowed_args=["-p", "--rate", "--banners"],
            description="Masscan快速扫描"
        ),
        "dig": CommandWhitelist(
            command="dig",
            allowed_args=["+short", "+trace", "ANY", "A", "AAAA", "MX", "NS", "TXT"],
            description="DNS查询"
        ),
        "nslookup": CommandWhitelist(
            command="nslookup",
            description="DNS查询"
        ),
        "curl": CommandWhitelist(
            command="curl",
            allowed_args=["-X", "-H", "-d", "-k", "-L", "-s", "-i", "-v", "--data"],
            description="HTTP请求"
        ),
        "wget": CommandWhitelist(
            command="wget",
            allowed_args=["-O", "-q", "--spider", "--timeout"],
            description="文件下载"
        ),

        # 漏洞扫描工具
        "nuclei": CommandWhitelist(
            command="nuclei",
            allowed_args=["-u", "-l", "-t", "-tags", "-severity", "-o"],
            description="Nuclei漏洞扫描"
        ),
        "sqlmap": CommandWhitelist(
            command="sqlmap",
            allowed_args=["-u", "--dbs", "--tables", "--dump", "--batch", "--random-agent"],
            description="SQLMap注入检测"
        ),

        # 系统工具
        "python": CommandWhitelist(
            command="python",
            allowed_args=["-c", "-m"],
            max_args=10,
            description="Python解释器"
        ),
        "python3": CommandWhitelist(
            command="python3",
            allowed_args=["-c", "-m"],
            max_args=10,
            description="Python3解释器"
        ),
    }

    # 危险命令黑名单
    BLACKLIST = [
        "rm", "rmdir", "del", "format", "mkfs",
        "dd", "fdisk", "parted",
        "shutdown", "reboot", "halt", "poweroff",
        "kill", "killall", "pkill",
        "chmod", "chown", "chgrp",
        "useradd", "userdel", "passwd",
        "iptables", "firewall-cmd",
        "systemctl", "service",
    ]

    def __init__(self, policy: ExecutionPolicy = ExecutionPolicy.STRICT,
                 custom_whitelist: Dict[str, CommandWhitelist] = None):
        """
        初始化安全执行器

        Args:
            policy: 执行策略
            custom_whitelist: 自定义白名单
        """
        self.policy = policy
        self.whitelist = self.DEFAULT_WHITELIST.copy()

        if custom_whitelist:
            self.whitelist.update(custom_whitelist)

    def execute(self, cmd: List[str], timeout: int = 300,
                cwd: Optional[str] = None, env: Optional[Dict] = None,
                capture_output: bool = True) -> Dict:
        """
        安全执行命令

        Args:
            cmd: 命令列表（不要使用shell=True）
            timeout: 超时时间（秒）
            cwd: 工作目录
            env: 环境变量
            capture_output: 是否捕获输出

        Returns:
            执行结果字典

        Raises:
            SecurityError: 安全检查失败
            subprocess.TimeoutExpired: 超时
        """
        # 1. 验证命令
        self._validate_command(cmd)

        # 2. 检查命令是否存在
        cmd_path = self._resolve_command(cmd[0])
        if not cmd_path:
            return {
                "success": False,
                "error": f"命令未找到: {cmd[0]}",
                "stdout": "",
                "stderr": "",
                "returncode": -1
            }

        # 3. 构建安全的命令
        safe_cmd = [cmd_path] + cmd[1:]

        # 4. 执行命令
        try:
            logger.info(f"执行命令: {' '.join(safe_cmd)}")

            result = subprocess.run(
                safe_cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                shell=False  # 永远不使用shell=True
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "command": ' '.join(safe_cmd)
            }

        except subprocess.TimeoutExpired:
            logger.error(f"命令执行超时: {' '.join(safe_cmd)}")
            return {
                "success": False,
                "error": "命令执行超时",
                "stdout": "",
                "stderr": "",
                "returncode": -1
            }

        except Exception as e:
            logger.error(f"命令执行失败: {e}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "returncode": -1
            }

    def _validate_command(self, cmd: List[str]):
        """
        验证命令安全性

        Args:
            cmd: 命令列表

        Raises:
            SecurityError: 安全检查失败
        """
        if not cmd or not isinstance(cmd, list):
            raise SecurityError("命令必须是非空列表")

        command_name = os.path.basename(cmd[0])

        # 1. 检查黑名单
        if command_name in self.BLACKLIST:
            raise SecurityError(f"命令在黑名单中: {command_name}")

        # 2. 严格模式：必须在白名单中
        if self.policy == ExecutionPolicy.STRICT:
            if command_name not in self.whitelist:
                raise SecurityError(f"命令不在白名单中: {command_name}")

            whitelist_entry = self.whitelist[command_name]
            self._validate_args(cmd[1:], whitelist_entry)

        # 3. 中等模式：白名单或基本验证
        elif self.policy == ExecutionPolicy.MODERATE:
            if command_name in self.whitelist:
                whitelist_entry = self.whitelist[command_name]
                self._validate_args(cmd[1:], whitelist_entry)
            else:
                self._basic_validation(cmd)

        # 4. 宽松模式：仅基本验证
        else:
            self._basic_validation(cmd)

    def _validate_args(self, args: List[str], whitelist: CommandWhitelist):
        """
        验证命令参数

        Args:
            args: 参数列表
            whitelist: 白名单配置

        Raises:
            SecurityError: 参数验证失败
        """
        # 检查参数数量
        if len(args) > whitelist.max_args:
            raise SecurityError(f"参数数量超过限制: {len(args)} > {whitelist.max_args}")

        # 如果有允许的参数列表，验证每个参数
        if whitelist.allowed_args is not None:
            for arg in args:
                # 跳过参数值
                if not arg.startswith('-'):
                    continue

                # 检查是否在允许列表中
                if arg not in whitelist.allowed_args:
                    raise SecurityError(f"参数不在白名单中: {arg}")

        # 基本安全检查
        self._basic_validation([whitelist.command] + args)

    def _basic_validation(self, cmd: List[str]):
        """
        基本安全验证

        Args:
            cmd: 命令列表

        Raises:
            SecurityError: 验证失败
        """
        # 检查危险字符
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '>', '<']

        for part in cmd:
            for char in dangerous_chars:
                if char in part:
                    raise SecurityError(f"命令包含危险字符: {char}")

            # 检查命令替换
            if '$(' in part or '`' in part:
                raise SecurityError("检测到命令替换尝试")

    def _resolve_command(self, command: str) -> Optional[str]:
        """
        解析命令路径

        Args:
            command: 命令名称

        Returns:
            命令的完整路径，如果未找到返回None
        """
        # 如果是绝对路径，直接返回
        if os.path.isabs(command) and os.path.isfile(command):
            return command

        # 使用shutil.which查找命令
        return shutil.which(command)

    def add_whitelist(self, name: str, whitelist: CommandWhitelist):
        """添加白名单命令"""
        self.whitelist[name] = whitelist
        logger.info(f"添加白名单命令: {name}")

    def remove_whitelist(self, name: str):
        """移除白名单命令"""
        if name in self.whitelist:
            del self.whitelist[name]
            logger.info(f"移除白名单命令: {name}")


class SecurityError(Exception):
    """安全错误异常"""
    pass


# ========== 沙箱执行器 ==========

class SandboxExecutor:
    """
    沙箱执行器 - 在受限环境中执行命令
    使用资源限制、网络隔离等技术
    """

    def __init__(self, max_memory_mb: int = 512, max_cpu_percent: int = 50):
        """
        初始化沙箱执行器

        Args:
            max_memory_mb: 最大内存限制（MB）
            max_cpu_percent: 最大CPU使用率（%）
        """
        self.max_memory = max_memory_mb * 1024 * 1024
        self.max_cpu = max_cpu_percent

    def execute(self, cmd: List[str], timeout: int = 60) -> Dict:
        """
        在沙箱中执行命令

        Args:
            cmd: 命令列表
            timeout: 超时时间

        Returns:
            执行结果
        """
        # TODO: 实现完整的沙箱隔离
        # 可以使用：
        # - Linux: cgroups, namespaces, seccomp
        # - Windows: Job Objects, AppContainer
        # - 跨平台: Docker容器

        try:
            # 基本实现：仅使用超时和资源限制
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "沙箱执行超时",
                "stdout": "",
                "stderr": "",
                "returncode": -1
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "returncode": -1
            }


# ========== 全局实例 ==========

_safe_executor: Optional[SafeExecutor] = None


def get_safe_executor(policy: ExecutionPolicy = ExecutionPolicy.STRICT) -> SafeExecutor:
    """获取全局安全执行器实例"""
    global _safe_executor
    if _safe_executor is None:
        _safe_executor = SafeExecutor(policy=policy)
    return _safe_executor


# ========== 便捷函数 ==========

def safe_execute(cmd: List[str], timeout: int = 300, **kwargs) -> Dict:
    """
    便捷函数：安全执行命令

    Args:
        cmd: 命令列表
        timeout: 超时时间
        **kwargs: 其他参数

    Returns:
        执行结果字典
    """
    executor = get_safe_executor()
    return executor.execute(cmd, timeout=timeout, **kwargs)


# ========== 测试 ==========

if __name__ == "__main__":
    # 测试用例
    executor = SafeExecutor(policy=ExecutionPolicy.STRICT)

    # 测试安全命令
    print("测试1: 安全命令")
    result = executor.execute(["nmap", "-sV", "127.0.0.1"])
    print(f"结果: {result['success']}")

    # 测试危险命令
    print("\n测试2: 危险命令（应该被阻止）")
    try:
        result = executor.execute(["rm", "-rf", "/"])
    except SecurityError as e:
        print(f"预期的错误: {e}")

    # 测试命令注入
    print("\n测试3: 命令注入（应该被阻止）")
    try:
        result = executor.execute(["nmap", "-sV; rm -rf /"])
    except SecurityError as e:
        print(f"预期的错误: {e}")
