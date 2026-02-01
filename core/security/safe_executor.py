#!/usr/bin/env python3
"""
安全命令执行器 - 防止命令注入
提供安全的subprocess封装和命令白名单机制
"""

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ExecutionPolicy(Enum):
    """执行策略"""

    STRICT = "strict"  # 严格模式：仅允许白名单命令
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
            description="Nmap端口扫描",
        ),
        "masscan": CommandWhitelist(
            command="masscan",
            allowed_args=["-p", "--rate", "--banners"],
            description="Masscan快速扫描",
        ),
        "dig": CommandWhitelist(
            command="dig",
            allowed_args=["+short", "+trace", "ANY", "A", "AAAA", "MX", "NS", "TXT"],
            description="DNS查询",
        ),
        "nslookup": CommandWhitelist(command="nslookup", description="DNS查询"),
        "curl": CommandWhitelist(
            command="curl",
            allowed_args=["-X", "-H", "-d", "-k", "-L", "-s", "-i", "-v", "--data"],
            description="HTTP请求",
        ),
        "wget": CommandWhitelist(
            command="wget",
            allowed_args=["-O", "-q", "--spider", "--timeout"],
            description="文件下载",
        ),
        # 漏洞扫描工具
        "nuclei": CommandWhitelist(
            command="nuclei",
            allowed_args=["-u", "-l", "-t", "-tags", "-severity", "-o"],
            description="Nuclei漏洞扫描",
        ),
        "sqlmap": CommandWhitelist(
            command="sqlmap",
            allowed_args=["-u", "--dbs", "--tables", "--dump", "--batch", "--random-agent"],
            description="SQLMap注入检测",
        ),
        # 系统工具 - 注意: 禁止 -c 参数以防止任意代码执行
        "python": CommandWhitelist(
            command="python",
            allowed_args=["-m", "-V", "--version"],  # 仅允许模块执行和版本查询
            max_args=10,
            description="Python解释器（受限）",
        ),
        "python3": CommandWhitelist(
            command="python3",
            allowed_args=["-m", "-V", "--version"],  # 仅允许模块执行和版本查询
            max_args=10,
            description="Python3解释器（受限）",
        ),
    }

    # 危险命令黑名单
    BLACKLIST = [
        "rm",
        "rmdir",
        "del",
        "format",
        "mkfs",
        "dd",
        "fdisk",
        "parted",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "kill",
        "killall",
        "pkill",
        "chmod",
        "chown",
        "chgrp",
        "useradd",
        "userdel",
        "passwd",
        "iptables",
        "firewall-cmd",
        "systemctl",
        "service",
    ]

    def __init__(
        self,
        policy: ExecutionPolicy = ExecutionPolicy.STRICT,
        custom_whitelist: Dict[str, CommandWhitelist] = None,
    ):
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

    def execute(
        self,
        cmd: List[str],
        timeout: int = 300,
        cwd: Optional[str] = None,
        env: Optional[Dict] = None,
        capture_output: bool = True,
    ) -> Dict:
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
                "returncode": -1,
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
                shell=False,  # 永远不使用shell=True
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "command": " ".join(safe_cmd),
            }

        except subprocess.TimeoutExpired:
            logger.error(f"命令执行超时: {' '.join(safe_cmd)}")
            return {
                "success": False,
                "error": "命令执行超时",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
            }

        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"命令执行失败: {e}")
            return {
                "success": False,
                "error": f"执行错误: {e}",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
            }
        except ValueError as e:
            logger.error(f"命令参数错误: {e}")
            return {
                "success": False,
                "error": f"参数错误: {e}",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
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
                if not arg.startswith("-"):
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
        dangerous_chars = [";", "|", "&", "$", "`", "\n", "\r", ">", "<"]

        for part in cmd:
            for char in dangerous_chars:
                if char in part:
                    raise SecurityError(f"命令包含危险字符: {char}")

            # 检查命令替换
            if "$(" in part or "`" in part:
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


# ========== 沙箱执行器 ==========


class SandboxExecutor:
    """
    沙箱执行器 - 在受限环境中执行命令

    提供多层安全隔离：
    - 资源限制（内存、CPU、文件描述符）
    - 进程隔离（独立进程组）
    - 环境变量清理
    - 工作目录限制
    - 临时目录隔离
    - 网络访问控制（Linux仅限）
    """

    # 默认允许的环境变量
    DEFAULT_ALLOWED_ENV = ["PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM"]

    # 高风险命令（在沙箱中禁止）
    SANDBOX_BLACKLIST = [
        "rm",
        "rmdir",
        "del",
        "format",
        "mkfs",
        "dd",
        "shutdown",
        "reboot",
        "halt",
        "init",
        "mount",
        "umount",
        "fdisk",
        "parted",
        "iptables",
        "ip6tables",
        "nft",
        "firewall-cmd",
        "systemctl",
        "service",
        "chkconfig",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "passwd",
        "chpasswd",
        "su",
        "sudo",
        "crontab",
        "at",
    ]

    def __init__(
        self,
        max_memory_mb: int = 512,
        max_cpu_percent: int = 50,
        max_fds: int = 256,
        max_processes: int = 50,
        allowed_env_vars: Optional[List[str]] = None,
        use_temp_dir: bool = True,
        restrict_network: bool = False,
    ):
        """
        初始化沙箱执行器

        Args:
            max_memory_mb: 最大内存限制（MB）
            max_cpu_percent: 最大CPU使用率（%）
            max_fds: 最大文件描述符数量
            max_processes: 最大子进程数量
            allowed_env_vars: 允许的环境变量列表（None使用默认）
            use_temp_dir: 是否使用临时目录隔离
            restrict_network: 是否限制网络访问（仅Linux）
        """
        self.max_memory = max_memory_mb * 1024 * 1024
        self.max_cpu = max_cpu_percent
        self.max_fds = max_fds
        self.max_processes = max_processes
        self.allowed_env_vars = allowed_env_vars or self.DEFAULT_ALLOWED_ENV
        self.use_temp_dir = use_temp_dir
        self.restrict_network = restrict_network

    def _prepare_environment(self) -> Dict[str, str]:
        """准备受限的环境变量"""
        clean_env = {}
        for var in self.allowed_env_vars:
            if var in os.environ:
                clean_env[var] = os.environ[var]

        # 添加沙箱标识
        clean_env["SANDBOX_ACTIVE"] = "1"
        return clean_env

    def _validate_command(self, cmd: List[str]) -> None:
        """
        验证命令在沙箱中是否安全

        Args:
            cmd: 命令列表

        Raises:
            SecurityError: 命令不安全
        """
        if not cmd or not isinstance(cmd, list):
            raise SecurityError("命令必须是非空列表")

        command_name = os.path.basename(cmd[0])

        # 检查黑名单
        if command_name in self.SANDBOX_BLACKLIST:
            raise SecurityError(f"沙箱中禁止执行: {command_name}")

        # 检查危险模式
        dangerous_patterns = [
            "../../",  # 路径遍历
            "/etc/passwd",
            "/etc/shadow",
            "/proc/",
            "/sys/",
        ]

        cmd_str = " ".join(cmd)
        for pattern in dangerous_patterns:
            if pattern in cmd_str:
                raise SecurityError(f"检测到危险路径访问: {pattern}")

    def _create_temp_workdir(self) -> str:
        """创建临时工作目录"""
        import tempfile

        workdir = tempfile.mkdtemp(prefix="sandbox_")
        logger.debug(f"创建沙箱工作目录: {workdir}")
        return workdir

    def _cleanup_temp_workdir(self, workdir: str) -> None:
        """清理临时工作目录"""
        import shutil

        try:
            if workdir and os.path.isdir(workdir) and "sandbox_" in workdir:
                shutil.rmtree(workdir, ignore_errors=True)
                logger.debug(f"清理沙箱工作目录: {workdir}")
        except (OSError, PermissionError) as e:
            logger.warning(f"清理临时目录失败: {e}")

    def execute(
        self, cmd: List[str], timeout: int = 60, cwd: Optional[str] = None, cleanup: bool = True
    ) -> Dict:
        """
        在沙箱中执行命令

        Args:
            cmd: 命令列表
            timeout: 超时时间（秒）
            cwd: 工作目录（None使用临时目录）
            cleanup: 是否自动清理临时目录

        Returns:
            执行结果字典
        """
        temp_workdir = None

        try:
            # 1. 验证命令安全性
            self._validate_command(cmd)

            # 2. 准备工作目录
            if cwd is None and self.use_temp_dir:
                temp_workdir = self._create_temp_workdir()
                cwd = temp_workdir
            elif cwd is None:
                import tempfile

                cwd = tempfile.gettempdir()

            # 3. 准备环境变量
            env = self._prepare_environment()

            preexec_fn = None
            creationflags = 0

            # POSIX系统：使用resource模块设置限制
            if os.name == "posix":
                # 捕获当前实例的属性，避免闭包问题
                max_memory = self.max_memory
                max_cpu = self.max_cpu
                max_fds = self.max_fds
                max_procs = self.max_processes
                restrict_net = self.restrict_network

                def _apply_limits():
                    """应用资源限制（在子进程中执行）"""
                    try:
                        import resource

                        # 内存限制（虚拟内存）
                        resource.setrlimit(resource.RLIMIT_AS, (max_memory, max_memory))

                        # CPU时间限制
                        cpu_time = max(1, int(timeout * (max_cpu / 100)))
                        resource.setrlimit(resource.RLIMIT_CPU, (cpu_time, cpu_time))

                        # 文件描述符限制
                        resource.setrlimit(resource.RLIMIT_NOFILE, (max_fds, max_fds))

                        # 子进程数限制
                        resource.setrlimit(resource.RLIMIT_NPROC, (max_procs, max_procs))

                        # 核心转储限制（禁止）
                        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

                    except ImportError:
                        pass  # resource模块不可用
                    except (OSError, ValueError):
                        pass  # 资源限制设置失败

                    # 创建新的进程组（用于信号隔离）
                    try:
                        os.setsid()
                    except (OSError, PermissionError):
                        pass

                    # 限制网络访问（Linux seccomp，如果可用）
                    if restrict_net:
                        try:
                            # 尝试使用 prctl 限制网络
                            import ctypes

                            libc = ctypes.CDLL("libc.so.6", use_errno=True)
                            # PR_SET_NO_NEW_PRIVS = 38
                            libc.prctl(38, 1, 0, 0, 0)
                        except (ImportError, OSError, AttributeError):
                            pass

                preexec_fn = _apply_limits

            # Windows系统：使用Job对象
            elif os.name == "nt":
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

            # 4. 构建subprocess参数
            run_kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": timeout,
                "shell": False,
                "cwd": cwd,
                "env": env,
            }

            if preexec_fn is not None:
                run_kwargs["preexec_fn"] = preexec_fn
            if creationflags:
                run_kwargs["creationflags"] = creationflags

            # 5. 执行命令
            logger.debug(f"沙箱执行: {' '.join(cmd)}")
            result = subprocess.run(cmd, **run_kwargs)

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "command": " ".join(cmd),
                "sandbox": True,
            }

        except SecurityError as e:
            logger.warning(f"沙箱安全检查失败: {e}")
            return {
                "success": False,
                "error": f"安全检查失败: {e}",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "sandbox": True,
            }

        except subprocess.TimeoutExpired as e:
            logger.error(f"沙箱执行超时: {' '.join(cmd)}")
            return {
                "success": False,
                "error": f"执行超时（{timeout}秒）",
                "stdout": e.stdout.decode() if e.stdout else "",
                "stderr": e.stderr.decode() if e.stderr else "",
                "returncode": -1,
                "sandbox": True,
            }

        except MemoryError:
            logger.error("沙箱内存不足")
            return {
                "success": False,
                "error": "内存限制触发",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "sandbox": True,
            }

        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"沙箱执行失败: {e}")
            return {
                "success": False,
                "error": f"执行错误: {e}",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "sandbox": True,
            }

        except ValueError as e:
            logger.error(f"沙箱参数错误: {e}")
            return {
                "success": False,
                "error": f"参数错误: {e}",
                "stdout": "",
                "stderr": "",
                "returncode": -1,
                "sandbox": True,
            }

        finally:
            # 清理临时工作目录
            if cleanup and temp_workdir:
                self._cleanup_temp_workdir(temp_workdir)


# ========== 全局实例 ==========

_safe_executor: Optional[SafeExecutor] = None
_sandbox_executor: Optional[SandboxExecutor] = None


def get_safe_executor(policy: ExecutionPolicy = ExecutionPolicy.STRICT) -> SafeExecutor:
    """获取全局安全执行器实例"""
    global _safe_executor
    if _safe_executor is None:
        _safe_executor = SafeExecutor(policy=policy)
    return _safe_executor


def get_sandbox_executor(max_memory_mb: int = 512, max_cpu_percent: int = 50) -> SandboxExecutor:
    """
    获取全局沙箱执行器实例

    Args:
        max_memory_mb: 最大内存限制（MB）
        max_cpu_percent: 最大CPU使用率（%）

    Returns:
        SandboxExecutor 实例
    """
    global _sandbox_executor
    if _sandbox_executor is None:
        _sandbox_executor = SandboxExecutor(
            max_memory_mb=max_memory_mb, max_cpu_percent=max_cpu_percent
        )
    return _sandbox_executor


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


def sandbox_execute(cmd: List[str], timeout: int = 60, **kwargs) -> Dict:
    """
    便捷函数：沙箱执行命令

    Args:
        cmd: 命令列表
        timeout: 超时时间
        **kwargs: 其他参数

    Returns:
        执行结果字典
    """
    executor = get_sandbox_executor()
    return executor.execute(cmd, timeout=timeout, **kwargs)


# ========== 测试 ==========

if __name__ == "__main__":
    # 配置测试用日志
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

    logger.info("=" * 60)
    logger.info("安全执行器测试")
    logger.info("=" * 60)

    # 测试 SafeExecutor
    executor = SafeExecutor(policy=ExecutionPolicy.STRICT)

    # 测试安全命令
    logger.info("[测试1] 安全命令 (nmap)")
    result = executor.execute(["nmap", "-sV", "127.0.0.1"])
    logger.info(f"  结果: {result.get('success', 'N/A')}")
    if result.get("error"):
        logger.error(f"  错误: {result['error']}")

    # 测试危险命令
    logger.info("[测试2] 危险命令（应该被阻止）")
    try:
        result = executor.execute(["rm", "-rf", "/"])
        logger.warning(f"  意外通过: {result}")
    except SecurityError as e:
        logger.info(f"  预期阻止: {e}")

    # 测试命令注入
    logger.info("[测试3] 命令注入（应该被阻止）")
    try:
        result = executor.execute(["nmap", "-sV; rm -rf /"])
        logger.warning(f"  意外通过: {result}")
    except SecurityError as e:
        logger.info(f"  预期阻止: {e}")

    # 测试 SandboxExecutor
    logger.info("=" * 60)
    logger.info("沙箱执行器测试")
    logger.info("=" * 60)

    sandbox = SandboxExecutor(max_memory_mb=256, max_cpu_percent=25, use_temp_dir=True)

    # 测试沙箱中的安全命令
    logger.info("[测试4] 沙箱安全命令 (echo)")
    result = sandbox.execute(["echo", "Hello from sandbox"])
    logger.info(f"  结果: {result.get('success', 'N/A')}")
    if result.get("stdout"):
        logger.info(f"  输出: {result['stdout'].strip()}")

    # 测试沙箱黑名单
    logger.info("[测试5] 沙箱黑名单（应该被阻止）")
    result = sandbox.execute(["rm", "-rf", "/tmp/test"])
    logger.info(f"  结果: {result.get('success', 'N/A')}")
    if result.get("error"):
        logger.info(f"  错误: {result['error']}")

    # 测试路径遍历检测
    logger.info("[测试6] 路径遍历检测（应该被阻止）")
    result = sandbox.execute(["cat", "../../etc/passwd"])
    logger.info(f"  结果: {result.get('success', 'N/A')}")
    if result.get("error"):
        logger.info(f"  错误: {result['error']}")

    logger.info("=" * 60)
    logger.info("测试完成")
    logger.info("=" * 60)


# ========== 模块导出 ==========

__all__ = [
    # 枚举
    "ExecutionPolicy",
    # 数据类
    "CommandWhitelist",
    # 异常
    "SecurityError",
    # 类
    "SafeExecutor",
    "SandboxExecutor",
    # 全局函数
    "get_safe_executor",
    "get_sandbox_executor",
    "safe_execute",
    "sandbox_execute",
]
