"""
统一子进程执行器

解决问题: 54处重复的 subprocess 执行模式
"""

import json
import logging
import platform
import shlex
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Union

from core.result import ToolResult

logger = logging.getLogger(__name__)


class SubprocessRunner:
    """统一的子进程执行器"""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timeout

    def run(
        self,
        cmd: Union[str, List[str]],
        timeout: Optional[float] = None,
        parse_json: bool = False,
        tool_name: Optional[str] = None,
        install_cmd: Optional[str] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        allow_shell: bool = False,
    ) -> ToolResult:
        """执行命令并返回统一结果

        Args:
            cmd: 命令列表（推荐）或字符串
            timeout: 超时时间(秒)
            parse_json: 是否解析JSON输出
            tool_name: 工具名称(用于错误提示)
            install_cmd: 安装命令(工具未安装时提示)
            cwd: 工作目录
            env: 环境变量
            allow_shell: 是否允许 shell 模式（默认禁用，仅在确实需要 shell 特性时启用）

        安全警告:
            字符串形式的 cmd 会自动通过 shlex.split() 转为列表以避免 shell=True。
            如确需 shell 特性（管道、通配符等），请显式设置 allow_shell=True。
        """
        timeout = timeout or self.timeout

        # 字符串命令转为列表，避免 shell=True
        use_shell = False
        if isinstance(cmd, str):
            if allow_shell:
                use_shell = True
                logger.warning("subprocess 显式启用 shell 模式，注意注入风险: %s", cmd.split()[0])
            else:
                # Windows 上 shlex.split 使用 posix=False 以正确处理路径
                posix = platform.system() != "Windows"
                cmd = shlex.split(cmd, posix=posix)

        tool_name = tool_name or (cmd[0] if isinstance(cmd, list) else cmd.split()[0])

        # 检查工具是否存在
        executable = cmd[0] if isinstance(cmd, list) else cmd.split()[0]
        if not shutil.which(executable):
            hint = f" (安装: {install_cmd})" if install_cmd else ""
            return ToolResult.fail(f"{tool_name} 未安装{hint}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                shell=use_shell,
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            # 命令执行失败
            if result.returncode != 0:
                error_msg = stderr or f"{tool_name}执行失败 (code={result.returncode})"
                return ToolResult.fail(error_msg, data={"raw_output": stdout or stderr})

            # 解析JSON输出
            if parse_json and stdout:
                try:
                    data = json.loads(stdout)
                    if isinstance(data, dict):
                        return ToolResult.ok(data=data)
                    return ToolResult.ok(data={"result": data})
                except json.JSONDecodeError:
                    return ToolResult.fail(
                        f"{tool_name} 输出JSON解析失败",
                        data={"raw_output": stdout},
                    )

            return ToolResult.ok(data={"output": stdout, **({"stderr": stderr} if stderr else {})})

        except subprocess.TimeoutExpired:
            return ToolResult.timeout(f"{tool_name} 执行超时 ({timeout}s)")
        except FileNotFoundError:
            hint = f" (安装: {install_cmd})" if install_cmd else ""
            return ToolResult.fail(f"{tool_name} 未安装{hint}")
        except Exception as e:
            logger.exception("subprocess执行异常: %s", cmd)
            return ToolResult.fail(str(e))

    def run_ndjson(
        self,
        cmd: Union[str, List[str]],
        timeout: Optional[float] = None,
        tool_name: Optional[str] = None,
    ) -> ToolResult:
        """执行命令并解析NDJSON输出(每行一个JSON)"""
        result = self.run(cmd, timeout=timeout, tool_name=tool_name)
        if not result.success:
            return result

        output = result.data.get("output", "")
        items = []
        for line in output.splitlines():
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return ToolResult.ok(data={"items": items, "count": len(items)})

    async def async_run(
        self,
        cmd: Union[str, List[str]],
        timeout: Optional[float] = None,
        parse_json: bool = False,
        tool_name: Optional[str] = None,
    ) -> ToolResult:
        """异步执行命令"""
        import asyncio

        return await asyncio.to_thread(self.run, cmd, timeout, parse_json, tool_name)


# 全局实例
_runner: Optional[SubprocessRunner] = None


def get_subprocess_runner(timeout: float = 60.0) -> SubprocessRunner:
    """获取全局 SubprocessRunner 实例"""
    global _runner
    if _runner is None:
        _runner = SubprocessRunner(timeout)
    return _runner
