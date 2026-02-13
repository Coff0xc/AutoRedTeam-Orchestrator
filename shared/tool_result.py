"""
统一工具返回格式

解决问题: 206处重复的错误返回模式
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ToolResult:
    """统一的工具执行结果"""

    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    raw_output: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        result = {"success": self.success}
        if self.success:
            result.update(self.data)
        else:
            result["error"] = self.error
        if self.raw_output:
            result["raw_output"] = self.raw_output
        return result

    @classmethod
    def ok(cls, **data) -> "ToolResult":
        """成功结果"""
        return cls(success=True, data=data)

    @classmethod
    def fail(cls, error: str, raw_output: str = None) -> "ToolResult":
        """失败结果"""
        return cls(success=False, error=error, raw_output=raw_output)

    @classmethod
    def timeout(cls, operation: str, timeout: float) -> "ToolResult":
        """超时结果"""
        return cls(success=False, error=f"{operation}超时 ({timeout}s)")

    @classmethod
    def not_installed(cls, tool: str, install_cmd: str = None) -> "ToolResult":
        """工具未安装"""
        msg = f"{tool}未安装"
        if install_cmd:
            msg += f"，请运行: {install_cmd}"
        return cls(success=False, error=msg)

    @classmethod
    def parse_error(cls, raw_output: str) -> "ToolResult":
        """解析错误，返回原始输出"""
        return cls(success=True, data={"raw_output": raw_output}, raw_output=raw_output)
