#!/usr/bin/env python3
"""
统一响应格式化模块

所有 MCP 工具和内部函数应通过此模块构造响应，避免手动构造 dict。

使用示例:
    from utils.responses import success, error, tool_not_found

    # 成功响应
    return success(data={'ports': [22, 80]}, target='192.168.1.1')

    # 错误响应
    return error("目标不可达", error_type="ConnectionError")

    # 工具未找到
    return tool_not_found("nmap")
"""

from typing import Any, Dict


def success(
    data: Any = None,
    message: str = "",
    **extra: Any,
) -> Dict[str, Any]:
    """构造成功响应

    Args:
        data: 返回数据
        message: 可选的消息
        **extra: 额外字段 (如 target, url 等)

    Returns:
        标准化的成功响应
    """
    response: Dict[str, Any] = {"success": True}
    if data is not None:
        response["data"] = data
    if message:
        response["message"] = message
    response.update(extra)
    return response


def error(
    message: str,
    error_type: str = "Error",
    hint: str = "",
    **extra: Any,
) -> Dict[str, Any]:
    """构造错误响应

    Args:
        message: 错误消息
        error_type: 错误类型
        hint: 修复提示
        **extra: 额外字段

    Returns:
        标准化的错误响应
    """
    response: Dict[str, Any] = {
        "success": False,
        "error": message,
        "error_type": error_type,
    }
    if hint:
        response["hint"] = hint
    response.update(extra)
    return response


def tool_not_found(tool_name: str) -> Dict[str, Any]:
    """工具未安装的标准错误"""
    return error(
        f"{tool_name} 未安装或路径未配置",
        error_type="FileNotFoundError",
        hint=f"请检查 config/external_tools.yaml 中的 {tool_name} 配置",
    )


def validation_error(param: str, value: Any, expected: str = "") -> Dict[str, Any]:
    """参数验证失败的标准错误"""
    msg = f"参数 '{param}' 无效: {value}"
    if expected:
        msg += f" (期望: {expected})"
    return error(msg, error_type="ValidationError", **{param: value})


def import_error(module: str, hint: str = "") -> Dict[str, Any]:
    """模块导入失败的标准错误"""
    return error(
        f"模块 '{module}' 导入失败",
        error_type="ImportError",
        hint=hint or f"请确保 {module} 已正确安装",
    )
