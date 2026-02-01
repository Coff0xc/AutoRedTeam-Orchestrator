#!/usr/bin/env python3
"""
横向移动工具函数 - Lateral Movement Utilities
通用工具函数和辅助方法

用于授权安全测试，仅限合法渗透测试使用
"""

import concurrent.futures
import logging
import platform
import socket
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type, Union

from .base import (
    BaseLateralModule,
    Credentials,
    ExecutionResult,
    LateralConfig,
)

logger = logging.getLogger(__name__)


class OSType(Enum):
    """操作系统类型"""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class PortStatus(Enum):
    """端口状态"""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


# 常见端口和服务映射
COMMON_PORTS = {
    22: ("ssh", "SSH"),
    23: ("telnet", "Telnet"),
    135: ("rpc", "RPC Endpoint Mapper"),
    139: ("netbios", "NetBIOS Session"),
    445: ("smb", "SMB"),
    3389: ("rdp", "RDP"),
    5985: ("winrm", "WinRM HTTP"),
    5986: ("winrm-ssl", "WinRM HTTPS"),
}


def check_port(host: str, port: int, timeout: float = 3.0) -> PortStatus:
    """
    检查端口状态

    Args:
        host: 目标主机
        port: 端口号
        timeout: 超时时间

    Returns:
        PortStatus 枚举
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            return PortStatus.OPEN
        else:
            return PortStatus.CLOSED

    except socket.timeout:
        return PortStatus.FILTERED
    except OSError:
        return PortStatus.UNKNOWN


def scan_ports(
    host: str,
    ports: Optional[List[int]] = None,
    timeout: float = 3.0,
    parallel: bool = True,
    max_workers: int = 10,
) -> Dict[int, PortStatus]:
    """
    扫描多个端口

    Args:
        host: 目标主机
        ports: 端口列表 (默认为横向移动常用端口)
        timeout: 超时时间
        parallel: 是否并行扫描
        max_workers: 最大并发数

    Returns:
        端口状态字典
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    results: Dict[int, PortStatus] = {}

    if parallel:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(check_port, host, port, timeout): port for port in ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    results[port] = future.result()
                except (concurrent.futures.CancelledError, TimeoutError, OSError):
                    results[port] = PortStatus.UNKNOWN
    else:
        for port in ports:
            results[port] = check_port(host, port, timeout)

    return results


def detect_os(host: str, timeout: float = 5.0) -> OSType:
    """
    检测远程主机操作系统类型

    基于开放端口推断

    Args:
        host: 目标主机
        timeout: 超时时间

    Returns:
        OSType 枚举
    """
    # Windows 特有端口
    windows_ports = [135, 139, 445, 3389, 5985, 5986]
    # Linux 常见端口
    linux_ports = [22]

    port_status = scan_ports(host, windows_ports + linux_ports, timeout)

    windows_score = sum(1 for p in windows_ports if port_status.get(p) == PortStatus.OPEN)

    linux_score = sum(1 for p in linux_ports if port_status.get(p) == PortStatus.OPEN)

    # 如果有 Windows 特有端口开放
    if windows_score > 0:
        return OSType.WINDOWS

    # 如果只有 SSH 开放
    if linux_score > 0 and windows_score == 0:
        return OSType.LINUX

    return OSType.UNKNOWN


def get_available_methods(host: str, timeout: float = 3.0) -> List[str]:
    """
    获取可用的横向移动方法

    Args:
        host: 目标主机
        timeout: 超时时间

    Returns:
        可用方法列表
    """
    methods = []

    port_status = scan_ports(host, timeout=timeout)

    if port_status.get(445) == PortStatus.OPEN:
        methods.append("smb")
        methods.append("psexec")

    if port_status.get(135) == PortStatus.OPEN:
        methods.append("wmi")

    if port_status.get(22) == PortStatus.OPEN:
        methods.append("ssh")

    if port_status.get(5985) == PortStatus.OPEN:
        methods.append("winrm")

    if port_status.get(5986) == PortStatus.OPEN:
        methods.append("winrm-ssl")

    return methods


def create_lateral(
    method: str, target: str, credentials: Credentials, config: Optional[LateralConfig] = None
) -> Optional[BaseLateralModule]:
    """
    创建横向移动模块实例

    Args:
        method: 方法名称 (smb, ssh, wmi, winrm, psexec)
        target: 目标主机
        credentials: 凭证
        config: 配置

    Returns:
        横向移动模块实例
    """
    from .psexec import PsExecLateral
    from .smb import SMBLateral
    from .ssh import SSHLateral
    from .winrm import WinRMLateral
    from .wmi import WMILateral

    module_map: Dict[str, Type[BaseLateralModule]] = {
        "smb": SMBLateral,
        "ssh": SSHLateral,
        "wmi": WMILateral,
        "winrm": WinRMLateral,
        "winrm-ssl": WinRMLateral,
        "psexec": PsExecLateral,
    }

    module_class = module_map.get(method.lower())
    if not module_class:
        logger.error(f"未知的横向移动方法: {method}")
        return None

    # WinRM SSL 特殊处理
    if method.lower() == "winrm-ssl":
        if config is None:
            config = LateralConfig()
        config.winrm_use_ssl = True

    return module_class(target, credentials, config)


def auto_lateral(
    target: str,
    credentials: Credentials,
    config: Optional[LateralConfig] = None,
    preferred_methods: Optional[List[str]] = None,
) -> Optional[BaseLateralModule]:
    """
    自动选择并创建横向移动模块

    根据目标可用服务自动选择最佳方法

    Args:
        target: 目标主机
        credentials: 凭证
        config: 配置
        preferred_methods: 优先方法列表

    Returns:
        已连接的横向移动模块实例，失败返回 None
    """
    available = get_available_methods(target)

    if not available:
        logger.warning(f"未发现可用的横向移动端口: {target}")
        return None

    # 默认优先级
    default_priority = ["psexec", "smb", "wmi", "winrm", "ssh"]

    if preferred_methods:
        methods_to_try = [m for m in preferred_methods if m in available]
    else:
        methods_to_try = [m for m in default_priority if m in available]

    for method in methods_to_try:
        logger.info(f"尝试 {method} 连接到 {target}")
        module = create_lateral(method, target, credentials, config)

        if module and module.connect():
            logger.info(f"成功通过 {method} 连接到 {target}")
            return module

        if module:
            module.disconnect()

    logger.error(f"所有方法均失败: {target}")
    return None


def batch_execute(
    targets: List[str],
    credentials: Credentials,
    command: str,
    method: Optional[str] = None,
    config: Optional[LateralConfig] = None,
    parallel: bool = True,
    max_workers: int = 5,
    callback: Optional[Callable[[str, ExecutionResult], None]] = None,
) -> Dict[str, ExecutionResult]:
    """
    批量执行命令

    Args:
        targets: 目标列表
        credentials: 凭证
        command: 命令
        method: 方法 (None 则自动选择)
        config: 配置
        parallel: 是否并行
        max_workers: 最大并发
        callback: 执行回调

    Returns:
        目标 -> 执行结果 字典
    """
    results: Dict[str, ExecutionResult] = {}

    def execute_target(target: str) -> ExecutionResult:
        try:
            if method:
                module = create_lateral(method, target, credentials, config)
            else:
                module = auto_lateral(target, credentials, config)

            if not module:
                return ExecutionResult(success=False, error=f"无法连接到 {target}")

            if not module.is_connected:
                if not module.connect():
                    return ExecutionResult(success=False, error=f"连接失败: {target}")

            result = module.execute(command)
            module.disconnect()

            if callback:
                callback(target, result)

            return result

        except Exception as e:
            return ExecutionResult(success=False, error=str(e))

    if parallel:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(execute_target, target): target for target in targets
            }

            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results[target] = future.result()
                except Exception as e:
                    results[target] = ExecutionResult(success=False, error=str(e))
    else:
        for target in targets:
            results[target] = execute_target(target)

    return results


def spray_credentials(
    targets: List[str],
    credentials_list: List[Credentials],
    methods: Optional[List[str]] = None,
    parallel: bool = True,
    max_workers: int = 3,
    callback: Optional[Callable[[str, Credentials, str], None]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    凭据喷洒

    Args:
        targets: 目标列表
        credentials_list: 凭据列表
        methods: 要尝试的方法
        parallel: 是否并行
        max_workers: 最大并发
        callback: 成功回调 (target, creds, method)

    Returns:
        成功的 target -> {creds, method} 字典
    """
    success: Dict[str, Dict[str, Any]] = {}

    def try_target(target: str) -> Optional[Dict[str, Any]]:
        available = get_available_methods(target)

        methods_to_try = methods or available

        for creds in credentials_list:
            for method in methods_to_try:
                if method not in available:
                    continue

                module = create_lateral(method, target, creds)
                if module and module.connect():
                    module.disconnect()

                    if callback:
                        callback(target, creds, method)

                    return {
                        "credentials": creds,
                        "method": method,
                    }

                if module:
                    module.disconnect()

        return None

    if parallel:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(try_target, target): target for target in targets}

            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    if result:
                        success[target] = result
                except Exception as exc:
                    logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    else:
        for target in targets:
            result = try_target(target)
            if result:
                success[target] = result

    return success


def get_local_platform() -> OSType:
    """获取本地操作系统类型"""
    system = platform.system().lower()

    if system == "windows":
        return OSType.WINDOWS
    elif system == "linux":
        return OSType.LINUX
    elif system == "darwin":
        return OSType.MACOS
    else:
        return OSType.UNKNOWN


def is_valid_ip(ip: str) -> bool:
    """验证 IP 地址格式"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        pass

    # IPv6
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        return False


def resolve_hostname(hostname: str) -> Optional[str]:
    """解析主机名到 IP"""
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return None


def parse_target_list(targets: Union[str, List[str]]) -> List[str]:
    """
    解析目标列表

    支持格式:
    - 单个 IP: "192.168.1.1"
    - IP 范围: "192.168.1.1-10"
    - CIDR: "192.168.1.0/24"
    - 逗号分隔: "192.168.1.1,192.168.1.2"
    - 列表: ["192.168.1.1", "192.168.1.2"]
    """
    if isinstance(targets, list):
        result = []
        for t in targets:
            result.extend(parse_target_list(t))
        return result

    targets = targets.strip()

    # 逗号分隔
    if "," in targets:
        result = []
        for t in targets.split(","):
            result.extend(parse_target_list(t.strip()))
        return result

    # CIDR
    if "/" in targets:
        try:
            import ipaddress

            network = ipaddress.ip_network(targets, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return [targets]

    # IP 范围
    if "-" in targets:
        try:
            parts = targets.rsplit(".", 1)
            if len(parts) == 2:
                base = parts[0]
                range_part = parts[1]

                if "-" in range_part:
                    start, end = range_part.split("-")
                    return [f"{base}.{i}" for i in range(int(start), int(end) + 1)]
        except Exception as exc:
            logging.getLogger(__name__).warning("Suppressed exception", exc_info=True)

    return [targets]


def format_result(result: ExecutionResult, verbose: bool = False) -> str:
    """格式化执行结果"""
    lines = []

    status = "SUCCESS" if result.success else "FAILED"
    lines.append(f"[{status}] (耗时: {result.duration:.2f}s)")

    if result.output:
        lines.append("Output:")
        lines.append(result.output.rstrip())

    if result.error and (verbose or not result.success):
        lines.append("Error:")
        lines.append(result.error.rstrip())

    if verbose:
        lines.append(f"Exit Code: {result.exit_code}")
        if result.method:
            lines.append(f"Method: {result.method}")

    return "\n".join(lines)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    logger.info("=== Lateral Movement Utilities ===")
    logger.info(f"本地平台: {get_local_platform().value}")

    logger.info("常见横向移动端口:")
    for port, (name, desc) in COMMON_PORTS.items():
        logger.info(f"  {port}: {name} ({desc})")

    logger.info("使用示例:")
    logger.info("  from core.lateral.utils import check_port, detect_os, create_lateral")
    logger.info("  status = check_port('192.168.1.100', 445)")
    logger.info("  os_type = detect_os('192.168.1.100')")
