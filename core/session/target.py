#!/usr/bin/env python3
"""
target.py - 目标定义模块

定义扫描目标的数据结构，支持多种目标类型的解析和标准化。
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class TargetType(Enum):
    """目标类型枚举"""

    URL = "url"  # 完整URL: http://example.com/path
    IP = "ip"  # IP地址: 192.168.1.1
    DOMAIN = "domain"  # 域名: example.com
    CIDR = "cidr"  # CIDR网段: 192.168.1.0/24
    HOST_PORT = "host_port"  # 主机:端口: example.com:8080


class TargetStatus(Enum):
    """目标状态枚举"""

    PENDING = "pending"  # 等待扫描
    SCANNING = "scanning"  # 正在扫描
    COMPLETED = "completed"  # 扫描完成
    FAILED = "failed"  # 扫描失败
    SKIPPED = "skipped"  # 已跳过


# IP地址正则
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# CIDR网段正则
CIDR_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$"
)

# 域名正则
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

# Host:Port 正则
HOST_PORT_PATTERN = re.compile(r"^(.+):(\d{1,5})$")


@dataclass
class Target:
    """
    扫描目标数据类

    表示一个待扫描的目标，支持多种格式的自动解析。

    Attributes:
        value: 原始目标值
        type: 目标类型
        status: 目标状态
        scheme: URL协议 (http/https)
        host: 主机名或IP
        port: 端口号
        path: URL路径
        created_at: 创建时间
        updated_at: 更新时间
        tags: 标签列表
        metadata: 扩展元数据
    """

    value: str  # 原始值
    type: TargetType  # 目标类型
    status: TargetStatus = TargetStatus.PENDING  # 目标状态

    # 解析后的属性
    scheme: Optional[str] = None  # http/https
    host: Optional[str] = None  # 主机名或IP
    port: Optional[int] = None  # 端口
    path: Optional[str] = None  # 路径

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理"""
        # 确保 tags 和 metadata 不为 None
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}

    @classmethod
    def parse(cls, value: str) -> "Target":
        """
        解析目标字符串，自动识别目标类型

        Args:
            value: 目标字符串 (URL/IP/域名/CIDR/Host:Port)

        Returns:
            Target: 解析后的目标对象

        Examples:
            >>> Target.parse("http://example.com:8080/api")
            >>> Target.parse("192.168.1.1")
            >>> Target.parse("example.com")
            >>> Target.parse("192.168.1.0/24")
            >>> Target.parse("example.com:443")
        """
        value = value.strip()
        if not value:
            raise ValueError("目标值不能为空")

        # 1. 尝试解析为URL
        if value.startswith(("http://", "https://", "//")):
            return cls._parse_url(value)

        # 2. 尝试解析为CIDR
        if CIDR_PATTERN.match(value):
            return cls._parse_cidr(value)

        # 3. 尝试解析为IP
        if IP_PATTERN.match(value):
            return cls._parse_ip(value)

        # 4. 尝试解析为 Host:Port
        host_port_match = HOST_PORT_PATTERN.match(value)
        if host_port_match:
            host_part = host_port_match.group(1)
            port_part = host_port_match.group(2)
            # 验证端口范围
            port = int(port_part)
            if 1 <= port <= 65535:
                return cls._parse_host_port(value, host_part, port)

        # 5. 默认解析为域名
        if DOMAIN_PATTERN.match(value):
            return cls._parse_domain(value)

        # 6. 无法识别，尝试作为URL处理
        if "/" in value or ":" in value:
            return cls._parse_url(f"http://{value}")

        # 7. 最后尝试作为域名
        return cls._parse_domain(value)

    @classmethod
    def _parse_url(cls, value: str) -> "Target":
        """解析URL类型目标"""
        # 处理 // 开头的URL
        if value.startswith("//"):
            value = "http:" + value

        parsed = urlparse(value)

        # 提取端口
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        return cls(
            value=value,
            type=TargetType.URL,
            scheme=parsed.scheme or "http",
            host=parsed.hostname or "",
            port=port,
            path=parsed.path or "/",
        )

    @classmethod
    def _parse_ip(cls, value: str) -> "Target":
        """解析IP类型目标"""
        # 验证IP地址有效性
        try:
            ipaddress.ip_address(value)
        except ValueError as e:
            raise ValueError(f"无效的IP地址: {value}") from e

        return cls(value=value, type=TargetType.IP, host=value)

    @classmethod
    def _parse_domain(cls, value: str) -> "Target":
        """解析域名类型目标"""
        return cls(value=value, type=TargetType.DOMAIN, host=value)

    @classmethod
    def _parse_cidr(cls, value: str) -> "Target":
        """解析CIDR网段类型目标"""
        # 验证CIDR有效性
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as e:
            raise ValueError(f"无效的CIDR网段: {value}") from e

        return cls(value=value, type=TargetType.CIDR, host=value.split("/")[0])

    @classmethod
    def _parse_host_port(cls, value: str, host: str, port: int) -> "Target":
        """解析 Host:Port 类型目标"""
        return cls(value=value, type=TargetType.HOST_PORT, host=host, port=port)

    @property
    def base_url(self) -> str:
        """
        获取基础URL

        Returns:
            str: 基础URL (scheme://host:port)

        Examples:
            >>> target = Target.parse("http://example.com:8080/api/v1")
            >>> target.base_url
            'http://example.com:8080'
        """
        if self.type == TargetType.URL:
            scheme = self.scheme or "http"
            host = self.host or ""
            port = self.port

            # 判断是否需要显示端口
            if port and not (
                (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            ):
                return f"{scheme}://{host}:{port}"
            return f"{scheme}://{host}"

        elif self.type == TargetType.HOST_PORT:
            scheme = self.scheme or "http"
            return f"{scheme}://{self.host}:{self.port}"

        elif self.type in (TargetType.IP, TargetType.DOMAIN):
            scheme = self.scheme or "http"
            if self.port:
                return f"{scheme}://{self.host}:{self.port}"
            return f"{scheme}://{self.host}"

        # CIDR类型返回空字符串
        return ""

    @property
    def netloc(self) -> str:
        """
        获取网络位置 (host:port)

        Returns:
            str: 网络位置字符串

        Examples:
            >>> target = Target.parse("http://example.com:8080/api")
            >>> target.netloc
            'example.com:8080'
        """
        if not self.host:
            return ""

        if self.port and self.port not in (80, 443):
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def full_url(self) -> str:
        """
        获取完整URL (包含路径)

        Returns:
            str: 完整URL
        """
        base = self.base_url
        if not base:
            return ""

        path = self.path or "/"
        if not path.startswith("/"):
            path = "/" + path

        return base + path

    def set_status(self, status: TargetStatus) -> None:
        """
        设置目标状态

        Args:
            status: 新状态
        """
        self.status = status
        self.updated_at = datetime.now()

    def add_tag(self, tag: str) -> None:
        """
        添加标签

        Args:
            tag: 标签字符串
        """
        if tag and tag not in self.tags:
            self.tags.append(tag)
            self.updated_at = datetime.now()

    def remove_tag(self, tag: str) -> bool:
        """
        移除标签

        Args:
            tag: 标签字符串

        Returns:
            bool: 是否成功移除
        """
        if tag in self.tags:
            self.tags.remove(tag)
            self.updated_at = datetime.now()
            return True
        return False

    def set_metadata(self, key: str, value: Any) -> None:
        """
        设置元数据

        Args:
            key: 键
            value: 值
        """
        self.metadata[key] = value
        self.updated_at = datetime.now()

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        获取元数据

        Args:
            key: 键
            default: 默认值

        Returns:
            元数据值
        """
        return self.metadata.get(key, default)

    def expand_cidr(self) -> List["Target"]:
        """
        展开CIDR网段为IP列表

        Returns:
            List[Target]: IP目标列表

        Raises:
            ValueError: 如果不是CIDR类型
        """
        if self.type != TargetType.CIDR:
            raise ValueError("只能展开CIDR类型目标")

        network = ipaddress.ip_network(self.value, strict=False)
        targets = []

        for ip in network.hosts():
            target = Target(
                value=str(ip),
                type=TargetType.IP,
                host=str(ip),
                tags=self.tags.copy(),
                metadata={**self.metadata, "parent_cidr": self.value},
            )
            targets.append(target)

        return targets

    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典

        Returns:
            Dict[str, Any]: 字典表示
        """
        return {
            "value": self.value,
            "type": self.type.value,
            "status": self.status.value,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Target":
        """
        从字典创建目标对象

        Args:
            data: 字典数据

        Returns:
            Target: 目标对象
        """
        return cls(
            value=data["value"],
            type=TargetType(data["type"]),
            status=TargetStatus(data.get("status", "pending")),
            scheme=data.get("scheme"),
            host=data.get("host"),
            port=data.get("port"),
            path=data.get("path"),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else datetime.now()
            ),
            updated_at=(
                datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None
            ),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )

    def __str__(self) -> str:
        """字符串表示"""
        return f"Target({self.value}, type={self.type.value}, status={self.status.value})"

    def __repr__(self) -> str:
        """详细表示"""
        return (
            f"Target(value={self.value!r}, type={self.type!r}, status={self.status!r}, "
            f"host={self.host!r}, port={self.port!r})"
        )

    def __eq__(self, other: object) -> bool:
        """相等比较"""
        if not isinstance(other, Target):
            return False
        return self.value == other.value and self.type == other.type

    def __hash__(self) -> int:
        """哈希值"""
        return hash((self.value, self.type))
