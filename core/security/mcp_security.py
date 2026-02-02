#!/usr/bin/env python3
"""
MCP 安全中间件

提供 MCP 服务器的安全加固功能：
- 输入验证
- 请求速率限制
- 参数清理
- 危险操作确认

Usage:
    from core.security.mcp_security import MCPSecurityMiddleware, InputValidator

    security = MCPSecurityMiddleware()

    # 验证输入
    if not security.validate_target("192.168.1.1"):
        raise ValueError("Invalid target")

    # 速率限制
    if not security.check_rate_limit("scan_operation"):
        raise RateLimitError("Too many requests")
"""

import inspect
import ipaddress
import logging
import os
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """操作风险等级"""

    SAFE = "safe"  # 无风险（读取、查询）
    LOW = "low"  # 低风险（被动扫描）
    MEDIUM = "medium"  # 中风险（主动扫描）
    HIGH = "high"  # 高风险（漏洞利用）
    CRITICAL = "critical"  # 危险操作（数据修改、横向移动）


# 风险等级顺序（用于比较），定义为模块常量避免重复创建
RISK_ORDER = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


@dataclass
class ValidationResult:
    """验证结果"""

    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sanitized_value: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "sanitized_value": self.sanitized_value,
        }


@dataclass
class RateLimitConfig:
    """速率限制配置"""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_limit: int = 10
    max_keys: int = 10000  # 最大键数，防止内存泄漏


class InputValidator:
    """输入验证器

    提供各类输入的验证和清理功能
    """

    # 危险字符正则
    DANGEROUS_CHARS = re.compile(r'[;\|\$\`\&\>\<\(\)\{\}\[\]\\\'"]')

    # 命令注入模式
    COMMAND_INJECTION_PATTERNS = [
        re.compile(r";\s*\w+"),  # ; command
        re.compile(r"\|\s*\w+"),  # | command
        re.compile(r"\$\("),  # $(command)
        re.compile(r"`[^`]+`"),  # `command`
        re.compile(r"&&\s*\w+"),  # && command
        re.compile(r"\|\|\s*\w+"),  # || command
    ]

    # 路径遍历模式
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r"\.\./"),  # ../
        re.compile(r"\.\.\\"),  # ..\
        re.compile(r"%2e%2e%2f", re.IGNORECASE),  # url encoded ../
        re.compile(r"%2e%2e/", re.IGNORECASE),  # partial encoded
        re.compile(r"\.\.%2f", re.IGNORECASE),  # partial encoded
        re.compile(r"%2e%2e%5c", re.IGNORECASE),  # url encoded ..\
        re.compile(r"\.\.%5c", re.IGNORECASE),  # partial encoded ..\
        re.compile(r"\.\./\.\./"),  # nested ../
        re.compile(r"\.\.;/"),  # semicolon bypass
    ]

    # 私有/保留 IP 范围
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    def validate_target(
        self,
        target: str,
        allowed_types: Optional[List[str]] = None,
        allow_private: bool = True,
    ) -> ValidationResult:
        """验证扫描目标

        Args:
            target: 目标字符串
            allowed_types: 允许的目标类型 ["ip", "domain", "url", "network"]
            allow_private: 是否允许私有 IP

        Returns:
            ValidationResult
        """
        errors = []
        warnings = []
        allowed_types = allowed_types or ["ip", "domain", "url", "network"]

        if not target:
            return ValidationResult(valid=False, errors=["目标不能为空"])

        if len(target) > 2048:
            return ValidationResult(valid=False, errors=["目标长度超过限制"])

        # 优先检测危险字符和命令注入（防御优先）
        if self.DANGEROUS_CHARS.search(target):
            return ValidationResult(
                valid=False,
                errors=["目标包含危险字符"],
            )

        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if pattern.search(target):
                return ValidationResult(
                    valid=False,
                    errors=["检测到潜在的命令注入"],
                )

        # 检测目标类型
        target_type = self._detect_target_type(target)

        if target_type == "unknown":
            return ValidationResult(
                valid=False,
                errors=[f"无法识别目标类型: {target[:50]}"],
            )

        if target_type not in allowed_types:
            return ValidationResult(
                valid=False,
                errors=[f"不允许的目标类型: {target_type}"],
            )

        # IP 特定验证
        if target_type == "ip":
            try:
                ip = ipaddress.ip_address(target)
                if not allow_private and self._is_private_ip(ip):
                    return ValidationResult(
                        valid=False,
                        errors=["不允许扫描私有 IP 地址"],
                    )
            except ValueError as e:
                return ValidationResult(valid=False, errors=[str(e)])

        # 网段验证
        if target_type == "network":
            try:
                network = ipaddress.ip_network(target, strict=False)
                if network.num_addresses > 65536:
                    warnings.append("大型网段扫描可能需要很长时间")
            except ValueError as e:
                return ValidationResult(valid=False, errors=[str(e)])

        # URL 验证（含 SSRF 检查）
        if target_type == "url":
            validation = self._validate_url(target, allow_private)
            if not validation.valid:
                return validation
            errors.extend(validation.errors)
            warnings.extend(validation.warnings)

        # 域名验证
        if target_type == "domain":
            validation = self._validate_domain(target)
            if not validation.valid:
                return validation

        return ValidationResult(
            valid=True,
            errors=errors,
            warnings=warnings,
            sanitized_value=target.strip(),
        )

    def validate_port(
        self,
        port: Any,
        allow_range: bool = True,
    ) -> ValidationResult:
        """验证端口

        Args:
            port: 端口号或端口范围字符串
            allow_range: 是否允许端口范围

        Returns:
            ValidationResult
        """
        if isinstance(port, int):
            if not (1 <= port <= 65535):
                return ValidationResult(
                    valid=False,
                    errors=["端口号必须在 1-65535 之间"],
                )
            return ValidationResult(valid=True, sanitized_value=port)

        if isinstance(port, str):
            port = port.strip()

            # 检查端口范围
            if "-" in port:
                if not allow_range:
                    return ValidationResult(
                        valid=False,
                        errors=["不允许端口范围"],
                    )
                try:
                    parts = port.split("-")
                    if len(parts) != 2:
                        return ValidationResult(
                            valid=False,
                            errors=["无效的端口范围格式"],
                        )
                    start_port = int(parts[0])
                    end_port = int(parts[1])

                    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                        return ValidationResult(
                            valid=False,
                            errors=["端口范围超出有效值"],
                        )
                    if start_port > end_port:
                        return ValidationResult(
                            valid=False,
                            errors=["端口范围起始值大于结束值"],
                        )

                    warnings = []
                    if end_port - start_port > 10000:
                        warnings.append("大范围端口扫描")

                    return ValidationResult(
                        valid=True,
                        warnings=warnings,
                        sanitized_value=f"{start_port}-{end_port}",
                    )
                except ValueError:
                    return ValidationResult(
                        valid=False,
                        errors=["无效的端口范围格式"],
                    )

            # 单个端口
            try:
                port_int = int(port)
                if not (1 <= port_int <= 65535):
                    return ValidationResult(
                        valid=False,
                        errors=["端口号必须在 1-65535 之间"],
                    )
                return ValidationResult(valid=True, sanitized_value=port_int)
            except ValueError:
                return ValidationResult(
                    valid=False,
                    errors=["无效的端口号"],
                )

        return ValidationResult(
            valid=False,
            errors=["端口必须是整数或字符串"],
        )

    def validate_path(self, path: str, base_dir: Optional[str] = None) -> ValidationResult:
        """验证文件路径

        Args:
            path: 文件路径
            base_dir: 允许的基础目录

        Returns:
            ValidationResult
        """
        if not path:
            return ValidationResult(valid=False, errors=["路径不能为空"])

        # 检测路径遍历
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if pattern.search(path):
                return ValidationResult(
                    valid=False,
                    errors=["检测到路径遍历尝试"],
                )

        # 检测空字节
        if "\x00" in path:
            return ValidationResult(
                valid=False,
                errors=["路径包含空字节"],
            )

        # 基础目录限制（使用 realpath 解析符号链接）
        if base_dir:
            abs_path = os.path.realpath(path)
            abs_base = os.path.realpath(base_dir)
            if not abs_path.startswith(abs_base):
                return ValidationResult(
                    valid=False,
                    errors=["路径超出允许的目录范围"],
                )

        return ValidationResult(valid=True, sanitized_value=path)

    def sanitize_string(
        self,
        value: str,
        max_length: int = 1000,
        allowed_chars: Optional[str] = None,
    ) -> str:
        """清理字符串

        Args:
            value: 输入字符串
            max_length: 最大长度
            allowed_chars: 允许的字符（正则字符类，如 'a-zA-Z0-9'）

        Returns:
            清理后的字符串
        """
        if not value:
            return ""

        # 截断
        value = value[:max_length]

        # 移除控制字符
        value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)

        # 移除非允许字符（预编译确保安全）
        if allowed_chars:
            try:
                pattern = re.compile(f"[^{allowed_chars}]")
                value = pattern.sub("", value)
            except re.error:
                logger.warning("sanitize_string: 无效的 allowed_chars 模式, 跳过字符过滤")

        return value.strip()

    def _detect_target_type(self, target: str) -> str:
        """检测目标类型"""
        # URL
        if target.startswith(("http://", "https://")):
            return "url"

        # CIDR
        if "/" in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return "network"
            except ValueError:
                pass

        # IP
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass

        # 域名
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
        if re.match(domain_pattern, target):
            return "domain"

        return "unknown"

    def _is_private_ip(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """检查是否为私有 IP"""
        for network in self.PRIVATE_IP_RANGES:
            if ip in network:
                return True
        return False

    def _validate_url(self, url: str, allow_private: bool = True) -> ValidationResult:
        """验证 URL（含 SSRF 检查）"""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return ValidationResult(
                valid=False,
                errors=["仅支持 HTTP/HTTPS 协议"],
            )
        if not parsed.netloc:
            return ValidationResult(
                valid=False,
                errors=["URL 缺少主机名"],
            )

        # SSRF 检查：提取主机名检查私有 IP
        if not allow_private:
            hostname = parsed.hostname
            if hostname:
                try:
                    ip = ipaddress.ip_address(hostname)
                    if self._is_private_ip(ip):
                        return ValidationResult(
                            valid=False,
                            errors=["URL 主机为私有 IP 地址"],
                        )
                except ValueError:
                    pass  # 非 IP 地址的域名，正常放行

        return ValidationResult(valid=True)

    def _validate_domain(self, domain: str) -> ValidationResult:
        """验证域名"""
        if len(domain) > 253:
            return ValidationResult(
                valid=False,
                errors=["域名长度超过限制"],
            )

        labels = domain.split(".")
        for label in labels:
            if len(label) > 63:
                return ValidationResult(
                    valid=False,
                    errors=["域名标签长度超过限制"],
                )
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", label):
                return ValidationResult(
                    valid=False,
                    errors=["域名格式无效"],
                )

        return ValidationResult(valid=True)


class RateLimiter:
    """速率限制器

    使用滑动窗口算法实现请求限流
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._minute_windows: Dict[str, List[float]] = defaultdict(list)
        self._hour_windows: Dict[str, List[float]] = defaultdict(list)
        self._burst_tokens: Dict[str, int] = defaultdict(lambda: self.config.burst_limit)
        self._last_refill: Dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> Tuple[bool, str]:
        """检查是否允许请求

        Args:
            key: 限流键（如操作类型、IP、用户等）

        Returns:
            (allowed, reason)
        """
        now = time.time()

        with self._lock:
            # 定期清理过期键，防止内存泄漏
            self._evict_stale_keys(now)

            # 清理过期记录
            self._cleanup(key, now)

            # 检查突发限制（令牌桶）
            self._refill_tokens(key, now)
            if self._burst_tokens[key] <= 0:
                return False, "超过突发请求限制"

            # 检查每分钟限制
            minute_count = len(self._minute_windows[key])
            if minute_count >= self.config.requests_per_minute:
                return False, f"超过每分钟请求限制 ({self.config.requests_per_minute})"

            # 检查每小时限制
            hour_count = len(self._hour_windows[key])
            if hour_count >= self.config.requests_per_hour:
                return False, f"超过每小时请求限制 ({self.config.requests_per_hour})"

            # 记录请求
            self._minute_windows[key].append(now)
            self._hour_windows[key].append(now)
            self._burst_tokens[key] -= 1

            return True, "ok"

    def _cleanup(self, key: str, now: float):
        """清理过期记录"""
        minute_ago = now - 60
        hour_ago = now - 3600

        self._minute_windows[key] = [
            t for t in self._minute_windows[key] if t > minute_ago
        ]
        self._hour_windows[key] = [
            t for t in self._hour_windows[key] if t > hour_ago
        ]

    def _evict_stale_keys(self, now: float):
        """清除过期的空键，防止内存无限增长"""
        if len(self._minute_windows) <= self.config.max_keys:
            return

        stale_keys = []
        hour_ago = now - 3600
        for key in list(self._minute_windows.keys()):
            # 如果该键的所有记录都过期了，移除它
            if not self._hour_windows.get(key) or all(
                t <= hour_ago for t in self._hour_windows.get(key, [])
            ):
                stale_keys.append(key)

        for key in stale_keys:
            self._minute_windows.pop(key, None)
            self._hour_windows.pop(key, None)
            self._burst_tokens.pop(key, None)
            self._last_refill.pop(key, None)

    def _refill_tokens(self, key: str, now: float):
        """补充令牌"""
        last = self._last_refill.get(key, now)
        elapsed = now - last

        # 每秒补充 1 个令牌
        tokens_to_add = int(elapsed)
        if tokens_to_add > 0:
            self._burst_tokens[key] = min(
                self._burst_tokens[key] + tokens_to_add,
                self.config.burst_limit,
            )
            self._last_refill[key] = now

    def get_remaining(self, key: str) -> Dict[str, int]:
        """获取剩余配额"""
        now = time.time()

        with self._lock:
            self._cleanup(key, now)

            return {
                "minute": self.config.requests_per_minute - len(self._minute_windows[key]),
                "hour": self.config.requests_per_hour - len(self._hour_windows[key]),
                "burst": self._burst_tokens[key],
            }


class OperationAuthorizer:
    """操作授权器

    控制高风险操作的执行权限
    """

    # 操作风险等级映射
    OPERATION_RISKS: Dict[str, RiskLevel] = {
        # 安全操作
        "port_scan": RiskLevel.LOW,
        "dns_lookup": RiskLevel.SAFE,
        "http_probe": RiskLevel.SAFE,
        "tech_detect": RiskLevel.SAFE,
        "subdomain_enum": RiskLevel.LOW,

        # 中等风险
        "vuln_scan": RiskLevel.MEDIUM,
        "dir_scan": RiskLevel.MEDIUM,
        "sqli_detect": RiskLevel.MEDIUM,
        "xss_detect": RiskLevel.MEDIUM,

        # 高风险
        "exploit": RiskLevel.HIGH,
        "brute_force": RiskLevel.HIGH,
        "poc_execute": RiskLevel.HIGH,

        # 危险操作
        "lateral_move": RiskLevel.CRITICAL,
        "credential_dump": RiskLevel.CRITICAL,
        "persistence": RiskLevel.CRITICAL,
        "c2_beacon": RiskLevel.CRITICAL,
        "exfiltrate": RiskLevel.CRITICAL,
    }

    def __init__(self, max_risk: RiskLevel = RiskLevel.HIGH):
        self.max_risk = max_risk
        self._authorized_operations: Dict[str, float] = {}  # operation -> expiry_time
        self._lock = threading.Lock()

    def check_authorization(self, operation: str) -> Tuple[bool, str]:
        """检查操作是否被授权

        Args:
            operation: 操作名称

        Returns:
            (authorized, reason)
        """
        risk = self.OPERATION_RISKS.get(operation, RiskLevel.MEDIUM)

        # 安全操作直接放行
        if risk == RiskLevel.SAFE:
            return True, "safe_operation"

        with self._lock:
            # 清理过期授权
            self._cleanup_expired()

            # 超过最大风险等级
            if RISK_ORDER.index(risk) > RISK_ORDER.index(self.max_risk):
                return False, (
                    f"操作风险等级 ({risk.value}) 超过允许的最大等级 ({self.max_risk.value})"
                )

            # 危险操作需要显式授权
            if risk == RiskLevel.CRITICAL:
                if operation not in self._authorized_operations:
                    return False, "危险操作需要显式授权"

            return True, "authorized"

    def authorize_operation(self, operation: str, duration: int = 300):
        """授权操作

        Args:
            operation: 操作名称
            duration: 授权持续时间（秒）
        """
        with self._lock:
            self._authorized_operations[operation] = time.time() + duration
            logger.info("已授权操作: %s (持续 %ds)", operation, duration)

    def revoke_operation(self, operation: str):
        """撤销操作授权"""
        with self._lock:
            self._authorized_operations.pop(operation, None)
            logger.info("已撤销操作授权: %s", operation)

    def get_risk_level(self, operation: str) -> RiskLevel:
        """获取操作风险等级"""
        return self.OPERATION_RISKS.get(operation, RiskLevel.MEDIUM)

    def _cleanup_expired(self):
        """清理过期的授权（在锁内调用）"""
        now = time.time()
        expired = [op for op, expiry in self._authorized_operations.items() if expiry <= now]
        for op in expired:
            del self._authorized_operations[op]
            logger.info("授权已过期: %s", op)


class MCPSecurityMiddleware:
    """MCP 安全中间件

    组合输入验证、速率限制和操作授权
    """

    def __init__(
        self,
        rate_limit_config: Optional[RateLimitConfig] = None,
        max_risk: RiskLevel = RiskLevel.HIGH,
    ):
        self.validator = InputValidator()
        self.rate_limiter = RateLimiter(rate_limit_config)
        self.authorizer = OperationAuthorizer(max_risk)

    def validate_target(self, target: str, **kwargs) -> ValidationResult:
        """验证目标"""
        return self.validator.validate_target(target, **kwargs)

    def validate_port(self, port: Any, **kwargs) -> ValidationResult:
        """验证端口"""
        return self.validator.validate_port(port, **kwargs)

    def check_rate_limit(self, key: str) -> Tuple[bool, str]:
        """检查速率限制"""
        return self.rate_limiter.check(key)

    def check_operation(self, operation: str) -> Tuple[bool, str]:
        """检查操作授权"""
        return self.authorizer.check_authorization(operation)

    def authorize(self, operation: str, duration: int = 300):
        """授权操作"""
        self.authorizer.authorize_operation(operation, duration)

    def sanitize(self, value: str, **kwargs) -> str:
        """清理字符串"""
        return self.validator.sanitize_string(value, **kwargs)

    def secure_tool(self, operation: str = None, rate_limit_key: str = None):
        """装饰器：保护 MCP 工具

        Args:
            operation: 操作名称（用于授权检查）
            rate_limit_key: 速率限制键

        Usage:
            @security.secure_tool(operation="port_scan", rate_limit_key="scan")
            async def port_scan(target: str):
                ...
        """
        def decorator(func: Callable) -> Callable:
            # 解析函数签名以支持位置参数的 target
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())

            @wraps(func)
            async def wrapper(*args, **kwargs):
                # 速率限制
                if rate_limit_key:
                    allowed, reason = self.check_rate_limit(rate_limit_key)
                    if not allowed:
                        return {"success": False, "error": f"Rate limited: {reason}"}

                # 操作授权
                op_name = operation or func.__name__
                authorized, reason = self.check_operation(op_name)
                if not authorized:
                    return {"success": False, "error": f"Not authorized: {reason}"}

                # 输入验证（支持位置参数和关键字参数中的 target）
                target_value = kwargs.get("target")
                target_idx = None
                if target_value is None and "target" in param_names:
                    target_idx = param_names.index("target")
                    if target_idx < len(args):
                        target_value = args[target_idx]

                if target_value is not None:
                    result = self.validate_target(target_value)
                    if not result.valid:
                        return {"success": False, "error": f"Invalid target: {result.errors}"}
                    # 替换为清洗后的值
                    if "target" in kwargs:
                        kwargs["target"] = result.sanitized_value
                    elif target_idx is not None and target_idx < len(args):
                        args = list(args)
                        args[target_idx] = result.sanitized_value
                        args = tuple(args)

                return await func(*args, **kwargs)

            return wrapper
        return decorator
