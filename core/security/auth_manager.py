#!/usr/bin/env python3
"""
认证授权管理器 - MCP工具访问控制
提供API Key管理、工具分级授权、审计日志
"""

import hashlib
import hmac
import secrets
import time
import json
import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ToolLevel(Enum):
    """工具危险等级"""
    SAFE = 1        # 安全工具（信息收集）
    MODERATE = 2    # 中等风险（漏洞扫描）
    DANGEROUS = 3   # 高风险（漏洞利用）
    CRITICAL = 4    # 极高风险（横向移动、持久化）


class Permission(Enum):
    """权限类型"""
    READ = "read"           # 只读（查看结果）
    SCAN = "scan"           # 扫描（信息收集、漏洞检测）
    EXPLOIT = "exploit"     # 利用（漏洞利用）
    ADMIN = "admin"         # 管理员（所有权限）


@dataclass
class APIKey:
    """API密钥"""
    key_id: str
    key_hash: str
    name: str
    permissions: Set[Permission]
    max_tool_level: ToolLevel
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    usage_count: int = 0
    rate_limit: int = 100  # 每小时请求限制
    enabled: bool = True
    metadata: Dict = field(default_factory=dict)


@dataclass
class AuditLog:
    """审计日志"""
    timestamp: datetime
    key_id: str
    tool_name: str
    params: Dict
    success: bool
    error: Optional[str] = None
    ip_address: Optional[str] = None


class AuthManager:
    """认证授权管理器"""

    # 工具危险等级映射
    TOOL_LEVELS = {
        # SAFE - 信息收集
        "port_scan": ToolLevel.SAFE,
        "dns_lookup": ToolLevel.SAFE,
        "whois_query": ToolLevel.SAFE,
        "http_probe": ToolLevel.SAFE,
        "tech_detect": ToolLevel.SAFE,
        "subdomain_bruteforce": ToolLevel.SAFE,
        "dir_bruteforce": ToolLevel.SAFE,

        # MODERATE - 漏洞扫描
        "sqli_detect": ToolLevel.MODERATE,
        "xss_detect": ToolLevel.MODERATE,
        "ssrf_detect": ToolLevel.MODERATE,
        "xxe_detect": ToolLevel.MODERATE,
        "vuln_check": ToolLevel.MODERATE,
        "nuclei_scan": ToolLevel.MODERATE,
        "weak_password_detect": ToolLevel.MODERATE,

        # DANGEROUS - 漏洞利用
        "exploit_sqli_extract": ToolLevel.DANGEROUS,
        "exploit_rce": ToolLevel.DANGEROUS,
        "exploit_upload": ToolLevel.DANGEROUS,
        "brute_force": ToolLevel.DANGEROUS,

        # CRITICAL - 后渗透
        "lateral_smb_exec": ToolLevel.CRITICAL,
        "lateral_ssh_exec": ToolLevel.CRITICAL,
        "lateral_wmi_exec": ToolLevel.CRITICAL,
        "persistence_windows": ToolLevel.CRITICAL,
        "persistence_linux": ToolLevel.CRITICAL,
        "credential_dump": ToolLevel.CRITICAL,
        "c2_beacon_start": ToolLevel.CRITICAL,
    }

    def __init__(self, storage_path: str = None):
        """
        初始化认证管理器

        Args:
            storage_path: 存储路径
        """
        self.storage_path = storage_path or "data/auth"
        Path(self.storage_path).mkdir(parents=True, exist_ok=True)

        self.keys: Dict[str, APIKey] = {}
        self.audit_logs: List[AuditLog] = []
        self.rate_limit_tracker: Dict[str, List[float]] = {}

        self._load_keys()
        logger.info("认证管理器初始化完成")

    def generate_key(self, name: str, permissions: List[Permission],
                    max_tool_level: ToolLevel = ToolLevel.MODERATE,
                    expires_days: int = None, rate_limit: int = 100) -> Dict:
        """
        生成API密钥

        Args:
            name: 密钥名称
            permissions: 权限列表
            max_tool_level: 最大工具等级
            expires_days: 过期天数（None表示永不过期）
            rate_limit: 速率限制（每小时）

        Returns:
            包含key_id和secret的字典
        """
        # 生成密钥
        key_id = secrets.token_urlsafe(16)
        secret = secrets.token_urlsafe(32)
        key_hash = self._hash_key(secret)

        # 计算过期时间
        expires_at = None
        if expires_days:
            expires_at = datetime.now() + timedelta(days=expires_days)

        # 创建密钥对象
        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            name=name,
            permissions=set(permissions),
            max_tool_level=max_tool_level,
            created_at=datetime.now(),
            expires_at=expires_at,
            rate_limit=rate_limit
        )

        self.keys[key_id] = api_key
        self._save_keys()

        logger.info(f"生成API密钥: {name} (ID: {key_id})")

        return {
            "key_id": key_id,
            "secret": secret,
            "full_key": f"{key_id}.{secret}",
            "expires_at": expires_at.isoformat() if expires_at else None
        }

    def verify_key(self, full_key: str) -> Optional[APIKey]:
        """
        验证API密钥

        Args:
            full_key: 完整密钥（key_id.secret）

        Returns:
            APIKey对象，验证失败返回None
        """
        try:
            key_id, secret = full_key.split('.', 1)
        except ValueError:
            logger.warning("无效的密钥格式")
            return None

        api_key = self.keys.get(key_id)
        if not api_key:
            logger.warning(f"密钥不存在: {key_id}")
            return None

        # 检查密钥是否启用
        if not api_key.enabled:
            logger.warning(f"密钥已禁用: {key_id}")
            return None

        # 检查是否过期
        if api_key.expires_at and datetime.now() > api_key.expires_at:
            logger.warning(f"密钥已过期: {key_id}")
            return None

        # 验证密钥
        if not self._verify_key_hash(secret, api_key.key_hash):
            logger.warning(f"密钥验证失败: {key_id}")
            return None

        # 检查速率限制
        if not self._check_rate_limit(key_id, api_key.rate_limit):
            logger.warning(f"速率限制超出: {key_id}")
            return None

        # 更新使用信息
        api_key.last_used = datetime.now()
        api_key.usage_count += 1

        return api_key

    def check_permission(self, api_key: APIKey, tool_name: str) -> bool:
        """
        检查工具访问权限

        Args:
            api_key: API密钥对象
            tool_name: 工具名称

        Returns:
            是否有权限
        """
        # 管理员权限
        if Permission.ADMIN in api_key.permissions:
            return True

        # 获取工具等级
        tool_level = self.TOOL_LEVELS.get(tool_name, ToolLevel.MODERATE)

        # 检查等级限制
        if tool_level.value > api_key.max_tool_level.value:
            logger.warning(f"工具等级超出限制: {tool_name} ({tool_level.name})")
            return False

        # 检查具体权限
        if tool_level == ToolLevel.SAFE:
            return Permission.READ in api_key.permissions or Permission.SCAN in api_key.permissions

        elif tool_level == ToolLevel.MODERATE:
            return Permission.SCAN in api_key.permissions

        elif tool_level in [ToolLevel.DANGEROUS, ToolLevel.CRITICAL]:
            return Permission.EXPLOIT in api_key.permissions

        return False

    def audit(self, key_id: str, tool_name: str, params: Dict,
             success: bool, error: str = None, ip_address: str = None):
        """
        记录审计日志

        Args:
            key_id: 密钥ID
            tool_name: 工具名称
            params: 参数
            success: 是否成功
            error: 错误信息
            ip_address: IP地址
        """
        log = AuditLog(
            timestamp=datetime.now(),
            key_id=key_id,
            tool_name=tool_name,
            params=params,
            success=success,
            error=error,
            ip_address=ip_address
        )

        self.audit_logs.append(log)

        # 定期保存审计日志
        if len(self.audit_logs) >= 100:
            self._save_audit_logs()

    def revoke_key(self, key_id: str):
        """撤销密钥"""
        if key_id in self.keys:
            self.keys[key_id].enabled = False
            self._save_keys()
            logger.info(f"密钥已撤销: {key_id}")

    def list_keys(self) -> List[Dict]:
        """列出所有密钥"""
        return [
            {
                "key_id": k.key_id,
                "name": k.name,
                "permissions": [p.value for p in k.permissions],
                "max_tool_level": k.max_tool_level.name,
                "created_at": k.created_at.isoformat(),
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "last_used": k.last_used.isoformat() if k.last_used else None,
                "usage_count": k.usage_count,
                "enabled": k.enabled
            }
            for k in self.keys.values()
        ]

    def get_audit_logs(self, key_id: str = None, limit: int = 100) -> List[Dict]:
        """获取审计日志"""
        logs = self.audit_logs
        if key_id:
            logs = [log for log in logs if log.key_id == key_id]

        logs = logs[-limit:]

        return [
            {
                "timestamp": log.timestamp.isoformat(),
                "key_id": log.key_id,
                "tool_name": log.tool_name,
                "params": log.params,
                "success": log.success,
                "error": log.error,
                "ip_address": log.ip_address
            }
            for log in logs
        ]

    def _hash_key(self, secret: str) -> str:
        """哈希密钥"""
        return hashlib.sha256(secret.encode()).hexdigest()

    def _verify_key_hash(self, secret: str, key_hash: str) -> bool:
        """验证密钥哈希"""
        return hmac.compare_digest(self._hash_key(secret), key_hash)

    def _check_rate_limit(self, key_id: str, limit: int) -> bool:
        """检查速率限制"""
        now = time.time()
        hour_ago = now - 3600

        # 清理旧记录
        if key_id in self.rate_limit_tracker:
            self.rate_limit_tracker[key_id] = [
                t for t in self.rate_limit_tracker[key_id] if t > hour_ago
            ]
        else:
            self.rate_limit_tracker[key_id] = []

        # 检查限制
        if len(self.rate_limit_tracker[key_id]) >= limit:
            return False

        # 记录本次请求
        self.rate_limit_tracker[key_id].append(now)
        return True

    def _load_keys(self):
        """加载密钥"""
        keys_file = Path(self.storage_path) / "keys.json"
        if not keys_file.exists():
            return

        try:
            with open(keys_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for key_data in data:
                api_key = APIKey(
                    key_id=key_data["key_id"],
                    key_hash=key_data["key_hash"],
                    name=key_data["name"],
                    permissions={Permission(p) for p in key_data["permissions"]},
                    max_tool_level=ToolLevel[key_data["max_tool_level"]],
                    created_at=datetime.fromisoformat(key_data["created_at"]),
                    expires_at=datetime.fromisoformat(key_data["expires_at"]) if key_data.get("expires_at") else None,
                    last_used=datetime.fromisoformat(key_data["last_used"]) if key_data.get("last_used") else None,
                    usage_count=key_data.get("usage_count", 0),
                    rate_limit=key_data.get("rate_limit", 100),
                    enabled=key_data.get("enabled", True)
                )
                self.keys[api_key.key_id] = api_key

            logger.info(f"加载了 {len(self.keys)} 个API密钥")

        except Exception as e:
            logger.error(f"加载密钥失败: {e}")

    def _save_keys(self):
        """保存密钥"""
        keys_file = Path(self.storage_path) / "keys.json"

        data = [
            {
                "key_id": k.key_id,
                "key_hash": k.key_hash,
                "name": k.name,
                "permissions": [p.value for p in k.permissions],
                "max_tool_level": k.max_tool_level.name,
                "created_at": k.created_at.isoformat(),
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "last_used": k.last_used.isoformat() if k.last_used else None,
                "usage_count": k.usage_count,
                "rate_limit": k.rate_limit,
                "enabled": k.enabled
            }
            for k in self.keys.values()
        ]

        with open(keys_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _save_audit_logs(self):
        """保存审计日志"""
        log_file = Path(self.storage_path) / f"audit_{datetime.now().strftime('%Y%m%d')}.json"

        data = [
            {
                "timestamp": log.timestamp.isoformat(),
                "key_id": log.key_id,
                "tool_name": log.tool_name,
                "params": log.params,
                "success": log.success,
                "error": log.error,
                "ip_address": log.ip_address
            }
            for log in self.audit_logs
        ]

        with open(log_file, 'a', encoding='utf-8') as f:
            for entry in data:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')

        self.audit_logs.clear()


# 全局实例
_auth_manager: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    """获取全局认证管理器"""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager
