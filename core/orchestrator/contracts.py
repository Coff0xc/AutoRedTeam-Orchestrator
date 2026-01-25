#!/usr/bin/env python3
"""
contracts.py - 阶段数据协议规范

定义统一的数据结构和适配器，解决阶段间数据传递不一致的问题。

核心概念:
1. Credential - 统一凭证结构
2. VulnFinding - 统一漏洞发现结构
3. AccessGrant - 统一访问权限结构
4. PhaseDataAdapter - 阶段数据适配器基类
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib


class SecretType(Enum):
    """凭证密钥类型"""
    PASSWORD = 'password'
    NTLM_HASH = 'ntlm_hash'
    SSH_KEY = 'ssh_key'
    API_TOKEN = 'api_token'
    BEARER_TOKEN = 'bearer_token'
    SESSION_COOKIE = 'session_cookie'
    KERBEROS_TICKET = 'kerberos_ticket'
    CERTIFICATE = 'certificate'
    AWS_KEY = 'aws_key'
    AZURE_KEY = 'azure_key'
    GCP_KEY = 'gcp_key'
    UNKNOWN = 'unknown'


class VulnSeverity(Enum):
    """漏洞严重程度"""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'


class AccessLevel(Enum):
    """访问权限级别"""
    NONE = 'none'
    READ = 'read'
    WRITE = 'write'
    ADMIN = 'admin'
    ROOT = 'root'
    SYSTEM = 'system'
    DOMAIN_ADMIN = 'domain_admin'


@dataclass
class Credential:
    """统一凭证结构
    
    解决不同阶段使用 username/user/login, password/pass/passwd 等
    不一致命名的问题。
    
    Attributes:
        username: 用户名
        secret: 密钥内容（密码/哈希/密钥/令牌）
        secret_type: 密钥类型
        domain: 域名（Windows环境）
        host: 关联主机
        port: 关联端口
        service: 关联服务（ssh/smb/rdp等）
        source_phase: 发现该凭证的阶段
        confidence: 置信度 0-1
        verified: 是否已验证可用
        discovered_at: 发现时间
        metadata: 额外元数据
    """
    username: str
    secret: str
    secret_type: SecretType = SecretType.PASSWORD
    domain: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    source_phase: Optional[str] = None
    confidence: float = 1.0
    verified: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if isinstance(self.secret_type, str):
            self.secret_type = SecretType(self.secret_type)
    
    @property
    def unique_id(self) -> str:
        """生成唯一标识"""
        key = f"{self.username}:{self.secret_type.value}:{self.host}:{self.service}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'username': self.username,
            'secret': self.secret,
            'secret_type': self.secret_type.value,
            'domain': self.domain,
            'host': self.host,
            'port': self.port,
            'service': self.service,
            'source_phase': self.source_phase,
            'confidence': self.confidence,
            'verified': self.verified,
            'discovered_at': self.discovered_at.isoformat(),
            'metadata': self.metadata,
        }
    
    def to_safe_dict(self) -> Dict[str, Any]:
        """脱敏导出"""
        return {
            'username': self.username,
            'secret': '[REDACTED]',
            'secret_type': self.secret_type.value,
            'domain': self.domain,
            'host': self.host,
            'service': self.service,
            'source_phase': self.source_phase,
            'verified': self.verified,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Credential':
        return cls(
            username=data.get('username', ''),
            secret=data.get('secret', ''),
            secret_type=SecretType(data.get('secret_type', 'unknown')),
            domain=data.get('domain'),
            host=data.get('host'),
            port=data.get('port'),
            service=data.get('service'),
            source_phase=data.get('source_phase'),
            confidence=data.get('confidence', 1.0),
            verified=data.get('verified', False),
            discovered_at=datetime.fromisoformat(data['discovered_at']) if data.get('discovered_at') else datetime.now(),
            metadata=data.get('metadata', {}),
        )
    
    @classmethod
    def from_legacy(cls, data: Dict[str, Any], source_phase: Optional[str] = None) -> 'Credential':
        """从旧格式数据创建凭证
        
        兼容各种命名方式:
        - username/user/login/account
        - password/pass/passwd/secret/pwd
        - ntlm_hash/hash/nt_hash
        """
        # 提取用户名
        username = (
            data.get('username') or 
            data.get('user') or 
            data.get('login') or 
            data.get('account') or 
            data.get('name') or
            ''
        )
        
        # 提取密钥
        secret = (
            data.get('password') or 
            data.get('pass') or 
            data.get('passwd') or 
            data.get('secret') or
            data.get('pwd') or
            data.get('ntlm_hash') or
            data.get('hash') or
            data.get('nt_hash') or
            data.get('token') or
            data.get('api_key') or
            ''
        )
        
        # 推断密钥类型
        secret_type = SecretType.PASSWORD
        if data.get('ntlm_hash') or data.get('nt_hash') or data.get('hash'):
            secret_type = SecretType.NTLM_HASH
        elif data.get('ssh_key') or data.get('private_key'):
            secret = data.get('ssh_key') or data.get('private_key') or secret
            secret_type = SecretType.SSH_KEY
        elif data.get('token') or data.get('bearer'):
            secret_type = SecretType.BEARER_TOKEN
        elif data.get('api_key') or data.get('apikey'):
            secret_type = SecretType.API_TOKEN
        elif data.get('session') or data.get('cookie'):
            secret_type = SecretType.SESSION_COOKIE
        
        return cls(
            username=username,
            secret=secret,
            secret_type=secret_type,
            domain=data.get('domain') or data.get('workgroup'),
            host=data.get('host') or data.get('target') or data.get('ip'),
            port=data.get('port'),
            service=data.get('service') or data.get('protocol'),
            source_phase=source_phase,
            confidence=data.get('confidence', 1.0),
            verified=data.get('verified', False),
        )


@dataclass
class VulnFinding:
    """统一漏洞发现结构
    
    解决不同检测器返回结果格式不一致的问题。
    
    Attributes:
        vuln_id: 漏洞唯一ID
        vuln_type: 漏洞类型 (sqli/xss/rce/ssrf等)
        severity: 严重程度
        url: 受影响URL
        method: HTTP方法
        param: 受影响参数
        payload: 使用的payload
        evidence: 漏洞证据
        verified: 是否已验证
        exploitable: 是否可利用
        cve_ids: 关联CVE
        cvss_score: CVSS评分
        remediation: 修复建议
        source_detector: 发现该漏洞的检测器
        request_info: 请求信息
        response_info: 响应信息
        discovered_at: 发现时间
        metadata: 额外元数据
    """
    vuln_id: str
    vuln_type: str
    severity: VulnSeverity
    url: str
    method: str = 'GET'
    param: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    verified: bool = False
    exploitable: bool = False
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    source_detector: Optional[str] = None
    request_info: Optional[Dict[str, Any]] = None
    response_info: Optional[Dict[str, Any]] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = VulnSeverity(self.severity.lower())
        if not self.vuln_id:
            self.vuln_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """生成漏洞唯一ID"""
        key = f"{self.vuln_type}:{self.url}:{self.param}:{self.payload}"
        return hashlib.md5(key.encode()).hexdigest()[:16]
    
    @property
    def is_critical(self) -> bool:
        return self.severity in (VulnSeverity.CRITICAL, VulnSeverity.HIGH)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id,
            'vuln_type': self.vuln_type,
            'severity': self.severity.value,
            'url': self.url,
            'method': self.method,
            'param': self.param,
            'payload': self.payload,
            'evidence': self.evidence,
            'verified': self.verified,
            'exploitable': self.exploitable,
            'cve_ids': self.cve_ids,
            'cvss_score': self.cvss_score,
            'remediation': self.remediation,
            'source_detector': self.source_detector,
            'request_info': self.request_info,
            'response_info': self.response_info,
            'discovered_at': self.discovered_at.isoformat(),
            'metadata': self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnFinding':
        return cls(
            vuln_id=data.get('vuln_id', ''),
            vuln_type=data.get('vuln_type', data.get('type', 'unknown')),
            severity=VulnSeverity(data.get('severity', 'info').lower()),
            url=data.get('url', ''),
            method=data.get('method', 'GET'),
            param=data.get('param'),
            payload=data.get('payload'),
            evidence=data.get('evidence'),
            verified=data.get('verified', False),
            exploitable=data.get('exploitable', False),
            cve_ids=data.get('cve_ids', []),
            cvss_score=data.get('cvss_score'),
            remediation=data.get('remediation'),
            source_detector=data.get('source_detector'),
            request_info=data.get('request_info'),
            response_info=data.get('response_info'),
            discovered_at=datetime.fromisoformat(data['discovered_at']) if data.get('discovered_at') else datetime.now(),
            metadata=data.get('metadata', {}),
        )
    
    @classmethod
    def from_legacy(cls, data: Dict[str, Any], source_detector: Optional[str] = None) -> 'VulnFinding':
        """从旧格式检测结果创建漏洞发现
        
        兼容各种检测器输出格式
        """
        # 提取漏洞类型
        vuln_type = (
            data.get('vuln_type') or
            data.get('type') or
            data.get('vulnerability_type') or
            data.get('category') or
            'unknown'
        )
        
        # 提取严重程度
        severity_str = str(
            data.get('severity') or
            data.get('risk') or
            data.get('level') or
            'info'
        ).lower()
        
        # 映射严重程度
        severity_map = {
            'critical': VulnSeverity.CRITICAL,
            'crit': VulnSeverity.CRITICAL,
            'high': VulnSeverity.HIGH,
            'medium': VulnSeverity.MEDIUM,
            'med': VulnSeverity.MEDIUM,
            'low': VulnSeverity.LOW,
            'info': VulnSeverity.INFO,
            'informational': VulnSeverity.INFO,
        }
        severity = severity_map.get(severity_str, VulnSeverity.INFO)
        
        # 提取URL
        url = (
            data.get('url') or
            data.get('target') or
            data.get('endpoint') or
            data.get('uri') or
            ''
        )
        
        # 提取参数
        param = (
            data.get('param') or
            data.get('parameter') or
            data.get('vulnerable_param') or
            data.get('injection_point')
        )
        
        # 提取payload
        payload = (
            data.get('payload') or
            data.get('poc') or
            data.get('exploit') or
            data.get('attack_string')
        )
        
        # 提取证据
        evidence = (
            data.get('evidence') or
            data.get('proof') or
            data.get('output') or
            data.get('response_snippet') or
            data.get('detail')
        )
        
        return cls(
            vuln_id=data.get('vuln_id', data.get('id', '')),
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            method=data.get('method', 'GET'),
            param=param,
            payload=payload,
            evidence=evidence,
            verified=data.get('verified', data.get('confirmed', False)),
            exploitable=data.get('exploitable', data.get('exploited', False)),
            cve_ids=data.get('cve_ids', data.get('cves', [])),
            cvss_score=data.get('cvss_score', data.get('cvss')),
            remediation=data.get('remediation', data.get('fix', data.get('recommendation'))),
            source_detector=source_detector or data.get('detector', data.get('scanner')),
        )


@dataclass
class AccessGrant:
    """统一访问权限结构
    
    记录通过漏洞利用获得的访问权限。
    """
    host: str
    access_level: AccessLevel
    method: str  # 获取方式: exploit/credential/session
    shell_type: Optional[str] = None  # webshell/reverse_shell/bind_shell
    shell_path: Optional[str] = None
    session_id: Optional[str] = None
    credential: Optional[Credential] = None
    port: Optional[int] = None
    service: Optional[str] = None
    os_info: Optional[str] = None
    user_context: Optional[str] = None  # 当前用户上下文
    source_vuln: Optional[str] = None  # 来源漏洞ID
    obtained_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if isinstance(self.access_level, str):
            self.access_level = AccessLevel(self.access_level)
    
    @property
    def is_privileged(self) -> bool:
        """是否为特权访问"""
        return self.access_level in (
            AccessLevel.ADMIN, 
            AccessLevel.ROOT, 
            AccessLevel.SYSTEM,
            AccessLevel.DOMAIN_ADMIN
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'host': self.host,
            'access_level': self.access_level.value,
            'method': self.method,
            'shell_type': self.shell_type,
            'shell_path': self.shell_path,
            'session_id': self.session_id,
            'credential': self.credential.to_dict() if self.credential else None,
            'port': self.port,
            'service': self.service,
            'os_info': self.os_info,
            'user_context': self.user_context,
            'source_vuln': self.source_vuln,
            'obtained_at': self.obtained_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'metadata': self.metadata,
        }
    
    def to_safe_dict(self) -> Dict[str, Any]:
        """脱敏导出"""
        result = self.to_dict()
        if result.get('credential') and self.credential:
            result['credential'] = self.credential.to_safe_dict()
        if result.get('session_id'):
            result['session_id'] = '[REDACTED]'
        return result


class PhaseDataAdapter(ABC):
    """阶段数据适配器基类
    
    每个阶段执行器应实现对应的适配器，统一数据输出格式。
    """
    
    @abstractmethod
    def extract_credentials(self, raw_data: Dict[str, Any]) -> List[Credential]:
        """从原始数据中提取凭证"""
        pass
    
    @abstractmethod
    def extract_vulns(self, raw_data: Dict[str, Any]) -> List[VulnFinding]:
        """从原始数据中提取漏洞发现"""
        pass
    
    @abstractmethod
    def extract_accesses(self, raw_data: Dict[str, Any]) -> List[AccessGrant]:
        """从原始数据中提取访问权限"""
        pass


class ReconDataAdapter(PhaseDataAdapter):
    """侦察阶段数据适配器"""
    
    def extract_credentials(self, raw_data: Dict[str, Any]) -> List[Credential]:
        """从侦察结果中提取发现的凭证"""
        credentials = []
        
        # 从敏感文件发现中提取
        sensitive_files = raw_data.get('sensitive_files', [])
        for file_info in sensitive_files:
            if '.env' in file_info.get('path', ''):
                # 解析.env文件内容
                content = file_info.get('content', '')
                creds = self._parse_env_file(content)
                credentials.extend(creds)
        
        # 从Git泄露中提取
        git_data = raw_data.get('git_exposure', {})
        if git_data.get('credentials'):
            for cred in git_data['credentials']:
                credentials.append(Credential.from_legacy(cred, source_phase='recon'))
        
        return credentials
    
    def _parse_env_file(self, content: str) -> List[Credential]:
        """解析.env文件内容提取凭证"""
        credentials = []
        password_keys = ['PASSWORD', 'PASS', 'SECRET', 'KEY', 'TOKEN', 'API_KEY']
        
        lines = content.split('\n')
        current_user = None
        
        for line in lines:
            line = line.strip()
            if '=' not in line or line.startswith('#'):
                continue
            
            key, value = line.split('=', 1)
            key = key.strip().upper()
            value = value.strip().strip('"').strip("'")
            
            if 'USER' in key or 'NAME' in key:
                current_user = value
            elif any(pk in key for pk in password_keys):
                credentials.append(Credential(
                    username=current_user or 'unknown',
                    secret=value,
                    secret_type=SecretType.PASSWORD if 'PASSWORD' in key else SecretType.API_TOKEN,
                    source_phase='recon',
                ))
        
        return credentials
    
    def extract_vulns(self, raw_data: Dict[str, Any]) -> List[VulnFinding]:
        """侦察阶段通常不产出漏洞，但可能发现信息泄露"""
        vulns = []
        
        sensitive_files = raw_data.get('sensitive_files', [])
        for file_info in sensitive_files:
            path = file_info.get('path', '')
            
            # 信息泄露类发现
            if any(x in path for x in ['.git', '.env', 'config', 'backup']):
                vulns.append(VulnFinding(
                    vuln_id='',
                    vuln_type='info_disclosure',
                    severity=VulnSeverity.HIGH if '.git' in path or '.env' in path else VulnSeverity.MEDIUM,
                    url=file_info.get('url', ''),
                    evidence=f"发现敏感文件: {path}",
                    source_detector='recon_engine',
                ))
        
        return vulns
    
    def extract_accesses(self, raw_data: Dict[str, Any]) -> List[AccessGrant]:
        """侦察阶段不产出访问权限"""
        return []


class VulnScanDataAdapter(PhaseDataAdapter):
    """漏洞扫描阶段数据适配器"""
    
    def extract_credentials(self, raw_data: Dict[str, Any]) -> List[Credential]:
        """漏洞扫描阶段可能发现弱口令"""
        credentials = []
        
        findings = raw_data.get('findings', [])
        for finding in findings:
            if finding.get('type') in ('weak_password', 'default_credential'):
                cred_data = finding.get('credential', {})
                if cred_data:
                    credentials.append(Credential.from_legacy(
                        cred_data, 
                        source_phase='vuln_scan'
                    ))
        
        return credentials
    
    def extract_vulns(self, raw_data: Dict[str, Any]) -> List[VulnFinding]:
        """提取扫描发现的漏洞"""
        vulns = []
        
        findings = raw_data.get('findings', [])
        for finding in findings:
            vulns.append(VulnFinding.from_legacy(
                finding, 
                source_detector='vuln_scan'
            ))
        
        return vulns
    
    def extract_accesses(self, raw_data: Dict[str, Any]) -> List[AccessGrant]:
        """漏洞扫描阶段不产出访问权限"""
        return []


class ExploitDataAdapter(PhaseDataAdapter):
    """漏洞利用阶段数据适配器"""
    
    def extract_credentials(self, raw_data: Dict[str, Any]) -> List[Credential]:
        """从利用结果中提取凭证"""
        credentials = []
        
        # 从数据提取结果中获取
        extracted_data = raw_data.get('extracted_data', {})
        if extracted_data.get('credentials'):
            for cred in extracted_data['credentials']:
                credentials.append(Credential.from_legacy(cred, source_phase='exploit'))
        
        # 从shell会话中获取
        shells = raw_data.get('shells', [])
        for shell in shells:
            if shell.get('dumped_credentials'):
                for cred in shell['dumped_credentials']:
                    credentials.append(Credential.from_legacy(cred, source_phase='exploit'))
        
        return credentials
    
    def extract_vulns(self, raw_data: Dict[str, Any]) -> List[VulnFinding]:
        """提取已验证的漏洞"""
        vulns = []
        
        exploited = raw_data.get('exploited_vulns', [])
        for vuln in exploited:
            finding = VulnFinding.from_legacy(vuln, source_detector='exploit_engine')
            finding.verified = True
            finding.exploitable = True
            vulns.append(finding)
        
        return vulns
    
    def extract_accesses(self, raw_data: Dict[str, Any]) -> List[AccessGrant]:
        """提取获得的访问权限"""
        accesses = []
        
        shells = raw_data.get('shells', [])
        for shell in shells:
            accesses.append(AccessGrant(
                host=shell.get('host', ''),
                access_level=AccessLevel.WRITE if shell.get('type') == 'webshell' else AccessLevel.READ,
                method='exploit',
                shell_type=shell.get('type'),
                shell_path=shell.get('path'),
                user_context=shell.get('user'),
                source_vuln=shell.get('source_vuln'),
            ))
        
        access_info = raw_data.get('access', {})
        if access_info:
            level_map = {
                'root': AccessLevel.ROOT,
                'admin': AccessLevel.ADMIN,
                'system': AccessLevel.SYSTEM,
                'user': AccessLevel.WRITE,
            }
            accesses.append(AccessGrant(
                host=access_info.get('host', ''),
                access_level=level_map.get(access_info.get('level'), AccessLevel.READ),
                method='exploit',
                user_context=access_info.get('user'),
                os_info=access_info.get('os'),
            ))
        
        return accesses


class PrivEscDataAdapter(PhaseDataAdapter):
    """权限提升阶段数据适配器"""
    
    def extract_credentials(self, raw_data: Dict[str, Any]) -> List[Credential]:
        """从权限提升结果中提取凭证"""
        credentials = []
        
        # 提权过程中可能发现新凭证
        discovered = raw_data.get('discovered_credentials', [])
        for cred in discovered:
            credentials.append(Credential.from_legacy(cred, source_phase='privilege_escalation'))
        
        # SAM/LSASS转储
        if raw_data.get('sam_dump'):
            for entry in raw_data['sam_dump']:
                credentials.append(Credential(
                    username=entry.get('user', ''),
                    secret=entry.get('ntlm', ''),
                    secret_type=SecretType.NTLM_HASH,
                    host=raw_data.get('host'),
                    source_phase='privilege_escalation',
                ))
        
        return credentials
    
    def extract_vulns(self, raw_data: Dict[str, Any]) -> List[VulnFinding]:
        """权限提升阶段发现的漏洞"""
        vulns = []
        
        methods = raw_data.get('successful_methods', [])
        for method in methods:
            vulns.append(VulnFinding(
                vuln_id='',
                vuln_type='privilege_escalation',
                severity=VulnSeverity.CRITICAL,
                url=raw_data.get('host', ''),
                evidence=f"成功提权方法: {method.get('name', 'unknown')}",
                verified=True,
                exploitable=True,
                source_detector='priv_esc_module',
            ))
        
        return vulns
    
    def extract_accesses(self, raw_data: Dict[str, Any]) -> List[AccessGrant]:
        """提取提升后的访问权限"""
        accesses = []
        
        if raw_data.get('elevated'):
            accesses.append(AccessGrant(
                host=raw_data.get('host', ''),
                access_level=AccessLevel.ROOT if raw_data.get('level') == 'root' else AccessLevel.SYSTEM,
                method='privilege_escalation',
                user_context=raw_data.get('new_user', 'root/SYSTEM'),
                source_vuln=raw_data.get('method'),
            ))
        
        return accesses


class LateralMoveDataAdapter(PhaseDataAdapter):
    """横向移动阶段数据适配器"""
    
    def extract_credentials(self, raw_data: Dict[str, Any]) -> List[Credential]:
        """从横向移动结果中提取凭证"""
        credentials = []
        
        # 新主机上发现的凭证
        for host_data in raw_data.get('compromised_hosts', []):
            if host_data.get('credentials'):
                for cred in host_data['credentials']:
                    cred['host'] = host_data.get('host')
                    credentials.append(Credential.from_legacy(cred, source_phase='lateral_movement'))
        
        return credentials
    
    def extract_vulns(self, raw_data: Dict[str, Any]) -> List[VulnFinding]:
        """横向移动发现的漏洞"""
        vulns: List[VulnFinding] = []
        
        for host_data in raw_data.get('compromised_hosts', []):
            if host_data.get('method'):
                vulns.append(VulnFinding(
                    vuln_id='',
                    vuln_type='lateral_movement',
                    severity=VulnSeverity.HIGH,
                    url=host_data.get('host', ''),
                    evidence=f"横向移动成功: {host_data.get('method', 'unknown')}",
                    verified=True,
                    source_detector='lateral_move_module',
                ))
        
        return vulns
    
    def extract_accesses(self, raw_data: Dict[str, Any]) -> List[AccessGrant]:
        """提取新获得的访问权限"""
        accesses: List[AccessGrant] = []
        
        for host_data in raw_data.get('compromised_hosts', []):
            accesses.append(AccessGrant(
                host=host_data.get('host', ''),
                access_level=AccessLevel(host_data.get('access_level', 'read')),
                method='lateral_movement',
                user_context=host_data.get('user'),
                os_info=host_data.get('os'),
            ))
        
        return accesses


# ============================================================================
# 数据协议管理器
# ============================================================================

class PhaseDataManager:
    """阶段数据管理器
    
    统一管理各阶段的数据适配和转换，确保数据流转一致性。
    """
    
    _adapters: Dict[str, PhaseDataAdapter] = {
        'recon': ReconDataAdapter(),
        'vuln_scan': VulnScanDataAdapter(),
        'exploit': ExploitDataAdapter(),
        'privilege_escalation': PrivEscDataAdapter(),
        'lateral_movement': LateralMoveDataAdapter(),
    }
    
    @classmethod
    def get_adapter(cls, phase: str) -> Optional[PhaseDataAdapter]:
        """获取指定阶段的数据适配器"""
        return cls._adapters.get(phase)
    
    @classmethod
    def register_adapter(cls, phase: str, adapter: PhaseDataAdapter) -> None:
        """注册自定义适配器"""
        cls._adapters[phase] = adapter
    
    @classmethod
    def extract_all_credentials(
        cls,
        phase: str,
        raw_data: Dict[str, Any]
    ) -> List[Credential]:
        """从指定阶段数据中提取所有凭证"""
        adapter = cls.get_adapter(phase)
        if adapter:
            return adapter.extract_credentials(raw_data)
        return []
    
    @classmethod
    def extract_all_vulns(
        cls,
        phase: str,
        raw_data: Dict[str, Any]
    ) -> List[VulnFinding]:
        """从指定阶段数据中提取所有漏洞"""
        adapter = cls.get_adapter(phase)
        if adapter:
            return adapter.extract_vulns(raw_data)
        return []
    
    @classmethod
    def extract_all_accesses(
        cls,
        phase: str,
        raw_data: Dict[str, Any]
    ) -> List[AccessGrant]:
        """从指定阶段数据中提取所有访问权限"""
        adapter = cls.get_adapter(phase)
        if adapter:
            return adapter.extract_accesses(raw_data)
        return []
    
    @classmethod
    def normalize_credential(cls, data: Dict[str, Any], source: Optional[str] = None) -> Credential:
        """标准化凭证数据"""
        return Credential.from_legacy(data, source_phase=source)
    
    @classmethod
    def normalize_vuln(cls, data: Dict[str, Any], source: Optional[str] = None) -> VulnFinding:
        """标准化漏洞数据"""
        return VulnFinding.from_legacy(data, source_detector=source)


# ============================================================================
# 阶段结果容器
# ============================================================================

@dataclass
class PhaseResult:
    """阶段执行结果容器
    
    统一封装各阶段的执行结果，确保数据结构一致。
    """
    phase: str
    success: bool
    credentials: List[Credential] = field(default_factory=list)
    vulns: List[VulnFinding] = field(default_factory=list)
    accesses: List[AccessGrant] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    executed_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def merge(self, other: 'PhaseResult') -> 'PhaseResult':
        """合并两个阶段结果"""
        return PhaseResult(
            phase=self.phase,
            success=self.success and other.success,
            credentials=self.credentials + other.credentials,
            vulns=self.vulns + other.vulns,
            accesses=self.accesses + other.accesses,
            raw_data={**self.raw_data, **other.raw_data},
            errors=self.errors + other.errors,
            duration_seconds=self.duration_seconds + other.duration_seconds,
            executed_at=self.executed_at,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'phase': self.phase,
            'success': self.success,
            'credentials': [c.to_safe_dict() for c in self.credentials],
            'vulns': [v.to_dict() for v in self.vulns],
            'accesses': [a.to_safe_dict() for a in self.accesses],
            'errors': self.errors,
            'duration_seconds': self.duration_seconds,
            'executed_at': self.executed_at.isoformat(),
            'metadata': self.metadata,
        }
    
    @classmethod
    def from_raw(
        cls,
        phase: str,
        success: bool,
        raw_data: Dict[str, Any],
        duration: float = 0.0,
    ) -> 'PhaseResult':
        """从原始数据创建阶段结果
        
        自动使用适配器提取结构化数据。
        """
        adapter = PhaseDataManager.get_adapter(phase)
        
        credentials: List[Credential] = []
        vulns: List[VulnFinding] = []
        accesses: List[AccessGrant] = []
        
        if adapter:
            credentials = adapter.extract_credentials(raw_data)
            vulns = adapter.extract_vulns(raw_data)
            accesses = adapter.extract_accesses(raw_data)
        
        return cls(
            phase=phase,
            success=success,
            credentials=credentials,
            vulns=vulns,
            accesses=accesses,
            raw_data=raw_data,
            duration_seconds=duration,
        )


# ============================================================================
# 累积状态容器
# ============================================================================

@dataclass
class AccumulatedState:
    """累积状态容器
    
    跟踪整个渗透测试过程中累积的发现。
    """
    all_credentials: List[Credential] = field(default_factory=list)
    all_vulns: List[VulnFinding] = field(default_factory=list)
    all_accesses: List[AccessGrant] = field(default_factory=list)
    phase_results: List[PhaseResult] = field(default_factory=list)
    
    def add_phase_result(self, result: PhaseResult) -> None:
        """添加阶段结果到累积状态"""
        self.phase_results.append(result)
        
        # 去重添加凭证
        existing_ids = {c.unique_id for c in self.all_credentials}
        for cred in result.credentials:
            if cred.unique_id not in existing_ids:
                self.all_credentials.append(cred)
                existing_ids.add(cred.unique_id)
        
        # 去重添加漏洞
        existing_vuln_ids = {v.vuln_id for v in self.all_vulns}
        for vuln in result.vulns:
            if vuln.vuln_id not in existing_vuln_ids:
                self.all_vulns.append(vuln)
                existing_vuln_ids.add(vuln.vuln_id)
        
        # 添加访问权限
        self.all_accesses.extend(result.accesses)
    
    def get_verified_credentials(self) -> List[Credential]:
        """获取已验证的凭证"""
        return [c for c in self.all_credentials if c.verified]
    
    def get_exploitable_vulns(self) -> List[VulnFinding]:
        """获取可利用的漏洞"""
        return [v for v in self.all_vulns if v.exploitable]
    
    def get_privileged_accesses(self) -> List[AccessGrant]:
        """获取特权访问"""
        return [a for a in self.all_accesses if a.is_privileged]
    
    def get_hosts_with_access(self) -> List[str]:
        """获取已获得访问权限的主机列表"""
        return list(set(a.host for a in self.all_accesses))
    
    def to_summary(self) -> Dict[str, Any]:
        """生成摘要"""
        return {
            'total_credentials': len(self.all_credentials),
            'verified_credentials': len(self.get_verified_credentials()),
            'total_vulns': len(self.all_vulns),
            'exploitable_vulns': len(self.get_exploitable_vulns()),
            'critical_vulns': len([v for v in self.all_vulns if v.is_critical]),
            'total_accesses': len(self.all_accesses),
            'privileged_accesses': len(self.get_privileged_accesses()),
            'compromised_hosts': len(self.get_hosts_with_access()),
            'phases_completed': len(self.phase_results),
            'phases_succeeded': len([r for r in self.phase_results if r.success]),
        }