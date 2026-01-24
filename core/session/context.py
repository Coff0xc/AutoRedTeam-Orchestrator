#!/usr/bin/env python3
"""
context.py - 扫描上下文模块

管理扫描过程中的所有状态和收集的信息。
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from datetime import datetime
from enum import Enum
import uuid
import copy

if TYPE_CHECKING:
    from .target import Target
    from .result import Vulnerability, ScanResult


class ScanPhase(Enum):
    """扫描阶段枚举"""
    INIT = 'init'                    # 初始化
    RECON = 'recon'                  # 信息收集
    FINGERPRINT = 'fingerprint'      # 指纹识别
    DISCOVERY = 'discovery'          # 资产发现
    VULN_SCAN = 'vuln_scan'          # 漏洞扫描
    EXPLOITATION = 'exploitation'    # 漏洞利用
    POST_EXPLOIT = 'post_exploit'    # 后渗透
    REPORTING = 'reporting'          # 报告生成
    COMPLETED = 'completed'          # 完成
    FAILED = 'failed'                # 失败


class ContextStatus(Enum):
    """上下文状态枚举"""
    ACTIVE = 'active'       # 活动中
    PAUSED = 'paused'       # 已暂停
    COMPLETED = 'completed' # 已完成
    FAILED = 'failed'       # 已失败
    CANCELLED = 'cancelled' # 已取消


@dataclass
class ScanContext:
    """
    扫描上下文数据类

    保存扫描过程中的所有状态、收集的信息和HTTP会话信息。

    Attributes:
        session_id: 会话唯一ID
        target: 扫描目标
        started_at: 开始时间
        ended_at: 结束时间
        phase: 当前扫描阶段
        status: 上下文状态
        config: 扫描配置
        fingerprints: 指纹信息
        technologies: 技术栈列表
        ports: 开放端口
        subdomains: 子域名
        directories: 目录
        parameters: 参数
        vulnerabilities: 发现的漏洞
        cookies: HTTP Cookie
        headers: HTTP 请求头
        auth_token: 认证令牌
        requests_sent: 发送的请求数
        errors_count: 错误计数
    """

    # 基本信息
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target: Optional['Target'] = None
    started_at: datetime = field(default_factory=datetime.now)
    ended_at: Optional[datetime] = None

    # 状态
    phase: ScanPhase = ScanPhase.INIT
    status: ContextStatus = ContextStatus.ACTIVE

    # 配置
    config: Dict[str, Any] = field(default_factory=dict)

    # 收集的信息
    fingerprints: Dict[str, Any] = field(default_factory=dict)    # 指纹信息
    technologies: List[str] = field(default_factory=list)         # 技术栈
    ports: List[Dict[str, Any]] = field(default_factory=list)     # 开放端口
    subdomains: List[str] = field(default_factory=list)           # 子域名
    directories: List[str] = field(default_factory=list)          # 目录
    parameters: List[Dict[str, Any]] = field(default_factory=list) # 参数
    js_files: List[str] = field(default_factory=list)             # JS文件
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)  # API端点

    # 发现的漏洞
    vulnerabilities: List['Vulnerability'] = field(default_factory=list)

    # HTTP会话状态
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    proxy: Optional[str] = None

    # 统计
    requests_sent: int = 0
    errors_count: int = 0

    # 日志和备注
    logs: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理"""
        # 确保所有集合类型字段不为None
        _list_fields = [
            'technologies', 'ports', 'subdomains', 'directories',
            'parameters', 'js_files', 'api_endpoints', 'vulnerabilities',
            'logs', 'notes'
        ]
        _dict_fields = ['fingerprints', 'cookies', 'headers', 'config', 'metadata']

        for field_name in _list_fields:
            if getattr(self, field_name) is None:
                setattr(self, field_name, [])

        for field_name in _dict_fields:
            if getattr(self, field_name) is None:
                setattr(self, field_name, {})

    def set_target(self, target: 'Target') -> None:
        """
        设置扫描目标

        Args:
            target: 目标对象
        """
        self.target = target
        self.log('info', f"设置扫描目标: {target.value}")

    def set_phase(self, phase: ScanPhase) -> None:
        """
        设置扫描阶段

        Args:
            phase: 扫描阶段
        """
        old_phase = self.phase
        self.phase = phase
        self.log('info', f"扫描阶段变更: {old_phase.value} -> {phase.value}")

    def set_status(self, status: ContextStatus) -> None:
        """
        设置上下文状态

        Args:
            status: 上下文状态
        """
        self.status = status
        if status in (ContextStatus.COMPLETED, ContextStatus.FAILED, ContextStatus.CANCELLED):
            self.ended_at = datetime.now()

    def add_vulnerability(self, vuln: 'Vulnerability') -> None:
        """
        添加漏洞

        Args:
            vuln: 漏洞对象
        """
        # 避免重复添加
        for existing in self.vulnerabilities:
            if (existing.url == vuln.url and
                existing.type == vuln.type and
                existing.param == vuln.param):
                # 如果新漏洞置信度更高，则更新
                if vuln.confidence > existing.confidence:
                    self.vulnerabilities.remove(existing)
                    break
                else:
                    return

        self.vulnerabilities.append(vuln)
        self.log('warning', f"发现漏洞: [{vuln.severity.value}] {vuln.title}")

    def add_fingerprint(
        self,
        category: str,
        name: str,
        version: Optional[str] = None,
        confidence: float = 1.0
    ) -> None:
        """
        添加指纹信息

        Args:
            category: 分类 (server/framework/cms/etc.)
            name: 名称
            version: 版本 (可选)
            confidence: 置信度
        """
        if category not in self.fingerprints:
            self.fingerprints[category] = []

        fingerprint = {
            'name': name,
            'version': version,
            'confidence': confidence,
            'detected_at': datetime.now().isoformat()
        }

        # 检查是否已存在
        for existing in self.fingerprints[category]:
            if existing['name'] == name:
                # 如果新的置信度更高，更新
                if confidence > existing.get('confidence', 0):
                    existing.update(fingerprint)
                return

        self.fingerprints[category].append(fingerprint)

        # 同时添加到技术栈
        tech_name = f"{name} {version}" if version else name
        if tech_name not in self.technologies:
            self.technologies.append(tech_name)

    def add_port(
        self,
        port: int,
        protocol: str = 'tcp',
        service: Optional[str] = None,
        version: Optional[str] = None,
        state: str = 'open'
    ) -> None:
        """
        添加开放端口

        Args:
            port: 端口号
            protocol: 协议 (tcp/udp)
            service: 服务名
            version: 版本
            state: 状态
        """
        # 检查是否已存在
        for existing in self.ports:
            if existing['port'] == port and existing['protocol'] == protocol:
                # 更新信息
                if service:
                    existing['service'] = service
                if version:
                    existing['version'] = version
                return

        self.ports.append({
            'port': port,
            'protocol': protocol,
            'service': service,
            'version': version,
            'state': state,
            'discovered_at': datetime.now().isoformat()
        })

    def add_subdomain(self, subdomain: str) -> None:
        """
        添加子域名

        Args:
            subdomain: 子域名
        """
        subdomain = subdomain.lower().strip()
        if subdomain and subdomain not in self.subdomains:
            self.subdomains.append(subdomain)

    def add_directory(self, directory: str, status_code: int = None) -> None:
        """
        添加目录

        Args:
            directory: 目录路径
            status_code: HTTP状态码
        """
        directory = directory.strip()
        if directory and directory not in self.directories:
            self.directories.append(directory)
            if status_code:
                self.metadata.setdefault('dir_status', {})[directory] = status_code

    def add_parameter(
        self,
        name: str,
        location: str,
        url: str,
        param_type: str = 'string'
    ) -> None:
        """
        添加参数

        Args:
            name: 参数名
            location: 位置 (query/body/header/cookie)
            url: 所在URL
            param_type: 参数类型
        """
        param = {
            'name': name,
            'location': location,
            'url': url,
            'type': param_type,
            'discovered_at': datetime.now().isoformat()
        }

        # 检查是否已存在
        for existing in self.parameters:
            if existing['name'] == name and existing['url'] == url:
                return

        self.parameters.append(param)

    def add_api_endpoint(
        self,
        path: str,
        method: str = 'GET',
        params: List[str] = None,
        authenticated: bool = False
    ) -> None:
        """
        添加API端点

        Args:
            path: API路径
            method: HTTP方法
            params: 参数列表
            authenticated: 是否需要认证
        """
        endpoint = {
            'path': path,
            'method': method.upper(),
            'params': params or [],
            'authenticated': authenticated,
            'discovered_at': datetime.now().isoformat()
        }

        # 检查是否已存在
        for existing in self.api_endpoints:
            if existing['path'] == path and existing['method'] == method.upper():
                return

        self.api_endpoints.append(endpoint)

    def add_js_file(self, url: str) -> None:
        """
        添加JS文件

        Args:
            url: JS文件URL
        """
        if url and url not in self.js_files:
            self.js_files.append(url)

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """
        设置Cookie

        Args:
            cookies: Cookie字典
        """
        self.cookies.update(cookies)

    def set_headers(self, headers: Dict[str, str]) -> None:
        """
        设置请求头

        Args:
            headers: 请求头字典
        """
        self.headers.update(headers)

    def set_auth_token(self, token: str, token_type: str = 'Bearer') -> None:
        """
        设置认证令牌

        Args:
            token: 令牌值
            token_type: 令牌类型 (Bearer/Basic/etc.)
        """
        self.auth_token = token
        self.headers['Authorization'] = f"{token_type} {token}"

    def increment_requests(self, count: int = 1) -> None:
        """
        增加请求计数

        Args:
            count: 增加数量
        """
        self.requests_sent += count

    def increment_errors(self, count: int = 1) -> None:
        """
        增加错误计数

        Args:
            count: 增加数量
        """
        self.errors_count += count

    def log(self, level: str, message: str, data: Any = None) -> None:
        """
        记录日志

        Args:
            level: 日志级别 (debug/info/warning/error)
            message: 日志消息
            data: 附加数据
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message,
        }
        if data is not None:
            log_entry['data'] = data
        self.logs.append(log_entry)

    def add_note(self, note: str) -> None:
        """
        添加备注

        Args:
            note: 备注内容
        """
        if note:
            self.notes.append(note)

    def get_summary(self) -> Dict[str, Any]:
        """
        获取扫描摘要

        Returns:
            Dict[str, Any]: 摘要字典
        """
        duration = None
        if self.ended_at:
            duration = (self.ended_at - self.started_at).total_seconds()

        # 统计漏洞
        vuln_stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value
            if severity in vuln_stats:
                vuln_stats[severity] += 1

        return {
            'session_id': self.session_id,
            'target': self.target.value if self.target else None,
            'status': self.status.value,
            'phase': self.phase.value,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'duration': duration,
            'stats': {
                'requests_sent': self.requests_sent,
                'errors_count': self.errors_count,
                'vulnerabilities': len(self.vulnerabilities),
                'vuln_by_severity': vuln_stats,
                'technologies': len(self.technologies),
                'ports': len(self.ports),
                'subdomains': len(self.subdomains),
                'directories': len(self.directories),
                'parameters': len(self.parameters),
                'api_endpoints': len(self.api_endpoints),
            }
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        导出为字典

        Returns:
            Dict[str, Any]: 完整字典表示
        """
        return {
            'session_id': self.session_id,
            'target': self.target.to_dict() if self.target else None,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'phase': self.phase.value,
            'status': self.status.value,
            'config': self.config,
            'fingerprints': self.fingerprints,
            'technologies': self.technologies,
            'ports': self.ports,
            'subdomains': self.subdomains,
            'directories': self.directories,
            'parameters': self.parameters,
            'js_files': self.js_files,
            'api_endpoints': self.api_endpoints,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities],
            'cookies': self.cookies,
            'headers': self.headers,
            'auth_token': self.auth_token,
            'proxy': self.proxy,
            'requests_sent': self.requests_sent,
            'errors_count': self.errors_count,
            'logs': self.logs,
            'notes': self.notes,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanContext':
        """
        从字典创建上下文对象

        Args:
            data: 字典数据

        Returns:
            ScanContext: 上下文对象
        """
        from .target import Target
        from .result import Vulnerability

        # 解析目标
        target = None
        if data.get('target'):
            target = Target.from_dict(data['target'])

        # 解析漏洞
        vulns = []
        for v_data in data.get('vulnerabilities', []):
            vulns.append(Vulnerability.from_dict(v_data))

        context = cls(
            session_id=data.get('session_id', str(uuid.uuid4())),
            target=target,
            started_at=datetime.fromisoformat(data['started_at']) if data.get('started_at') else datetime.now(),
            ended_at=datetime.fromisoformat(data['ended_at']) if data.get('ended_at') else None,
            phase=ScanPhase(data.get('phase', 'init')),
            status=ContextStatus(data.get('status', 'active')),
            config=data.get('config', {}),
            fingerprints=data.get('fingerprints', {}),
            technologies=data.get('technologies', []),
            ports=data.get('ports', []),
            subdomains=data.get('subdomains', []),
            directories=data.get('directories', []),
            parameters=data.get('parameters', []),
            js_files=data.get('js_files', []),
            api_endpoints=data.get('api_endpoints', []),
            vulnerabilities=vulns,
            cookies=data.get('cookies', {}),
            headers=data.get('headers', {}),
            auth_token=data.get('auth_token'),
            proxy=data.get('proxy'),
            requests_sent=data.get('requests_sent', 0),
            errors_count=data.get('errors_count', 0),
            logs=data.get('logs', []),
            notes=data.get('notes', []),
            metadata=data.get('metadata', {}),
        )

        return context

    def to_scan_result(self) -> 'ScanResult':
        """
        转换为扫描结果对象

        Returns:
            ScanResult: 扫描结果
        """
        from .result import ScanResult

        result = ScanResult(
            session_id=self.session_id,
            target=self.target.value if self.target else '',
            status=self.status.value,
            started_at=self.started_at,
            ended_at=self.ended_at,
            vulnerabilities=copy.deepcopy(self.vulnerabilities),
            fingerprints=copy.deepcopy(self.fingerprints),
            technologies=self.technologies.copy(),
            ports=copy.deepcopy(self.ports),
            subdomains=self.subdomains.copy(),
            total_requests=self.requests_sent,
            errors_count=self.errors_count,
            scan_config=self.config.copy(),
            metadata=copy.deepcopy(self.metadata),
        )

        result.calculate_stats()
        return result

    def clone(self) -> 'ScanContext':
        """
        克隆上下文

        Returns:
            ScanContext: 新的上下文对象
        """
        return ScanContext.from_dict(self.to_dict())

    def __str__(self) -> str:
        """字符串表示"""
        target_str = self.target.value if self.target else 'N/A'
        return f"ScanContext({self.session_id[:8]}, target={target_str}, phase={self.phase.value})"

    def __repr__(self) -> str:
        """详细表示"""
        return (
            f"ScanContext(session_id={self.session_id!r}, "
            f"phase={self.phase!r}, status={self.status!r}, "
            f"vulns={len(self.vulnerabilities)})"
        )
