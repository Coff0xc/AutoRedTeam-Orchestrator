#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具分类定义模块

提供工具分类枚举、分类描述和层级结构。
支持细粒度的工具分类管理。
"""

from enum import Enum
from typing import Dict, List


class ToolCategory(Enum):
    """工具分类枚举

    按功能领域组织工具分类，涵盖红队全生命周期。
    """

    # ============ 信息收集 ============
    RECON = 'recon'                    # 综合信息收集
    FINGERPRINT = 'fingerprint'        # 指纹识别
    SUBDOMAIN = 'subdomain'            # 子域名枚举
    PORT_SCAN = 'port_scan'            # 端口扫描
    DNS = 'dns'                        # DNS查询
    WHOIS = 'whois'                    # WHOIS查询
    WEB_PROBE = 'web_probe'            # Web探测
    OSINT = 'osint'                    # 开源情报

    # ============ 漏洞检测 ============
    VULN_SCAN = 'vuln_scan'            # 综合漏洞扫描
    INJECTION = 'injection'            # 注入漏洞 (SQLi, CMDi, etc.)
    XSS = 'xss'                        # 跨站脚本
    SSRF = 'ssrf'                      # 服务端请求伪造
    XXE = 'xxe'                        # XML外部实体
    SSTI = 'ssti'                      # 服务端模板注入
    LFI = 'lfi'                        # 本地文件包含
    RFI = 'rfi'                        # 远程文件包含
    DESERIALIZE = 'deserialize'        # 反序列化漏洞
    AUTH = 'auth'                      # 认证漏洞
    CSRF = 'csrf'                      # 跨站请求伪造
    IDOR = 'idor'                      # 不安全的直接对象引用
    UPLOAD = 'upload'                  # 文件上传漏洞

    # ============ API安全 ============
    API_SECURITY = 'api_security'      # API安全综合
    JWT = 'jwt'                        # JWT安全测试
    CORS = 'cors'                      # CORS配置测试
    GRAPHQL = 'graphql'                # GraphQL安全
    WEBSOCKET = 'websocket'            # WebSocket安全
    OAUTH = 'oauth'                    # OAuth安全
    REST = 'rest'                      # REST API安全
    GRPC = 'grpc'                      # gRPC安全

    # ============ 供应链安全 ============
    SUPPLY_CHAIN = 'supply_chain'      # 供应链安全综合
    SBOM = 'sbom'                      # 软件物料清单
    DEPENDENCY = 'dependency'          # 依赖审计
    CICD = 'cicd'                      # CI/CD安全

    # ============ 云原生安全 ============
    CLOUD_NATIVE = 'cloud_native'      # 云原生综合
    K8S = 'k8s'                        # Kubernetes安全
    DOCKER = 'docker'                  # Docker安全
    AWS = 'aws'                        # AWS安全
    AZURE = 'azure'                    # Azure安全
    GCP = 'gcp'                        # GCP安全

    # ============ 红队工具 ============
    C2 = 'c2'                          # C2通信
    LATERAL = 'lateral'                # 横向移动
    PERSISTENCE = 'persistence'        # 持久化
    CREDENTIAL = 'credential'          # 凭证获取
    EVASION = 'evasion'                # 免杀绕过
    STEALTH = 'stealth'                # 隐蔽通信
    AD = 'ad'                          # Active Directory
    POST_EXPLOIT = 'post_exploit'      # 后渗透
    PRIVILEGE_ESC = 'privilege_esc'    # 提权

    # ============ 漏洞情报 ============
    CVE = 'cve'                        # CVE情报
    POC = 'poc'                        # PoC生成/执行
    EXPLOIT = 'exploit'                # 漏洞利用

    # ============ 前端分析 ============
    JS_ANALYSIS = 'js_analysis'        # JavaScript分析
    FRONTEND = 'frontend'              # 前端安全

    # ============ 系统工具 ============
    REPORT = 'report'                  # 报告生成
    TASK = 'task'                      # 任务队列
    CONFIG = 'config'                  # 配置管理
    SESSION = 'session'                # 会话管理
    AI = 'ai'                          # AI决策
    PAYLOAD = 'payload'                # Payload生成

    # ============ 综合测试 ============
    PENTEST = 'pentest'                # 综合渗透测试
    EXTERNAL = 'external'              # 外部工具集成
    MISC = 'misc'                      # 其他工具


# 分类描述映射
CATEGORY_DESCRIPTIONS: Dict[ToolCategory, str] = {
    # 信息收集
    ToolCategory.RECON: "综合信息收集工具",
    ToolCategory.FINGERPRINT: "Web/服务指纹识别",
    ToolCategory.SUBDOMAIN: "子域名枚举与发现",
    ToolCategory.PORT_SCAN: "端口扫描与服务识别",
    ToolCategory.DNS: "DNS查询与枚举",
    ToolCategory.WHOIS: "WHOIS信息查询",
    ToolCategory.WEB_PROBE: "Web服务探测",
    ToolCategory.OSINT: "开源情报收集",

    # 漏洞检测
    ToolCategory.VULN_SCAN: "综合漏洞扫描",
    ToolCategory.INJECTION: "注入漏洞检测 (SQL/CMD/LDAP)",
    ToolCategory.XSS: "跨站脚本漏洞检测",
    ToolCategory.SSRF: "服务端请求伪造检测",
    ToolCategory.XXE: "XML外部实体注入检测",
    ToolCategory.SSTI: "服务端模板注入检测",
    ToolCategory.LFI: "本地文件包含检测",
    ToolCategory.RFI: "远程文件包含检测",
    ToolCategory.DESERIALIZE: "反序列化漏洞检测",
    ToolCategory.AUTH: "认证漏洞检测",
    ToolCategory.CSRF: "跨站请求伪造检测",
    ToolCategory.IDOR: "不安全直接对象引用检测",
    ToolCategory.UPLOAD: "文件上传漏洞检测",

    # API安全
    ToolCategory.API_SECURITY: "API安全综合测试",
    ToolCategory.JWT: "JWT令牌安全测试",
    ToolCategory.CORS: "CORS配置安全测试",
    ToolCategory.GRAPHQL: "GraphQL接口安全测试",
    ToolCategory.WEBSOCKET: "WebSocket协议安全测试",
    ToolCategory.OAUTH: "OAuth认证安全测试",
    ToolCategory.REST: "REST API安全测试",
    ToolCategory.GRPC: "gRPC服务安全测试",

    # 供应链
    ToolCategory.SUPPLY_CHAIN: "供应链安全综合检测",
    ToolCategory.SBOM: "软件物料清单生成与分析",
    ToolCategory.DEPENDENCY: "依赖组件漏洞审计",
    ToolCategory.CICD: "CI/CD流水线安全检测",

    # 云原生
    ToolCategory.CLOUD_NATIVE: "云原生安全综合检测",
    ToolCategory.K8S: "Kubernetes集群安全检测",
    ToolCategory.DOCKER: "Docker容器安全检测",
    ToolCategory.AWS: "AWS云服务安全检测",
    ToolCategory.AZURE: "Azure云服务安全检测",
    ToolCategory.GCP: "GCP云服务安全检测",

    # 红队
    ToolCategory.C2: "Command & Control通信",
    ToolCategory.LATERAL: "横向移动工具",
    ToolCategory.PERSISTENCE: "持久化后门植入",
    ToolCategory.CREDENTIAL: "凭证提取与破解",
    ToolCategory.EVASION: "免杀与绕过技术",
    ToolCategory.STEALTH: "隐蔽通信与流量混淆",
    ToolCategory.AD: "Active Directory渗透",
    ToolCategory.POST_EXPLOIT: "后渗透利用工具",
    ToolCategory.PRIVILEGE_ESC: "权限提升工具",

    # CVE
    ToolCategory.CVE: "CVE漏洞情报查询",
    ToolCategory.POC: "PoC生成与执行",
    ToolCategory.EXPLOIT: "漏洞利用模块",

    # 前端
    ToolCategory.JS_ANALYSIS: "JavaScript代码分析",
    ToolCategory.FRONTEND: "前端安全检测",

    # 系统
    ToolCategory.REPORT: "渗透测试报告生成",
    ToolCategory.TASK: "异步任务队列管理",
    ToolCategory.CONFIG: "配置管理工具",
    ToolCategory.SESSION: "会话状态管理",
    ToolCategory.AI: "AI辅助决策引擎",
    ToolCategory.PAYLOAD: "Payload生成器",

    # 综合
    ToolCategory.PENTEST: "综合渗透测试工具",
    ToolCategory.EXTERNAL: "外部工具集成接口",
    ToolCategory.MISC: "其他工具",
}


# 分类层级结构 - 用于工具组织和展示
CATEGORY_HIERARCHY: Dict[str, List[ToolCategory]] = {
    # 信息收集阶段
    'reconnaissance': [
        ToolCategory.RECON,
        ToolCategory.FINGERPRINT,
        ToolCategory.SUBDOMAIN,
        ToolCategory.PORT_SCAN,
        ToolCategory.DNS,
        ToolCategory.WHOIS,
        ToolCategory.WEB_PROBE,
        ToolCategory.OSINT,
    ],

    # 漏洞检测阶段
    'vulnerability': [
        ToolCategory.VULN_SCAN,
        ToolCategory.INJECTION,
        ToolCategory.XSS,
        ToolCategory.SSRF,
        ToolCategory.XXE,
        ToolCategory.SSTI,
        ToolCategory.LFI,
        ToolCategory.RFI,
        ToolCategory.DESERIALIZE,
        ToolCategory.AUTH,
        ToolCategory.CSRF,
        ToolCategory.IDOR,
        ToolCategory.UPLOAD,
    ],

    # API安全
    'api_security': [
        ToolCategory.API_SECURITY,
        ToolCategory.JWT,
        ToolCategory.CORS,
        ToolCategory.GRAPHQL,
        ToolCategory.WEBSOCKET,
        ToolCategory.OAUTH,
        ToolCategory.REST,
        ToolCategory.GRPC,
    ],

    # 供应链安全
    'supply_chain': [
        ToolCategory.SUPPLY_CHAIN,
        ToolCategory.SBOM,
        ToolCategory.DEPENDENCY,
        ToolCategory.CICD,
    ],

    # 云原生安全
    'cloud_native': [
        ToolCategory.CLOUD_NATIVE,
        ToolCategory.K8S,
        ToolCategory.DOCKER,
        ToolCategory.AWS,
        ToolCategory.AZURE,
        ToolCategory.GCP,
    ],

    # 红队攻击
    'red_team': [
        ToolCategory.C2,
        ToolCategory.LATERAL,
        ToolCategory.PERSISTENCE,
        ToolCategory.CREDENTIAL,
        ToolCategory.EVASION,
        ToolCategory.STEALTH,
        ToolCategory.AD,
        ToolCategory.POST_EXPLOIT,
        ToolCategory.PRIVILEGE_ESC,
    ],

    # 漏洞利用
    'exploitation': [
        ToolCategory.CVE,
        ToolCategory.POC,
        ToolCategory.EXPLOIT,
    ],

    # 前端分析
    'frontend_analysis': [
        ToolCategory.JS_ANALYSIS,
        ToolCategory.FRONTEND,
    ],

    # 系统工具
    'system': [
        ToolCategory.REPORT,
        ToolCategory.TASK,
        ToolCategory.CONFIG,
        ToolCategory.SESSION,
        ToolCategory.AI,
        ToolCategory.PAYLOAD,
    ],

    # 综合
    'general': [
        ToolCategory.PENTEST,
        ToolCategory.EXTERNAL,
        ToolCategory.MISC,
    ],
}


# ATT&CK映射 - 将工具分类映射到MITRE ATT&CK战术
ATTCK_MAPPING: Dict[str, List[ToolCategory]] = {
    'reconnaissance': [
        ToolCategory.RECON,
        ToolCategory.FINGERPRINT,
        ToolCategory.SUBDOMAIN,
        ToolCategory.PORT_SCAN,
        ToolCategory.DNS,
        ToolCategory.WHOIS,
        ToolCategory.OSINT,
    ],
    'resource_development': [
        ToolCategory.PAYLOAD,
        ToolCategory.EVASION,
    ],
    'initial_access': [
        ToolCategory.EXPLOIT,
        ToolCategory.POC,
    ],
    'execution': [
        ToolCategory.C2,
        ToolCategory.POST_EXPLOIT,
    ],
    'persistence': [
        ToolCategory.PERSISTENCE,
    ],
    'privilege_escalation': [
        ToolCategory.PRIVILEGE_ESC,
    ],
    'defense_evasion': [
        ToolCategory.EVASION,
        ToolCategory.STEALTH,
    ],
    'credential_access': [
        ToolCategory.CREDENTIAL,
        ToolCategory.AUTH,
    ],
    'discovery': [
        ToolCategory.RECON,
        ToolCategory.AD,
    ],
    'lateral_movement': [
        ToolCategory.LATERAL,
    ],
    'collection': [
        ToolCategory.JS_ANALYSIS,
        ToolCategory.FRONTEND,
    ],
    'command_and_control': [
        ToolCategory.C2,
        ToolCategory.STEALTH,
    ],
    'exfiltration': [
        ToolCategory.C2,
    ],
    'impact': [
        ToolCategory.EXPLOIT,
    ],
}


def get_category_description(category: ToolCategory) -> str:
    """获取分类描述

    Args:
        category: 工具分类枚举

    Returns:
        分类描述文本
    """
    return CATEGORY_DESCRIPTIONS.get(category, f"未知分类: {category.value}")


def get_categories_by_phase(phase: str) -> List[ToolCategory]:
    """根据阶段获取分类列表

    Args:
        phase: 阶段名称 (如 'reconnaissance', 'vulnerability', 'red_team')

    Returns:
        该阶段的分类列表
    """
    return CATEGORY_HIERARCHY.get(phase, [])


def get_phase_for_category(category: ToolCategory) -> str:
    """获取分类所属阶段

    Args:
        category: 工具分类枚举

    Returns:
        阶段名称
    """
    for phase, categories in CATEGORY_HIERARCHY.items():
        if category in categories:
            return phase
    return 'general'


def get_attck_tactics(category: ToolCategory) -> List[str]:
    """获取分类对应的ATT&CK战术

    Args:
        category: 工具分类枚举

    Returns:
        ATT&CK战术列表
    """
    tactics = []
    for tactic, categories in ATTCK_MAPPING.items():
        if category in categories:
            tactics.append(tactic)
    return tactics


def list_all_phases() -> List[str]:
    """列出所有阶段名称

    Returns:
        阶段名称列表
    """
    return list(CATEGORY_HIERARCHY.keys())


def list_all_categories() -> List[ToolCategory]:
    """列出所有工具分类

    Returns:
        工具分类枚举列表
    """
    return list(ToolCategory)


# 分类图标 (用于UI展示)
CATEGORY_ICONS: Dict[ToolCategory, str] = {
    ToolCategory.RECON: "search",
    ToolCategory.FINGERPRINT: "fingerprint",
    ToolCategory.SUBDOMAIN: "dns",
    ToolCategory.PORT_SCAN: "radar",
    ToolCategory.VULN_SCAN: "bug",
    ToolCategory.INJECTION: "database",
    ToolCategory.XSS: "code",
    ToolCategory.JWT: "key",
    ToolCategory.CORS: "shield",
    ToolCategory.GRAPHQL: "graphql",
    ToolCategory.C2: "tower",
    ToolCategory.LATERAL: "network",
    ToolCategory.PERSISTENCE: "anchor",
    ToolCategory.CREDENTIAL: "lock",
    ToolCategory.CVE: "alert",
    ToolCategory.POC: "flask",
    ToolCategory.REPORT: "file-text",
    ToolCategory.AI: "brain",
    # ... 其他图标
}


def get_category_icon(category: ToolCategory) -> str:
    """获取分类图标

    Args:
        category: 工具分类枚举

    Returns:
        图标名称
    """
    return CATEGORY_ICONS.get(category, "tool")
