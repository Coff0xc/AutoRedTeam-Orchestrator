#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 数据模型
定义 CVE 条目、CVSS 评分、参考链接、PoC 模板等核心数据结构

作者: AutoRedTeam-Orchestrator
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """漏洞严重性等级"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """根据 CVSS 分数推断严重性等级"""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score >= 0.1:
            return cls.LOW
        else:
            return cls.NONE

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """从字符串解析严重性等级"""
        if not value:
            return cls.UNKNOWN

        value_lower = value.lower().strip()
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "none": cls.NONE,
            "informational": cls.NONE,
            "info": cls.NONE,
        }
        return mapping.get(value_lower, cls.UNKNOWN)


@dataclass
class CVSS:
    """CVSS 评分"""

    version: str  # 2.0, 3.0, 3.1, 4.0
    score: float  # 0.0 - 10.0
    vector: str  # CVSS 向量字符串
    severity: Severity  # 严重性等级

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "version": self.version,
            "score": self.score,
            "vector": self.vector,
            "severity": self.severity.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVSS":
        """从字典创建"""
        return cls(
            version=data.get("version", "3.1"),
            score=float(data.get("score", 0.0)),
            vector=data.get("vector", ""),
            severity=Severity.from_string(data.get("severity", "")),
        )

    @classmethod
    def from_score(cls, score: float, version: str = "3.1", vector: str = "") -> "CVSS":
        """从分数创建 CVSS 对象"""
        return cls(version=version, score=score, vector=vector, severity=Severity.from_cvss(score))


@dataclass
class Reference:
    """参考链接"""

    url: str  # 链接地址
    source: str  # 来源 (NVD, Vendor, etc.)
    tags: List[str] = field(default_factory=list)  # 标签 (Exploit, Patch, etc.)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {"url": self.url, "source": self.source, "tags": self.tags}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Reference":
        """从字典创建"""
        return cls(
            url=data.get("url", ""), source=data.get("source", ""), tags=data.get("tags", [])
        )


@dataclass
class CVEEntry:
    """CVE 条目 - 核心数据模型"""

    cve_id: str  # CVE-2024-1234
    title: str  # 漏洞标题
    description: str  # 漏洞描述

    # 评分信息
    cvss: Optional[CVSS] = None  # CVSS 评分
    severity: Severity = Severity.UNKNOWN  # 严重性等级

    # 影响范围
    affected_products: List[str] = field(default_factory=list)  # 受影响产品 (CPE)
    affected_versions: List[str] = field(default_factory=list)  # 受影响版本
    cwe_ids: List[str] = field(default_factory=list)  # CWE 分类

    # 时间信息
    published_date: Optional[datetime] = None  # 发布时间
    modified_date: Optional[datetime] = None  # 修改时间

    # 参考链接
    references: List[Reference] = field(default_factory=list)

    # PoC 信息
    has_poc: bool = False  # 是否有 PoC
    poc_urls: List[str] = field(default_factory=list)  # PoC 链接
    exploit_available: bool = False  # 是否有公开利用

    # 元数据
    source: str = ""  # 数据来源 (nvd, nuclei, exploitdb)
    tags: List[str] = field(default_factory=list)  # 标签
    raw_data: Optional[Dict[str, Any]] = None  # 原始数据

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "cvss": self.cvss.to_dict() if self.cvss else None,
            "severity": self.severity.value,
            "affected_products": self.affected_products,
            "affected_versions": self.affected_versions,
            "cwe_ids": self.cwe_ids,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "modified_date": self.modified_date.isoformat() if self.modified_date else None,
            "references": [ref.to_dict() for ref in self.references],
            "has_poc": self.has_poc,
            "poc_urls": self.poc_urls,
            "exploit_available": self.exploit_available,
            "source": self.source,
            "tags": self.tags,
        }

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVEEntry":
        """从字典创建"""
        # 解析 CVSS
        cvss_data = data.get("cvss")
        cvss = CVSS.from_dict(cvss_data) if cvss_data else None

        # 解析参考链接
        refs_data = data.get("references", [])
        references = [
            Reference.from_dict(ref) if isinstance(ref, dict) else ref for ref in refs_data
        ]

        # 解析时间
        pub_date = data.get("published_date")
        mod_date = data.get("modified_date")

        if isinstance(pub_date, str):
            try:
                pub_date = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pub_date = None
        elif not isinstance(pub_date, datetime):
            pub_date = None

        if isinstance(mod_date, str):
            try:
                mod_date = datetime.fromisoformat(mod_date.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                mod_date = None
        elif not isinstance(mod_date, datetime):
            mod_date = None

        return cls(
            cve_id=data.get("cve_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            cvss=cvss,
            severity=Severity.from_string(data.get("severity", "")),
            affected_products=data.get("affected_products", []),
            affected_versions=data.get("affected_versions", []),
            cwe_ids=data.get("cwe_ids", []),
            published_date=pub_date,
            modified_date=mod_date,
            references=references,
            has_poc=data.get("has_poc", False),
            poc_urls=data.get("poc_urls", []),
            exploit_available=data.get("exploit_available", False),
            source=data.get("source", ""),
            tags=data.get("tags", []),
            raw_data=data.get("raw_data"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "CVEEntry":
        """从 JSON 字符串创建"""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def merge_with(self, other: "CVEEntry") -> "CVEEntry":
        """
        合并另一个 CVE 条目的信息
        保留更完整的数据
        """
        # 优先使用更详细的描述
        description = (
            self.description
            if len(self.description) >= len(other.description)
            else other.description
        )

        # 合并受影响产品
        affected_products = list(set(self.affected_products + other.affected_products))
        affected_versions = list(set(self.affected_versions + other.affected_versions))
        cwe_ids = list(set(self.cwe_ids + other.cwe_ids))

        # 合并参考链接
        ref_urls = {ref.url for ref in self.references}
        merged_refs = list(self.references)
        for ref in other.references:
            if ref.url not in ref_urls:
                merged_refs.append(ref)

        # 合并 PoC
        poc_urls = list(set(self.poc_urls + other.poc_urls))
        has_poc = self.has_poc or other.has_poc
        exploit_available = self.exploit_available or other.exploit_available

        # 合并标签
        tags = list(set(self.tags + other.tags))

        # 使用较高的 CVSS 分数
        cvss = self.cvss
        if other.cvss:
            if not cvss or other.cvss.score > cvss.score:
                cvss = other.cvss

        return CVEEntry(
            cve_id=self.cve_id,
            title=self.title or other.title,
            description=description,
            cvss=cvss,
            severity=self.severity if self.severity != Severity.UNKNOWN else other.severity,
            affected_products=affected_products,
            affected_versions=affected_versions,
            cwe_ids=cwe_ids,
            published_date=self.published_date or other.published_date,
            modified_date=max(
                filter(None, [self.modified_date, other.modified_date]), default=None
            ),
            references=merged_refs,
            has_poc=has_poc,
            poc_urls=poc_urls,
            exploit_available=exploit_available,
            source=(
                f"{self.source},{other.source}"
                if other.source and other.source not in self.source
                else self.source
            ),
            tags=tags,
        )


@dataclass
class PoCMatcher:
    """PoC 匹配器"""

    type: str = "word"  # word, regex, status, size, binary, dsl
    part: str = "body"  # body, header, status, all
    words: List[str] = field(default_factory=list)
    regex: List[str] = field(default_factory=list)
    status: List[int] = field(default_factory=list)
    condition: str = "or"  # and, or
    negative: bool = False  # 是否取反
    case_insensitive: bool = False  # 是否忽略大小写

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "type": self.type,
            "part": self.part,
            "words": self.words,
            "regex": self.regex,
            "status": self.status,
            "condition": self.condition,
            "negative": self.negative,
            "case_insensitive": self.case_insensitive,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PoCMatcher":
        """从字典创建"""
        return cls(
            type=data.get("type", "word"),
            part=data.get("part", "body"),
            words=data.get("words", []),
            regex=data.get("regex", []),
            status=data.get("status", []),
            condition=data.get("condition", "or"),
            negative=data.get("negative", False),
            case_insensitive=data.get("case-insensitive", data.get("case_insensitive", False)),
        )


@dataclass
class PoCExtractor:
    """PoC 提取器"""

    type: str = "regex"  # regex, json, xpath, kval
    name: str = ""  # 提取结果命名
    part: str = "body"  # body, header, all
    regex: List[str] = field(default_factory=list)
    json_path: List[str] = field(default_factory=list)
    group: int = 1  # 正则分组
    internal: bool = False  # 是否内部使用

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "type": self.type,
            "name": self.name,
            "part": self.part,
            "regex": self.regex,
            "json": self.json_path,
            "group": self.group,
            "internal": self.internal,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PoCExtractor":
        """从字典创建"""
        return cls(
            type=data.get("type", "regex"),
            name=data.get("name", ""),
            part=data.get("part", "body"),
            regex=data.get("regex", []),
            json_path=data.get("json", []),
            group=data.get("group", 1),
            internal=data.get("internal", False),
        )


@dataclass
class PoCTemplate:
    """PoC 模板 - 兼容 Nuclei 格式"""

    id: str  # 模板 ID
    name: str  # 模板名称
    cve_id: Optional[str] = None  # 关联的 CVE ID

    # HTTP 请求配置
    method: str = "GET"  # HTTP 方法
    path: str = "/"  # 请求路径
    paths: List[str] = field(default_factory=list)  # 多路径
    headers: Dict[str, str] = field(default_factory=dict)  # 请求头
    body: Optional[str] = None  # 请求体

    # 匹配与提取
    matchers: List[PoCMatcher] = field(default_factory=list)
    matchers_condition: str = "or"  # and, or
    extractors: List[PoCExtractor] = field(default_factory=list)

    # 元数据
    severity: Severity = Severity.MEDIUM  # 严重性
    tags: List[str] = field(default_factory=list)
    author: str = ""  # 作者
    description: str = ""  # 描述
    reference: List[str] = field(default_factory=list)  # 参考链接

    # 高级配置
    stop_at_first_match: bool = True  # 首次匹配后停止
    redirect: bool = True  # 是否跟随重定向
    max_redirects: int = 10  # 最大重定向次数
    cookie_reuse: bool = False  # 是否复用 Cookie
    timeout: int = 10  # 超时时间 (秒)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "cve_id": self.cve_id,
            "method": self.method,
            "path": self.path,
            "paths": self.paths,
            "headers": self.headers,
            "body": self.body,
            "matchers": [m.to_dict() for m in self.matchers],
            "matchers_condition": self.matchers_condition,
            "extractors": [e.to_dict() for e in self.extractors],
            "severity": self.severity.value,
            "tags": self.tags,
            "author": self.author,
            "description": self.description,
            "reference": self.reference,
            "stop_at_first_match": self.stop_at_first_match,
            "redirect": self.redirect,
            "max_redirects": self.max_redirects,
            "cookie_reuse": self.cookie_reuse,
            "timeout": self.timeout,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PoCTemplate":
        """从字典创建"""
        # 解析 info 部分 (Nuclei 格式)
        info = data.get("info", {})

        # 解析 matchers
        matchers_data = data.get("matchers", [])
        # 也尝试从 requests 中获取
        requests_data = data.get("requests", [])
        if requests_data and isinstance(requests_data, list) and len(requests_data) > 0:
            req = requests_data[0]
            if "matchers" in req:
                matchers_data = req.get("matchers", [])

        matchers = [PoCMatcher.from_dict(m) for m in matchers_data]

        # 解析 extractors
        extractors_data = data.get("extractors", [])
        if requests_data and isinstance(requests_data, list) and len(requests_data) > 0:
            req = requests_data[0]
            if "extractors" in req:
                extractors_data = req.get("extractors", [])

        extractors = [PoCExtractor.from_dict(e) for e in extractors_data]

        # 获取路径
        path = data.get("path", "/")
        paths = data.get("paths", [])
        if requests_data and isinstance(requests_data, list) and len(requests_data) > 0:
            req = requests_data[0]
            paths = req.get("path", []) or paths
            if isinstance(paths, str):
                paths = [paths]

        # 提取 CVE ID
        cve_id = data.get("cve_id")
        classification = info.get("classification", {})
        if not cve_id and classification:
            cve_id = classification.get("cve-id")

        return cls(
            id=data.get("id", ""),
            name=info.get("name", data.get("name", "")),
            cve_id=cve_id,
            method=data.get("method", "GET"),
            path=path,
            paths=paths,
            headers=data.get("headers", {}),
            body=data.get("body"),
            matchers=matchers,
            matchers_condition=data.get("matchers-condition", data.get("matchers_condition", "or")),
            extractors=extractors,
            severity=Severity.from_string(info.get("severity", data.get("severity", "medium"))),
            tags=info.get("tags", data.get("tags", [])),
            author=info.get("author", data.get("author", "")),
            description=info.get("description", data.get("description", "")),
            reference=info.get("reference", data.get("reference", [])),
            stop_at_first_match=data.get(
                "stop-at-first-match", data.get("stop_at_first_match", True)
            ),
            redirect=data.get("redirects", data.get("redirect", True)),
            max_redirects=data.get("max-redirects", data.get("max_redirects", 10)),
            cookie_reuse=data.get("cookie-reuse", data.get("cookie_reuse", False)),
            timeout=data.get("timeout", 10),
        )


@dataclass
class SyncStatus:
    """同步状态"""

    source: str  # 数据源名称
    last_sync: Optional[datetime] = None  # 最后同步时间
    new_count: int = 0  # 新增数量
    updated_count: int = 0  # 更新数量
    error_count: int = 0  # 错误数量
    status: str = "pending"  # pending, running, success, failed
    message: str = ""  # 状态消息

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "source": self.source,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
            "new_count": self.new_count,
            "updated_count": self.updated_count,
            "error_count": self.error_count,
            "status": self.status,
            "message": self.message,
        }


@dataclass
class CVEStats:
    """CVE 统计信息"""

    total_count: int = 0  # 总数
    poc_available_count: int = 0  # 有 PoC 的数量
    by_severity: Dict[str, int] = field(default_factory=dict)  # 按严重性统计
    by_source: Dict[str, int] = field(default_factory=dict)  # 按来源统计
    by_year: Dict[int, int] = field(default_factory=dict)  # 按年份统计
    last_updated: Optional[datetime] = None  # 最后更新时间

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "total_count": self.total_count,
            "poc_available_count": self.poc_available_count,
            "by_severity": self.by_severity,
            "by_source": self.by_source,
            "by_year": self.by_year,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }


# 类型别名
CVEList = List[CVEEntry]
PoCList = List[PoCTemplate]
