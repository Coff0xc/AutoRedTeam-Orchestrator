#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 情报模块
提供 CVE 数据管理、搜索、同步和 PoC 执行功能

作者: AutoRedTeam-Orchestrator
"""

# 数据模型
from .models import (
    # 枚举
    Severity,

    # 核心数据类
    CVSS,
    Reference,
    CVEEntry,

    # PoC 相关
    PoCMatcher,
    PoCExtractor,
    PoCTemplate,

    # 统计和状态
    SyncStatus,
    CVEStats,

    # 类型别名
    CVEList,
    PoCList,
)

# 数据源
from .sources import (
    # 基类
    CVESource,
    RateLimiter,

    # 具体数据源
    NVDSource,
    NucleiSource,
    ExploitDBSource,
    GitHubPoCSource,
    AggregatedSource,

    # 便捷函数
    create_nvd_source,
    create_nuclei_source,
    create_exploitdb_source,
    create_github_poc_source,
    create_aggregated_source,
)

# 存储
from .storage import (
    CVEStorage,
    get_storage,
    reset_storage,
)

# 搜索
from .search import (
    CVESearchEngine,
    SearchFilter,
    SearchOptions,
    SearchResult,
    create_search_engine,
)

# 管理器
from .manager import (
    CVEManager,
    get_cve_manager,
    reset_cve_manager,
)

# PoC 引擎
from .poc_engine import (
    PoCEngine,
    PoCResult,
    VariableReplacer,
    get_poc_engine,
    reset_poc_engine,
    load_poc,
    execute_poc,
    execute_poc_batch,
)


__all__ = [
    # === 数据模型 ===
    # 枚举
    'Severity',

    # 核心数据类
    'CVSS',
    'Reference',
    'CVEEntry',

    # PoC 相关
    'PoCMatcher',
    'PoCExtractor',
    'PoCTemplate',

    # 统计和状态
    'SyncStatus',
    'CVEStats',

    # 类型别名
    'CVEList',
    'PoCList',

    # === 数据源 ===
    'CVESource',
    'RateLimiter',
    'NVDSource',
    'NucleiSource',
    'ExploitDBSource',
    'GitHubPoCSource',
    'AggregatedSource',
    'create_nvd_source',
    'create_nuclei_source',
    'create_exploitdb_source',
    'create_github_poc_source',
    'create_aggregated_source',

    # === 存储 ===
    'CVEStorage',
    'get_storage',
    'reset_storage',

    # === 搜索 ===
    'CVESearchEngine',
    'SearchFilter',
    'SearchOptions',
    'SearchResult',
    'create_search_engine',

    # === 管理器 ===
    'CVEManager',
    'get_cve_manager',
    'reset_cve_manager',

    # === PoC 引擎 ===
    'PoCEngine',
    'PoCResult',
    'VariableReplacer',
    'get_poc_engine',
    'reset_poc_engine',
    'load_poc',
    'execute_poc',
    'execute_poc_batch',
]


__version__ = '3.0.0'
__author__ = 'AutoRedTeam-Orchestrator'


# 快速入门示例
"""
# CVE 搜索
from core.cve import get_cve_manager

manager = get_cve_manager()

# 搜索 CVE
results = manager.search(keyword='Log4j', has_poc=True, limit=10)
for cve in results:
    print(f"{cve.cve_id}: {cve.severity.value} - {cve.title}")

# 获取 CVE 详情
cve = await manager.get_detail('CVE-2021-44228', refresh=True)

# 同步数据
await manager.sync(days=7)

# 获取统计
stats = manager.stats()
print(f"总 CVE 数: {stats.total_count}")


# PoC 执行
from core.cve import get_poc_engine, PoCTemplate

engine = get_poc_engine()

# 从字典加载模板
template = engine.load_template_from_dict({
    'id': 'test-poc',
    'info': {
        'name': 'Test PoC',
        'severity': 'high',
    },
    'method': 'GET',
    'path': '/admin',
    'matchers': [
        {'type': 'status', 'status': [200]}
    ]
})

# 执行 PoC
result = engine.execute('https://target.com', template)
if result.vulnerable:
    print(f"发现漏洞: {result.evidence}")
"""
