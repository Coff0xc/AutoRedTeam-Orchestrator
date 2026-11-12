#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE 情报模块
提供 CVE 数据管理、搜索、同步和 PoC 执行功能

Package exports are loaded on first access so importing ``core.cve.update_manager``
or ``core.cve.poc_engine`` does not import the auto-exploit engine.

作者: AutoRedTeam-Orchestrator
"""

from __future__ import annotations

import importlib
from typing import Any

__version__ = "3.0.0"
__author__ = "AutoRedTeam-Orchestrator"

_EXPORTS: dict[str, str] = {
    "Severity": ".models",
    "CVSS": ".models",
    "Reference": ".models",
    "CVEEntry": ".models",
    "PoCMatcher": ".models",
    "PoCExtractor": ".models",
    "PoCTemplate": ".models",
    "SyncStatus": ".models",
    "CVEStats": ".models",
    "CVEList": ".models",
    "PoCList": ".models",
    "CVESource": ".sources",
    "RateLimiter": ".sources",
    "NVDSource": ".sources",
    "NucleiSource": ".sources",
    "ExploitDBSource": ".sources",
    "GitHubPoCSource": ".sources",
    "AggregatedSource": ".sources",
    "create_nvd_source": ".sources",
    "create_nuclei_source": ".sources",
    "create_exploitdb_source": ".sources",
    "create_github_poc_source": ".sources",
    "create_aggregated_source": ".sources",
    "CVEStorage": ".storage",
    "get_storage": ".storage",
    "reset_storage": ".storage",
    "CVESearchEngine": ".search",
    "SearchFilter": ".search",
    "SearchOptions": ".search",
    "SearchResult": ".search",
    "create_search_engine": ".search",
    "CVEManager": ".manager",
    "get_cve_manager": ".manager",
    "reset_cve_manager": ".manager",
    "PoCEngine": ".poc_engine",
    "PoCResult": ".poc_engine",
    "VariableReplacer": ".poc_engine",
    "get_poc_engine": ".poc_engine",
    "reset_poc_engine": ".poc_engine",
    "load_poc": ".poc_engine",
    "execute_poc": ".poc_engine",
    "execute_poc_batch": ".poc_engine",
    "AIPoCGenerator": ".ai_poc_generator",
    "VulnType": ".ai_poc_generator",
    "CVEInfo": ".ai_poc_generator",
    "KeywordMatcher": ".ai_poc_generator",
    "CVEParser": ".ai_poc_generator",
    "PoCTemplateGenerator": ".ai_poc_generator",
    "generate_poc": ".ai_poc_generator",
    "CVEAutoExploitEngine": ".auto_exploit",
    "AutoExploitResult": ".auto_exploit",
    "AutoExploitStatus": ".auto_exploit",
    "get_auto_exploit_engine": ".auto_exploit",
    "auto_exploit_cve": ".auto_exploit",
    "exploit_cve_with_description": ".auto_exploit",
    "generate_cve_poc": ".auto_exploit",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
