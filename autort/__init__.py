"""AutoRedTeam SDK — 企业级渗透测试 Python API

提供简洁的异步接口封装 core/ 引擎，支持:
- 扫描与侦察 (Scanner)
- 漏洞利用 (Exploiter)
- 一键渗透 (AutoPentest)
- 红队操作 (RedTeam)
- 报告生成 (Reporter)

Usage:
    from autort import Scanner, Exploiter, AutoPentest

    scanner = Scanner("http://target.com")
    results = await scanner.full_recon()
"""

from autort.exploiter import Exploiter
from autort.pentest import AutoPentest
from autort.redteam import RedTeam
from autort.report import Reporter
from autort.scanner import Scanner

__all__ = ["Scanner", "Exploiter", "AutoPentest", "RedTeam", "Reporter"]
__version__ = "3.1.0"
