"""AutoRedTeam CLI — AI驱动的渗透测试命令行工具

基于 typer 构建，封装 autort SDK 提供命令行接口。

Usage:
    autort scan http://target.com --full
    autort detect http://target.com -c sqli,xss
    autort exploit http://target.com --cve CVE-2021-44228
    autort pentest http://target.com
    autort report <session_id> -f html
    autort tools
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="autort",
    help="AutoRedTeam — AI驱动的渗透测试工具",
    no_args_is_help=True,
    add_completion=False,
)


# ──────────────────────────── scan ────────────────────────────


@app.command()
def scan(
    target: str = typer.Argument(..., help="目标 URL 或 IP"),
    full: bool = typer.Option(False, "--full", help="完整10阶段侦察"),
    recon_only: bool = typer.Option(False, "--recon-only", help="仅侦察（同 --full）"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="端口范围"),
    top_ports: Optional[int] = typer.Option(None, "--top", help="扫描 Top N 常用端口"),
    quick: bool = typer.Option(False, "--quick", "-q", help="快速模式"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """扫描目标 — 端口扫描 / 完整侦察"""
    from autort import Scanner

    config = {}
    if quick:
        config["quick_mode"] = True

    scanner = Scanner(target, config=config)

    if full or recon_only:
        result = asyncio.run(scanner.full_recon())
    elif top_ports:
        result = asyncio.run(scanner.port_scan(top=top_ports))
    else:
        result = asyncio.run(scanner.port_scan(ports))

    _output(result, output)


# ──────────────────────────── detect ────────────────────────────


@app.command()
def detect(
    target: str = typer.Argument(..., help="目标 URL"),
    category: Optional[str] = typer.Option(
        None, "--category", "-c", help="检测类别（逗号分隔），如 sqli,xss,ssrf"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """漏洞检测 — 扫描目标漏洞"""
    from autort import Scanner

    categories = [c.strip() for c in category.split(",")] if category else None
    scanner = Scanner(target)
    result = asyncio.run(scanner.detect_vulns(categories=categories))
    _output(result, output)


# ──────────────────────────── exploit ────────────────────────────


@app.command()
def exploit(
    target: str = typer.Argument(..., help="目标 URL 或 IP"),
    cve: Optional[str] = typer.Option(None, "--cve", help="CVE ID，如 CVE-2021-44228"),
    auto: bool = typer.Option(False, "--auto", help="自动检测并利用所有漏洞"),
    top_n: int = typer.Option(5, "--top-n", help="自动模式下最多尝试的漏洞数"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """漏洞利用 — CVE利用 / 自动利用"""
    from autort import Exploiter

    exploiter = Exploiter(target)

    if cve:
        result = asyncio.run(exploiter.cve_exploit(cve))
    elif auto:
        result = asyncio.run(exploiter.auto_exploit(top_n=top_n))
    else:
        typer.echo("请指定 --cve <CVE-ID> 或 --auto", err=True)
        raise typer.Exit(1)

    _output(result, output)


# ──────────────────────────── cve-search ────────────────────────────


@app.command("cve-search")
def cve_search(
    keyword: str = typer.Argument(..., help="搜索关键词"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="严重性过滤"),
    has_poc: Optional[bool] = typer.Option(None, "--has-poc", help="仅显示有PoC的CVE"),
    limit: int = typer.Option(20, "--limit", "-n", help="结果数量"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """CVE 搜索"""
    from autort import Exploiter

    exploiter = Exploiter("")
    result = asyncio.run(
        exploiter.cve_search(keyword=keyword, severity=severity, has_poc=has_poc, limit=limit)
    )
    _output(result, output)


# ──────────────────────────── pentest ────────────────────────────


@app.command()
def pentest(
    target: str = typer.Argument(..., help="目标 URL"),
    phases: Optional[str] = typer.Option(
        None, "--phases", help="指定阶段（逗号分隔），如 recon,vuln_scan,exploit"
    ),
    resume: Optional[str] = typer.Option(None, "--resume", help="恢复会话 ID"),
    quick: bool = typer.Option(False, "--quick", "-q", help="快速模式"),
    timeout: int = typer.Option(3600, "--timeout", "-t", help="超时时间（秒）"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """一键渗透测试"""
    from autort import AutoPentest

    config = {"timeout": timeout}
    if quick:
        config["quick_mode"] = True

    pt = AutoPentest(target, config=config)

    if resume:
        result = asyncio.run(pt.resume(resume))
    else:
        phase_list = [p.strip() for p in phases.split(",")] if phases else None
        result = asyncio.run(pt.run(phases=phase_list))

    _output(result, output)


# ──────────────────────────── report ────────────────────────────


@app.command()
def report(
    session_id: str = typer.Argument(..., help="会话 ID"),
    format: str = typer.Option(
        "html", "--format", "-f", help="输出格式: html / json / markdown / executive"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """生成渗透报告"""
    from autort import Reporter

    reporter = Reporter(session_id)
    result = asyncio.run(reporter.generate(format=format))
    _output(result, output)


# ──────────────────────────── tools ────────────────────────────


@app.command()
def tools():
    """查看外部工具状态（nmap/nuclei/sqlmap/...）"""
    from core.tools.tool_manager import ToolManager

    manager = ToolManager()
    status = manager.get_status()
    _output(status, None)


# ──────────────────────────── version ────────────────────────────


@app.command()
def version():
    """显示版本信息"""
    from autort import __version__

    typer.echo(f"AutoRedTeam v{__version__}")


# ──────────────────────────── helpers ────────────────────────────


def _output(data, filepath: Optional[str]):
    """统一输出处理"""
    if isinstance(data, (dict, list)):
        text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    else:
        text = str(data)

    if filepath:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        typer.echo(f"结果已保存到 {filepath}")
    else:
        typer.echo(text)


def main():
    """CLI 入口点"""
    app()


if __name__ == "__main__":
    main()
