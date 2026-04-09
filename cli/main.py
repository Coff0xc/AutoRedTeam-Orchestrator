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
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="autort",
    help="AutoRedTeam — AI驱动的渗透测试工具",
    no_args_is_help=True,
    add_completion=False,
)


def _show_disclaimer() -> None:
    """启动时显示法律声明"""
    try:
        from core.config.models import LEGAL_DISCLAIMER

        typer.echo(LEGAL_DISCLAIMER, err=True)
    except ImportError:
        typer.echo("⚠️ For AUTHORIZED penetration testing only.", err=True)


# 注册启动回调
@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """AutoRedTeam CLI — 启动时显示法律声明"""
    if ctx.invoked_subcommand is None:
        return  # no_args_is_help 会处理
    _show_disclaimer()


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
    format: str = typer.Option(
        "json", "--format", "-f", help="输出格式: json/sarif"
    ),
    ci: bool = typer.Option(False, "--ci", help="CI 模式: 精简输出 + 非零退出码"),
    severity_threshold: str = typer.Option(
        "high", "--severity-threshold", help="CI 失败阈值: info/low/medium/high/critical"
    ),
    exit_code: bool = typer.Option(
        False, "--exit-code", help="发现漏洞时返回非零退出码"
    ),
):
    """漏洞检测 — 扫描目标漏洞"""
    from autort import Scanner

    categories = [c.strip() for c in category.split(",")] if category else None
    scanner = Scanner(target)
    result = asyncio.run(scanner.detect_vulns(categories=categories))

    # CI 模式隐含 --exit-code
    if ci:
        exit_code = True

    # SARIF 格式转换
    if format.lower() == "sarif":
        from core.reporting.sarif import findings_to_sarif

        sarif_data = findings_to_sarif(result if isinstance(result, list) else [result])
        _output(sarif_data, output)
    else:
        _output(result, output)

    # CI 模式: 输出精简摘要
    if ci:
        _ci_summary(result, severity_threshold)

    # 退出码: 发现达到阈值的漏洞时返回非零
    if exit_code:
        from core.reporting.sarif import severity_meets_threshold

        findings = result if isinstance(result, list) else [result]
        for f in findings:
            sev = str(f.get("severity", "")).lower()
            if sev and severity_meets_threshold(sev, severity_threshold):
                raise typer.Exit(2)


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


# ──────────────────────────── nuclei ────────────────────────────


@app.command()
def nuclei(
    target: str = typer.Argument(..., help="目标 URL"),
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="模板标签（逗号分隔），如 cve,rce"),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="严重性过滤（逗号分隔），如 high,critical"
    ),
    template_dir: Optional[str] = typer.Option(
        None, "--template-dir", "-d", help="模板目录路径"
    ),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="最大并发数"),
    limit: Optional[int] = typer.Option(None, "--limit", "-n", help="最大模板数"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """Nuclei 模板扫描 — 纯Python引擎，无需nuclei二进制"""
    from autort import Scanner

    tag_list = [t.strip() for t in tags.split(",")] if tags else None
    sev_list = [s.strip() for s in severity.split(",")] if severity else None

    scanner = Scanner(target)
    result = asyncio.run(
        scanner.nuclei_scan(
            tags=tag_list,
            severity=sev_list,
            template_dir=template_dir,
            concurrency=concurrency,
            limit=limit,
        )
    )
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


def _ci_summary(findings, threshold: str):
    """CI 模式: 输出精简漏洞摘要到 stderr"""
    from core.reporting.sarif import SEVERITY_ORDER, severity_meets_threshold

    if not isinstance(findings, list):
        return

    counts: dict = {}
    exceeded = 0
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
        if severity_meets_threshold(sev, threshold):
            exceeded += 1

    # 按 severity 降序输出
    sorted_sevs = sorted(counts.keys(), key=lambda s: SEVERITY_ORDER.get(s, -1), reverse=True)
    parts = [f"{s}: {counts[s]}" for s in sorted_sevs]
    summary = " | ".join(parts) if parts else "none"

    typer.echo(f"[CI] Findings: {summary}", err=True)
    if exceeded > 0:
        typer.echo(
            f"[CI] {exceeded} finding(s) meet threshold ({threshold}), exit code 2",
            err=True,
        )
    else:
        typer.echo(f"[CI] No findings meet threshold ({threshold})", err=True)


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
