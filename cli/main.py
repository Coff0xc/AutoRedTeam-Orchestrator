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


def _configure_stdio_encoding() -> None:
    """Keep Typer/Rich help usable on Windows narrow-codepage consoles."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower()
        if "utf" in encoding or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):  # pragma: no cover - stream implementation dependent
            pass


_configure_stdio_encoding()

app = typer.Typer(
    name="autort",
    help="AutoRedTeam — MCP-native 授权安全自动化工作台",
    no_args_is_help=True,
    add_completion=False,
)

ai_redteam_app = typer.Typer(
    name="ai-redteam",
    help="声明式 AI 红队场景（默认 dry-run，不触发目标调用）",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(ai_redteam_app, name="ai-redteam")

ai_surface_app = typer.Typer(
    name="ai-surface",
    help="AI/MCP 工具攻击面静态盘点（只读，不执行工具）",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(ai_surface_app, name="ai-surface")

code_agent_app = typer.Typer(
    name="code-agent",
    help="代码 Agent 静态分析（call-chain context expansion，不执行代码）",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(code_agent_app, name="code-agent")

runtime_api_app = typer.Typer(
    name="runtime-api",
    help="Agent runtime 只读本地 Web/API",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(runtime_api_app, name="runtime-api")

sandbox_app = typer.Typer(
    name="sandbox",
    help="本地沙箱验证和诊断",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(sandbox_app, name="sandbox")

capabilities_app = typer.Typer(
    name="capabilities",
    help="AI red-team 重构能力矩阵",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(capabilities_app, name="capabilities")

tools_app = typer.Typer(
    name="tools",
    help="MCP 工具面契约检查（静态分析，不执行 handler）",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(tools_app, name="tools")

llm_app = typer.Typer(
    name="llm",
    help="OrcaRouter Cyber Inference — API key or OAuth 2.0 + PKCE login",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(llm_app, name="llm")

llm_key_app = typer.Typer(
    name="key",
    help="Paste or clear an OrcaRouter API key (sk-orca-…)",
    no_args_is_help=True,
    add_completion=False,
)
llm_app.add_typer(llm_key_app, name="key")


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
    format: str = typer.Option("json", "--format", "-f", help="输出格式: json/sarif"),
    ci: bool = typer.Option(False, "--ci", help="CI 模式: 精简输出 + 非零退出码"),
    severity_threshold: str = typer.Option(
        "high", "--severity-threshold", help="CI 失败阈值: info/low/medium/high/critical"
    ),
    exit_code: bool = typer.Option(False, "--exit-code", help="发现漏洞时返回非零退出码"),
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
    tags: Optional[str] = typer.Option(
        None, "--tags", "-t", help="模板标签（逗号分隔），如 cve,rce"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s", help="严重性过滤（逗号分隔），如 high,critical"
    ),
    template_dir: Optional[str] = typer.Option(None, "--template-dir", "-d", help="模板目录路径"),
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


# ──────────────────────────── ai-redteam ────────────────────────────


@ai_redteam_app.command("run")
def ai_redteam_run(
    scenario: str = typer.Argument(..., help="AI 红队场景 YAML/JSON 路径"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
    format: str = typer.Option("json", "--format", "-f", help="输出格式: json/markdown"),
    ci: bool = typer.Option(False, "--ci", help="CI 模式: 达到阈值的失败评分返回非零"),
    severity_threshold: str = typer.Option(
        "high", "--severity-threshold", help="CI 失败阈值: info/low/medium/high/critical"
    ),
):
    """规划 AI 红队场景 — dry-run，只生成 attempts/scores/trace，不请求目标"""
    from core.ai_redteam import AIRedTeamRunner, load_scenario
    from core.ai_redteam.report import render_markdown, should_fail_ci

    try:
        scenario_model = load_scenario(scenario)
        result = AIRedTeamRunner(scenario_model).run()
    except (OSError, ValueError, PermissionError) as exc:
        typer.echo(f"AI red-team scenario failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    result_dict = result.to_dict()
    if format.lower() == "markdown":
        _output(render_markdown(result_dict), output)
    else:
        _output(result_dict, output)

    if ci and should_fail_ci(result_dict, severity_threshold):
        raise typer.Exit(2)


@ai_redteam_app.command("catalog")
def ai_redteam_catalog(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """列出内置 probes/converters/strategies/scorers 元数据"""
    from core.ai_redteam import (
        CONVERTERS,
        PROBES,
        SCORERS,
        STRATEGIES,
        catalog_summary,
        plugin_summary,
    )

    _output(
        {
            "success": True,
            "summary": catalog_summary(),
            "probes": PROBES,
            "converters": CONVERTERS,
            "strategies": STRATEGIES,
            "scorers": SCORERS,
            "plugins": plugin_summary(),
        },
        output,
    )


@ai_redteam_app.command("convert")
def ai_redteam_convert(
    prompt: str = typer.Argument(..., help="要转换的本地提示文本"),
    converter: str = typer.Option("identity", "--converter", "-c", help="转换器名称"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """本地 Prompt converter；不调用模型、目标或工具"""
    from core.ai_redteam import convert_prompt

    _output({"success": True, "result": convert_prompt(prompt, converter).to_dict()}, output)


@ai_redteam_app.command("eval-run")
def ai_redteam_eval_run(
    run_state: str = typer.Argument(..., help="AgentRunState JSON 文件路径"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """本地评测 AgentRunState — Giskard/Inspect 风格 deterministic eval"""
    from core.ai_redteam import evaluate_run_cases

    try:
        data = json.loads(Path(run_state).read_text(encoding="utf-8"))
        result = evaluate_run_cases(_run_state_from_dict(data))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        typer.echo(f"AI red-team eval failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    _output(result, output)


# ──────────────────────────── ai-surface ────────────────────────────


def _emit_surface_result(
    result,
    output: Optional[str],
    fmt: str,
    severity_threshold: str,
    exit_code: bool,
) -> None:
    """输出静态表面扫描结果，支持 SARIF 与 CI 阈值退出码。"""
    data = result.to_dict()
    findings = data.get("findings", [])

    if fmt.lower() == "sarif":
        from core.reporting.sarif import findings_to_sarif

        coverage = data.get("summary", {}).get("static_coverage")
        run_properties = {"static_coverage": coverage} if coverage else None
        _output(findings_to_sarif(findings, run_properties=run_properties), output)
    else:
        _output(data, output)

    if exit_code:
        from core.reporting.sarif import severity_meets_threshold

        for finding in findings:
            risk = str(finding.get("risk_level") or finding.get("severity") or "info").lower()
            if severity_meets_threshold(risk, severity_threshold):
                raise typer.Exit(2)


@ai_surface_app.command("scan")
def ai_surface_scan(
    path: str = typer.Option("handlers", "--path", "-p", help="handler 文件或目录"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
    format: str = typer.Option("json", "--format", "-f", help="输出格式: json/sarif"),
    severity_threshold: str = typer.Option(
        "high", "--severity-threshold", help="CI 失败阈值: info/low/moderate/high/critical"
    ),
    exit_code: bool = typer.Option(False, "--exit-code", help="发现达阈值项时返回非零退出码"),
    auth_mode: str = typer.Option(
        "strict",
        "--auth-mode",
        help="auth-gate 检测: strict(报高危缺授权) | lenient(外部仓库不报缺授权)",
    ),
    exclude_tests: bool = typer.Option(
        True,
        "--exclude-tests/--include-tests",
        help="跳过 tests/、test_*.py、*_test.py 和 conftest.py",
    ),
    reconcile: Optional[bool] = typer.Option(
        None,
        "--reconcile/--no-reconcile",
        help="与本仓库 capability manifest 对账。默认在仓库根和 handlers/ 上开启",
    ),
):
    """静态盘点 MCP/AI 工具边界 — 解析源码，不导入或执行 handler"""
    from core.ai_surface import scan_handler_surface

    try:
        result = scan_handler_surface(
            path,
            flag_missing_auth=(auth_mode.lower() != "lenient"),
            exclude_tests=exclude_tests,
            reconcile=reconcile,
        )
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError) as exc:
        typer.echo(f"AI surface scan failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    _emit_surface_result(result, output, format, severity_threshold, exit_code)


@ai_surface_app.command("scan-mcp-config")
def ai_surface_scan_mcp_config(
    path: str = typer.Option(..., "--path", "-p", help="MCP JSON 配置文件路径 (mcpServers)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
    format: str = typer.Option("json", "--format", "-f", help="输出格式: json/sarif"),
    severity_threshold: str = typer.Option(
        "high", "--severity-threshold", help="CI 失败阈值: info/low/moderate/high/critical"
    ),
    exit_code: bool = typer.Option(False, "--exit-code", help="发现达阈值项时返回非零退出码"),
):
    """静态审计 MCP 配置 — 危险命令暴露与明文 secret，不执行任何 server"""
    from core.ai_surface import scan_mcp_config

    try:
        result = scan_mcp_config(path)
    except (OSError, ValueError) as exc:
        typer.echo(f"MCP config scan failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    _emit_surface_result(result, output, format, severity_threshold, exit_code)


@ai_surface_app.command("scan-skills")
def ai_surface_scan_skills(
    path: str = typer.Option(..., "--path", "-p", help="skill/prompt 目录或文件"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
    format: str = typer.Option("json", "--format", "-f", help="输出格式: json/sarif"),
    severity_threshold: str = typer.Option(
        "high", "--severity-threshold", help="CI 失败阈值: info/low/moderate/high/critical"
    ),
    exit_code: bool = typer.Option(False, "--exit-code", help="发现达阈值项时返回非零退出码"),
):
    """静态审计 skill/prompt 指令 — 高危指令标记，不安装或启用任何 skill"""
    from core.ai_surface import scan_skill_surface

    try:
        result = scan_skill_surface(path)
    except (OSError, ValueError) as exc:
        typer.echo(f"Skill surface scan failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    _emit_surface_result(result, output, format, severity_threshold, exit_code)


# ──────────────────────────── tools ────────────────────────────


@tools_app.command("lint")
def tools_lint(
    path: str = typer.Option("handlers", "--path", "-p", help="handler 文件或目录"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
    exit_code: bool = typer.Option(False, "--exit-code", help="存在 error 级问题时返回非零退出码"),
    auth_mode: str = typer.Option(
        "strict",
        "--auth-mode",
        help="auth-gate 检测: strict(报高危缺授权) | lenient(外部仓库不报缺授权)",
    ),
):
    """检查工具面是否符合统一契约（授权门禁/schema 质量/证据契约）"""
    from core.tooling import lint_tool_contracts

    try:
        result = lint_tool_contracts(path, flag_missing_auth=auth_mode.lower() != "lenient")
    except (OSError, ValueError) as exc:
        typer.echo(f"Tool contract lint failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    data = result.to_dict()
    _output(data, output)

    if exit_code and data["summary"]["errors"]:
        raise typer.Exit(2)


# ──────────────────────────── code-agent ────────────────────────────


@code_agent_app.command("expand")
def code_agent_expand(
    path: str = typer.Option("core", "--path", "-p", help="Python 文件或目录"),
    seed: Optional[str] = typer.Option(None, "--seed", "-s", help="函数名或 qualified name"),
    file_path: Optional[str] = typer.Option(None, "--file", help="包含 seed 的文件路径"),
    line: Optional[int] = typer.Option(None, "--line", help="seed 所在行号"),
    max_depth: int = typer.Option(2, "--max-depth", "-d", help="调用链扩展深度"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """静态扩展代码调用链上下文 — 不导入模块、不执行代码"""
    from core.code_agent import expand_code_context

    try:
        result = expand_code_context(
            path=path,
            seed=seed,
            file_path=file_path,
            line=line,
            max_depth=max_depth,
        )
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError) as exc:
        typer.echo(f"Code agent expansion failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    _output(result.to_dict(), output)


# ──────────────────────────── runtime-api ────────────────────────────


@runtime_api_app.command("serve")
def runtime_api_serve(
    run_state: Optional[str] = typer.Option(
        None, "--run-state", help="AgentRunState JSON 文件路径"
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="监听地址，默认仅 localhost"),
    port: int = typer.Option(8765, "--port", help="监听端口"),
):
    """启动只读 runtime API: GET /api/runs 和 /api/runs/{run_id}"""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        typer.echo("runtime-api serve is read-only but must bind localhost by default", err=True)
        raise typer.Exit(2)

    try:
        from core.agent_runtime import register_runtime_run, serve_runtime_http

        if run_state:
            data = json.loads(Path(run_state).read_text(encoding="utf-8"))
            state = _run_state_from_dict(data)
            register_runtime_run(state)
            typer.echo(f"loaded runtime run: {state.run_id}")
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        typer.echo(f"runtime API failed to start: {exc}", err=True)
        raise typer.Exit(2) from exc

    typer.echo(f"runtime API listening on http://{host}:{port}/api/runs")
    serve_runtime_http(host=host, port=port)


# ──────────────────────────── sandbox ────────────────────────────


@sandbox_app.command("docker-smoke")
def sandbox_docker_smoke(
    image: str = typer.Option("python:3.12-slim", "--image", help="Docker 镜像"),
    timeout: int = typer.Option(30, "--timeout", help="超时秒数"),
    require: bool = typer.Option(False, "--require", help="Docker 不可用或 smoke 失败时返回非零"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """运行本地 Docker sandbox smoke；默认网络隔离为 none"""
    from core.agent_runtime import smoke_docker_sandbox

    result = smoke_docker_sandbox(image=image, timeout_seconds=timeout)
    _output(result, output)
    if require and not result.get("success"):
        raise typer.Exit(2)


# ──────────────────────────── capabilities ────────────────────────────


@capabilities_app.command("matrix")
def capabilities_matrix(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """输出 PentAGI/promptfoo/garak/PyRIT 等目标能力覆盖矩阵"""
    from core.ai_capabilities import capability_matrix

    _output(capability_matrix(), output)


@capabilities_app.command("readiness")
def capabilities_readiness(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """输出全量重构 readiness 和剩余约束"""
    from core.ai_capabilities import refactor_readiness

    _output(refactor_readiness(), output)


@capabilities_app.command("manifest")
def capabilities_manifest(
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        "-p",
        help="筛选 profile: safe, scan, active-lab, full",
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """输出 MCP capability manifest；默认显示全部 surface。"""
    from core.capability_manifest import CapabilityManifestError
    from core.capability_manifest import capability_manifest as build_manifest

    try:
        payload = build_manifest(profile)
    except CapabilityManifestError as exc:
        raise typer.BadParameter(str(exc), param_hint="--profile") from exc
    _output(payload, output)


@capabilities_app.command("profiles")
def capabilities_profiles(
    output: Optional[str] = typer.Option(None, "--output", "-o", help="输出文件路径"),
):
    """输出 MCP capability profiles、继承关系和运行边界。"""
    from core.capability_manifest import capability_profiles as build_profiles

    _output(build_profiles(), output)


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


# ──────────────────────────── llm (OrcaRouter) ────────────────────────────


def _orca_credential_or_exit():
    """Resolve the OrcaRouter credential or exit with actionable guidance."""
    from core.llm.orcarouter import resolve_credential

    credential = resolve_credential()
    if credential is None:
        typer.echo(
            "No OrcaRouter credential found. Run `autort llm connect` for an "
            "OAuth 2.0 + PKCE login, `autort llm key set` to paste an sk-orca-… "
            "key, or export ORCAROUTER_API_KEY.",
            err=True,
        )
        raise typer.Exit(2)
    return credential


@llm_app.command("status")
def llm_status(as_json: bool = typer.Option(False, "--json", help="Emit JSON")):
    """Show provider, origins, credential source (masked) and model selection"""
    from core.llm.orcarouter import (
        CredentialStore,
        catalog,
        model_is_compatible,
        provider_status,
        resolve_credential,
    )

    store = CredentialStore()
    status = provider_status(store=store)
    stored = status.get("stored") or {}
    selected_model = str(stored.get("model") or "")

    if selected_model:
        credential = resolve_credential(store=store)
        if credential is not None:
            result = catalog.load_catalog(credential.api_key, capability="chat", timeout=5.0)
            if not model_is_compatible(result.models, selected_model, capability="chat"):
                store.update_model("")
                status["model_notice"] = (
                    f"Stored model {selected_model} is not in the current catalog; "
                    "selection cleared."
                )
                selected_model = ""

    status["selected_model"] = selected_model or status["default_model"]
    status["credential_source"] = (status.get("credential") or {}).get("source") or "none"

    if as_json:
        _output(status, None)
        return

    credential_info = status.get("credential")
    if credential_info:
        key_line = (
            f"{credential_info['key']} (source: {credential_info['source']}, "
            f"scope: {credential_info['scope']})"
        )
    else:
        key_line = "<none — run `autort llm connect` or `autort llm key set`>"

    typer.echo(f"Provider   : {status['label']} ({status['provider']})")
    typer.echo(f"Auth base  : {status['auth_base']}")
    typer.echo(f"API base   : {status['api_base']}")
    typer.echo(f"Credential : {key_line}")
    typer.echo(f"Model      : {status['selected_model']}")
    if status.get("model_notice"):
        typer.echo(f"Notice     : {status['model_notice']}")
    typer.echo(f"Cyber docs : {status['provider_page']}")
    typer.echo(f"Cyber models: {status['cyber_catalog']}")


@llm_app.command("connect")
def llm_connect(
    flow: str = typer.Option(
        "loopback",
        "--flow",
        help="loopback (browser callback) or oob (consent screen shows a code)",
    ),
    timeout: float = typer.Option(180.0, "--timeout", help="Seconds to wait for approval"),
    open_browser: bool = typer.Option(
        True, "--open/--no-open", help="Open the consent page automatically"
    ),
    force: bool = typer.Option(False, "--force", help="Authorize even if a key is stored"),
):
    """Sign in with OAuth 2.0 + PKCE (S256); stores a durable OrcaRouter key"""
    from core.llm.orcarouter import (
        AUTHORIZED_APPS_URL,
        KEY_DASHBOARD_URL,
        OrcaAuthError,
        OrcaCredentialError,
        PkceCredentialSource,
        default_browser_opener,
    )

    if flow not in ("loopback", "oob"):
        typer.echo("--flow must be 'loopback' or 'oob'", err=True)
        raise typer.Exit(2)

    def show_url(url: str) -> None:
        typer.echo("Open this URL to authorize AutoRedTeam with OrcaRouter:")
        typer.echo(f"  {url}")

    def read_code(url: str) -> str:
        return typer.prompt("Authorization code shown by OrcaRouter")

    source = PkceCredentialSource()
    try:
        credential = source.acquire(
            flow=flow,
            open_browser=default_browser_opener if open_browser else None,
            on_authorize_url=show_url,
            code_prompt=read_code,
            timeout=timeout,
            reuse_stored=not force,
        )
    except (OrcaAuthError, OrcaCredentialError) as exc:
        typer.echo(f"OrcaRouter login failed: {exc}", err=True)
        raise typer.Exit(2) from exc

    typer.echo(
        f"Credential {credential.masked()} is stored (source: {credential.source}, "
        f"scope: {credential.scope})."
    )
    typer.echo(f"Keys: {KEY_DASHBOARD_URL}")
    typer.echo(f"Revoke this app: {AUTHORIZED_APPS_URL}")


@llm_app.command("logout")
def llm_logout():
    """Remove the stored OrcaRouter credential"""
    from core.llm.orcarouter import CredentialStore

    removed = CredentialStore().clear()
    typer.echo("Stored OrcaRouter credential removed." if removed else "No stored credential.")


@llm_key_app.command("set")
def llm_key_set(
    key: Optional[str] = typer.Option(
        None, "--key", help="Key value; omit to be prompted without echo"
    ),
):
    """Store an existing OrcaRouter API key (sk-orca-…)"""
    from core.llm.orcarouter import ApiKeyCredentialSource, OrcaCredentialError

    value = (key or typer.prompt("OrcaRouter API key", hide_input=True)).strip()
    try:
        credential = ApiKeyCredentialSource().save(value)
    except OrcaCredentialError as exc:
        typer.echo(f"Could not store the key: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"Stored credential {credential.masked()} (source: api_key).")


@llm_key_app.command("clear")
def llm_key_clear():
    """Remove the stored API key"""
    from core.llm.orcarouter import CredentialStore

    removed = CredentialStore().clear()
    typer.echo("Stored credential removed." if removed else "No stored credential.")


@llm_app.command("models")
def llm_models(
    capability: str = typer.Option(
        "chat", "--capability", help="chat/embedding/image/video/rerank"
    ),
    require_input: str = typer.Option(
        "", "--require-input", help="Required input modalities, comma separated (e.g. image)"
    ),
    refresh: bool = typer.Option(False, "--refresh", help="Bypass the in-process cache"),
    select: bool = typer.Option(False, "--select", help="Choose a model and remember it"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON"),
):
    """List models from the live OrcaRouter catalog, filtered by capability"""
    from core.llm.orcarouter import (
        SUPPORTED_CAPABILITIES,
        CredentialStore,
        catalog,
        model_is_compatible,
    )

    if capability not in SUPPORTED_CAPABILITIES:
        typer.echo(f"--capability must be one of: {', '.join(SUPPORTED_CAPABILITIES)}", err=True)
        raise typer.Exit(2)

    credential = _orca_credential_or_exit()
    required_inputs = tuple(
        item.strip().lower() for item in require_input.split(",") if item.strip()
    )

    result = catalog.load_catalog(
        credential.api_key,
        capability=capability,
        required_inputs=required_inputs,
        use_cache=not refresh,
    )
    if as_json:
        _output(result.to_dict(), None)
        return

    if result.degraded:
        typer.echo(
            f"[degraded] Live catalog unavailable ({result.error}); showing the "
            "verified fallback list. Use --refresh to retry.",
            err=True,
        )
    if not result.models:
        typer.echo(
            f"No {capability}-compatible models are available for this workspace.",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"{len(result.models)} {capability} model(s) — source: {result.source}")
    for index, model in enumerate(result.models, start=1):
        details = [",".join(model.input_modalities)]
        if model.context_length:
            details.append(f"{model.context_length} ctx")
        if model.reasoning_efforts:
            details.append("reasoning: " + "/".join(model.reasoning_efforts))
        typer.echo(f"{index:>3}. {model.id}  [{' | '.join(details)}]")

    if not select:
        return

    answer = typer.prompt("Select a model number or id").strip()
    chosen = ""
    if answer.isdigit() and 1 <= int(answer) <= len(result.models):
        chosen = result.models[int(answer) - 1].id
    elif model_is_compatible(
        result.models, answer, capability=capability, required_inputs=required_inputs
    ):
        chosen = answer
    if not chosen:
        typer.echo("That model is not in the filtered list; selection unchanged.", err=True)
        raise typer.Exit(2)

    store = CredentialStore()
    if store.update_model(chosen):
        typer.echo(f"Selected {chosen}.")
    else:
        typer.echo(
            f"Selected {chosen} for this session only. Export AUTORT_LLM_MODEL="
            f"{chosen} to make it persistent (no stored credential file)."
        )


@llm_app.command("use")
def llm_use(model: str = typer.Argument(..., help="Model id from `autort llm models`")):
    """Validate a model against the live catalog and remember it"""
    from core.llm.orcarouter import (
        CredentialStore,
        OrcaCatalogError,
        catalog,
        model_is_compatible,
    )

    credential = _orca_credential_or_exit()
    try:
        result = catalog.load_catalog(credential.api_key, capability="chat")
    except OrcaCatalogError as exc:  # pragma: no cover - load_catalog falls back
        typer.echo(f"Catalog unavailable: {exc}", err=True)
        raise typer.Exit(2) from exc

    if not model_is_compatible(result.models, model, capability="chat"):
        typer.echo(
            f"{model} is not a chat-compatible model in the current catalog. "
            "Run `autort llm models` to pick one.",
            err=True,
        )
        raise typer.Exit(2)

    store = CredentialStore()
    if store.update_model(model):
        typer.echo(f"Selected {model}.")
    else:
        typer.echo(
            f"{model} is compatible. Export AUTORT_LLM_MODEL={model} to persist it "
            "(no stored credential file)."
        )


@llm_app.command("ping")
def llm_ping(
    prompt: str = typer.Option(
        "Reply with the single word: ready", "--prompt", help="Prompt for the test call"
    ),
    model: Optional[str] = typer.Option(None, "--model", help="Override the model id"),
):
    """Send one real request through the OrcaRouter provider code path"""
    from core.llm.provider import LLMProvider

    llm = LLMProvider(provider="orcarouter", model=model)
    if not llm.available:
        typer.echo(
            "OrcaRouter provider is not ready: no credential or no OpenAI-compatible "
            "client. Run `autort llm connect`.",
            err=True,
        )
        raise typer.Exit(2)

    response = llm.complete(prompt, max_tokens=32)
    if response is None:
        typer.echo("The OrcaRouter request failed; see the log for details.", err=True)
        raise typer.Exit(1)
    typer.echo(f"[{llm.model}] {response.strip()}")


def _run_state_from_dict(data: dict):
    """Rebuild AgentRunState from runtime or AI red-team result JSON."""
    from core.agent_runtime import agent_run_state_from_dict

    return agent_run_state_from_dict(data)


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
        try:
            typer.echo(text)
        except UnicodeEncodeError:
            sys.stdout.buffer.write(text.encode("utf-8", errors="replace") + b"\n")


def main():
    """CLI 入口点"""
    app()


if __name__ == "__main__":
    main()
