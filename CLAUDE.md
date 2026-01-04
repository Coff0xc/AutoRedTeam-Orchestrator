# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AutoRedTeam-Orchestrator is an AI-driven automated penetration testing framework based on Model Context Protocol (MCP). It provides 35+ pure Python security tools covering OWASP Top 10, designed for seamless integration with AI editors (Windsurf/Cursor/Claude Desktop/Kiro).

Requirements: Python 3.10+, Windows/Linux/macOS (no external tools required)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Use via Claude Code / Kiro CLI (recommended)
# Just ask: "对 example.com 进行渗透测试"
```

## MCP Tools (46+ Pure Python)

### Core Tools (全自动)
- `auto_pentest(target, deep_scan=True)` - 全自动渗透测试
- `generate_report(target, format)` - 生成渗透测试报告 (markdown/json/html/pdf)
- `smart_analyze(target)` - 智能分析目标

### Task Queue Tools (任务队列)
- `task_submit(tool_name, target)` - 提交后台异步任务
- `task_status(task_id)` - 查询任务状态
- `task_cancel(task_id)` - 取消等待中的任务
- `task_list(limit)` - 列出所有任务

### Advanced Pentest Tools (渗透增强 v2.2)
- `oob_detect(url, param, vuln_type)` - OOB带外检测 (盲SSRF/XXE/SQLi)
- `session_create(name)` - 创建HTTP会话
- `session_login(session_id, login_url, username, password)` - 会话登录
- `session_request(session_id, url, method)` - 带认证的HTTP请求
- `session_context(session_id)` - 获取会话上下文
- `smart_payload(vuln_type, payload, waf)` - Payload变异 (WAF绕过)
- `verify_vuln(url, param, vuln_type, payload, rounds)` - 统计学漏洞验证

### Recon Tools (信息收集)
- `port_scan` - 端口扫描
- `dns_lookup` - DNS查询
- `http_probe` - HTTP探测
- `ssl_info` - SSL证书信息
- `whois_query` - Whois查询
- `tech_detect` - 技术栈识别
- `subdomain_bruteforce` - 子域名枚举
- `dir_bruteforce` - 目录扫描
- `sensitive_scan` - 敏感文件探测
- `full_recon` - 完整侦察

### Vulnerability Detection (漏洞检测)
- `vuln_check` - 基础漏洞检测
- `sqli_detect` - SQL注入检测
- `xss_detect` - XSS检测
- `csrf_detect` - CSRF检测
- `ssrf_detect` - SSRF检测
- `cmd_inject_detect` - 命令注入检测
- `xxe_detect` - XXE检测
- `idor_detect` - IDOR越权检测
- `auth_bypass_detect` - 认证绕过检测
- `file_upload_detect` - 文件上传漏洞检测
- `logic_vuln_check` - 逻辑漏洞检测

### CVE & Payload Tools
- `cve_search` - CVE漏洞搜索
- `sqli_payloads` - SQL注入Payload
- `xss_payloads` - XSS Payload
- `reverse_shell_gen` - 反向Shell生成
- `google_dorks` - Google Dork生成

## OWASP Top 10 Coverage

| OWASP | 漏洞类型 | 工具 |
|-------|---------|------|
| A01 | Broken Access Control | idor_detect, auth_bypass_detect |
| A02 | Cryptographic Failures | ssl_info |
| A03 | Injection | sqli_detect, xss_detect, cmd_inject_detect, xxe_detect |
| A04 | Insecure Design | logic_vuln_check |
| A05 | Security Misconfiguration | sensitive_scan, vuln_check |
| A06 | Vulnerable Components | cve_search, tech_detect |
| A07 | Auth Failures | auth_bypass_detect |
| A08 | Software Integrity | file_upload_detect |
| A09 | Logging Failures | sensitive_scan |
| A10 | SSRF | ssrf_detect |

## Commands

```bash
# Start MCP server (HTTP mode - legacy)
python main.py

# Start with custom host/port
python main.py -H 0.0.0.0 -p 5000

# Debug mode
python main.py -d

# Run standalone auto recon (without server)
python auto_recon.py

# Test server functionality (requires server running)
python test_server.py
```

## Architecture

```
┌─────────────────────────────────────────┐
│   AI Editor Layer (MCP Protocol)        │
│   Claude Code / Cursor / Windsurf / Kiro│
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│   MCP Stdio Server (mcp_stdio_server.py)│
│   - 35+ Pure Python Security Tools      │
│   - OWASP Top 10 Full Coverage          │
│   - Windows/Linux/macOS Compatible      │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│   Tool Execution Layer                  │
│   - Recon (port, dns, subdomain, dir)   │
│   - Vuln Scan (sqli, xss, csrf, ssrf)   │
│   - Advanced (xxe, idor, cmd_inject)    │
│   - Logic (auth_bypass, file_upload)    │
│   - CVE Search & Payload Generation     │
└─────────────────────────────────────────┘
```

## Key Components

- **mcp_stdio_server.py**: MCP stdio server with 46+ pure Python tools (recommended)
- **utils/task_queue.py**: Lightweight task queue for async execution
- **modules/oob_detector.py**: OOB detection with Interactsh/DNSLog
- **modules/smart_payload_engine.py**: Payload mutation for WAF bypass
- **modules/vuln_verifier.py**: Statistical vulnerability verification
- **core/session_manager.py**: HTTP session management with auth support
- **main.py**: Legacy Flask HTTP server
- **auto_recon.py**: Standalone auto reconnaissance engine
- **core/**: Legacy HTTP server components

## Configuration

MCP config (`~/.claude/mcp.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["E:/A-2026-project/Github-project/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

## Language

Code comments and documentation are in Chinese (简体中文). Maintain this convention.

## Coding Guidelines (CRITICAL)

- **Cross-Platform Compatibility**: This project runs on Windows, Linux, and macOS.
- **Path Handling**:
  - **NEVER** use hardcoded paths like `/tmp/` or `/var/log/`.
  - **ALWAYS** use `os.path.join`, `pathlib.Path`, or `tempfile.gettempdir()` for paths.
  - **Example**: Use `os.path.join(tempfile.gettempdir(), 'app.log')` instead of `/tmp/app.log`.
- **Encoding**: Always specify `encoding='utf-8'` when opening files (e.g., `open(file, 'w', encoding='utf-8')`).
- **External Tools**: Check for tool availability (e.g., `shutil.which('nmap')`) before execution. Do not assume tools exist.
