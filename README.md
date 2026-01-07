# 🔥 AutoRedTeam-Orchestrator
[English](README_EN.md)

> AI 驱动的自动化红队编排框架，集成 155+ 安全工具与 2000+ Payload，覆盖 MITRE ATT&CK 95%+，原生 MCP，适配 Windsurf / Cursor / Claude Desktop / Kiro。

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/MCP-Native-00ADD8?style=for-the-badge" alt="MCP"/>
  <img src="https://img.shields.io/badge/Tools-155+-FF6B6B?style=for-the-badge" alt="Tools"/>
  <img src="https://img.shields.io/badge/Payloads-2000+-orange?style=for-the-badge" alt="Payloads"/>
  <img src="https://img.shields.io/badge/ATT%26CK-95%25+-red?style=for-the-badge" alt="ATT&CK Coverage"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

---

## 🧭 项目概览
- AI 原生：指纹识别、攻击链规划、历史反馈学习、自动选工具/Payload。
- 全流程自动化：子域/端口/WAF/指纹 → 漏洞发现与验证 → 报告。
- 红队增强：横向移动（SMB/SSH/WMI）、C2（Beacon/DNS/HTTP）、混淆免杀、隐蔽通信、持久化、凭证获取、AD 攻击。
- 安全扩展：API 安全（JWT/CORS/Headers/GraphQL/WebSocket）、供应链（CycloneDX/SPDX SBOM、OSV 审计、CI/CD 扫描）、云原生（K8s/gRPC）。
- 性能可靠：异步扫描、多层缓存、性能监控、任务队列、响应去重与误报过滤。
- 资源丰富：Nuclei 11997+ 模板，Shiro/Log4j/Fastjson 等实战 Payload，100+ WAF 绕过，NoSQL/GraphQL/JSON 注入。

---

## 🛠️ 功能总览（精选命令）
| 模块 | 能力 | 示例命令 |
| --- | --- | --- |
| 🔎 智能侦察 | 全自动/深度侦察、指纹/WAF | `auto_recon` `intelligent_recon` `complete_recon_workflow` `identify_tech` |
| 🛡️ 漏洞扫描 | Nuclei 全量/CVE、Shiro/Log4j/SQLi/XSS、SSL | `nuclei_complete_scan` `nuclei_cve` `deep_vuln_scan` `xss_scan` `sslscan` |
| 🧩 API / 供应链 / 云 | JWT/CORS/Headers/GraphQL/WebSocket；SBOM/依赖审计/CI-CD；K8s/gRPC | `jwt_full_scan` `cors_bypass_test` `graphql_full_scan` `websocket_full_scan` `sbom_generate` `dependency_audit` `cicd_security_scan` `k8s_full_scan` `grpc_full_scan` |
| 🎯 漏洞利用 & Payload | Payload 查询/生成、EXP 获取、反弹 Shell、MSF | `get_payloads` `query_payload_library` `get_exploit` `reverse_shell` `msfvenom` |
| 🕵️ 红队行动 | 横向/C2/免杀/隐蔽/持久化/凭证/AD | `lateral_smb_exec` `lateral_ssh_exec` `c2_beacon_start` `evasion_obfuscate_payload` `stealth_proxy_pool` `persistence_windows` `credential_dump` `ad_kerberos_attack` |
| 📑 报告与调度 | 报告、任务队列、性能/缓存 | `generate_report` `task_submit` `task_status` `perf_summary` `cache_stats` |
| 🔍 辅助 | CVE 搜索、AI 攻击计划、服务扫描 | `cve_search` `ai_attack_plan` `smart_service_scan` |

---

## ⚡ 快速开始
```bash
git clone https://github.com/Coff0xc/AutoRedTeam-Orchestrator.git
cd AutoRedTeam-Orchestrator

chmod +x setup.sh && sudo ./setup.sh   # 安装外部依赖
pip install -r requirements.txt
cp config/config.yaml.example config/config.yaml
# nuclei -update-templates             # 可选：更新模板
```

- 环境：Kali/Ubuntu/Debian，Python 3.10+，部分功能需 root。
- 可选：`impacket`(SMB/WMI)、`paramiko`(SSH 隧道)、`pycryptodome`(AES)。

---

## 🚀 使用
### 方式一：MCP（推荐）
```bash
./setup_windsurf_mcp.sh   # 自动写入 MCP 配置
```
在编辑器对话直接描述：
- “对 example.com 做一次完整侦察并输出报告”
- “扫描 192.168.1.0/24 开放端口并识别服务”
- “检查 https://target.com 是否存在 Log4j/Shiro”

### 方式二：独立 HTTP
```bash
python main.py -H 0.0.0.0 -p 5000
# 浏览 http://localhost:5000/tools 查看工具列表
```

---

## 🔧 配置
编辑 `config/config.yaml`：
```yaml
server: {host: "127.0.0.1", port: 5000}
ai: {provider: "openai", model: "gpt-4", api_key: ""}
scanning: {default_threads: 10, default_delay: 100, rate_limit: 150}
api_keys: {shodan: "", censys_id: "", censys_secret: "", virustotal: ""}
wordlists:
  directories: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
  passwords: "/usr/share/wordlists/rockyou.txt"
  subdomains: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
```

---

## 🗂️ 目录速览
```
main.py / mcp_stdio_server.py / auto_recon.py / mcp_tools.py
core/ (attack_chain, tool_chain, intelligent_recon_engine, response_filter,
      c2/, lateral/, evasion/, stealth/, persistence/, credential/, ad/, cve/)
modules/ (async_scanner, ai_decision_engine, adaptive_payload_engine,
          enhanced_detector_tools, api_security_tools, supply_chain_tools,
          cloud_security_tools, smart_payload_selector, mega_payloads,
          vuln_correlation_engine, performance_monitor, smart_cache, nuclei_tools, ...)
payloads/complete_payload_db.json
utils/ (report_generator.py, task_queue.py, tool_checker.py)
config/, setup.sh, setup_windsurf_mcp.sh
```

---

## ✨ v2.6.0 亮点（2026-01-07）
- API 安全：JWT/CORS/安全头/GraphQL/WebSocket 全量检测。
- 供应链：CycloneDX/SPDX SBOM、OSV 依赖审计、CI/CD 配置扫描。
- 云安全：K8s 特权/HostPath/RBAC/NetworkPolicy/Secrets；gRPC 反射/TLS/认证检测。
- 响应过滤：SPA 误报识别、404 基线、内容去重；修复 `sensitive_scan` / `auth_bypass_detect` 误报。
- 工具数 155+，ATT&CK 覆盖 95%+。

---

## 🛤️ 路线图
- [ ] Web UI
- [ ] 分布式扫描
- [ ] 更多云（GCP/阿里云）
- [ ] AI 自动化漏洞利用
- [x] Red Team 横向/C2/免杀/隐蔽/持久化/凭证/AD
- [x] API/供应链/云安全扩展
- [x] 性能监控与智能缓存

---

## ⚖️ 合规声明
仅用于授权的安全测试与研究，使用前请取得书面授权；遵守当地法律与道德，滥用后果自负。

---

## 🤝 贡献与联系
- PR / Issue 欢迎。
- Email: Coff0xc@protonmail.com
- Issues: https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues
```
