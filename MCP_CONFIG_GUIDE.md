# MCP 配置指南

本指南介绍如何在各种 AI 编辑器中配置 AutoRedTeam-Orchestrator MCP 服务器。

## 目录

- [通用 MCP 编辑器](#通用-mcp-编辑器)
- [Cursor](#cursor)
- [Windsurf](#windsurf)
- [Kiro CLI](#kiro-cli)
- [常见问题](#常见问题)

---

## 通用 MCP 编辑器

### 配置文件位置

大多数支持 MCP 的 AI 编辑器使用以下配置文件位置：

| 系统 | 路径 |
|------|------|
| Windows | `%APPDATA%\<EditorName>\config.json` |
| macOS | `~/Library/Application Support/<EditorName>/config.json` |
| Linux | `~/.config/<EditorName>/config.json` |

### 配置示例

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

### Windows 示例

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["E:/Projects/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": { "PYTHONIOENCODING": "utf-8" }
    }
  }
}
```

### 验证配置

1. 重启 AI 编辑器
2. 在对话中输入: `使用 port_scan 扫描 127.0.0.1`
3. 如果配置正确，AI 编辑器会调用 MCP 工具

---

## Cursor

### 配置文件位置

| 系统 | 路径 |
|------|------|
| Windows | `%USERPROFILE%\.cursor\mcp.json` |
| macOS | `~/.cursor/mcp.json` |
| Linux | `~/.cursor/mcp.json` |

### 配置示例

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

### 启用 MCP

1. 打开 Cursor 设置 (Ctrl+,)
2. 搜索 "MCP"
3. 确保 "Enable MCP" 已勾选
4. 重启 Cursor

---

## Windsurf

### 配置文件位置

| 系统 | 路径 |
|------|------|
| Windows | `%USERPROFILE%\.windsurf\mcp.json` |
| macOS | `~/.windsurf/mcp.json` |
| Linux | `~/.windsurf/mcp.json` |

### 配置示例

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
```

### 注意事项

- Windsurf 需要设置 `PYTHONIOENCODING=utf-8` 以正确处理中文输出
- 确保 Python 路径在系统 PATH 中

---

## Kiro CLI

### 配置文件位置

| 系统 | 路径 |
|------|------|
| Windows | `%USERPROFILE%\.kiro\mcp.json` |
| macOS | `~/.kiro/mcp.json` |
| Linux | `~/.kiro/mcp.json` |

### 配置示例

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

### 使用方法

```bash
# 启动 Kiro CLI
kiro-cli chat

# 在对话中使用工具
> 使用 port_scan 扫描 192.168.1.1 的常见端口
```

---

## 通用配置选项

### 使用 Python 虚拟环境

如果你使用虚拟环境，需要指定完整的 Python 路径：

```json
{
  "mcpServers": {
    "redteam": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

### Windows 虚拟环境

```json
{
  "mcpServers": {
    "redteam": {
      "command": "E:/Projects/AutoRedTeam-Orchestrator/venv/Scripts/python.exe",
      "args": ["E:/Projects/AutoRedTeam-Orchestrator/mcp_stdio_server.py"]
    }
  }
}
```

### 环境变量配置

```json
{
  "mcpServers": {
    "redteam": {
      "command": "python",
      "args": ["/path/to/mcp_stdio_server.py"],
      "env": {
        "PYTHONIOENCODING": "utf-8",
        "VERIFY_SSL": "false",
        "RATE_LIMIT_DELAY": "0.5",
        "MAX_THREADS": "30"
      }
    }
  }
}
```

---

## 常见问题

### Q: 工具无法调用，提示 "MCP server not found"

**A:** 检查以下几点：
1. 配置文件路径是否正确
2. Python 是否在系统 PATH 中
3. `mcp_stdio_server.py` 路径是否正确（使用绝对路径）
4. 重启编辑器

### Q: 中文输出乱码

**A:** 在配置中添加环境变量：
```json
"env": {
  "PYTHONIOENCODING": "utf-8"
}
```

### Q: 提示缺少依赖

**A:** 安装依赖：
```bash
pip install -r requirements.txt
```

### Q: Windows 下路径问题

**A:** 使用正斜杠 `/` 或双反斜杠 `\\`：
```json
"args": ["E:/Projects/mcp_stdio_server.py"]
// 或
"args": ["E:\\Projects\\mcp_stdio_server.py"]
```

### Q: 如何查看 MCP 日志

**A:**
- 各 AI 编辑器: 打开开发者工具查看日志
- Cursor: 打开开发者工具 (Help > Toggle Developer Tools)
- 在 `mcp_stdio_server.py` 中添加日志输出到文件

### Q: 如何测试 MCP 服务器是否正常

**A:** 直接运行服务器：
```bash
python mcp_stdio_server.py
```
如果没有报错，说明服务器可以正常启动。

---

## 工具列表

配置成功后，你可以使用以下工具（部分）：

| 工具 | 功能 |
|------|------|
| `port_scan` | 端口扫描 |
| `dns_lookup` | DNS 查询 |
| `http_probe` | HTTP 探测 |
| `sqli_detect` | SQL 注入检测 |
| `xss_detect` | XSS 检测 |
| `auto_pentest` | 全自动渗透测试 |
| `cve_search` | CVE 漏洞搜索 |

完整工具列表请参阅 [README.md](README.md)。

---

## 获取帮助

如果遇到问题：
1. 查看 [Issue](https://github.com/Coff0xc/AutoRedTeam-Orchestrator/issues)
2. 提交新 Issue
3. 参考 [CONTRIBUTING.md](CONTRIBUTING.md)
