import json
from pathlib import Path

from core.ai_surface import INVENTORY_HOME_ENV, INVENTORY_SCHEMA, discover_agent_stack
from core.ai_surface.discover import _codex_mcp_servers

SECRET_URL = "https://secret.example.invalid/mcp"
SECRET_TOKEN = "tok_live_should_not_leak"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _server_json(name: str, **fields) -> str:
    return json.dumps({"mcpServers": {name: fields}})


def _build_stack(home: Path, project: Path) -> None:
    _write(
        home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        _server_json("desktop", command="npx", env={"TOKEN": SECRET_TOKEN}),
    )
    _write(
        home
        / "AppData"
        / "Local"
        / "Packages"
        / "Claude_testhash"
        / "LocalCache"
        / "Roaming"
        / "Claude"
        / "claude_desktop_config.json",
        _server_json("msix", command="npx"),
    )
    _write(
        home / ".cursor" / "mcp.json",
        _server_json("cursor-user", command=r"C:\Program Files\nodejs\npx.cmd"),
    )
    _write(
        home / ".claude.json",
        _server_json("claude-user", url=SECRET_URL, env={"API_KEY": SECRET_TOKEN}),
    )
    _write(
        home / ".claude" / "settings.json",
        json.dumps({"theme": "dark"}),
    )
    _write(home / ".claude" / "skills" / "notes" / "SKILL.md", "Review the local notes.")
    _write(
        home / ".gemini" / "settings.json",
        json.dumps(
            {
                "mcpServers": {
                    "gemini": {"httpUrl": SECRET_URL},
                }
            }
        ),
    )
    _write(
        home / ".codex" / "config.toml",
        "[mcp_servers.docs]\n"
        f'url = "{SECRET_URL}"\n'
        "[mcp_servers.shell]\n"
        'command = "npx"\n',
    )
    _write(
        home / ".codeium" / "windsurf" / "mcp_config.json",
        _server_json("windsurf", command="npx"),
    )
    _write(
        home / "AppData" / "Roaming" / "Code" / "User" / "mcp.json",
        json.dumps({"servers": {"vscode-user": {"command": "python"}}}),
    )
    _write(project / ".mcp.json", _server_json("portable", command="autoredteam-mcp"))
    _write(
        project / ".cursor" / "mcp.json",
        json.dumps({"mcp": {"servers": {"cursor-project": {"command": "npx"}}}}),
    )
    _write(
        project / ".vscode" / "mcp.json",
        json.dumps({"servers": {"vscode-project": {"url": SECRET_URL}}}),
    )
    _write(project / ".claude" / "skills" / "lab" / "SKILL.md", "Map the local notes.")


def _payload_text(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False)


def test_inventory_empty_home_has_no_servers(tmp_path: Path):
    result = discover_agent_stack(home=tmp_path, project=tmp_path).to_dict()

    assert result["schema"] == INVENTORY_SCHEMA
    assert result["success"] is True
    assert result["network"] is False
    assert result["summary"]["server_count"] == 0
    assert result["summary"]["config_count"] == 0
    assert result["summary"]["skill_count"] == 0
    assert result["configs"] == []
    assert result["skills"] == []


def test_inventory_discovers_documented_clients_without_leaking_secrets(tmp_path: Path):
    home = tmp_path / "home"
    project = tmp_path / "repo"
    _build_stack(home, project)

    result = discover_agent_stack(home=home, project=project).to_dict()
    text = _payload_text(result)
    by_client = {}
    for item in result["configs"]:
        by_client.setdefault(item["client"], []).append(item)
    servers = {server["name"]: server for item in result["configs"] for server in item["servers"]}
    skill_names = {item["name"] for item in result["skills"]}

    assert SECRET_URL not in text
    assert SECRET_TOKEN not in text
    assert "pzs8sxrjxfjjc" not in text
    assert result["summary"]["server_count"] >= 10
    assert set(result["summary"]["clients"]) >= {
        "claude-desktop",
        "claude-code",
        "cursor",
        "vscode",
        "gemini-cli",
        "codex",
        "windsurf",
        "mcp-json",
    }
    assert {item["client"] for item in result["configs"] if item["scope"] == "user"} >= {
        "claude-desktop",
        "cursor",
        "vscode",
        "gemini-cli",
        "codex",
        "windsurf",
        "claude-code",
    }
    assert servers["cursor-user"]["command"] == "npx.cmd"
    assert servers["cursor-user"]["transport"] == "stdio"
    assert servers["claude-user"]["remote"] is True
    assert servers["claude-user"]["has_env"] is True
    assert servers["claude-user"]["command"] == ""
    assert servers["docs"]["transport"] == "http"
    assert servers["shell"]["transport"] == "stdio"
    assert skill_names == {"notes", "lab"}
    assert len(by_client["claude-desktop"]) == 2
    for item in result["configs"] + result["skills"]:
        resolved = Path(item["path"]).resolve()
        assert tmp_path.resolve() in resolved.parents or resolved == tmp_path.resolve()


def test_inventory_skips_mixed_settings_without_servers(tmp_path: Path):
    home = tmp_path / "home"
    _write(home / ".claude" / "settings.json", json.dumps({"editor": "vim"}))
    _write(home / ".gemini" / "settings.json", json.dumps({"model": "flash"}))
    _write(home / ".cursor" / "mcp.json", _server_json("keep", command="npx"))

    result = discover_agent_stack(home=home, project=home).to_dict()
    clients = {item["client"] for item in result["configs"]}

    assert clients == {"cursor"}


def test_inventory_home_env_and_invalid_json_warning(tmp_path: Path, monkeypatch):
    home = tmp_path / "env-home"
    _write(home / ".cursor" / "mcp.json", "{not json")
    monkeypatch.setenv(INVENTORY_HOME_ENV, str(home))

    result = discover_agent_stack(project=home).to_dict()

    assert result["summary"]["config_count"] == 1
    assert result["configs"][0]["servers"] == []
    assert any("JSONDecodeError" in warning for warning in result["warnings"])


def test_inventory_skips_symlinked_config(tmp_path: Path):
    real = tmp_path / "real.json"
    real.write_text(_server_json("hidden", command="npx"), encoding="utf-8")
    link_dir = tmp_path / ".cursor"
    link_dir.mkdir()
    link = link_dir / "mcp.json"
    try:
        link.symlink_to(real)
    except OSError:
        return
    if not link.is_symlink():
        return

    result = discover_agent_stack(home=tmp_path, project=tmp_path).to_dict()

    assert result["summary"]["server_count"] == 0
    assert result["configs"] == []


def test_inventory_missing_project_raises(tmp_path: Path):
    missing = tmp_path / "nope"
    try:
        discover_agent_stack(home=tmp_path, project=missing)
    except FileNotFoundError:
        return
    raise AssertionError("missing project must raise FileNotFoundError")


def test_inventory_does_not_import_real_profile_as_project(tmp_path: Path):
    project = tmp_path / "repo"
    project.mkdir()
    result = discover_agent_stack(home=tmp_path, project=project).to_dict()
    blocked = {
        (Path.home() / ".cursor" / "mcp.json").resolve(),
        (Path.home() / ".codex" / "config.toml").resolve(),
        (Path.home() / ".claude.json").resolve(),
        (Path.home() / ".gemini" / "settings.json").resolve(),
    }
    found = {Path(item["path"]).resolve() for item in result["configs"]}

    assert found.isdisjoint(blocked)
    assert result["summary"]["server_count"] == 0


def test_inventory_file_project_is_explicit_config(tmp_path: Path):
    config = tmp_path / "custom.json"
    _write(config, _server_json("explicit", command="npx"))

    result = discover_agent_stack(home=tmp_path, project=config).to_dict()
    explicit = [item for item in result["configs"] if item["scope"] == "explicit"]

    assert len(explicit) == 1
    assert explicit[0]["servers"][0]["name"] == "explicit"


def test_discover_module_has_no_network_imports():
    source = Path("core/ai_surface/discover.py").read_text(encoding="utf-8")
    for needle in ("import requests", "import httpx", "import aiohttp", "import socket", "urllib"):
        assert needle not in source


def test_codex_table_parser_reads_command_and_url_only():
    parsed = _codex_mcp_servers(
        "[other]\n"
        'value = "1"\n'
        "[mcp_servers.docs]\n"
        f'url = "{SECRET_URL}"\n'
        'args = ["-y", "pkg"]\n'
        '[mcp_servers."quoted"]\n'
        'command = "npx"\n'
    )

    assert set(parsed) == {"docs", "quoted"}
    assert parsed["docs"]["url"] == SECRET_URL
    assert "args" not in parsed["docs"]
    assert parsed["quoted"]["command"] == "npx"
