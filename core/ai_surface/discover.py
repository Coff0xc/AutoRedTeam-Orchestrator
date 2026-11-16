"""Discover local MCP client configs and skill roots.

Read-only. The inventory never starts a server, never calls initialize, never
connects, and never copies env values, arguments, or remote URLs into output.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

INVENTORY_SCHEMA = "autort.inventory/v1"
INVENTORY_HOME_ENV = "AUTORT_INVENTORY_HOME"
_MAX_CONFIGS = 256
_MAX_SKILLS = 256
_REMOTE_FIELDS = ("url", "serverUrl", "baseUrl", "httpUrl", "http_url")

# Documented client files relative to the inventory home. Existence is the
# filter, so Windows, macOS, and Linux locators are all checked.
_USER_FILES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("claude-desktop", ("AppData", "Roaming", "Claude", "claude_desktop_config.json")),
    ("claude-desktop", ("Library", "Application Support", "Claude", "claude_desktop_config.json")),
    ("claude-desktop", (".config", "Claude", "claude_desktop_config.json")),
    ("claude-code", (".claude.json",)),
    ("claude-code", (".claude", "settings.json")),
    ("cursor", (".cursor", "mcp.json")),
    ("vscode", ("AppData", "Roaming", "Code", "User", "mcp.json")),
    ("vscode", ("AppData", "Roaming", "Code - Insiders", "User", "mcp.json")),
    ("vscode", (".config", "Code", "User", "mcp.json")),
    ("vscode", ("Library", "Application Support", "Code", "User", "mcp.json")),
    ("gemini-cli", (".gemini", "settings.json")),
    ("codex", (".codex", "config.toml")),
    ("windsurf", (".codeium", "windsurf", "mcp_config.json")),
)

_PROJECT_FILES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("mcp-json", (".mcp.json",)),
    ("cursor", (".cursor", "mcp.json")),
    ("vscode", (".vscode", "mcp.json")),
    ("gemini-cli", (".gemini", "settings.json")),
    ("codex", (".codex", "config.toml")),
)

_SKILL_ROOTS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (("claude-code", (".claude", "skills")),)

_MIXED_SETTINGS_CLIENTS = frozenset({"claude-code", "gemini-cli"})


@dataclass
class InventoryServer:
    """One MCP server declared in a discovered config. No args, env, or URLs."""

    name: str
    transport: str
    command: str
    remote: bool
    has_env: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "remote": self.remote,
            "has_env": self.has_env,
        }


@dataclass
class InventoryConfig:
    """One MCP config file found on disk."""

    client: str
    scope: str
    path: str
    kind: str
    servers: List[InventoryServer] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client": self.client,
            "scope": self.scope,
            "path": self.path,
            "kind": self.kind,
            "servers": [item.to_dict() for item in self.servers],
        }


@dataclass
class InventorySkill:
    """One SKILL.md path. The body is not read."""

    client: str
    name: str
    path: str

    def to_dict(self) -> Dict[str, Any]:
        return {"client": self.client, "name": self.name, "path": self.path}


@dataclass
class InventoryResult:
    """autort.inventory/v1 document."""

    home: str
    project: str
    configs: List[InventoryConfig] = field(default_factory=list)
    skills: List[InventorySkill] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        clients = sorted(
            {item.client for item in self.configs} | {item.client for item in self.skills}
        )
        return {
            "schema": INVENTORY_SCHEMA,
            "success": True,
            "network": False,
            "home": self.home,
            "project": self.project,
            "summary": {
                "config_count": len(self.configs),
                "server_count": sum(len(item.servers) for item in self.configs),
                "skill_count": len(self.skills),
                "clients": clients,
            },
            "configs": [item.to_dict() for item in self.configs],
            "skills": [item.to_dict() for item in self.skills],
            "warnings": list(self.warnings),
        }


def discover_agent_stack(
    *,
    home: Optional[str | Path] = None,
    project: Optional[str | Path] = None,
    extra_files: Optional[Sequence[str | Path]] = None,
) -> InventoryResult:
    """List local MCP configs and skill roots under home and project.

    ``home`` defaults to ``AUTORT_INVENTORY_HOME`` or the user home. Project
    ancestors are walked until ``home`` or the filesystem root. Missing home
    directories yield an empty user inventory.
    """
    home_path = _resolve_home(home)
    project_path = Path.cwd() if project is None else Path(project)
    project_path = project_path.expanduser()
    if not project_path.exists():
        raise FileNotFoundError(f"Inventory project path does not exist: {project_path}")
    if project_path.is_file():
        extra = list(extra_files or [])
        extra.append(project_path)
        extra_files = extra
        project_path = project_path.parent
    try:
        project_path = project_path.resolve()
    except OSError:
        project_path = project_path.absolute()

    result = InventoryResult(home=str(home_path), project=str(project_path))
    seen_configs: set[Path] = set()
    seen_skills: set[Path] = set()

    for client, rel in _USER_FILES:
        _add_config(
            result,
            seen_configs,
            home_path.joinpath(*rel),
            client=client,
            scope="user",
        )
    for msix in _msix_claude_configs(home_path):
        _add_config(
            result,
            seen_configs,
            msix,
            client="claude-desktop",
            scope="user",
        )
    _add_skills(result, seen_skills, home_path)

    for directory in _project_dirs(project_path, home_path):
        for client, rel in _PROJECT_FILES:
            _add_config(
                result,
                seen_configs,
                directory.joinpath(*rel),
                client=client,
                scope="project",
            )
        _add_skills(result, seen_skills, directory)

    for extra in extra_files or ():
        extra_path = Path(extra)
        _add_config(
            result,
            seen_configs,
            extra_path,
            client=_client_for_extra(extra_path),
            scope="explicit",
        )

    result.configs.sort(key=lambda item: (item.client, item.path.casefold()))
    result.skills.sort(key=lambda item: (item.client, item.path.casefold()))
    return result


def _resolve_home(home: Optional[str | Path]) -> Path:
    if home is None:
        env = os.environ.get(INVENTORY_HOME_ENV, "").strip()
        home_path = Path(env) if env else Path.home()
    else:
        home_path = Path(home)
    home_path = home_path.expanduser()
    try:
        return home_path.resolve()
    except OSError:
        return home_path.absolute()


def _project_dirs(project: Path, home: Path) -> List[Path]:
    directories: List[Path] = []
    seen: set[Path] = set()
    current = project
    real_home = _real_home()
    while True:
        if current in seen:
            break
        seen.add(current)
        # A fake --home must not walk into the operator's real profile and
        # pick up ~/.cursor or ~/.codex as "project" configs.
        if current == real_home and current != home:
            break
        directories.append(current)
        if current == home:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent
    return directories


def _real_home() -> Path:
    try:
        return Path.home().resolve()
    except OSError:
        return Path.home()


def _msix_claude_configs(home: Path) -> Iterable[Path]:
    packages = home / "AppData" / "Local" / "Packages"
    if not packages.is_dir() or packages.is_symlink():
        return
    try:
        children = list(packages.iterdir())
    except OSError:
        return
    for package in children:
        if package.is_symlink() or not package.is_dir():
            continue
        if not package.name.startswith("Claude_"):
            continue
        yield package / "LocalCache" / "Roaming" / "Claude" / "claude_desktop_config.json"


def _add_config(
    result: InventoryResult,
    seen: set[Path],
    path: Path,
    *,
    client: str,
    scope: str,
) -> None:
    if len(result.configs) >= _MAX_CONFIGS:
        warning = f"Stopped after {_MAX_CONFIGS} MCP config files"
        if warning not in result.warnings:
            result.warnings.append(warning)
        return
    if not _is_regular_file(path):
        return
    try:
        resolved = path.resolve()
    except OSError as exc:
        result.warnings.append(f"{path}: {type(exc).__name__}")
        return
    if resolved in seen:
        return
    seen.add(resolved)
    servers, warning = _load_servers(resolved)
    if warning:
        result.warnings.append(warning)
    if not servers and client in _MIXED_SETTINGS_CLIENTS:
        seen.remove(resolved)
        return
    result.configs.append(
        InventoryConfig(
            client=client,
            scope=scope,
            path=str(resolved),
            kind="mcp-config",
            servers=servers,
        )
    )


def _add_skills(result: InventoryResult, seen: set[Path], root: Path) -> None:
    for client, rel in _SKILL_ROOTS:
        skill_root = root.joinpath(*rel)
        if not _is_regular_dir(skill_root):
            continue
        try:
            children = sorted(skill_root.iterdir(), key=lambda item: item.name.casefold())
        except OSError as exc:
            result.warnings.append(f"{skill_root}: {type(exc).__name__}")
            continue
        candidates = [skill_root / "SKILL.md"]
        for child in children:
            if child.is_symlink() or not child.is_dir():
                continue
            candidates.append(child / "SKILL.md")
        for skill_file in candidates:
            warning = f"Stopped after {_MAX_SKILLS} SKILL.md files"
            if len(result.skills) >= _MAX_SKILLS:
                if warning not in result.warnings:
                    result.warnings.append(warning)
                return
            if not _is_regular_file(skill_file):
                continue
            try:
                resolved = skill_file.resolve()
            except OSError as exc:
                result.warnings.append(f"{skill_file}: {type(exc).__name__}")
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            if resolved.name.lower() == "skill.md":
                name = resolved.parent.name
            else:
                name = resolved.stem
            result.skills.append(InventorySkill(client=client, name=name, path=str(resolved)))


def _is_regular_file(path: Path) -> bool:
    try:
        return path.is_file() and not path.is_symlink()
    except OSError:
        return False


def _is_regular_dir(path: Path) -> bool:
    try:
        return path.is_dir() and not path.is_symlink()
    except OSError:
        return False


def _client_for_extra(path: Path) -> str:
    name = path.name.lower()
    parts = {part.lower() for part in path.parts}
    if name == "claude_desktop_config.json":
        return "claude-desktop"
    if name == "config.toml" and ".codex" in parts:
        return "codex"
    if name == "mcp_config.json":
        return "windsurf"
    if name in {".mcp.json", "mcp.json"}:
        return "mcp-json"
    if path.parent.name.lower() == ".cursor":
        return "cursor"
    if path.parent.name.lower() == ".vscode":
        return "vscode"
    if path.parent.name.lower() == ".gemini":
        return "gemini-cli"
    return "mcp-json"


def _load_servers(path: Path) -> Tuple[List[InventoryServer], Optional[str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [], f"{path}: {type(exc).__name__}"
    if path.suffix.lower() == ".toml":
        mapping = _codex_mcp_servers(text)
        return [_server_record(name, body) for name, body in mapping.items()], None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], f"{path}: JSONDecodeError: {exc.msg}"
    mapping = _mcp_server_map(data)
    if mapping is None:
        return [], None
    servers: List[InventoryServer] = []
    for name, body in mapping.items():
        if isinstance(body, dict):
            servers.append(_server_record(str(name), body))
    return servers, None


def _mcp_server_map(data: object) -> Optional[dict]:
    if not isinstance(data, dict):
        return None
    for value in (data.get("mcpServers"), data.get("servers")):
        if isinstance(value, dict):
            return value
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return None


def _server_record(name: str, body: Dict[str, Any]) -> InventoryServer:
    command = str(body.get("command") or "")
    remote = any(body.get(field) for field in _REMOTE_FIELDS)
    env = body.get("env")
    has_env = bool(isinstance(env, dict) and env) or bool(body.get("envFile"))
    if remote:
        transport = "http"
    elif command:
        transport = "stdio"
    else:
        transport = "unknown"
    return InventoryServer(
        name=name,
        transport=transport,
        command=Path(command).name if command else "",
        remote=remote,
        has_env=has_env,
    )


def _codex_mcp_servers(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse Codex ``[mcp_servers.name]`` tables without a TOML library."""
    servers: Dict[str, Dict[str, Any]] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = _codex_table_name(line[1:-1].strip())
            if current is not None and current not in servers:
                servers[current] = {}
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in _REMOTE_FIELDS or key == "command":
            servers[current][key] = _unquote_toml_scalar(value.strip())
        elif key in {"envFile", "env_file"}:
            servers[current]["envFile"] = _unquote_toml_scalar(value.strip())
    return servers


def _codex_table_name(header: str) -> Optional[str]:
    prefix = "mcp_servers."
    if not header.startswith(prefix):
        return None
    return _unquote_toml_scalar(header[len(prefix) :].strip())


def _unquote_toml_scalar(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        return text[1:-1]
    return text
