"""Static scanners for MCP, skill, and agent attack surface.

The scanner is read-only. It parses Python handler files with ``ast`` and never
imports handler modules, registers tools, calls targets, or executes payloads.
MCP config scanning normalizes the common client shapes and does not connect.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from core.ai_surface.models import (
    RISK_ORDER,
    SurfaceFinding,
    SurfaceRiskLevel,
    SurfaceScanResult,
    max_risk,
)

AUTH_DECORATORS: Dict[str, Tuple[str, SurfaceRiskLevel]] = {
    "require_moderate_auth": ("moderate", SurfaceRiskLevel.MODERATE),
    "require_dangerous_auth": ("dangerous", SurfaceRiskLevel.HIGH),
    "require_critical_auth": ("critical", SurfaceRiskLevel.CRITICAL),
}

RISK_TERMS: Dict[str, SurfaceRiskLevel] = {
    "c2": SurfaceRiskLevel.CRITICAL,
    "beacon": SurfaceRiskLevel.CRITICAL,
    "credential": SurfaceRiskLevel.CRITICAL,
    "exfil": SurfaceRiskLevel.CRITICAL,
    "kerberos": SurfaceRiskLevel.CRITICAL,
    "lateral": SurfaceRiskLevel.CRITICAL,
    "persistence": SurfaceRiskLevel.CRITICAL,
    "psexec": SurfaceRiskLevel.CRITICAL,
    "spray": SurfaceRiskLevel.CRITICAL,
    "stager": SurfaceRiskLevel.CRITICAL,
    "webshell": SurfaceRiskLevel.CRITICAL,
    "winrm": SurfaceRiskLevel.CRITICAL,
    "wmi": SurfaceRiskLevel.CRITICAL,
    "amsi": SurfaceRiskLevel.HIGH,
    "attack_chain": SurfaceRiskLevel.HIGH,
    "attack_path": SurfaceRiskLevel.HIGH,
    "bypass": SurfaceRiskLevel.HIGH,
    "command": SurfaceRiskLevel.HIGH,
    "escalate": SurfaceRiskLevel.HIGH,
    "exploit": SurfaceRiskLevel.HIGH,
    "ffuf": SurfaceRiskLevel.HIGH,
    "masscan": SurfaceRiskLevel.HIGH,
    "nmap": SurfaceRiskLevel.HIGH,
    "payload": SurfaceRiskLevel.HIGH,
    "poc": SurfaceRiskLevel.HIGH,
    "shell": SurfaceRiskLevel.HIGH,
    "sqlmap": SurfaceRiskLevel.HIGH,
    "aws": SurfaceRiskLevel.MODERATE,
    "detect": SurfaceRiskLevel.MODERATE,
    "dir_scan": SurfaceRiskLevel.MODERATE,
    "dns": SurfaceRiskLevel.MODERATE,
    "enum": SurfaceRiskLevel.MODERATE,
    "fingerprint": SurfaceRiskLevel.MODERATE,
    "graphql": SurfaceRiskLevel.MODERATE,
    "jwt": SurfaceRiskLevel.MODERATE,
    "k8s": SurfaceRiskLevel.MODERATE,
    "oauth": SurfaceRiskLevel.MODERATE,
    "pentest": SurfaceRiskLevel.MODERATE,
    "recon": SurfaceRiskLevel.MODERATE,
    "redteam": SurfaceRiskLevel.MODERATE,
    "scan": SurfaceRiskLevel.MODERATE,
    "subdomain": SurfaceRiskLevel.MODERATE,
}

TARGET_PARAMS = {
    "domain",
    "endpoint",
    "host",
    "ip",
    "ports",
    "target",
    "targets",
    "url",
    "urls",
}

SKILL_RISK_TERMS: Dict[str, SurfaceRiskLevel] = {
    "credential": SurfaceRiskLevel.CRITICAL,
    "exfil": SurfaceRiskLevel.CRITICAL,
    "persistence": SurfaceRiskLevel.CRITICAL,
    "c2": SurfaceRiskLevel.CRITICAL,
    "shell": SurfaceRiskLevel.HIGH,
    "command": SurfaceRiskLevel.HIGH,
    "network": SurfaceRiskLevel.HIGH,
    "write": SurfaceRiskLevel.MODERATE,
    "delete": SurfaceRiskLevel.MODERATE,
    "token": SurfaceRiskLevel.MODERATE,
    "secret": SurfaceRiskLevel.MODERATE,
}

SAFE_RUNTIME_HELPER_CALLS = {
    "blocked_handler_runtime_response",
    "complete_handler_runtime_action",
    "complete_handler_runtime_payload",
    "gate_handler_runtime_action",
    "sanitize_runtime_inputs",
}

_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
        "wordlists",
    }
)
_GENERAL_COMMANDS = frozenset({"powershell", "pwsh", "cmd", "bash", "sh", "python", "node"})
_SECRET_ENV_TERMS = ("key", "token", "secret", "password")
_MCP_CONFIG_NAMES = frozenset({".mcp.json", "mcp.json", "claude_desktop_config.json"})
_SKIP_TEXT_NAMES = frozenset(
    {
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "package-lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "yarn.lock",
    }
)
_MAX_TEXT_BYTES = 1_048_576


def scan_handler_surface(
    path: str | Path = "handlers",
    *,
    auth_decorators: Optional[Dict[str, Tuple[str, SurfaceRiskLevel]]] = None,
    flag_missing_auth: bool = True,
    exclude_tests: bool = True,
    reconcile: Optional[bool] = None,
) -> SurfaceScanResult:
    """Scan MCP handler files for tool exposure and local risk gates.

    Args:
        path: handler 文件或目录。
        auth_decorators: 额外的 授权装饰器名 -> (level, risk) 映射，供外部项目
            注册自己的授权装饰器，避免"有授权却误报缺失"。
        flag_missing_auth: True(默认) 时对高危、无已知授权装饰器的工具报 auth-gate
            issue；False 时移除该类 issue，适合确认不采用此授权体系的外部仓库。
        exclude_tests: True(默认) 时跳过 ``tests/``、``test_*.py``、``*_test.py``
            和 ``conftest.py``，避免测试夹具被当成生产工具面。
        reconcile: 是否与本仓库 capability manifest 对账。None 时，扫描仓库根或
            ``handlers/`` 目录会自动对账；单文件和外部目录不对账。
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Surface scan path does not exist: {root}")

    catalog = dict(AUTH_DECORATORS)
    if auth_decorators:
        catalog.update(auth_decorators)

    files = _iter_python_files(root, exclude_tests=exclude_tests)
    result = SurfaceScanResult(root_path=str(root))
    for file_path in files:
        result.scanned_files += 1
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            result.warnings.append(f"{file_path}: {type(exc).__name__}: {exc}")
            continue

        visitor = _HandlerToolVisitor(
            file_path=file_path,
            auth_catalog=catalog,
            string_bindings=_collect_string_bindings(tree),
        )
        visitor.visit(tree)
        result.findings.extend(visitor.findings)

    if not flag_missing_auth:
        _relax_missing_auth_issues(result.findings)

    result.findings.sort(key=lambda item: (-RISK_ORDER[item.risk_level], item.file_path, item.line))
    if _should_reconcile(root, reconcile):
        from core.ai_surface.coverage import reconcile_capability_manifest
        from core.capability_manifest import CAPABILITIES

        reconcile_capability_manifest(result, CAPABILITIES)
    return result


def scan_skill_surface(path: str | Path) -> SurfaceScanResult:
    """Scan local agent skills or plugin prompts for risky instructions."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Skill scan path does not exist: {root}")
    files, skipped = _iter_text_files(root)
    result = SurfaceScanResult(root_path=str(root))
    result.warnings.extend(skipped)
    for file_path in files:
        result.scanned_files += 1
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.warnings.append(f"{file_path}: {type(exc).__name__}: {exc}")
            continue
        risk_terms, risk_level = _risk_terms([text], catalog=SKILL_RISK_TERMS)
        issues = []
        if risk_level == SurfaceRiskLevel.CRITICAL:
            issues.append("critical_skill_instruction_requires_review")
        elif risk_level == SurfaceRiskLevel.HIGH:
            issues.append("high_risk_skill_instruction_requires_review")
        recommendations = (
            ["Require human review before installing or enabling this skill."]
            if issues
            else ["No high-risk instruction marker found."]
        )
        result.findings.append(
            SurfaceFinding(
                tool_name=file_path.stem,
                file_path=str(file_path),
                line=1,
                risk_level=risk_level if risk_terms else SurfaceRiskLevel.LOW,
                risk_terms=risk_terms,
                issues=issues,
                recommendations=recommendations,
                description="Static skill/prompt instruction scan",
                finding_type="skill_instruction",
            )
        )
    result.findings.sort(key=lambda item: (-RISK_ORDER[item.risk_level], item.file_path, item.line))
    return result


def scan_mcp_config(path: str | Path) -> SurfaceScanResult:
    """Scan MCP JSON config for broad command exposure and env secrets.

    A directory is searched for known client filenames. ``mcpServers``,
    ``mcp.servers``, and a top-level ``servers`` object are the same inventory.
    The scan does not connect to a declared endpoint or read env values.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"MCP config path does not exist: {root}")
    result = SurfaceScanResult(root_path=str(root))
    files = _mcp_config_files(root)
    if not files:
        result.warnings.append("No MCP config file found")
        return result

    for file_path in files:
        result.scanned_files += 1
        try:
            text = file_path.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, json.JSONDecodeError) as exc:
            result.warnings.append(f"{file_path}: {type(exc).__name__}: {exc}")
            continue
        servers = _mcp_server_map(data)
        if servers is None:
            result.warnings.append(f"{file_path}: No MCP server object found")
            continue
        for name, server in servers.items():
            if isinstance(server, dict):
                result.findings.append(
                    _mcp_server_finding(
                        file_path, str(name), server, _json_key_line(text, str(name))
                    )
                )
    result.findings.sort(
        key=lambda item: (-RISK_ORDER[item.risk_level], item.file_path, item.tool_name)
    )
    return result


def _iter_python_files(root: Path, *, exclude_tests: bool = False) -> List[Path]:
    if root.is_file():
        if root.suffix.lower() != ".py":
            return []
        if exclude_tests and _is_test_path(root):
            return []
        return [root]
    files = [
        path
        for path in _walk_files(root)
        if path.suffix.lower() == ".py" and path.name != "__init__.py"
    ]
    if exclude_tests:
        files = [path for path in files if not _is_test_path(path)]
    return sorted(files)


def _is_test_path(path: Path) -> bool:
    """True for pytest modules and the tests directory."""
    if "tests" in path.parts or path.name == "conftest.py":
        return True
    return path.name.startswith("test_") or path.name.endswith("_test.py")


def _should_reconcile(root: Path, reconcile: Optional[bool]) -> bool:
    if reconcile is not None:
        return reconcile
    if root.is_file():
        return False
    if root.name == "handlers" and (root.parent / "core" / "capability_manifest.py").is_file():
        return True
    return (root / "core" / "capability_manifest.py").is_file() and (root / "handlers").is_dir()


def _iter_text_files(root: Path) -> Tuple[List[Path], List[str]]:
    suffixes = {".md", ".txt", ".yaml", ".yml", ".json", ".toml"}
    if root.is_file():
        return ([root] if root.suffix.lower() in suffixes else []), []
    files: List[Path] = []
    skipped: List[str] = []
    for path in _walk_files(root):
        if path.suffix.lower() not in suffixes or path.name.lower() in _SKIP_TEXT_NAMES:
            continue
        try:
            if path.stat().st_size > _MAX_TEXT_BYTES:
                skipped.append(f"{path}: skipped file larger than {_MAX_TEXT_BYTES} bytes")
                continue
        except OSError as exc:
            skipped.append(f"{path}: {type(exc).__name__}: {exc}")
            continue
        files.append(path)
    return sorted(files), skipped


def _walk_files(root: Path) -> Iterable[Path]:
    """Yield files without descending into dependency, VCS, or wordlist directories."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name not in _SKIP_DIR_NAMES:
                    stack.append(child)
                continue
            if child.is_file():
                yield child


def _mcp_config_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    return sorted(path for path in _walk_files(root) if path.name in _MCP_CONFIG_NAMES)


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


def _json_key_line(text: str, key: str) -> int:
    """Return the line of a JSON object key. The raw endpoint value is not used."""
    needle = json.dumps(key, ensure_ascii=False)
    start = 0
    while True:
        found = text.find(needle, start)
        if found < 0:
            return 1
        cursor = found + len(needle)
        while cursor < len(text) and text[cursor] in " \t\r\n":
            cursor += 1
        if cursor < len(text) and text[cursor] == ":":
            return text.count("\n", 0, found) + 1
        start = found + 1


def _mcp_server_finding(file_path: Path, name: str, server: dict, line: int) -> SurfaceFinding:
    command = str(server.get("command", ""))
    args = [str(item) for item in server.get("args", []) if item is not None]
    env = server.get("env", {})
    remote = any(server.get(field) for field in ("url", "serverUrl", "baseUrl"))
    risk_terms, risk_level = _risk_terms([command, " ".join(args)])
    issues: List[str] = []
    if command.lower() in _GENERAL_COMMANDS:
        risk_level = max_risk(risk_level, SurfaceRiskLevel.HIGH)
        issues.append("mcp_server_uses_general_command_runtime")
    if remote:
        risk_level = max_risk(risk_level, SurfaceRiskLevel.MODERATE)
        issues.append("mcp_server_declares_remote_endpoint")
    if isinstance(env, dict) and any(_env_key_is_secret(str(key)) for key in env):
        risk_level = max_risk(risk_level, SurfaceRiskLevel.MODERATE)
        issues.append("mcp_server_env_contains_secret_like_keys")
    if risk_level == SurfaceRiskLevel.INFO:
        risk_level = SurfaceRiskLevel.LOW
    description = (
        f"MCP server command: {command}" if command else "MCP server declares a remote endpoint"
    )
    return SurfaceFinding(
        tool_name=name,
        file_path=str(file_path),
        line=line,
        risk_level=risk_level,
        risk_terms=risk_terms,
        issues=issues,
        recommendations=_mcp_config_recommendations(issues),
        description=description,
        finding_type="mcp_config",
    )


def _env_key_is_secret(key: str) -> bool:
    haystack = key.lower().replace("-", "_")
    return any(_contains_term(haystack, term) for term in _SECRET_ENV_TERMS)


class _HandlerToolVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, auth_catalog=None, string_bindings=None):
        self.file_path = file_path
        self.auth_catalog = auth_catalog or AUTH_DECORATORS
        self.string_bindings = string_bindings or {}
        self.findings: List[SurfaceFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        kind = _surface_kind(node.decorator_list)
        if kind is not None:
            self.findings.append(self._build_finding(node, kind))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # low-level MCP SDK: 工具通过 Tool(name=..., description=..., inputSchema=...) 声明
        if _is_tool_constructor(node.func):
            finding = self._build_lowlevel_finding(node)
            if finding is not None:
                self.findings.append(finding)
        elif _is_detector_config(node.func):
            finding = self._build_factory_finding(node)
            if finding is not None:
                self.findings.append(finding)
        self.generic_visit(node)

    def _build_finding(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, kind: str
    ) -> SurfaceFinding:
        decorators = [_decorator_name(item) for item in node.decorator_list]
        parameters = _parameter_names(node)
        annotations = _parameter_annotations(node)
        called_names = sorted(_risk_relevant_called_names(_called_names(node)))
        doc = ast.get_docstring(node) or ""
        docstring = doc.strip().splitlines()[0] if doc.strip() else ""
        # Source registration can publish description= without putting that text
        # in the docstring. The haystack keeps both so a keyword cannot hide a term.
        declared_description = _decorator_keyword(
            node.decorator_list, kind, "description", self.string_bindings
        )
        shown = declared_description.strip() or docstring
        description = shown.splitlines()[0] if shown else ""
        auth_level, auth_risk = _auth_level(decorators, self.auth_catalog)
        risk_terms, term_risk = _risk_terms(
            [node.name, declared_description, docstring, " ".join(called_names)]
        )
        target_params = _target_params_needing_validation(parameters, annotations)

        risk_level = max_risk(auth_risk, term_risk)
        if target_params:
            risk_level = max_risk(risk_level, SurfaceRiskLevel.MODERATE)
        risk_level = _downgrade_read_only_risk(node.name, risk_level, risk_terms, target_params)
        if risk_level == SurfaceRiskLevel.INFO and description:
            risk_level = SurfaceRiskLevel.LOW

        declared_name = _decorator_keyword(node.decorator_list, kind, "name", self.string_bindings)
        tool_name = declared_name or node.name
        # prompt/resource 不用 @tool 的授权装饰器模型，授权以 manifest 为准。
        if kind == "tool":
            issues = _issues(risk_level, auth_level, decorators, target_params, risk_terms)
            recommendations = _recommendations(risk_level, auth_level, target_params, issues)
        else:
            issues = []
            recommendations = [
                "Prompt and resource authorization is declared in the capability manifest."
            ]
        finding = SurfaceFinding(
            tool_name=tool_name,
            file_path=str(self.file_path),
            line=node.lineno,
            risk_level=risk_level,
            auth_level=auth_level,
            decorators=decorators,
            parameters=parameters,
            risk_terms=risk_terms,
            issues=issues,
            recommendations=recommendations,
            description=description,
            finding_type={"tool": "mcp_tool", "prompt": "mcp_prompt", "resource": "mcp_resource"}[
                kind
            ],
            kind=kind,
        )
        finding.rule_id = _surface_rule_id(finding)
        return finding

    def _build_lowlevel_finding(self, node: ast.Call) -> Optional[SurfaceFinding]:
        keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        if "name" not in keywords:
            return None
        tool_name = _resolve_str(keywords["name"], self.string_bindings) or f"tool@{node.lineno}"
        description = _resolve_str(keywords.get("description"), self.string_bindings)
        parameters = _input_schema_params(keywords.get("inputSchema"))
        risk_terms, term_risk = _risk_terms([tool_name, description, " ".join(parameters)])
        target_params = [p for p in parameters if p.lower() in TARGET_PARAMS]

        risk_level = term_risk
        if target_params:
            risk_level = max_risk(risk_level, SurfaceRiskLevel.MODERATE)
        risk_level = _downgrade_read_only_risk(tool_name, risk_level, risk_terms, target_params)
        if risk_level == SurfaceRiskLevel.INFO and description:
            risk_level = SurfaceRiskLevel.LOW

        issues = _issues(risk_level, "none", [], target_params, risk_terms)
        recommendations = _recommendations(risk_level, "none", target_params, issues)
        finding = SurfaceFinding(
            tool_name=tool_name,
            file_path=str(self.file_path),
            line=node.lineno,
            risk_level=risk_level,
            auth_level="none",
            decorators=[],
            parameters=parameters,
            risk_terms=risk_terms,
            issues=issues,
            recommendations=recommendations,
            description=description.strip().splitlines()[0] if description.strip() else "",
            finding_type="mcp_tool_lowlevel",
            kind="tool",
        )
        finding.rule_id = _surface_rule_id(finding)
        return finding

    def _build_factory_finding(self, node: ast.Call) -> Optional[SurfaceFinding]:
        """detector_factory.DetectorConfig(name=...) 动态生成的工具，函数体不可见。"""
        tool_name = _call_string_arg(node, 0, "name", self.string_bindings)
        if not tool_name:
            return None
        description = _call_string_arg(node, 2, "description", self.string_bindings)
        description = description.strip().splitlines()[0] if description.strip() else ""
        risk_terms, term_risk = _risk_terms([tool_name, description])
        risk_level = term_risk if term_risk != SurfaceRiskLevel.INFO else SurfaceRiskLevel.LOW
        finding = SurfaceFinding(
            tool_name=tool_name,
            file_path=str(self.file_path),
            line=node.lineno,
            risk_level=risk_level,
            parameters=["url", "params"],
            risk_terms=risk_terms,
            recommendations=[
                "Registered by detector_factory. Auth and input validation are applied in "
                "create_detector_tool, not as a visible function decorator."
            ],
            description=description or "Detector factory tool",
            finding_type="mcp_tool_factory",
            kind="tool",
        )
        finding.rule_id = _surface_rule_id(finding)
        return finding


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _dotted_name(node.func) or ""
    return _dotted_name(node) or ""


def _dotted_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _surface_kind(decorators: Sequence[ast.expr]) -> Optional[str]:
    """Return tool, prompt, or resource when a function registers an MCP surface."""
    found: Optional[str] = None
    for decorator in decorators:
        short = _decorator_name(decorator).rsplit(".", 1)[-1]
        if short == "tool":
            return "tool"
        if short in {"prompt", "resource"}:
            found = short
    return found


def _decorator_keyword(
    decorators: Sequence[ast.expr], kind: str, key: str, bindings: Dict[str, str]
) -> str:
    for decorator in decorators:
        if not isinstance(decorator, ast.Call):
            continue
        if _decorator_name(decorator).rsplit(".", 1)[-1] != kind:
            continue
        for keyword in decorator.keywords:
            if keyword.arg == key:
                return _resolve_str(keyword.value, bindings)
    return ""


def _is_tool_constructor(func: ast.AST) -> bool:
    """识别 low-level MCP SDK 的 Tool(...) 构造 (mcp.types.Tool)。"""
    name = _dotted_name(func) or ""
    return name == "Tool" or name.endswith(".Tool")


def _is_detector_config(func: ast.AST) -> bool:
    name = _dotted_name(func) or ""
    return name == "DetectorConfig" or name.endswith(".DetectorConfig")


def _call_string_arg(node: ast.Call, index: int, keyword: str, bindings: Dict[str, str]) -> str:
    for item in node.keywords:
        if item.arg == keyword:
            return _resolve_str(item.value, bindings)
    if index < len(node.args):
        return _resolve_str(node.args[index], bindings)
    return ""


def _surface_rule_id(finding: SurfaceFinding) -> str:
    """Stable SARIF rule ids so Code Scanning can group by risk class."""
    issues = set(finding.issues)
    if "critical_tool_without_critical_auth" in issues:
        return "mcp_tool.auth-critical"
    if "high_risk_tool_without_dangerous_auth" in issues or (
        "payload_generation_without_auth_gate" in issues
    ):
        return "mcp_tool.auth-missing"
    if "declared_effects_omit_target_contact" in issues:
        return "mcp_tool.effect-mismatch"
    if "target_input_without_handler_validator" in issues:
        return "mcp_tool.target-input"
    if finding.kind == "prompt":
        return "mcp_prompt"
    if finding.kind == "resource":
        return "mcp_resource"
    if finding.finding_type == "mcp_tool_factory":
        return "mcp_tool.factory"
    if finding.finding_type == "mcp_tool_lowlevel":
        return "mcp_tool.lowlevel"
    if finding.risk_level in {SurfaceRiskLevel.HIGH, SurfaceRiskLevel.CRITICAL}:
        return "mcp_tool.high-risk"
    if finding.parameters and any(name.lower() in TARGET_PARAMS for name in finding.parameters):
        return "mcp_tool.network"
    if finding.finding_type == "skill_instruction":
        return "skill_instruction"
    if finding.finding_type == "mcp_config":
        return "mcp_config"
    return "mcp_tool"


def _collect_string_bindings(tree: ast.AST) -> Dict[str, str]:
    """收集 module 内 `X = "..."` 与 `self.X = "..."` 字符串绑定。

    用于解析 `Tool(name=self.name, ...)` 这类工具名来自类属性/常量的写法。
    """
    bindings: Dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
            continue
        for target in node.targets:
            key = None
            if isinstance(target, ast.Name):
                key = target.id
            elif isinstance(target, ast.Attribute):
                key = target.attr
            if key and key not in bindings:
                bindings[key] = node.value.value
    return bindings


def _resolve_str(node: Optional[ast.AST], bindings: Dict[str, str]) -> str:
    """尽力把 AST 节点解析为字符串：常量、名字/属性引用、或 f-string 常量片段。"""
    if node is None:
        return ""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return bindings.get(node.id, "")
    if isinstance(node, ast.Attribute):
        return bindings.get(node.attr, "")
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                inner = _resolve_str(value.value, bindings)
                if inner:
                    parts.append(inner)
        return " ".join(parts)
    return ""


def _input_schema_params(node: Optional[ast.AST]) -> List[str]:
    """从 inputSchema dict 字面量的 properties 提取参数名。"""
    if not isinstance(node, ast.Dict):
        return []
    for key, value in zip(node.keys, node.values):
        if (
            isinstance(key, ast.Constant)
            and key.value == "properties"
            and isinstance(value, ast.Dict)
        ):
            return [
                prop.value
                for prop in value.keys
                if isinstance(prop, ast.Constant) and isinstance(prop.value, str)
            ]
    return []


def _parameter_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    args = list(node.args.args) + list(node.args.kwonlyargs)
    names = [arg.arg for arg in args]
    if node.args.vararg:
        names.append(node.args.vararg.arg)
    if node.args.kwarg:
        names.append(node.args.kwarg.arg)
    return names


def _parameter_annotations(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Dict[str, str]:
    annotations: Dict[str, str] = {}
    args = list(node.args.args) + list(node.args.kwonlyargs)
    for arg in args:
        if arg.annotation is None:
            annotations[arg.arg] = ""
        else:
            annotations[arg.arg] = ast.unparse(arg.annotation).lower()
    if node.args.vararg:
        annotations[node.args.vararg.arg] = ""
    if node.args.kwarg:
        annotations[node.args.kwarg.arg] = ""
    return annotations


def _called_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterable[str]:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _dotted_name(child.func)
            if name:
                yield name


def _risk_relevant_called_names(called_names: Iterable[str]) -> Iterable[str]:
    """Filter observability helper calls before risk term matching."""
    for name in called_names:
        short_name = name.rsplit(".", 1)[-1]
        if short_name in SAFE_RUNTIME_HELPER_CALLS:
            continue
        yield name


def _auth_level(
    decorators: List[str],
    catalog: Optional[Dict[str, Tuple[str, SurfaceRiskLevel]]] = None,
) -> Tuple[str, SurfaceRiskLevel]:
    catalog = catalog or AUTH_DECORATORS
    level = "none"
    risk = SurfaceRiskLevel.INFO
    for decorator in decorators:
        name = decorator.rsplit(".", 1)[-1]
        if name in catalog:
            auth_level, auth_risk = catalog[name]
            if RISK_ORDER[auth_risk] > RISK_ORDER[risk]:
                level = auth_level
                risk = auth_risk
    return level, risk


def _contains_term(haystack: str, term: str) -> bool:
    """Match a risk term on identifier boundaries.

    ``scan`` matches ``port_scan`` and ``scan-host``. It does not match
    ``scanner`` or ``epoch``. ``_`` and ``-`` are boundaries; the haystack
    already normalizes ``-`` to ``_``.
    """
    start = 0
    while True:
        index = haystack.find(term, start)
        if index < 0:
            return False
        end = index + len(term)
        before_ok = index == 0 or not haystack[index - 1].isalnum()
        after_ok = end == len(haystack) or not haystack[end].isalnum()
        if before_ok and after_ok:
            return True
        start = index + 1


def _risk_terms(
    chunks: List[str], catalog: Optional[Dict[str, SurfaceRiskLevel]] = None
) -> Tuple[List[str], SurfaceRiskLevel]:
    haystack = " ".join(chunks).lower().replace("-", "_")
    terms: List[str] = []
    risk = SurfaceRiskLevel.INFO
    for term, term_risk in (catalog or RISK_TERMS).items():
        if _contains_term(haystack, term):
            terms.append(term)
            risk = max_risk(risk, term_risk)
    return terms, risk


def _mcp_config_recommendations(issues: List[str]) -> List[str]:
    recommendations: List[str] = []
    if "mcp_server_uses_general_command_runtime" in issues:
        recommendations.append("Prefer a narrow wrapper command with fixed arguments.")
    if "mcp_server_env_contains_secret_like_keys" in issues:
        recommendations.append("Use secret manager references and redact env from logs.")
    if "mcp_server_declares_remote_endpoint" in issues:
        recommendations.append(
            "Review the remote endpoint and its authentication before enabling it."
        )
    if not recommendations:
        recommendations.append("Review server command and env before enabling.")
    return recommendations


def _target_params_needing_validation(
    parameters: List[str], annotations: Dict[str, str]
) -> List[str]:
    target_params: List[str] = []
    for parameter in parameters:
        name = parameter.lower()
        if name not in TARGET_PARAMS:
            continue
        annotation = annotations.get(parameter, "")
        if "dict" in annotation:
            continue
        target_params.append(parameter)
    return target_params


def _downgrade_read_only_risk(
    tool_name: str,
    risk_level: SurfaceRiskLevel,
    risk_terms: List[str],
    target_params: List[str],
) -> SurfaceRiskLevel:
    if target_params or RISK_ORDER[risk_level] < RISK_ORDER[SurfaceRiskLevel.HIGH]:
        return risk_level
    name = tool_name.lower()
    read_only = any(token in name for token in ("list", "search", "stats", "status", "query"))
    active = any(token in name for token in ("execute", "exploit", "generate", "spray", "start"))
    if read_only and not active and set(risk_terms).issubset({"poc"}):
        return SurfaceRiskLevel.LOW
    return risk_level


def _issues(
    risk_level: SurfaceRiskLevel,
    auth_level: str,
    decorators: List[str],
    target_params: List[str],
    risk_terms: List[str],
) -> List[str]:
    issues: List[str] = []
    auth_rank = {
        "none": SurfaceRiskLevel.INFO,
        "moderate": SurfaceRiskLevel.MODERATE,
        "dangerous": SurfaceRiskLevel.HIGH,
        "critical": SurfaceRiskLevel.CRITICAL,
    }[auth_level]
    if (
        RISK_ORDER[risk_level] >= RISK_ORDER[SurfaceRiskLevel.HIGH]
        and RISK_ORDER[auth_rank] < RISK_ORDER[SurfaceRiskLevel.HIGH]
    ):
        issues.append("high_risk_tool_without_dangerous_auth")
    if risk_level == SurfaceRiskLevel.CRITICAL and auth_level != "critical":
        issues.append("critical_tool_without_critical_auth")
    if target_params and not any(name.endswith("validate_inputs") for name in decorators):
        issues.append("target_input_without_handler_validator")
    if "payload" in risk_terms and auth_level == "none":
        issues.append("payload_generation_without_auth_gate")
    return issues


def _recommendations(
    risk_level: SurfaceRiskLevel,
    auth_level: str,
    target_params: List[str],
    issues: List[str],
) -> List[str]:
    recommendations: List[str] = []
    if "critical_tool_without_critical_auth" in issues:
        recommendations.append("Enforce a critical-level authorization gate, or keep it plan-only.")
    elif "high_risk_tool_without_dangerous_auth" in issues:
        recommendations.append(
            "Enforce a strong authorization gate for this high-risk tool, or document why it is safe."
        )
    if "target_input_without_handler_validator" in issues:
        recommendations.append("Validate target/url-like parameters before use.")
    if RISK_ORDER[risk_level] >= RISK_ORDER[SurfaceRiskLevel.HIGH]:
        recommendations.append("Require human approval before any active execution path.")
    if target_params:
        recommendations.append("Apply scope policy, rate limits, and audit logging.")
    if auth_level == "none" and not recommendations:
        recommendations.append("Keep as local/static, or document the execution boundary.")
    return recommendations


_MISSING_AUTH_ISSUES = frozenset(
    {
        "high_risk_tool_without_dangerous_auth",
        "critical_tool_without_critical_auth",
        "payload_generation_without_auth_gate",
    }
)


def _relax_missing_auth_issues(findings: List[SurfaceFinding]) -> None:
    """移除 auth-gate 类 issue，用于确认不采用本授权体系的外部仓库。

    仅去掉"缺少已知授权装饰器"这类本项目特化的判定；risk_level、target 参数
    校验以及其他基于代码结构的发现保持不变。
    """
    for finding in findings:
        if not _MISSING_AUTH_ISSUES.intersection(finding.issues):
            continue
        finding.issues = [issue for issue in finding.issues if issue not in _MISSING_AUTH_ISSUES]
        finding.recommendations = [
            rec for rec in finding.recommendations if "authorization gate" not in rec.lower()
        ]
