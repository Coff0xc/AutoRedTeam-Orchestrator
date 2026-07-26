"""Static scanners for MCP, skill, and agent attack surface.

The scanner is read-only. It parses Python handler files with ``ast`` and never
imports handler modules, registers tools, calls targets, or executes payloads.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

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


def scan_handler_surface(
    path: str | Path = "handlers",
    *,
    auth_decorators: Optional[Dict[str, Tuple[str, SurfaceRiskLevel]]] = None,
    flag_missing_auth: bool = True,
) -> SurfaceScanResult:
    """Scan MCP handler files for tool exposure and local risk gates.

    Args:
        path: handler 文件或目录。
        auth_decorators: 额外的 授权装饰器名 -> (level, risk) 映射，供外部项目
            注册自己的授权装饰器，避免"有授权却误报缺失"。
        flag_missing_auth: True(默认) 时对高危、无已知授权装饰器的工具报 auth-gate
            issue；False 时移除该类 issue，适合确认不采用此授权体系的外部仓库。
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Surface scan path does not exist: {root}")

    catalog = dict(AUTH_DECORATORS)
    if auth_decorators:
        catalog.update(auth_decorators)

    files = _iter_python_files(root)
    result = SurfaceScanResult(root_path=str(root))
    for file_path in files:
        result.scanned_files += 1
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            result.warnings.append(f"{file_path}: {type(exc).__name__}: {exc}")
            continue

        bindings = _collect_string_bindings(tree)
        visitor = _HandlerToolVisitor(
            file_path=file_path,
            source=source,
            auth_catalog=catalog,
            string_bindings=bindings,
        )
        visitor.visit(tree)
        result.findings.extend(visitor.findings)

    if not flag_missing_auth:
        _relax_missing_auth_issues(result.findings)

    result.findings.sort(key=lambda item: (-RISK_ORDER[item.risk_level], item.file_path, item.line))
    return result


def scan_skill_surface(path: str | Path) -> SurfaceScanResult:
    """Scan local agent skills or plugin prompts for risky instructions."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Skill scan path does not exist: {root}")
    files = _iter_text_files(root)
    result = SurfaceScanResult(root_path=str(root))
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
    """Scan MCP JSON config for broad command exposure and env secrets."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"MCP config path does not exist: {root}")
    result = SurfaceScanResult(root_path=str(root), scanned_files=1)
    try:
        data = json.loads(root.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result.warnings.append(f"{root}: {type(exc).__name__}: {exc}")
        return result

    servers = data.get("mcpServers") if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        result.warnings.append("No mcpServers object found")
        return result

    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        command = str(server.get("command", ""))
        args = [str(item) for item in server.get("args", []) if item is not None]
        env = server.get("env", {})
        risk_terms, risk_level = _risk_terms([command, " ".join(args)])
        issues = []
        if command.lower() in {"powershell", "pwsh", "cmd", "bash", "sh", "python", "node"}:
            risk_level = max_risk(risk_level, SurfaceRiskLevel.HIGH)
            issues.append("mcp_server_uses_general_command_runtime")
        if isinstance(env, dict):
            secret_keys = [
                key
                for key in env
                if any(token in key.lower() for token in ("key", "token", "secret", "password"))
            ]
            if secret_keys:
                risk_level = max_risk(risk_level, SurfaceRiskLevel.MODERATE)
                issues.append("mcp_server_env_contains_secret_like_keys")
        result.findings.append(
            SurfaceFinding(
                tool_name=str(name),
                file_path=str(root),
                line=1,
                risk_level=(
                    risk_level if risk_level != SurfaceRiskLevel.INFO else SurfaceRiskLevel.LOW
                ),
                risk_terms=risk_terms,
                issues=issues,
                recommendations=_mcp_config_recommendations(issues),
                description=f"MCP server command: {command}",
                finding_type="mcp_config",
            )
        )
    result.findings.sort(
        key=lambda item: (-RISK_ORDER[item.risk_level], item.file_path, item.tool_name)
    )
    return result


def _iter_python_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    return sorted(
        path
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts and path.name != "__init__.py"
    )


def _iter_text_files(root: Path) -> List[Path]:
    suffixes = {".md", ".txt", ".yaml", ".yml", ".json", ".toml"}
    if root.is_file():
        return [root] if root.suffix.lower() in suffixes else []
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in suffixes and "__pycache__" not in path.parts
    )


class _HandlerToolVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source: str, auth_catalog=None, string_bindings=None):
        self.file_path = file_path
        self.source = source
        self.auth_catalog = auth_catalog or AUTH_DECORATORS
        self.string_bindings = string_bindings or {}
        self.findings: List[SurfaceFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        decorators = [_decorator_name(item) for item in node.decorator_list]
        if any(_is_tool_decorator(name) for name in decorators):
            self.findings.append(self._build_finding(node, decorators))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # low-level MCP SDK: 工具通过 Tool(name=..., description=..., inputSchema=...) 声明
        if _is_tool_constructor(node.func):
            finding = self._build_lowlevel_finding(node)
            if finding is not None:
                self.findings.append(finding)
        self.generic_visit(node)

    def _build_finding(self, node: ast.AsyncFunctionDef, decorators: List[str]) -> SurfaceFinding:
        parameters = _parameter_names(node)
        annotations = _parameter_annotations(node)
        called_names = sorted(_risk_relevant_called_names(_called_names(node)))
        doc = ast.get_docstring(node) or ""
        description = doc.strip().splitlines()[0] if doc.strip() else ""
        auth_level, auth_risk = _auth_level(decorators, self.auth_catalog)
        risk_terms, term_risk = _risk_terms([node.name, description, " ".join(called_names)])
        target_params = _target_params_needing_validation(parameters, annotations)

        risk_level = max_risk(auth_risk, term_risk)
        if target_params:
            risk_level = max_risk(risk_level, SurfaceRiskLevel.MODERATE)
        risk_level = _downgrade_read_only_risk(node.name, risk_level, risk_terms, target_params)
        if risk_level == SurfaceRiskLevel.INFO and description:
            risk_level = SurfaceRiskLevel.LOW

        issues = _issues(risk_level, auth_level, decorators, target_params, risk_terms)
        recommendations = _recommendations(risk_level, auth_level, target_params, issues)
        return SurfaceFinding(
            tool_name=node.name,
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
        )

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
        return SurfaceFinding(
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
        )


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


def _is_tool_decorator(name: str) -> bool:
    return name == "tool" or name.endswith(".tool")


def _is_tool_constructor(func: ast.AST) -> bool:
    """识别 low-level MCP SDK 的 Tool(...) 构造 (mcp.types.Tool)。"""
    name = _dotted_name(func) or ""
    return name == "Tool" or name.endswith(".Tool")


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


def _parameter_names(node: ast.AsyncFunctionDef) -> List[str]:
    args = list(node.args.args) + list(node.args.kwonlyargs)
    names = [arg.arg for arg in args]
    if node.args.vararg:
        names.append(node.args.vararg.arg)
    if node.args.kwarg:
        names.append(node.args.kwarg.arg)
    return names


def _parameter_annotations(node: ast.AsyncFunctionDef) -> Dict[str, str]:
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


def _called_names(node: ast.AsyncFunctionDef) -> Iterable[str]:
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


def _risk_terms(
    chunks: List[str], catalog: Optional[Dict[str, SurfaceRiskLevel]] = None
) -> Tuple[List[str], SurfaceRiskLevel]:
    haystack = " ".join(chunks).lower().replace("-", "_")
    terms: List[str] = []
    risk = SurfaceRiskLevel.INFO
    for term, term_risk in (catalog or RISK_TERMS).items():
        if term in haystack:
            terms.append(term)
            risk = max_risk(risk, term_risk)
    return terms, risk


def _mcp_config_recommendations(issues: List[str]) -> List[str]:
    recommendations: List[str] = []
    if "mcp_server_uses_general_command_runtime" in issues:
        recommendations.append("Prefer a narrow wrapper command with fixed arguments.")
    if "mcp_server_env_contains_secret_like_keys" in issues:
        recommendations.append("Use secret manager references and redact env from logs.")
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
