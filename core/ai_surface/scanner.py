"""Static scanners for MCP handler attack surface.

The scanner is read-only. It parses Python handler files with ``ast`` and never
imports handler modules, registers tools, calls targets, or executes payloads.
"""

from __future__ import annotations

import ast
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


def scan_handler_surface(path: str | Path = "handlers") -> SurfaceScanResult:
    """Scan MCP handler files for tool exposure and local risk gates."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Surface scan path does not exist: {root}")

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

        visitor = _HandlerToolVisitor(file_path=file_path, source=source)
        visitor.visit(tree)
        result.findings.extend(visitor.findings)

    result.findings.sort(
        key=lambda item: (-RISK_ORDER[item.risk_level], item.file_path, item.line)
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


class _HandlerToolVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source: str):
        self.file_path = file_path
        self.source = source
        self.findings: List[SurfaceFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        decorators = [_decorator_name(item) for item in node.decorator_list]
        if any(_is_tool_decorator(name) for name in decorators):
            self.findings.append(self._build_finding(node, decorators))
        self.generic_visit(node)

    def _build_finding(
        self, node: ast.AsyncFunctionDef, decorators: List[str]
    ) -> SurfaceFinding:
        parameters = _parameter_names(node)
        annotations = _parameter_annotations(node)
        called_names = sorted(_called_names(node))
        doc = ast.get_docstring(node) or ""
        description = doc.strip().splitlines()[0] if doc.strip() else ""
        auth_level, auth_risk = _auth_level(decorators)
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


def _auth_level(decorators: List[str]) -> Tuple[str, SurfaceRiskLevel]:
    level = "none"
    risk = SurfaceRiskLevel.INFO
    for decorator in decorators:
        name = decorator.rsplit(".", 1)[-1]
        if name in AUTH_DECORATORS:
            auth_level, auth_risk = AUTH_DECORATORS[name]
            if RISK_ORDER[auth_risk] > RISK_ORDER[risk]:
                level = auth_level
                risk = auth_risk
    return level, risk


def _risk_terms(chunks: List[str]) -> Tuple[List[str], SurfaceRiskLevel]:
    haystack = " ".join(chunks).lower().replace("-", "_")
    terms: List[str] = []
    risk = SurfaceRiskLevel.INFO
    for term, term_risk in RISK_TERMS.items():
        if term in haystack:
            terms.append(term)
            risk = max_risk(risk, term_risk)
    return terms, risk


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
    if RISK_ORDER[risk_level] >= RISK_ORDER[SurfaceRiskLevel.HIGH] and RISK_ORDER[
        auth_rank
    ] < RISK_ORDER[SurfaceRiskLevel.HIGH]:
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
        recommendations.append("Wrap with require_critical_auth or keep it plan-only.")
    elif "high_risk_tool_without_dangerous_auth" in issues:
        recommendations.append("Wrap with require_dangerous_auth or document why it is safe.")
    if "target_input_without_handler_validator" in issues:
        recommendations.append("Add validate_inputs for target/url-like parameters.")
    if RISK_ORDER[risk_level] >= RISK_ORDER[SurfaceRiskLevel.HIGH]:
        recommendations.append("Require HumanGate before any active execution path.")
    if target_params:
        recommendations.append("Apply scope policy, rate limits, and audit logging.")
    if auth_level == "none" and not recommendations:
        recommendations.append("Keep as local/static or document execution boundary.")
    return recommendations
