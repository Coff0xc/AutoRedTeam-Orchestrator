"""Read-only Python call-chain context expansion.

The implementation is original and intentionally small: it uses ``ast`` to map
local functions, resolve simple intra-project calls, expand callers/callees
around a seed, and score how security-relevant the context appears.
"""

from __future__ import annotations

import ast
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from core.code_agent.models import CallEdge, CodeContextResult, CodeFunction, ConfidenceScore


RISKY_CALL_TERMS = {
    "eval",
    "exec",
    "compile",
    "pickle.load",
    "pickle.loads",
    "yaml.load",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.run",
    "os.popen",
    "os.spawn",
    "os.system",
    "requests.delete",
    "requests.get",
    "requests.patch",
    "requests.post",
    "requests.put",
    "aiohttp.ClientSession",
}

SOURCE_TERMS = {
    "body",
    "command",
    "context",
    "data",
    "endpoint",
    "file",
    "headers",
    "host",
    "input",
    "payload",
    "query",
    "request",
    "target",
    "url",
}

GATE_TERMS = {
    "require_critical_auth",
    "require_dangerous_auth",
    "require_moderate_auth",
    "validate_inputs",
}


def expand_code_context(
    path: str | Path,
    seed: Optional[str] = None,
    file_path: Optional[str | Path] = None,
    line: Optional[int] = None,
    max_depth: int = 2,
) -> CodeContextResult:
    """Expand caller/callee context around a local Python function.

    Args:
        path: Python file or directory to scan.
        seed: Function id, qualified name, or simple function name.
        file_path: Optional file containing the seed.
        line: Optional line inside the seed function.
        max_depth: Caller/callee expansion depth.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"Code analysis path does not exist: {root}")
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")

    functions, warnings = _collect_functions(root)
    edges = _resolve_edges(functions)
    result = CodeContextResult(
        root_path=str(root),
        seed_function=None,
        max_depth=max_depth,
        functions_scanned=len(functions),
        edges_scanned=len(edges),
        warnings=warnings,
    )
    if not functions:
        result.warnings.append("No Python functions found")
        return result

    seed_function = _select_seed(functions, seed=seed, file_path=file_path, line=line)
    if seed_function is None:
        result.warnings.append("Seed function not found; selected highest-risk local function")
        seed_function = _highest_risk_function(functions, edges)

    context_ids = _expand_ids(seed_function.function_id, edges, max_depth=max_depth)
    context_functions = sorted(
        (function for function in functions.values() if function.function_id in context_ids),
        key=lambda item: (item.file_path, item.line_start, item.qualified_name),
    )
    context_edges = sorted(
        (
            edge
            for edge in edges
            if edge.caller_id in context_ids and edge.callee_id in context_ids
        ),
        key=lambda item: (item.file_path, item.line, item.call_name),
    )

    result.seed_function = seed_function
    result.context_functions = context_functions
    result.call_edges = context_edges
    result.confidence = _score_context(seed_function, context_functions, context_edges, edges)
    return result


def _collect_functions(root: Path) -> Tuple[Dict[str, CodeFunction], List[str]]:
    functions: Dict[str, CodeFunction] = {}
    warnings: List[str] = []
    for file in _iter_python_files(root):
        try:
            source = file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            warnings.append(f"{file}: {type(exc).__name__}: {exc}")
            continue
        visitor = _FunctionVisitor(file_path=file, module_name=_module_name(root, file))
        visitor.visit(tree)
        for function in visitor.functions:
            functions[function.function_id] = function
    return functions, warnings


def _iter_python_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    return sorted(
        path
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts and path.name != "__init__.py"
    )


def _module_name(root: Path, file: Path) -> str:
    if root.is_file():
        rel = file.name
    else:
        rel = str(file.relative_to(root))
    return rel.replace("\\", "/").removesuffix(".py").replace("/", ".")


class _FunctionVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, module_name: str):
        self.file_path = file_path
        self.module_name = module_name
        self.class_stack: List[str] = []
        self.functions: List[CodeFunction] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join([self.module_name, *self.class_stack, node.name])
        calls = _collect_calls(node)
        decorators = [_call_name(item) for item in node.decorator_list]
        parameters = [arg.arg for arg in node.args.args + node.args.kwonlyargs]
        risk_terms = sorted(
            {
                term
                for call in calls
                for term in RISKY_CALL_TERMS
                if call == term or call.endswith(f".{term}") or term.endswith(f".{call}")
            }
        )
        source_terms = sorted(
            {
                param
                for param in parameters
                if any(term in param.lower() for term in SOURCE_TERMS)
            }
        )
        self.functions.append(
            CodeFunction(
                function_id=f"{self.file_path}:{node.lineno}:{qualified}",
                qualified_name=qualified,
                file_path=str(self.file_path),
                line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                parameters=parameters,
                decorators=decorators,
                calls=sorted(set(calls)),
                risk_terms=risk_terms,
                source_terms=source_terms,
            )
        )
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)


def _collect_calls(node: ast.AST) -> List[str]:
    calls: List[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _call_name(child.func)
            if name:
                calls.append(name)
    return calls


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _resolve_edges(functions: Dict[str, CodeFunction]) -> List[CallEdge]:
    simple_index: Dict[str, List[CodeFunction]] = defaultdict(list)
    qual_index: Dict[str, CodeFunction] = {}
    for function in functions.values():
        simple_index[function.qualified_name.rsplit(".", 1)[-1]].append(function)
        qual_index[function.qualified_name] = function

    edges: List[CallEdge] = []
    for caller in functions.values():
        for call in caller.calls:
            callee = _resolve_call(call, simple_index, qual_index)
            if not callee or callee.function_id == caller.function_id:
                continue
            edges.append(
                CallEdge(
                    caller_id=caller.function_id,
                    callee_id=callee.function_id,
                    call_name=call,
                    file_path=caller.file_path,
                    line=caller.line_start,
                )
            )
    return edges


def _resolve_call(
    call: str,
    simple_index: Dict[str, List[CodeFunction]],
    qual_index: Dict[str, CodeFunction],
) -> CodeFunction | None:
    if call in qual_index:
        return qual_index[call]
    simple = call.rsplit(".", 1)[-1]
    candidates = simple_index.get(simple, [])
    if len(candidates) == 1:
        return candidates[0]
    return None


def _select_seed(
    functions: Dict[str, CodeFunction],
    seed: Optional[str],
    file_path: Optional[str | Path],
    line: Optional[int],
) -> CodeFunction | None:
    if seed:
        matches = [
            function
            for function in functions.values()
            if seed in {
                function.function_id,
                function.qualified_name,
                function.qualified_name.rsplit(".", 1)[-1],
            }
            or function.qualified_name.endswith(f".{seed}")
        ]
        if len(matches) == 1:
            return matches[0]
        if matches:
            return sorted(matches, key=lambda item: (item.file_path, item.line_start))[0]

    if file_path and line is not None:
        target = str(Path(file_path))
        for function in functions.values():
            if function.file_path.endswith(target) and function.line_start <= line <= function.line_end:
                return function
    return None


def _highest_risk_function(
    functions: Dict[str, CodeFunction],
    edges: List[CallEdge],
) -> CodeFunction:
    caller_counts: Dict[str, int] = defaultdict(int)
    for edge in edges:
        caller_counts[edge.callee_id] += 1

    def rank(function: CodeFunction) -> Tuple[int, int, int, str]:
        return (
            len(function.risk_terms),
            len(function.source_terms),
            caller_counts[function.function_id],
            function.qualified_name,
        )

    return max(functions.values(), key=rank)


def _expand_ids(seed_id: str, edges: List[CallEdge], max_depth: int) -> Set[str]:
    forward: Dict[str, Set[str]] = defaultdict(set)
    reverse: Dict[str, Set[str]] = defaultdict(set)
    for edge in edges:
        forward[edge.caller_id].add(edge.callee_id)
        reverse[edge.callee_id].add(edge.caller_id)

    seen = {seed_id}
    queue = deque([(seed_id, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for next_id in sorted(forward[current] | reverse[current]):
            if next_id not in seen:
                seen.add(next_id)
                queue.append((next_id, depth + 1))
    return seen


def _score_context(
    seed: CodeFunction,
    context_functions: List[CodeFunction],
    context_edges: List[CallEdge],
    all_edges: List[CallEdge],
) -> ConfidenceScore:
    value = 0.15
    reasons: List[str] = ["base_static_context"]
    if seed.risk_terms:
        value += 0.3
        reasons.append("seed_calls_risky_sink")
    if seed.source_terms:
        value += 0.2
        reasons.append("seed_has_user_controlled_parameter_names")
    if any(function.risk_terms for function in context_functions if function != seed):
        value += 0.15
        reasons.append("expanded_context_contains_risky_sink")
    caller_count = sum(1 for edge in all_edges if edge.callee_id == seed.function_id)
    if caller_count:
        value += min(0.15, 0.05 * caller_count)
        reasons.append("seed_has_resolved_local_callers")
    if context_edges:
        value += min(0.1, 0.02 * len(context_edges))
        reasons.append("local_call_chain_resolved")
    if any(term in seed.decorators for term in GATE_TERMS):
        value -= 0.05
        reasons.append("seed_has_local_auth_or_validation_gate")
    value = round(max(0.0, min(1.0, value)), 3)
    if value >= 0.75:
        level = "high"
    elif value >= 0.45:
        level = "medium"
    elif value > 0:
        level = "low"
    else:
        level = "none"
    return ConfidenceScore(value=value, level=level, reasons=reasons)
