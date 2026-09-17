"""MCP 工具契约检查 — 静态分析工具面是否符合统一契约。

复用 ``core.ai_surface`` 的 AST 扫描结果，追加契约规则：

- 授权/输入校验/payload 门禁（继承 ai_surface 的 issue 判定）
- 工具名重复（会让模型无法区分同名工具）
- 面向模型的 schema 质量：参数类型注解、docstring 的 ``Args:`` 段落
- 证据契约：高风险工具是否有能力返回 evidence / verified

本模块只读源码，不导入、不注册、不执行任何 handler。
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.ai_surface import SurfaceFinding, SurfaceRiskLevel, scan_handler_surface
from core.ai_surface.models import RISK_ORDER

# 继承自 ai_surface 的 issue → 契约错误
INHERITED_ISSUES: Dict[str, Tuple[str, str]] = {
    "high_risk_tool_without_dangerous_auth": ("error", "高风险工具缺少 dangerous 级授权门禁"),
    "critical_tool_without_critical_auth": ("error", "critical 级工具缺少 critical 级授权门禁"),
    "target_input_without_handler_validator": ("error", "存在 target/url 参数但没有输入校验"),
    "payload_generation_without_auth_gate": ("error", "payload 生成工具没有授权门禁"),
}

# 输出中能表达“我给了证据”的键名（领域既有约定）
_EVIDENCE_MARKERS = frozenset({"evidence", "verified", "verification_confidence"})

# 显式声明“本工具不观测目标”的装饰器，据此豁免证据契约。
# 见 handlers/tooling.py 的 no_target_contact。
_NO_TARGET_CONTACT = "no_target_contact"


@dataclass
class ContractIssue:
    """单条契约问题。"""

    rule: str
    severity: str  # error / warning / info
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "message": self.message}


@dataclass
class ToolContractReport:
    """单个工具的契约检查结果。"""

    tool_name: str
    file_path: str
    line: int
    risk_level: str
    auth_level: str
    issues: List[ContractIssue] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "file_path": self.file_path,
            "line": self.line,
            "risk_level": self.risk_level,
            "auth_level": self.auth_level,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass
class ToolLintResult:
    """工具面契约检查结果。"""

    root_path: str
    tools: List[ToolContractReport] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def _count(self, severity: str) -> int:
        return sum(1 for tool in self.tools for issue in tool.issues if issue.severity == severity)

    def summary(self) -> Dict[str, Any]:
        by_rule: Dict[str, int] = {}
        for tool in self.tools:
            for issue in tool.issues:
                by_rule[issue.rule] = by_rule.get(issue.rule, 0) + 1
        return {
            "tools_scanned": len(self.tools),
            "errors": self._count("error"),
            "warnings": self._count("warning"),
            "by_rule": dict(sorted(by_rule.items())),
            "tools_with_errors": sorted(
                tool.tool_name
                for tool in self.tools
                if any(issue.severity == "error" for issue in tool.issues)
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": True,
            "root_path": self.root_path,
            "summary": self.summary(),
            "tools": [tool.to_dict() for tool in self.tools],
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _function_index(paths: Iterable[str]) -> Dict[Tuple[str, int], ast.AST]:
    """把每个文件中“函数定义行号 → 函数节点”建成索引。

    每个文件只解析一次；无法解析的文件被跳过（调用方仍会得到 not_found 告警）。
    """
    index: Dict[Tuple[str, int], ast.AST] = {}
    for raw in paths:
        path = Path(raw)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index[(str(path), node.lineno)] = node
    return index


def _has_annotation(argument: ast.arg) -> bool:
    return argument.annotation is not None


def _untyped_params(node: ast.AST) -> List[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return []
    args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    return [arg.arg for arg in args if arg.arg not in ("self", "cls") and not _has_annotation(arg)]


def _docstring(node: ast.AST) -> str:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
        return ast.get_docstring(node) or ""
    return ""


def _declares_evidence_contract(node: ast.AST) -> bool:
    """判断工具是否在输出中暴露证据字段（启发式）。

    三条路径都算：
    - 使用统一 ``ToolResult`` / ``ensure_tool_result`` 返回值契约；
    - 在返回结构里直接给出 ``evidence`` / ``verified`` / ``verification_confidence``
      （领域既有约定，见 ``core/detectors/result.py`` 的 ``DetectionResult``）；
    - 序列化已知证据类型：对同一个名字既访问 ``.vulnerable`` 又调用 ``.to_dict()``
      （如 ``[r.to_dict() for r in results if r.vulnerable]``）。``.vulnerable`` 是
      ``DetectionResult`` 的指纹字段，其 ``to_dict()`` 已带 ``evidence``/``verified``，
      证据嵌套在 ``results[].findings[]`` 里，所以浅扫描看不到字面 ``evidence``。

    文档字符串被排除，避免一句“evidence”就把工具当成已合规。
    """
    docstring = _docstring(node)
    to_dict_receivers: set[str] = set()
    vulnerable_receivers: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in {"ToolResult", "ensure_tool_result"}:
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if child.value in _EVIDENCE_MARKERS and child.value not in docstring:
                return True
        if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
            if child.attr == "vulnerable":
                vulnerable_receivers.add(child.value.id)
            elif child.attr == "to_dict":
                to_dict_receivers.add(child.value.id)
    return bool(to_dict_receivers & vulnerable_receivers)


def _no_target_contact_exemption(node: ast.AST) -> Optional[str]:
    """读取 ``@no_target_contact("理由")`` 显式豁免声明。

    生成器（payload/代码/计划）和只读本地状态的工具没有可核验的证据，但源码里
    推不出这个区别——名字、授权级别、manifest 的 effects 都是按文件粗粒度声明的，
    实测都不可靠。所以豁免必须是每个工具自己写明的，且必须带理由。

    Returns:
        None   — 未声明豁免，按未合规处理
        ""     — 声明了但没有可用的理由（非字面量字符串或空串），视为无效声明
        str    — 有效的豁免理由
    """
    for item in getattr(node, "decorator_list", []):
        if not isinstance(item, ast.Call):
            continue
        func = item.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name != _NO_TARGET_CONTACT:
            continue
        if item.args:
            first = item.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value.strip()
        return ""
    return None


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _inherited_issues(finding: SurfaceFinding) -> List[ContractIssue]:
    issues: List[ContractIssue] = []
    for raw in finding.issues:
        spec = INHERITED_ISSUES.get(raw)
        if spec is None:
            issues.append(ContractIssue(rule=raw, severity="warning", message=raw))
            continue
        severity, message = spec
        issues.append(ContractIssue(rule=raw, severity=severity, message=message))
    return issues


def _contract_issues(finding: SurfaceFinding, node: Optional[ast.AST]) -> List[ContractIssue]:
    issues: List[ContractIssue] = []

    if node is None:
        issues.append(
            ContractIssue(
                rule="function_node_not_found",
                severity="warning",
                message="无法在源码中定位该工具函数，schema/证据检查被跳过",
            )
        )
        return issues

    if not _docstring(node):
        issues.append(
            ContractIssue(
                rule="missing_docstring",
                severity="warning",
                message="缺少 docstring；模型只能看到工具名，无法判断用途",
            )
        )
    elif finding.parameters and "Args:" not in _docstring(node):
        issues.append(
            ContractIssue(
                rule="missing_args_doc",
                severity="warning",
                message="有参数但 docstring 没有 Args: 段落，模型看不到参数语义",
            )
        )

    untyped = _untyped_params(node)
    if untyped:
        issues.append(
            ContractIssue(
                rule="untyped_parameters",
                severity="warning",
                message=f"参数缺少类型注解，无法生成可靠 schema: {', '.join(sorted(untyped))}",
            )
        )

    high_risk = RISK_ORDER[finding.risk_level] >= RISK_ORDER[SurfaceRiskLevel.HIGH]
    if high_risk and not _declares_evidence_contract(node):
        exemption = _no_target_contact_exemption(node)
        if exemption is None:
            issues.append(
                ContractIssue(
                    rule="no_evidence_contract",
                    severity="warning",
                    message="高风险工具未使用 ToolResult，evidence/verified 无法传递到调用方",
                )
            )
        elif not exemption:
            issues.append(
                ContractIssue(
                    rule="unjustified_no_target_contact",
                    severity="warning",
                    message="声明了不观测目标但没有给出理由；豁免必须说明为什么无需证据",
                )
            )

    return issues


def lint_tool_contracts(
    path: str | Path = "handlers", flag_missing_auth: bool = True
) -> ToolLintResult:
    """静态检查工具面的契约符合程度。

    Args:
        path: handler 文件或目录
        flag_missing_auth: 是否把“缺少本项目授权装饰器”判为错误（外部仓库应传 False）

    Returns:
        ToolLintResult，包含每个工具的问题清单与汇总
    """
    surface = scan_handler_surface(path, flag_missing_auth=flag_missing_auth)
    findings = surface.findings
    index = _function_index(sorted({finding.file_path for finding in findings}))

    reports: List[ToolContractReport] = []
    seen: Dict[str, str] = {}
    for finding in findings:
        issues = _inherited_issues(finding)
        node = index.get((finding.file_path, finding.line))
        issues.extend(_contract_issues(finding, node))

        if finding.tool_name in seen:
            issues.append(
                ContractIssue(
                    rule="duplicate_tool_name",
                    severity="error",
                    message=f"工具名与 {seen[finding.tool_name]} 重复，模型无法区分",
                )
            )
        else:
            seen[finding.tool_name] = f"{finding.file_path}:{finding.line}"

        reports.append(
            ToolContractReport(
                tool_name=finding.tool_name,
                file_path=finding.file_path,
                line=finding.line,
                risk_level=finding.risk_level.value,
                auth_level=finding.auth_level,
                issues=issues,
            )
        )

    return ToolLintResult(
        root_path=surface.root_path,
        tools=reports,
        warnings=list(surface.warnings),
    )


__all__ = [
    "ContractIssue",
    "ToolContractReport",
    "ToolLintResult",
    "lint_tool_contracts",
]
