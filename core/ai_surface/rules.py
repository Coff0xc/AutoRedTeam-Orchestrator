"""OWASP MCP Top 10 static rules for tool descriptions, configs, and skills.

Read-only text and argv checks. These functions never start a server, never
connect, and never execute a package manager.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Sequence

from core.ai_surface.models import SurfaceFinding, SurfaceRiskLevel, max_risk

ISSUE_TOOL_POISONING = "mcp_tool_description_instructs_model"
ISSUE_HIDDEN_UNICODE = "mcp_tool_description_hidden_unicode"
ISSUE_UNPINNED_PACKAGE = "mcp_server_unpinned_package"
ISSUE_REMOTE_SKILL_CODE = "skill_fetches_remote_code"
ISSUE_OVERLONG_DESCRIPTION = "mcp_tool_description_overlong"
ISSUE_SECRET_IN_SCHEMA = "mcp_tool_schema_contains_secret"
ISSUE_SKILL_PROMPT_INJECTION = "skill_prompt_injection"
ISSUE_SKILL_HARDCODED_SECRET = "skill_hardcoded_secret"
ISSUE_SKILL_SUSPICIOUS_URL = "skill_suspicious_download_url"
ISSUE_SKILL_UNVERIFIABLE = "skill_unverifiable_remote_code"
ISSUE_MISSING_SKILL_MD = "skill_missing_skill_md"
ISSUE_GENERAL_COMMAND = "mcp_server_uses_general_command_runtime"
ISSUE_SECRET_ENV_KEY = "mcp_server_env_contains_secret_like_keys"
ISSUE_REMOTE_ENDPOINT = "mcp_server_declares_remote_endpoint"
ISSUE_AUTH_CRITICAL = "critical_tool_without_critical_auth"
ISSUE_AUTH_MISSING = "high_risk_tool_without_dangerous_auth"
ISSUE_PAYLOAD_AUTH = "payload_generation_without_auth_gate"
ISSUE_EFFECT_MISMATCH = "declared_effects_omit_target_contact"

RULE_ID = {
    ISSUE_TOOL_POISONING: "mcp.MCP03.tool-poisoning",
    ISSUE_HIDDEN_UNICODE: "mcp.MCP03.hidden-unicode",
    ISSUE_UNPINNED_PACKAGE: "mcp.MCP04.unpinned-package",
    ISSUE_REMOTE_SKILL_CODE: "mcp.MCP04.remote-skill-code",
    ISSUE_OVERLONG_DESCRIPTION: "mcp.MCP10.overlong-description",
    ISSUE_SECRET_IN_SCHEMA: "mcp.MCP10.secret-in-schema",
    ISSUE_SKILL_PROMPT_INJECTION: "skill.prompt_injection",
    ISSUE_SKILL_HARDCODED_SECRET: "skill.hardcoded_secret",
    ISSUE_SKILL_SUSPICIOUS_URL: "skill.suspicious_download_url",
    ISSUE_SKILL_UNVERIFIABLE: "skill.unverifiable_remote_code",
    ISSUE_MISSING_SKILL_MD: "skill.missing_skill_md",
    ISSUE_GENERAL_COMMAND: "mcp.MCP05.general-command",
    ISSUE_SECRET_ENV_KEY: "mcp.MCP01.secret-env-key",
    ISSUE_REMOTE_ENDPOINT: "mcp.MCP09.remote-endpoint",
}

OWASP_MCP = {
    ISSUE_TOOL_POISONING: "MCP03",
    ISSUE_HIDDEN_UNICODE: "MCP03",
    ISSUE_UNPINNED_PACKAGE: "MCP04",
    ISSUE_REMOTE_SKILL_CODE: "MCP04",
    ISSUE_OVERLONG_DESCRIPTION: "MCP10",
    ISSUE_SECRET_IN_SCHEMA: "MCP10",
    ISSUE_SKILL_PROMPT_INJECTION: "MCP06",
    ISSUE_SKILL_HARDCODED_SECRET: "MCP01",
    ISSUE_SKILL_SUSPICIOUS_URL: "MCP04",
    ISSUE_SKILL_UNVERIFIABLE: "MCP04",
    ISSUE_MISSING_SKILL_MD: "MCP04",
    ISSUE_GENERAL_COMMAND: "MCP05",
    ISSUE_SECRET_ENV_KEY: "MCP01",
    ISSUE_REMOTE_ENDPOINT: "MCP09",
    ISSUE_AUTH_CRITICAL: "MCP07",
    ISSUE_AUTH_MISSING: "MCP07",
    ISSUE_PAYLOAD_AUTH: "MCP07",
    ISSUE_EFFECT_MISMATCH: "MCP02",
}

ISSUE_RISK = {
    ISSUE_TOOL_POISONING: SurfaceRiskLevel.HIGH,
    ISSUE_HIDDEN_UNICODE: SurfaceRiskLevel.HIGH,
    ISSUE_UNPINNED_PACKAGE: SurfaceRiskLevel.HIGH,
    ISSUE_REMOTE_SKILL_CODE: SurfaceRiskLevel.CRITICAL,
    ISSUE_OVERLONG_DESCRIPTION: SurfaceRiskLevel.MODERATE,
    ISSUE_SECRET_IN_SCHEMA: SurfaceRiskLevel.HIGH,
    ISSUE_SKILL_PROMPT_INJECTION: SurfaceRiskLevel.CRITICAL,
    ISSUE_SKILL_HARDCODED_SECRET: SurfaceRiskLevel.CRITICAL,
    ISSUE_SKILL_SUSPICIOUS_URL: SurfaceRiskLevel.HIGH,
    ISSUE_SKILL_UNVERIFIABLE: SurfaceRiskLevel.HIGH,
    ISSUE_MISSING_SKILL_MD: SurfaceRiskLevel.MODERATE,
    ISSUE_GENERAL_COMMAND: SurfaceRiskLevel.HIGH,
    ISSUE_SECRET_ENV_KEY: SurfaceRiskLevel.MODERATE,
    ISSUE_REMOTE_ENDPOINT: SurfaceRiskLevel.MODERATE,
    ISSUE_AUTH_CRITICAL: SurfaceRiskLevel.CRITICAL,
    ISSUE_AUTH_MISSING: SurfaceRiskLevel.HIGH,
    ISSUE_PAYLOAD_AUTH: SurfaceRiskLevel.HIGH,
    ISSUE_EFFECT_MISMATCH: SurfaceRiskLevel.MODERATE,
}

ISSUE_RECOMMENDATION = {
    ISSUE_TOOL_POISONING: (
        "Keep tool descriptions as capability cards. "
        "Do not put instructions to the model in the schema."
    ),
    ISSUE_HIDDEN_UNICODE: (
        "Remove zero-width or bidi override characters from the tool description."
    ),
    ISSUE_UNPINNED_PACKAGE: "Pin npx/uvx/pip package versions. Do not use @latest.",
    ISSUE_REMOTE_SKILL_CODE: "Do not download and execute remote scripts from a skill.",
    ISSUE_OVERLONG_DESCRIPTION: (
        "Shorten the tool description. Long text is a context-injection channel."
    ),
    ISSUE_SECRET_IN_SCHEMA: (
        "Remove secret literals from descriptions, defaults, and schema examples."
    ),
    ISSUE_SKILL_PROMPT_INJECTION: (
        "Remove instructions that try to override the agent or hide the skill's purpose."
    ),
    ISSUE_SKILL_HARDCODED_SECRET: "Remove secret literals from the skill text.",
    ISSUE_SKILL_SUSPICIOUS_URL: ("Do not point the agent at untrusted download URLs from a skill."),
    ISSUE_SKILL_UNVERIFIABLE: "Pin package versions in skill install steps.",
    ISSUE_MISSING_SKILL_MD: "Add a SKILL.md manifest before installing this skill.",
    ISSUE_GENERAL_COMMAND: "Prefer a narrow wrapper command with fixed arguments.",
    ISSUE_SECRET_ENV_KEY: "Use secret manager references and redact env from logs.",
    ISSUE_REMOTE_ENDPOINT: (
        "Review the remote endpoint and its authentication before enabling it."
    ),
}

# Prefer poisoning, then auth, then supply chain, then command, then shadow.
ISSUE_ORDER = (
    ISSUE_SKILL_PROMPT_INJECTION,
    ISSUE_SKILL_HARDCODED_SECRET,
    ISSUE_TOOL_POISONING,
    ISSUE_HIDDEN_UNICODE,
    ISSUE_REMOTE_SKILL_CODE,
    ISSUE_SKILL_UNVERIFIABLE,
    ISSUE_UNPINNED_PACKAGE,
    ISSUE_SECRET_IN_SCHEMA,
    ISSUE_AUTH_CRITICAL,
    ISSUE_AUTH_MISSING,
    ISSUE_PAYLOAD_AUTH,
    ISSUE_GENERAL_COMMAND,
    ISSUE_SECRET_ENV_KEY,
    ISSUE_REMOTE_ENDPOINT,
    ISSUE_EFFECT_MISMATCH,
    ISSUE_SKILL_SUSPICIOUS_URL,
    ISSUE_OVERLONG_DESCRIPTION,
    ISSUE_MISSING_SKILL_MD,
)

BLOCKING_SKILL_ISSUES = frozenset(
    {
        ISSUE_SKILL_PROMPT_INJECTION,
        ISSUE_SKILL_HARDCODED_SECRET,
        ISSUE_REMOTE_SKILL_CODE,
        "critical_skill_instruction_requires_review",
    }
)

OVERLONG_DESCRIPTION_CHARS = 2048

_PACKAGE_COMMANDS = frozenset(
    {
        "bunx",
        "bunx.exe",
        "npm",
        "npm.cmd",
        "npx",
        "npx.cmd",
        "pip",
        "pip.exe",
        "pip3",
        "pip3.exe",
        "pipx",
        "pipx.exe",
        "pnpm",
        "pnpm.cmd",
        "uv",
        "uv.exe",
        "uvx",
        "uvx.exe",
        "yarn",
        "yarn.cmd",
    }
)

_FLAG_WITH_VALUE = frozenset({"-c", "--call", "--from", "-p", "--package"})

_HIDDEN_UNICODE = (
    "\u200b",
    "\u200c",
    "\u200d",
    "\u2060",
    "\ufeff",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
)

_POISONING_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|context)",
        r"\b(discard|disregard)\s+(all\s+)?(previous|prior)\b",
        r"\byou\s+are\s+now\b",
        r"\bfrom\s+now\s+on\s+you\b",
        r"do\s+not\s+(tell|inform|mention|notify)\s+(the\s+)?(user|human|operator)",
        r"\bhidden\s+(instruction|prompt|directive)s?\b",
        r"\b(override|replace)\s+(the\s+)?(system|developer)\s+(prompt|instructions)\b",
        r"before\s+(you\s+)?(use|call|invoke|run)\s+this\s+tool\s*[,:]",
        r"\bsend\s+(the\s+)?(contents|secrets|files|keys|tokens)\s+to\b",
        r"\bnew\s+instructions\s*:",
        r"\bjailbreak\b",
    )
)

_REMOTE_SKILL_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for pattern in (
        r"(curl|wget)\b.{0,200}\|\s*(ba)?sh\b",
        r"\biwr\b.{0,200}\|\s*iex\b",
        r"invoke-webrequest.{0,200}invoke-expression",
        r"invoke-expression.{0,200}invoke-webrequest",
        r"pip(?:3)?\s+install\s+git\+",
        r"npm\s+install\s+-g\s+https?://",
    )
)

_SECRET_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"sk-(?:live|ant)-[A-Za-z0-9_-]{8,}",
        r"sk-[A-Za-z0-9]{20,}",
        r"ghp_[A-Za-z0-9]{20,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"xox[baprs]-[A-Za-z0-9-]{10,}",
        r"AIza[0-9A-Za-z_-]{20,}",
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
    )
)


def analyze_tool_text(description: str, schema_text: str = "") -> List[str]:
    """Return MCP03/MCP10 issues for a tool description and schema literals."""
    issues: List[str] = []
    haystack = description or ""
    if any(pattern.search(haystack) for pattern in _POISONING_PATTERNS):
        issues.append(ISSUE_TOOL_POISONING)
    if any(marker in haystack for marker in _HIDDEN_UNICODE):
        issues.append(ISSUE_HIDDEN_UNICODE)
    if len(haystack) >= OVERLONG_DESCRIPTION_CHARS:
        issues.append(ISSUE_OVERLONG_DESCRIPTION)
    combined = "\n".join(part for part in (haystack, schema_text) if part)
    if any(pattern.search(combined) for pattern in _SECRET_PATTERNS):
        issues.append(ISSUE_SECRET_IN_SCHEMA)
    return issues


def analyze_mcp_command(command: str, args: Sequence[str]) -> List[str]:
    """Return MCP04 issues for a client-config command and argv."""
    if _unpinned_packages(command, args):
        return [ISSUE_UNPINNED_PACKAGE]
    return []


_URL_RE = re.compile(r"https?://[^\s)\]>'\"`]+", re.IGNORECASE)
_UNPINNED_IN_SKILL = re.compile(
    r"\b(npx|uvx|npm|pnpm|yarn|pipx|pip3?)\s+"
    r"(?:-[yY]\s+|install\s+|exec\s+|dlx\s+|add\s+)*"
    r"(@?[A-Za-z0-9_./-]+(?:@[A-Za-z0-9_.*-]+)?)",
    re.IGNORECASE,
)


def analyze_skill_text(text: str) -> List[str]:
    """Return named skill-install issues for a SKILL.md or instruction file."""
    haystack = text or ""
    issues: List[str] = []
    if any(pattern.search(haystack) for pattern in _POISONING_PATTERNS):
        issues.append(ISSUE_SKILL_PROMPT_INJECTION)
    if any(pattern.search(haystack) for pattern in _SECRET_PATTERNS):
        issues.append(ISSUE_SKILL_HARDCODED_SECRET)
    if any(marker in haystack for marker in _HIDDEN_UNICODE):
        issues.append(ISSUE_HIDDEN_UNICODE)
    if any(pattern.search(haystack) for pattern in _REMOTE_SKILL_PATTERNS):
        issues.append(ISSUE_REMOTE_SKILL_CODE)
    if _unpinned_install_in_skill(haystack):
        issues.append(ISSUE_SKILL_UNVERIFIABLE)
    if _has_suspicious_download_url(haystack):
        issues.append(ISSUE_SKILL_SUSPICIOUS_URL)
    return issues


def _has_suspicious_download_url(text: str) -> bool:
    for raw in _URL_RE.findall(text or ""):
        url = raw.lower().rstrip(".,;:")
        if "/releases/download/" in url:
            return True
        if "raw.githubusercontent.com" in url:
            return True
        if "gist.githubusercontent.com" in url:
            return True
        if re.search(r"\.(?:sh|ps1|exe|bat|cmd|msi|dmg|zip)(?:\?|$)", url):
            return True
    return False


def _unpinned_install_in_skill(text: str) -> bool:
    for match in _UNPINNED_IN_SKILL.finditer(text or ""):
        command = match.group(1).lower()
        token = match.group(2)
        if token.startswith("-"):
            continue
        if token.lower() in {"install", "exec", "dlx", "add"}:
            continue
        if _looks_like_local_path(token) or token.lower().endswith((".txt", ".in")):
            continue
        if not _is_pinned(token, command):
            return True
    return False


def skill_finding_is_blocking(finding: SurfaceFinding) -> bool:
    """True when skill_read must withhold the body."""
    if finding.risk_level == SurfaceRiskLevel.CRITICAL:
        return True
    return any(issue in BLOCKING_SKILL_ISSUES for issue in finding.issues)


def apply_policy(finding: SurfaceFinding, issues: Iterable[str]) -> None:
    """Append policy issues, raise risk, and attach recommendations."""
    extra = [issue for issue in issues if issue not in finding.issues]
    if not extra:
        return
    finding.issues.extend(extra)
    finding.risk_level = max_risk(finding.risk_level, risk_for_issues(extra))
    for recommendation in recommendations_for_issues(extra):
        if recommendation not in finding.recommendations:
            finding.recommendations.append(recommendation)


def risk_for_issues(issues: Sequence[str]) -> SurfaceRiskLevel:
    risk = SurfaceRiskLevel.INFO
    for issue in issues:
        if issue in ISSUE_RISK:
            risk = max_risk(risk, ISSUE_RISK[issue])
    return risk


def recommendations_for_issues(issues: Sequence[str]) -> List[str]:
    return [ISSUE_RECOMMENDATION[issue] for issue in issues if issue in ISSUE_RECOMMENDATION]


def owasp_mcp_for_issues(issues: Sequence[str]) -> str:
    for issue in ISSUE_ORDER:
        if issue in issues and issue in OWASP_MCP:
            return OWASP_MCP[issue]
    return ""


def rule_id_for_issues(issues: Sequence[str]) -> str:
    for issue in ISSUE_ORDER:
        if issue in issues and issue in RULE_ID:
            return RULE_ID[issue]
    return ""


def _unpinned_packages(command: str, args: Sequence[str]) -> List[str]:
    name = Path(command or "").name.lower()
    if name not in _PACKAGE_COMMANDS:
        return []
    unpinned: List[str] = []
    for token in _package_tokens(args):
        if not _is_pinned(token, name):
            unpinned.append(token)
    return unpinned


def _package_tokens(args: Sequence[str]) -> List[str]:
    tokens: List[str] = []
    pending_value = False
    for raw in args:
        arg = str(raw)
        if pending_value:
            pending_value = False
            _collect_package_token(tokens, arg)
            continue
        if arg in _FLAG_WITH_VALUE:
            pending_value = True
            continue
        if arg.startswith("--package="):
            _collect_package_token(tokens, arg.split("=", 1)[1])
            continue
        if arg.startswith("--from="):
            _collect_package_token(tokens, arg.split("=", 1)[1])
            continue
        if arg.startswith("-"):
            continue
        if arg in {"install", "run", "exec", "dlx", "add"}:
            continue
        _collect_package_token(tokens, arg)
    return tokens


def _collect_package_token(tokens: List[str], arg: str) -> None:
    if _looks_like_local_path(arg):
        return
    if arg:
        tokens.append(arg)


def _looks_like_local_path(arg: str) -> bool:
    lowered = arg.lower()
    if lowered.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".ps1")):
        return True
    if arg.startswith((".", "/", "~")):
        return True
    if "\\" in arg or ":/" in arg or arg.startswith("file:"):
        return True
    return False


def _is_pinned(token: str, command: str) -> bool:
    if token.startswith("git+"):
        # pip git+https://...@<sha> is treated as pinned when a ref is present.
        return "@" in token.split("://", 1)[-1]
    if command.startswith("pip"):
        return "==" in token or "===" in token
    if token.endswith(("@latest", "@next", "@*")):
        return False
    if token.startswith("@"):
        return token.count("@") >= 2
    if "@" in token:
        version = token.rsplit("@", 1)[-1]
        return bool(version) and version not in {"latest", "next", "*"}
    return False
