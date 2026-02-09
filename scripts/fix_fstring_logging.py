#!/usr/bin/env python3
"""Convert f-string logging to lazy % formatting for performance.

f-string arguments are always evaluated even when the log level is disabled.
Lazy % formatting defers string interpolation until the message is actually logged.

Usage:
    python scripts/fix_fstring_logging.py --dry-run   # Preview changes
    python scripts/fix_fstring_logging.py              # Apply changes
"""

import os
import re
import sys
from pathlib import Path

# Files to skip (being edited by other agents)
SKIP_FILES = {
    "core/registry/base.py",
    "core/http/middleware.py",
    "core/http/client.py",
    "utils/command_executor.py",
    "handlers/error_handling.py",
    "utils/crypto.py",
}

# Directories to process
TARGET_DIRS = ["core", "modules", "handlers", "utils"]

# Skip these directory names
SKIP_DIRS = {"tests", "__pycache__", ".git", "venv", "backup", "scripts"}

# Pattern to match logger.xxx(f"...") on a single line
# Uses a non-greedy match for the f-string content between quotes
LOG_PATTERN = re.compile(
    r'(logger\.\w+)\(f(["\'])(.*?)\2\)'
)

# Pattern to match {expr} or {expr:fmt} inside f-string content
FSTRING_VAR = re.compile(r"\{([^{}]+?)(?::([^{}]*))?\}")


def convert_fstring_to_lazy(match: re.Match) -> str:
    """Convert a single f-string logging call to lazy format.

    Returns the original match string unchanged if the expression is too
    complex to safely convert (e.g. contains brackets, function calls).
    """
    log_call = match.group(1)  # e.g., logger.info
    quote = match.group(2)     # " or '
    content = match.group(3)   # The f-string content between quotes

    vars_found: list[str] = []
    has_complex = False

    def replace_var(m: re.Match) -> str:
        nonlocal has_complex
        expr = m.group(1).strip()
        fmt_spec = m.group(2)

        # Handle !r, !s, !a conversion flags (appear before format spec)
        conversion = None
        for flag in ("!r", "!s", "!a"):
            if expr.endswith(flag):
                conversion = flag[1]  # 'r', 's', or 'a'
                expr = expr[: -len(flag)].strip()
                break

        # Skip complex expressions: brackets, parens, nested braces, calls
        if any(c in expr for c in "[](){}"):
            has_complex = True
            return m.group(0)  # Keep original

        vars_found.append(expr)

        # Determine the format specifier to use
        if conversion:
            return f"%{conversion}"

        if fmt_spec:
            # Handle common format specs like .2f, .1f, d, s, etc.
            if fmt_spec == "s":
                return "%s"
            # Numeric specs like .2f, .1f, .4f, .2e, .1g, etc.
            if re.match(r"^\.?\d*[fdegFDEG]$", fmt_spec):
                return f"%{fmt_spec}"
            # Fallback: try to use as-is
            return f"%{fmt_spec}"

        return "%s"

    new_content = FSTRING_VAR.sub(replace_var, content)

    # If no vars found, complex expression detected, or still has unreplaced braces -> skip
    if not vars_found or has_complex or "{" in new_content:
        return match.group(0)

    vars_str = ", ".join(vars_found)
    return f'{log_call}({quote}{new_content}{quote}, {vars_str})'


def process_file(filepath: str, dry_run: bool = False) -> tuple[int, int]:
    """Process a single file. Returns (converted_count, skipped_count)."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    converted = 0
    skipped = 0

    def replace_and_count(match: re.Match) -> str:
        nonlocal converted, skipped
        result = convert_fstring_to_lazy(match)
        if result == match.group(0):
            skipped += 1
        else:
            converted += 1
        return result

    new_content = LOG_PATTERN.sub(replace_and_count, content)

    if converted > 0 and not dry_run:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)

    return converted, skipped


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    root = Path(__file__).resolve().parent.parent

    total_converted = 0
    total_skipped = 0
    files_modified = 0

    for target_dir in TARGET_DIRS:
        dir_path = root / target_dir
        if not dir_path.exists():
            continue

        for py_file in sorted(dir_path.rglob("*.py")):
            rel_path = py_file.relative_to(root).as_posix()

            # Skip excluded files
            if rel_path in SKIP_FILES:
                continue
            # Skip excluded directories
            if any(skip in py_file.parts for skip in SKIP_DIRS):
                continue

            converted, skipped = process_file(str(py_file), dry_run)
            if converted > 0 or skipped > 0:
                prefix = "[DRY] " if dry_run else ""
                status = f"{converted} converted"
                if skipped:
                    status += f", {skipped} skipped"
                print(f"  {prefix}{rel_path}: {status}")
                files_modified += converted > 0 and 1 or 0

            total_converted += converted
            total_skipped += skipped

    mode = "[DRY RUN] " if dry_run else ""
    print(
        f"\n{mode}Summary: {total_converted} converted, "
        f"{total_skipped} skipped, {files_modified} files modified"
    )


if __name__ == "__main__":
    main()
