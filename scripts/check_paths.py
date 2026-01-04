#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查硬编码路径的 pre-commit hook
防止在代码中使用 Linux 特有的路径（如 /tmp/, /dev/tty）
"""
import sys
import re
import io
from pathlib import Path

# Windows 兼容：强制 UTF-8 输出
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

FORBIDDEN_PATTERNS = [
    (r"open\s*\(\s*['\"]\/dev\/tty",
     "Use sys.platform != 'win32' check before opening /dev/tty"),
    (r"open\s*\(\s*['\"]\/tmp\/",
     "Use tempfile.gettempdir() instead of /tmp/"),
    (r"open\s*\(\s*['\"]\/var\/log\/",
     "Use tempfile.gettempdir() or logging module"),
    (r"Path\s*\(\s*['\"]\/tmp\/",
     "Use Path(tempfile.gettempdir()) instead"),
]

EXCLUDE_PATTERNS = [
    r'f["\'].*\/dev\/tcp',
    r'f["\'].*\/tmp\/f',
    r'["\'].*\/bin\/sh',
    r'["\'].*\/bin\/bash',
    r'OUTFILE.*\/tmp\/',
    r'DUMPFILE.*\/tmp\/',
    r'file:\/\/\/dev\/',
    r'\/var\/log\/.*\.log',
    r'\/var\/www\/html',
    r'\/etc\/passwd',
    r'dangerous_paths\s*=',
]

def is_excluded(line: str) -> bool:
    return any(re.search(p, line) for p in EXCLUDE_PATTERNS)

def check_file(filepath: str) -> list:
    errors = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if is_excluded(line):
                continue
            
            for pattern, suggestion in FORBIDDEN_PATTERNS:
                if re.search(pattern, line):
                    # 检查前几行是否有 sys.platform 检查
                    has_platform_check = False
                    for i in range(max(0, line_num - 4), line_num - 1):
                        if 'sys.platform' in lines[i] or 'platform.system' in lines[i]:
                            has_platform_check = True
                            break
                    
                    if not has_platform_check:
                        errors.append({
                            'file': filepath,
                            'line': line_num,
                            'content': stripped[:80],
                            'suggestion': suggestion
                        })
    except Exception as e:
        print(f"Warning: Cannot read {filepath}: {e}", file=sys.stderr)
    return errors

def main():
    if len(sys.argv) < 2:
        project_root = Path(__file__).parent.parent
        files = list(project_root.rglob('*.py'))
        files = [f for f in files if not any(
            p in str(f) for p in ['venv', '.venv', '__pycache__', '.git', 'node_modules']
        )]
    else:
        files = [Path(f) for f in sys.argv[1:] if f.endswith('.py')]

    all_errors = []
    for filepath in files:
        errors = check_file(str(filepath))
        all_errors.extend(errors)

    if all_errors:
        print("=" * 60)
        print("[X] Found hardcoded path issues (cross-platform compatibility)")
        print("=" * 60)
        for err in all_errors:
            print(f"\nFile: {err['file']}:{err['line']}")
            print(f"  Code: {err['content']}")
            print(f"  Fix:  {err['suggestion']}")
        print("\n" + "=" * 60)
        print(f"Total: {len(all_errors)} issue(s) found")
        print("=" * 60)
        sys.exit(1)
    else:
        print("[OK] No hardcoded path issues found")
        sys.exit(0)

if __name__ == "__main__":
    main()
