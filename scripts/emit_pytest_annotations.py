"""Print GitHub Actions error annotations from a pytest JUnit file."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main(path: str) -> int:
    report = Path(path)
    if not report.is_file():
        print("::error::pytest did not write a JUnit report")
        return 0
    tree = ET.parse(report)
    for case in tree.iter("testcase"):
        node = case.find("failure")
        if node is None:
            node = case.find("error")
        if node is None:
            continue
        name = f"{case.get('classname', '')}::{case.get('name', '')}"
        message = (node.get("message") or "failed").splitlines()[0][:300]
        print(f"::error::{name}: {message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
