"""Install the default wheel in a clean environment and check its boundary.

The unit suite runs from a source checkout, where the experimental engines are
still importable. This test builds or reuses the wheel, installs it into a
fresh virtualenv, and checks the published package.
"""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

EXCLUDED_MODULES = (
    "core.c2",
    "core.lateral",
    "core.persistence",
    "core.post_exploit",
    "core.privilege_escalation",
    "core.exfiltration",
    "core.evasion",
    "core.credential",
    "core.ad",
    "core.exploit",
)

_PROBE = r"""
import importlib
import json
import subprocess
import sys
from pathlib import Path

EXCLUDED = (
    "core.c2",
    "core.lateral",
    "core.persistence",
    "core.post_exploit",
    "core.privilege_escalation",
    "core.exfiltration",
    "core.evasion",
    "core.credential",
    "core.ad",
    "core.exploit",
)


def fail(message: str) -> None:
    raise SystemExit(message)


for name in EXCLUDED:
    try:
        importlib.import_module(name)
    except ModuleNotFoundError:
        continue
    fail(f"{name} is importable from the installed wheel")

import core
import handlers
from autort import Scanner

if Scanner is None or core is None or handlers is None:
    fail("safe imports did not resolve")

for name in ("autort.exploiter", "autort.pentest", "autort.redteam"):
    if name in sys.modules:
        fail(f"importing Scanner loaded {name}")


def run_cli(args: list[str]) -> dict:
    completed = subprocess.run(
        [sys.executable, "-m", "cli.main", *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        fail(completed.stderr or completed.stdout or f"exit {completed.returncode}")
    return json.loads(completed.stdout)


manifest = run_cli(["capabilities", "manifest", "--profile", "safe"])
names = {item["name"] for item in manifest["capabilities"]}
if manifest.get("profile") != "safe":
    fail(f"profile is {manifest.get('profile')!r}")
if "cve_search" not in names:
    fail("safe manifest is missing cve_search")
for hidden in ("auto_pentest", "exploit_vulnerability"):
    if hidden in names:
        fail(f"safe manifest includes {hidden}")

handlers_dir = Path(handlers.__file__).resolve().parent
scan = run_cli(["ai-surface", "scan", "--path", str(handlers_dir), "--format", "json"])
summary = scan["summary"]
if summary["scanned_files"] < 1:
    fail("installed handlers scan read no files")
flagged = {
    (item.get("tool_name"), issue)
    for item in scan.get("findings") or []
    for issue in item.get("issues") or []
}
allowed = {("session_create", "declared_effects_omit_target_contact")}
unexpected = sorted(flagged - allowed)
if unexpected:
    fail(f"installed handlers scan unexpected issues: {unexpected}")
if "static_coverage" not in summary:
    fail("installed handlers scan did not reconcile the manifest")

catalog = run_cli(["skills", "catalog"])
if catalog.get("execute_scripts") is not False:
    fail("installed skill catalog execute_scripts is not false")
if catalog.get("bodies_vendored") is not False:
    fail("installed skill catalog bodies_vendored is not false")
ids = {item.get("id") for item in catalog.get("packs") or []}
expected = {"pale-knight-redteam-skill", "transilienceai-communitytools"}
if ids != expected:
    fail(f"installed skill catalog packs {sorted(ids)}")
"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _wheel_path(tmp_path: Path) -> Path:
    configured = os.environ.get("AUTORT_WHEEL")
    if configured:
        candidate = Path(configured)
        if candidate.is_dir():
            wheels = sorted(candidate.glob("*.whl"))
            if len(wheels) != 1:
                raise AssertionError(f"expected one wheel in {candidate}, found {wheels}")
            return wheels[0]
        if candidate.is_file():
            return candidate
        raise AssertionError(f"AUTORT_WHEEL does not exist: {candidate}")

    dist = tmp_path / "dist"
    dist.mkdir()
    # Run outside the repository. A local build/ directory would hide the
    # PyPA build module when python -m build starts with the repo on sys.path.
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist), str(_repo_root())],
        cwd=tmp_path,
        check=True,
    )
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"expected one built wheel, found {wheels}")
    return wheels[0]


def _assert_wheel_omits_engines(wheel: Path) -> None:
    prefixes = tuple(name.replace(".", "/") + "/" for name in EXCLUDED_MODULES)
    with zipfile.ZipFile(wheel) as archive:
        leaked = [name for name in archive.namelist() if name.startswith(prefixes)]
    assert leaked == []


def _assert_wheel_package_data(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert "core/skills/pins.yaml" in names
    assert not any(name == "templates/" or name.startswith("templates/") for name in names)


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _install_wheel(venv: Path, wheel: Path) -> Path:
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = _venv_python(venv)
    subprocess.run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check", str(wheel)],
        check=True,
    )
    return python


@pytest.mark.slow
@pytest.mark.network
def test_installed_wheel_hides_experimental_engines(tmp_path: Path) -> None:
    """The published install keeps the safe audit and omits the experimental engines."""

    wheel = _wheel_path(tmp_path)
    _assert_wheel_omits_engines(wheel)
    _assert_wheel_package_data(wheel)
    python = _install_wheel(tmp_path / "venv", wheel)
    probe = tmp_path / "probe.py"
    probe.write_text(_PROBE, encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [str(python), str(probe)],
        cwd=work,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
