"""Prompt bodies and the published image follow the default wheel boundary."""

from __future__ import annotations

from pathlib import Path

from core.capability_manifest import CAPABILITIES, render_prompt_body

ROOT = Path(__file__).resolve().parents[1]
WHEEL_EXCLUDES = (
    "core/c2",
    "core/lateral",
    "core/persistence",
    "core/post_exploit",
    "core/privilege_escalation",
    "core/exfiltration",
    "core/evasion",
    "core/credential",
    "core/ad",
    "core/exploit",
)


class _CaptureMCP:
    def __init__(self):
        self.prompts = {}

    def prompt(self, **kwargs):
        def decorate(func):
            self.prompts[kwargs["name"]] = func
            return func

        return decorate


class _Counter:
    def add(self, category: str, count: int = 1):
        return None


class _Logger:
    def info(self, message, *args, **kwargs):
        return None


def test_prompt_bodies_repeat_the_manifest_constraint():
    from handlers.prompt_handlers import register_prompt_handlers

    mcp = _CaptureMCP()
    register_prompt_handlers(mcp, _Counter(), _Logger())
    prompts = {item.name: item for item in CAPABILITIES if item.kind == "prompt"}

    assert set(mcp.prompts) == set(prompts)
    samples = {
        "plan_pentest": {"target": "example.invalid", "scope": "lab"},
        "analyze_findings": {"findings_json": "{}"},
        "plan_attack_chain": {
            "target": "example.invalid",
            "vulnerabilities": "none",
            "access_level": "none",
        },
        "suggest_next_phase": {
            "current_phase": "saved",
            "findings_summary": "none",
            "access_level": "none",
        },
        "write_report": {
            "target": "example.invalid",
            "findings_json": "{}",
            "report_type": "executive",
        },
        "explain_vulnerability": {"vuln_type": "example", "context": ""},
    }
    for name, parameters in samples.items():
        body = mcp.prompts[name](**parameters)
        text = body[0]["content"]["text"]
        assert text == render_prompt_body(name, parameters)
        assert prompts[name].public_description() in text
        assert "procedure" in text
        assert "推荐工具" not in text


def test_image_context_matches_wheel_excludes():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "docker-publish.yml").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "pyproject-build --wheel" in dockerfile
    assert "RUN python -m build" not in dockerfile
    assert "WORKDIR /src" in dockerfile
    assert "AUTORT_CAPABILITY_PROFILE=safe" in dockerfile
    assert "nmap" not in dockerfile.lower()
    assert "COPY payloads" not in dockerfile
    assert "COPY core ./core" in dockerfile
    for package in WHEEL_EXCLUDES:
        assert package in dockerignore
        dotted = package.replace("/", ".")
        assert f'"{dotted}*"' in pyproject
    assert "platforms: linux/amd64,linux/arm64" in workflow
    assert "administration:" not in workflow
    assert "run: pyproject-build" in ci
    assert "run: python -m build" not in ci
    assert "ai-redteam eval-run config/ai_redteam.eval.example.yaml --ci" in ci
    assert "runtime-api run config/runtime.local.example.yaml --local --ci" in ci
    windows_job = ci.split("test-windows:", 1)[1].split("security:", 1)[0]
    assert "python-version: ['3.10', '3.12']" in windows_job
    assert "--maxfail" not in windows_job
    assert "not slow and not integration and not network" in windows_job


def test_env_example_documents_live_gates():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "AUTORT_CAPABILITY_PROFILE=safe" in text
    assert "AUTOREDTEAM_AUTH_MODE=strict" in text
    assert "AUTORT_LLM_PROVIDER=none" in text
    assert "OPENAI_API_KEY=your_openai_api_key_here" not in text
