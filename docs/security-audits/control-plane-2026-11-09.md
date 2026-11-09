# Control-plane review, 2026-11-09

This is a review of the maintained product boundary. It does not certify the experimental engines.

## What was already recorded

`claude-security-audit-2026-04-07.md` only lists dependency CVEs. `cryptography>=46.0.6` is already pinned in `requirements.txt`. `pyopenssl` is not a direct dependency, so that pin does not belong in this repository until some module imports it.

## What this pass checked

- Default MCP profile `safe` does not import handler modules that have no surface in that profile.
- Registered tool descriptions come from the capability manifest, not handler docstrings.
- The default wheel excludes the experimental engine packages listed in `pyproject.toml`.
- `core/ad/kerberos_attacks.py`, `core/web_scanner/`, `core/ai_decision_engine.py`, `core/result_aggregator.py`, `core/exfiltration/base_secure.py`, and three unused CVE helpers had no importers. They were removed.
- Evidence downgrade for findings without independent provenance is already implemented in the evidence gate.

## What is still true

- The source tree still contains experimental engines. A repository scan can still flag them.
- Handler modules for those engines still ship in the wheel. They fail with `ImportError` when the engine package is absent.
- A whole-repository dead-code proof does not exist. Vulture is configured but not run in CI. Dynamic imports mean a filename search both misses callers and reports false dead modules.
- Detection accuracy is not benchmarked. This pass did not change detector algorithms.
- `safe` still allows the local process to read caller-selected files. That is the trusted-local model in `docs/security-model.md`.

## Not accepted as done

There is no current audit that says the experimental engines are safe to expose, and there is no measured accuracy number for the detectors.
