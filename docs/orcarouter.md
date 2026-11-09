# OrcaRouter Cyber Inference provider

`orcarouter` is a named model provider for **authorized** red-team and blue-team work.
It routes scoped security reasoning to OrcaRouter's cyber models behind one
OpenAI-compatible endpoint, and it is a first-class entry in the provider registry — not
a generic "custom base URL" option.

- Provider page: <https://www.orcarouter.ai/cyber>
- Cyber model catalog: <https://www.orcarouter.ai/models?tier=cyber>
- Inference base URL: `https://api.orcarouter.ai/v1`
- Authorization origin: `https://www.orcarouter.ai`

OrcaRouter is an OpenAI-compatible AI gateway that routes many providers behind one
endpoint. The cyber tier is aimed at security teams that have completed business
verification and run scoped, authorized engagements; general-purpose gateways often
refuse or silently downgrade that kind of request. Blue-team work uses the same endpoint
with the gateway's controls (agent firewall, guardrails, code-review gate) in front of
it.

## Models

| Role | Model id |
| --- | --- |
| Default | `orcarouter/auto` — automatic routing, works with any key |
| Recommended cyber (verified security teams) | `orca/orcacyber-ultra-1.0` — security code scanning and multi-step reasoning over large codebases |
| Recommended cyber (verified security teams) | `orca/orcacyber-zero-1.5` (also `orca/orcacyber-zero-1.0`) — OrcaCyber harness |
| General fallback | `orcarouter/fusion` |

The live catalog is the only source of truth for what a workspace can call. Model ids
keep their `vendor/model` namespace exactly as the catalog returns them.

```bash
autort llm models                 # live GET /v1/models?capability=chat
autort llm models --select        # pick one and remember it
autort llm models --require-input image
```

If discovery fails, a small verified seed (`openai/gpt-5.5`, `anthropic/claude-opus-4.8`,
`google/gemini-3.5-flash`, `deepseek/deepseek-v4-pro`, `orcarouter/auto`) is shown and
marked `degraded`. The seed keeps GPT-5.5's `low`/`medium`/`high`/`xhigh` reasoning
ladder. A live success is authoritative and is never merged with the seed.

## Authentication

Two explicit choices; both end up as the same ordinary `sk-orca-…` API key, and both are
stored in the same place (`~/.config/autoredt/orcarouter.json`, mode `0600`, override with
`AUTORT_ORCA_CREDENTIALS`). The downstream provider and model catalog do not care which
path produced the key.

### 1. API key

```bash
autort llm key set               # hidden prompt
export ORCAROUTER_API_KEY=sk-orca-...
autort llm key clear
```

Keys are created and revoked in the OrcaRouter console:
<https://www.orcarouter.ai/console/keys>.

### 2. OAuth 2.0 + PKCE

```bash
autort llm connect               # Flow A: loopback redirect + browser
autort llm connect --flow oob    # Flow B: consent screen shows a code to paste
autort llm logout
```

- `S256` is always used; the verifier is fresh CSPRNG output per attempt and never leaves
  the process except in the exchange body.
- `state` is compared in constant time before any code is used.
- The exchange posts to `https://www.orcarouter.ai/api/v1/auth/keys` (not the inference
  origin, and never `/v1/auth/keys`).
- The response `scope` is read back. Anything other than `api` is refused, because the
  inference relay needs the `api` grant.
- The issued key is durable, not a refresh token. There is no refresh grant; the stored
  key is reused until it is revoked. A `401` from the relay marks that exact account and
  credential generation as needing reauthentication — it never triggers a retry loop or
  a fake refresh, and a late failure cannot flag a newer login.
- Flow B is the fallback for SSH sessions and hosts without a loopback browser. A device
  grant (Flow C) is not implemented.

Per-user key issuance is capped at 10 PKCE keys per 24 hours. The CLI reuses the stored
key on a second `connect`; use `--force` only when you intend to mint a new one.

## Configuration

Environment variables (explicit overrides win):

| Variable | Meaning |
| --- | --- |
| `AUTORT_LLM_PROVIDER=orcarouter` | Select the provider for `LLMProvider` (orchestrator AI enhancement) |
| `ORCAROUTER_API_KEY` | API-key credential |
| `AUTORT_LLM_MODEL` | Model id; defaults to `orcarouter/auto` |
| `AUTORT_LLM_BASE_URL` | Inference base URL override |
| `ORCA_BASE_URL` | Shared self-hosted origin (auth; inference becomes `<base>/v1`) |
| `ORCA_AUTH_BASE_URL` | Explicit authorization origin |
| `ORCA_API_BASE_URL` | Explicit inference/catalog origin |
| `AUTORT_ORCA_CREDENTIALS` | Credential file path |

Remote origins must be HTTPS; plain HTTP is accepted only for loopback development hosts.

`config.yaml`:

```yaml
ai:
  provider: "orcarouter"     # MCP smart_analyze / decision engine
  model: "orcarouter/auto"
  base_url: "https://api.orcarouter.ai/v1"

llm:
  provider: "orcarouter"     # orchestrator LLM enhancement
  model: "orcarouter/auto"
  base_url: "https://api.orcarouter.ai/v1"
```

## Verifying connectivity

```bash
autort llm status          # redacted credential source, origins, selected model
autort llm ping            # one real request through the provider code path
```

`autort llm models` never falls back to free-text model entry: if the catalog cannot be
reached it shows the verified seed with a degraded marker.

## Scope

The provider only carries the prompts this framework already sends (target analysis,
attack-chain planning, orchestration decisions). It adds no new offensive capability.
Use it only against targets and environments you are authorized to test.
