
---

## Dependency-chain CVEs (pip-audit scan results)

Found **4 known CVEs** across 2 packages:

| Package | Current Version | CVE | Severity | Fixed Version | Notes |
|---|---|---|---|---|---|
| `cryptography` | 44.0.3 | CVE-2026-26007 | **High** | ≥46.0.5 | ECDH/ECDSA small-subgroup attack — public keys are not validated for subgroup membership, leaking low bits of the private key (SECT curves) |
| `cryptography` | 44.0.3 | CVE-2026-34073 | Medium | ≥46.0.6 | X.509 name-constraints bypass — DNS name constraints not applied to the peer name |
| `pyopenssl` | 25.1.0 | CVE-2026-27448 | **High** | ≥26.0.0 | TLS SNI callback exception → connection allowed — the security callback can be bypassed |
| `pyopenssl` | 25.1.0 | CVE-2026-27459 | Medium | ≥26.0.0 | DTLS cookie callback buffer overflow on payloads >256 bytes |

**Impact assessment**:
- `cryptography` is depended on by `SecretsManager` (Fernet/PBKDF2) and `mcp_auth_middleware` — **directly affects authentication security**
- `pyopenssl` is a transitive dependency — if a C2 tunnel or recon module uses pyopenssl's TLS callbacks, the SNI bypass could lead to authentication downgrade

**Fix**: bump the version constraints in `requirements.txt`:
```
cryptography>=46.0.6,<48.0.0   # was >=42.0.0,<45.0.0
pyopenssl>=26.0.0               # new (pin a safe version)
```

Add to the fix-priority table:

| P0 | DEP-01 | Upgrade cryptography to ≥46.0.6 | 0.5h |
| P1 | DEP-02 | Upgrade pyopenssl to ≥26.0.0 | 0.5h |
