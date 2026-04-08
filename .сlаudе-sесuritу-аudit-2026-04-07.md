
---

## 依赖链 CVE (pip-audit 扫描结果)

共发现 **4 个已知 CVE**，涉及 2 个包：

| 包 | 当前版本 | CVE | 严重程度 | 修复版本 | 说明 |
|---|---|---|---|---|---|
| `cryptography` | 44.0.3 | CVE-2026-26007 | **High** | ≥46.0.5 | ECDH/ECDSA 小子群攻击 — 公钥未验证子群归属，可泄露私钥低位 (SECT 曲线) |
| `cryptography` | 44.0.3 | CVE-2026-34073 | Medium | ≥46.0.6 | X.509 名称约束绕过 — DNS 名称约束未应用于 peer name |
| `pyopenssl` | 25.1.0 | CVE-2026-27448 | **High** | ≥26.0.0 | TLS SNI 回调异常 → 连接被允许 — 安全回调可被绕过 |
| `pyopenssl` | 25.1.0 | CVE-2026-27459 | Medium | ≥26.0.0 | DTLS cookie 回调 >256 字节缓冲区溢出 |

**影响评估**:
- `cryptography` 被 `SecretsManager` (Fernet/PBKDF2) 和 `mcp_auth_middleware` 依赖 — **直接影响认证安全**
- `pyopenssl` 为间接依赖 — 如果 C2 隧道或 recon 模块使用了 pyopenssl 的 TLS 回调，SNI 绕过可导致认证降级

**修复**: 升级 `requirements.txt` 版本约束:
```
cryptography>=46.0.6,<48.0.0   # was >=42.0.0,<45.0.0
pyopenssl>=26.0.0               # 新增（pin 安全版本）
```

修复优先级表中追加:

| P0 | DEP-01 | 升级 cryptography ≥46.0.6 | 0.5h |
| P1 | DEP-02 | 升级 pyopenssl ≥26.0.0 | 0.5h |
