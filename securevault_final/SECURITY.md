# Security Policy — SecureVault

## Supported Versions

| Version | Supported |
|---------|-----------|
| 3.x     | ✅ Yes    |
| 2.x     | ⚠️ Critical fixes only |
| < 2.0   | ❌ No     |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Email: `security@securevault.local` (academic project — contact the EMSI team)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and issue a patch within 7 days for critical issues.

## Security Architecture

### Zero-Knowledge Design
The server **never** has access to the master password, the encryption key, or plaintext vault
contents. Keys are derived **in the browser** (WebCrypto) and the master password never leaves the
device — only `Auth_Hash = SHA-256(K_auth)` and the opaque encrypted blob are transmitted.

```
Master Password (browser only)
     │
     ▼
[PBKDF2-SHA256 600k / Argon2id]  ──► 512 bits
     ├─ K_enc  (bits 0-255)  ──► AES-256-GCM ──► opaque blob ──► SQLite (server)
     └─ K_auth (bits 256-511) ──► SHA-256 = Auth_Hash ──► constant-time compare (server)
```

### Cryptographic Choices

| Primitive | Algorithm | Parameters |
|-----------|-----------|------------|
| KDF (recommended) | Argon2id | m=64MB, t=3, p=4 |
| KDF (legacy) | PBKDF2-HMAC-SHA256 | 600,000 iterations |
| Symmetric encryption | AES-256-GCM | 96-bit random nonce per operation (client-side) |
| Auth proof (server-verified) | SHA-256(K_auth) | constant-time comparison |
| Token signing | RS256 (RSA) | 2048-bit key pair, asymmetric |

### Transport Security
- All production traffic over TLS 1.3 (enforced via Nginx)
- HSTS with 2-year max-age and `preload` flag
- CORS restricted to same origin

### Content Security Policy
Per-request nonces eliminate `unsafe-inline` from script-src and style-src. No external scripts are
loaded (all JS is self-hosted; charts are rendered with self-contained SVG). `frame-ancestors 'none'`,
`base-uri 'self'`, `form-action 'self'`.

### Authentication
- JWT (RS256) with 15-minute expiry
- Token rotation on refresh (old JTI blacklisted in Redis / in-memory fallback)
- Immediate blacklisting on logout
- 5 failed login attempts → 5-minute account lockout (in-memory + per-username)
- Timing-safe comparisons throughout (hmac.compare_digest)

### Rate Limiting
- Per-IP sliding-window limiter on all endpoints
- Stricter limits on auth endpoints (10 register / 60 s, 10 login / 60 s, 30 salt / 60 s)
- Redis-backed in production; in-memory fallback for development

### Memory Safety
- Cryptographic keys zeroed from memory after use (ctypes.memset)
- Master password never logged, never stored server-side, never included in JWT

## Known Limitations

1. **Vault blob size**: The entire vault is one encrypted blob, decrypted/re-encrypted client-side on
   every write — O(n) in entries. For very large vaults (1000+ entries) per-entry encryption could help.
2. **At-rest file encryption (SQLCipher)**: Not enabled in the local demo (`pysqlcipher3` is heavy on
   Windows). This is *not* a confidentiality gap — the stored blobs are already client-encrypted.
   SQLCipher (AES-256-CBC, kdf_iter 256000) is recommended as defense-in-depth in production.
3. **Argon2id in the browser**: Active when a `hash-wasm` module is loaded; otherwise it transparently
   falls back to native PBKDF2-SHA256 (600k iterations). The stored `kdf` reflects the algorithm used.
4. **In-memory rate limiting**: State is lost on restart; Redis backs it in production.

> ✅ *Resolved since the design review:* the master password is no longer sent to the server
> (previously via `X-Master-Password`). All key derivation and encryption now run in the browser.
