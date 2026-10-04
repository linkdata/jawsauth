[![build](https://github.com/linkdata/jawsauth/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/jawsauth/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/jawsauth/blob/gitcoverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/jawsauth/blob/gitcoverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/jawsauth?status.svg)](https://godoc.org/github.com/linkdata/jawsauth)

# jawsauth

OIDC-verified authentication for [JaWS](https://github.com/linkdata/jaws) sessions.

- Requires an OIDC-compliant provider.
- Uses OIDC discovery from the configured issuer.
- Verifies `id_token` and stores identity claims in session data.
- Adds PKCE (S256) and OIDC nonce verification to the authorization-code flow.
- Automatically refreshes the `id_token` in the background before it expires.
- Supports admin-only handlers: `Wrap`/`Handler` for any authenticated user, `WrapAdmin`/`HandlerAdmin` gated by `SetAdmins`.

Protected routes create JaWS sessions for unauthenticated visitors. Set
`Jaws.MaxSessions` and `Jaws.MaxSessionsPerIP` to bound session counts. When a
session cannot be created, login returns 503 with `Retry-After: 60`.
Post-login return targets longer than 2048 bytes fall back to `/`.

Admin allowlists trust the configured identity provider's email claims by default,
including providers such as Microsoft Entra ID that omit `email_verified`.
To require verified email for a non-empty admin allowlist, set
`Server.RequireVerifiedAdminEmail = true` before serving requests. This affects
`WrapAdmin`, `HandlerAdmin`, and `JawsAuth.IsAdmin`; ordinary login stays available.
`Server.IsAdmin(email)` only checks address membership. With strict mode enabled,
`mail` and `public_email` remain display fallbacks but cannot establish verified
email ownership. An empty admin list continues to allow every authenticated user.
UserInfo fallback requires a matching non-empty `sub`; its verification flag is
used only when that response supplies or confirms the same email.
