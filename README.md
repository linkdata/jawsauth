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
Post-login return targets longer than 8192 bytes fall back to `/`.

Admin allowlists match parsed addresses with ASCII case ignored; non-ASCII
characters are matched exactly. Session email values use the same case rules.
Email verification is not required by default. This supports providers such as
Microsoft Entra ID that omit `email_verified`, but relies on the provider's policy
for who may claim an address. Microsoft [advises against using its email claim for
authorization](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference).
To require verified email for a non-empty admin allowlist, set
`Server.RequireVerifiedAdminEmail = true` before serving requests. This affects
`WrapAdmin`, `HandlerAdmin`, and `JawsAuth.IsAdmin`; ordinary login stays available.
Providers that omit the verification claim cannot grant admin access in this mode.
`Server.IsAdmin(email)` only checks address membership. `mail` and `public_email`
are always considered unverified; they can match the allowlist only when strict
mode is disabled.
An empty admin list allows every authenticated user through the HTTP admin gates.
UserInfo fallback requires a matching non-empty `sub`; its verification flag is
used only when that response supplies the email or confirms the exact same email
claim, including case and whitespace.

Successful login rotates the JaWS session and discards pre-login application data.
UserInfo is fetched before rotation so its latency does not consume the new
session's idle lifetime.
Rotation requires a free slot under both session limits until the new cookie is
published. In particular, `MaxSessionsPerIP = 1` prevents login; allow room for
rotation when setting limits. If no slot is available, the default response is 503
and the existing session's authentication and refresh timer are preserved.
Restart login after capacity becomes available.

Logout and auth expiry cancel the session's live JaWS requests. Protected renders
also recheck authorization when the HTTP handler returns, cancelling requests
attached to that session during a concurrent revocation. Already-running handlers
can finish; applications needing authorization at each event must recheck current
claims, expiry, and `JawsAuth.IsAdmin` before acting. Changing `SetAdmins` also cancels
every page of sessions that lose admin access; their ordinary login remains valid.
Clients reconnect and reload. Use an HTTP endpoint for logout redirects: calling
`Request.Redirect` after `Server.Logout` in a JaWS event cannot send the redirect
because that request has been cancelled. Closed or expired JaWS sessions have
their tokens and timers discarded at the next scheduled refresh, which calls
`LogoutEvent` with a nil HTTP request.
