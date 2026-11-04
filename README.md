[![build](https://github.com/linkdata/jawsauth/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/jawsauth/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/jawsauth/blob/gitcoverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/jawsauth/blob/gitcoverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/jawsauth?status.svg)](https://godoc.org/github.com/linkdata/jawsauth)

# jawsauth

Verified OIDC or OAuth2 profile authentication for [JaWS](https://github.com/linkdata/jaws) sessions.

- OIDC mode discovers the issuer, verifies `id_token` and nonce, and refreshes before expiry.
- Profile mode accepts explicit HTTPS endpoints and a `Config.ProfileSubject` verifier for providers without ID tokens. Its authenticated profile response must contain a stable subject; email and names are not identity proof. JSON numbers arrive as `json.Number` so large numeric IDs remain exact.
- Both modes use authorization-code state and PKCE (S256). Pending flows expire after ten minutes; jawsauth extends only that JaWS session's grace while the user visits the provider.
- For OIDC providers that require an offline-access request to issue refresh tokens, set `Server.Options = []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}` before serving. This adds `access_type=offline` to the authorization redirect, not the token request.
- Profile authentication expires after 24 hours or the provider token's earlier expiry; it does not attempt OIDC refresh.
- Supports admin-only handlers: `Wrap`/`Handler` for any authenticated user, `WrapAdmin`/`HandlerAdmin` gated by `SetAdmins`.

Protected routes create JaWS sessions for unauthenticated visitors. Set
`Jaws.MaxSessions` and `Jaws.MaxSessionsPerIP` to bound session counts. When a
session cannot be created, login returns 503 with `Retry-After: 60`.
Post-login return targets longer than 8192 bytes fall back to `/`.
Login callback token/profile calls and startup discovery have a 15-second deadline;
OIDC background refresh requests have the same maximum timeout.
profile responses are capped at 32 KiB.

For multiple providers on one JaWS instance, give each `Config` a distinct
`Namespace` and callback directory (for example, `/oauth/github/callback` and
`/oauth/gitlab/callback`). `New` sets `Jaws.MakeAuth` for its own Server, so
install a composite `MakeAuth` after creating all provider Servers if pages need
to recognize more than one provider. Use `Server.CurrentClaims` to check each
provider's live session auth there. `HandleLink` is an opt-in POST handler:
authorize the existing session before calling it, then set `Server.LinkEvent` to
recheck the original identity and accept the newly verified subject. A successful
link keeps the original session; ordinary login still rotates it. Link callbacks
run only while the original JaWS session and one-use flow state remain valid.
Successful linking keeps the session whose idle grace was extended for the
provider visit. With no connected pages, that authenticated session can retain
that grace until the original flow's grace deadline, about ten minutes plus
the callback allowance after link start. `LinkEvent` must serialize its final
current-auth check and durable link write with logout and any other provider's
auth revocation. Set each provider's `SessionRotationLock` to the same lock so
ordinary login callbacks serialize JaWS session replacement with that write;
the original session is rechecked inside that lock, and the lock is not held
during provider requests. jawsauth cannot roll back an
application write if revocation finishes while `LinkEvent` is running; it
rejects the stale callback response.

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

Logout and auth expiry clear authentication and reload the session's JaWS pages.
Auth expiry preserves an ordinary login in progress but cancels a pending link;
explicit logout cancels either flow.
Protected requests during a pending login return 409 instead of replacing that flow.
Connected pages receive the reload command before their sockets close; pending
pages reload when they connect. Protected renders also recheck authorization when
the HTTP handler returns, retiring requests attached during a concurrent revocation.
Events and callbacks run normally until disconnection. Protected operations must
check current claims and expiry, plus `JawsAuth.IsAdmin` for administrator actions.
Changing `SetAdmins` also reloads every page of sessions that lose admin access;
their ordinary login remains valid.
Use an HTTP endpoint for logout redirects: calling `Request.Redirect` after
`Server.Logout` in a JaWS event cannot send the redirect because Reload closes the
connection and discards later messages. Closed or expired JaWS sessions have their
tokens and timers discarded at the next auth timer check (normally within one
minute), which calls
`LogoutEvent` with a nil HTTP request.
