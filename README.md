[![build](https://github.com/linkdata/jawsauth/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/jawsauth/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/jawsauth/blob/gitcoverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/jawsauth/blob/gitcoverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/jawsauth?status.svg)](https://godoc.org/github.com/linkdata/jawsauth)

# jawsauth

OIDC and OAuth2 profile authentication for [JaWS](https://github.com/linkdata/jaws)
sessions. Both modes use authorization-code state and PKCE (S256). `Wrap` and
`Handler` require a login; `WrapAdmin` and `HandlerAdmin` also apply the
`SetAdmins` allowlist.

## Setup

`Config` requires `RedirectURL`, `Issuer` and `ClientID`. The issuer, effective
provider endpoints and JWKS URI must use HTTPS;
`AllowInsecureIssuer` permits HTTP for tests and development. OIDC mode
discovers provider endpoints, verifies the ID token and nonce, and attempts
refresh before expiry when the provider issues a refresh token. Request offline
access with the `offline_access` scope for OIDC providers that support it, or
`oauth2.AccessTypeOffline` in `Server.Options` for Google. Check both the error
from `New` and `Server.Valid()` before serving protected routes; an invalid server
can return handlers without authentication.

Profile mode requires `AuthURL`, `TokenURL` and `UserInfoURL`, plus a
`ProfileSubject` function that extracts a stable subject from the authenticated
profile. Profile mode sets the `iss` claim to `Issuer` and `sub` to the
`ProfileSubject` result. The `iss`+`sub` pair identifies an account, so use a
distinct `Issuer` for each provider. Email and names are not identity proof.
Profile JSON numbers arrive as `json.Number` to preserve large IDs. Profile
authentication expires after 24 hours or the access token's earlier expiry.
An explicit `expires_in: 0` in the token response is rejected.

Set `Jaws.MaxSessions` and `Jaws.MaxSessionsPerIP` to bound sessions created by
unauthenticated requests; both limits are unlimited by default. An unauthenticated
protected GET starts a login flow and can retain its session for about ten minutes
while the user visits the provider. Login rotates the session and discards its
application data; rotation needs a free slot under both limits.
`MaxSessionsPerIP = 1` prevents login. If a slot is unavailable,
login returns 503 with `Retry-After: 60` and preserves the existing session.

## Multiple providers

- Providers sharing JaWS must have distinct `Namespace` values and callback
  directories; a shared namespace can clear another provider's login. Add each
  provider's registered paths to the other servers' `HandledPaths` so return
  targets cannot enter another provider's auth endpoints.
- `New` replaces `Jaws.MakeAuth`. When servers share JaWS, capture `jw.MakeAuth`
  immediately after each `New`, then install a composite function so templates
  use the intended provider's authentication and admin policy. Each
  server's `Wrap`, `Handler` and `CurrentClaims` check that provider's
  authentication.
- Register `HandleLink` as a POST handler to enable linking; `New` does not
  register it. Authorize the session before calling it. In `LinkEvent`, recheck
  the original provider's `CurrentClaims` before writing the link. Linking keeps
  the session; an ordinary login rotates it and signs out other providers.
  A re-login replacing existing auth calls its `LogoutEvent` before storing
  the new sign-in. Calling `Logout` on that event session cancels it. Other
  providers' `LogoutEvent` may run later with a nil request.
  Starting a link replaces this server's pending flow, including a running
  login callback.
- `New` shares one process-wide `SessionRotationLock` by default. To coordinate
  with other authentication methods or isolate independent JaWS instances, set
  a custom lock before serving; servers sharing a JaWS must use the same lock.
  jawsauth holds it during flow start, rotation, authentication clearing and
  `LinkEvent`.
  Do not take the lock around jawsauth handlers or `Server.Logout`, or within
  `LinkEvent`; do not call `Server.Logout` from `LinkEvent`. Bound `LinkEvent` I/O
  with a timeout; other sessions sharing the lock wait. One provider's logout
  does not cancel another provider's pending link.

## Admin access

Profile mode requires a verified email for a non-empty admin list by default;
OIDC mode does not. Set `RequireVerifiedAdminEmail = true` in OIDC mode unless
the provider guarantees verified addresses. In profile mode, `ProfileSubject`
may map a provider verification signal to `email_verified`; disable the check
only with the same guarantee. Providers without a verification signal cannot
grant admin access while the check is enabled.
[Microsoft warns against using its email claim for authorization](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference);
use application policy based on a stable identifier for Entra ID.
OIDC UserInfo fallback requires its `sub` to match the ID token's nonempty `sub`. Its
`email_verified` applies only to an email it supplies or one matching the ID
token email exactly. `mail` and `public_email` never count as verified.

`SetAdmins` parses valid addresses and retains other nonempty entries. It trims
whitespace and ignores ASCII case. An empty list allows every authenticated user
through the admin handlers.
`Server.IsAdmin(email)` checks only list membership; `JawsAuth.IsAdmin` and the
admin handlers enforce email verification when required. Neither `IsAdmin`
method proves a live login; check `CurrentClaims` before protected actions.

## Session lifetime

Pending OAuth flows expire after ten minutes. jawsauth extends the original
JaWS session's grace while the user visits the provider. Unauthenticated
protected GETs reuse a pending login's state, return target and grace deadline
while more than two minutes remain; near expiry, they start a new flow and
extend grace. While a callback runs and before session rotation, protected GETs
with its session cookie return 409 unless `LoginFailed` handles them. After
rotation, the old cookie starts a new flow. Logout and auth expiry clear this
server's credentials and reload every JaWS page in the session.
Auth expiry preserves a pending login but cancels a pending link. Explicit
logout cancels either flow. A new login on the same server, including one
started by `Wrap` or `Handler`, cancels a pending link.

Use an HTTP endpoint for a post-logout redirect. When `Server.Logout` clears
authentication, it reloads pages and closes their sockets, so a later JaWS
`Request.Redirect` cannot deliver the redirect.
