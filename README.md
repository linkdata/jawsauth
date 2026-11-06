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
unauthenticated requests; both limits are unlimited by default. A login start,
including an unauthenticated protected GET, can retain its session for about ten
minutes even if the client never reaches the provider. By default, login keeps
the same session and its application data, so a one-session limit permits login.
Set `Server.RotateSessionOnLogin` before serving requests when an attacker can
make a victim use an attacker-known pre-login cookie, reach JaWS from the same
client IP JaWS sees for the victim, and cannot learn the later cookie.
Rotation discards pre-login application data and needs a free slot under both
limits; `MaxSessionsPerIP = 1` then prevents login. If a slot is unavailable,
login returns 503 with `Retry-After: 60` and preserves the existing session.

## Multiple providers

- Providers sharing JaWS must have distinct `Namespace` values and callback
  directories; a shared namespace can clear another provider's login. Add each
  provider's registered paths to the other servers' `HandledPaths` so return
  targets cannot enter another provider's auth endpoints.
- `New` replaces `Jaws.MakeAuth` when it configures authentication. When servers
  share JaWS, capture `jw.MakeAuth` immediately after each configured `New`, then
  install a composite function so templates use the intended provider's
  authentication and admin policy. Each
  server's `Wrap`, `Handler` and `CurrentClaims` check that provider's
  authentication.
- Register `HandleLink` as a POST handler to enable linking; `New` does not
  register it. Authorize the session before calling it. In `LinkEvent`, recheck
  the original provider's `CurrentClaims` before writing the link. Linking keeps
  the session; ordinary login keeps it and leaves other providers signed in.
  With `RotateSessionOnLogin`, login signs out other providers, and re-login
  calls its `LogoutEvent` on the old session before storing the new sign-in.
  Calling `Logout` on that event session cancels it. Other providers'
  `LogoutEvent` may run later with a nil request. Before using one to log out
  another provider, check its `CurrentClaims`.
  Starting a link replaces this server's pending flow, including a running
  login callback.
- `New` shares one process-wide `SessionRotationLock` by default. To coordinate
  with other authentication methods or isolate independent JaWS instances, set
  a custom lock before serving; servers sharing a JaWS must use the same lock.
  jawsauth holds it during flow start, rotation, in-place login claim storage,
  authentication clearing and `LinkEvent`.
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
JaWS session's grace for the pending flow. Unauthenticated
protected GETs reuse a pending login's state, return target and grace deadline
while more than two minutes remain; near expiry, they start a new flow and
extend grace. Once in-place login stores claims, protected GETs with that
session cookie return 409 until login notification completes, unless
`LoginFailed` handles them. `CurrentClaims` remains nil during that interval.
With `RotateSessionOnLogin`, the old cookie starts a new flow after
rotation and cannot cancel that sign-in. Without rotation, successful login
reloads active JaWS pages after `LoginEvent`. Logout and auth expiry clear this
server's credentials and reload every JaWS page in the session. Auth expiry
preserves a pending login but cancels a pending link. Explicit logout on the
live session cancels either flow. A new login on the same server, including
one started by `Wrap` or `Handler`, cancels a pending link.

Use an HTTP endpoint for a post-logout redirect. When `Server.Logout` clears
authentication, it reloads pages and closes their sockets, so a later JaWS
`Request.Redirect` cannot deliver the redirect.
