[![build](https://github.com/linkdata/jawsauth/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/jawsauth/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/jawsauth/blob/gitcoverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/jawsauth/blob/gitcoverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/jawsauth?status.svg)](https://godoc.org/github.com/linkdata/jawsauth)

# jawsauth

OIDC and OAuth2 profile authentication for [JaWS](https://github.com/linkdata/jaws)
sessions. Both modes use authorization-code state and PKCE (S256). `Wrap` and
`Handler` require a login; `WrapAdmin` and `HandlerAdmin` also apply the
`SetAdmins` allowlist.

## Setup

`Config` requires `RedirectURL`, `Issuer` and `ClientID`. The issuer, endpoint
overrides, discovered endpoints and JWKS URI must use HTTPS;
`AllowInsecureIssuer` permits HTTP for tests and development. OIDC mode
discovers provider endpoints, verifies the ID token and nonce, and attempts
refresh before expiry when the provider issues a refresh token. Request offline
access with the `offline_access` scope for OIDC providers that support it, or
`oauth2.AccessTypeOffline` in `Server.Options` for Google. Check both the error
from `New` and `Server.Valid()` before serving protected routes; invalid servers
pass wrapped handlers through without authentication.

Profile mode requires `AuthURL`, `TokenURL` and `UserInfoURL`, plus a
`ProfileSubject` function that extracts a stable subject from the authenticated
profile. Profile mode sets the `iss` claim to `Issuer` and `sub` to the
`ProfileSubject` result. The `iss`+`sub` pair identifies an account, so use a
distinct `Issuer` for each provider. Email and names are not identity proof.
Profile JSON numbers arrive as `json.Number` to preserve large IDs. Profile
authentication expires after 24 hours or the access token's earlier expiry.
An explicit `expires_in: 0` in the token response is rejected.

Set `Jaws.MaxSessions` and `Jaws.MaxSessionsPerIP` to bound sessions created by
unauthenticated requests; both limits are unlimited by default. A login attempt
can retain an anonymous session for about ten minutes while the user visits the
provider. Login rotates the session and discards its application data; rotation
needs a free slot under both limits.
`MaxSessionsPerIP = 1` prevents login. If a slot is unavailable,
login returns 503 with `Retry-After: 60` and preserves the existing session.

## Multiple providers

- Give each `Config` a distinct `Namespace` and callback directory. Add each
  provider's registered paths to the other servers' `HandledPaths` so return
  targets cannot enter another provider's auth endpoints.
- `New` sets `Jaws.MakeAuth`. Install a composite `MakeAuth` if JaWS pages need
  data from several providers. Each server's `Wrap`, `Handler` and
  `CurrentClaims` check that provider's authentication.
- Register `HandleLink` as a POST handler to enable linking; `New` does not
  register it. Authorize the session before calling it. In `LinkEvent`, recheck
  the original provider's `CurrentClaims` before writing the link. Linking keeps
  the session; an ordinary login rotates it and signs out other providers.
  Their `LogoutEvent` may run later with a nil request.
- `New` gives each server a private `SessionRotationLock`. For cross-provider
  linking, assign one shared lock before serving. jawsauth holds it during
  flow start, rotation, authentication clearing and `LinkEvent`. Do not take it
  around jawsauth handlers or `Server.Logout`, or within `LinkEvent`; do not call
  `Server.Logout` from `LinkEvent`. Keep `LinkEvent` brief because other sessions
  sharing the lock wait. One provider's logout does not cancel another provider's
  pending link.

## Admin access

Profile mode requires a verified email for a non-empty admin list by default;
OIDC mode does not. Set `RequireVerifiedAdminEmail = true` in OIDC mode unless
the provider guarantees verified addresses. In profile mode, `ProfileSubject`
may map a provider verification signal to `email_verified`; disable the check
only with the same guarantee. Providers without a verification signal cannot
grant admin access while the check is enabled.
[Microsoft warns against using its email claim for authorization](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference);
use application policy based on a stable identifier for Entra ID.

`SetAdmins` parses valid addresses and compares them ignoring ASCII case. An
empty list allows every authenticated user through the admin handlers.
`Server.IsAdmin(email)` checks only list membership; `JawsAuth.IsAdmin` and the
admin handlers enforce email verification when required. Neither `IsAdmin`
method proves a live login; check `CurrentClaims` before protected actions.

## Session lifetime

Pending OAuth flows expire after ten minutes. jawsauth extends the original
JaWS session's grace while the user visits the provider. Unauthenticated
protected GET requests during a pending login redirect to the same provider
flow without replacing its state, return target or grace deadline. During a
running callback they return 409 unless `LoginFailed` handles them. Logout and
authentication expiry clear that server's credentials and reload its JaWS pages.
Auth expiry preserves a pending login but cancels a pending link. Explicit
logout cancels either flow. A new login on the same server, including one
started by `Wrap` or `Handler`, cancels a pending link.

Use an HTTP endpoint for a post-logout redirect. When `Server.Logout` clears
authentication, it reloads pages and closes their sockets, so a later JaWS
`Request.Redirect` cannot deliver the redirect.
