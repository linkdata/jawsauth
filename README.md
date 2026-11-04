[![build](https://github.com/linkdata/jawsauth/actions/workflows/go.yml/badge.svg)](https://github.com/linkdata/jawsauth/actions/workflows/go.yml)
[![coverage](https://github.com/linkdata/jawsauth/blob/gitcoverage/main/badge.svg)](https://html-preview.github.io/?url=https://github.com/linkdata/jawsauth/blob/gitcoverage/main/report.html)
[![Docs](https://godoc.org/github.com/linkdata/jawsauth?status.svg)](https://godoc.org/github.com/linkdata/jawsauth)

# jawsauth

OIDC and OAuth2 profile authentication for [JaWS](https://github.com/linkdata/jaws)
sessions. Both modes use authorization-code state and PKCE (S256). `Wrap` and
`Handler` require a login; `WrapAdmin` and `HandlerAdmin` also apply the
`SetAdmins` allowlist.

## Setup

`Config` requires `RedirectURL`, `Issuer` and `ClientID`. OIDC mode discovers
provider endpoints, verifies the ID token and nonce, and attempts refresh before
expiry when the provider issues a refresh token. Providers that issue refresh
tokens only with offline access can use
`Server.Options = []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}`.

Profile mode requires `AuthURL`, `TokenURL` and `UserInfoURL` over HTTPS, plus a
`ProfileSubject` function that extracts a stable subject from the authenticated
profile. HTTP endpoints require `AllowInsecureIssuer` for development. Email
and names are not identity proof. Profile JSON numbers arrive as `json.Number`
to preserve large IDs. Profile authentication expires after 24 hours or the
access token's earlier expiry.

Set `Jaws.MaxSessions` and `Jaws.MaxSessionsPerIP` to bound sessions created by
unauthenticated requests. A login attempt can retain an anonymous session for
ten minutes while the user visits the provider. Login rotates the session and
discards its application data; rotation needs a free slot under both limits.
In particular, `MaxSessionsPerIP = 1` prevents login. If a slot is unavailable,
login returns 503 with `Retry-After: 60` and preserves the existing session.

## Multiple providers

- Give each `Config` a distinct `Namespace` and callback directory. Add each
  provider's registered paths to the other servers' `HandledPaths` so return
  targets cannot enter another provider's auth endpoints.
- `New` installs that provider's `Jaws.MakeAuth`. Install a composite `MakeAuth`
  if JaWS pages need data from several providers. Each server's `Wrap` and
  `Handler` require its own authentication; `CurrentClaims` checks that
  provider's live claims.
- `HandleLink` is an opt-in POST handler. Authorize the existing session before
  calling it, then recheck the original provider's `CurrentClaims` in
  `LinkEvent` before writing the link. A link keeps the session; an ordinary
  login rotates it and signs out the other providers.
- `New` gives each server a private `SessionRotationLock`. For cross-provider
  linking, give the involved servers one shared lock before serving. jawsauth
  holds it during logout, expiry and `LinkEvent`, so do not acquire it around
  `Server.Logout` or inside `LinkEvent`; keep the callback brief. Logout of one
  provider does not cancel another provider's pending link, which must recheck
  the original authentication.

## Admin access

Email verification is optional by default. With a non-empty admin list, set
`Server.RequireVerifiedAdminEmail = true` unless the provider guarantees
verified addresses. Profile providers can map their verification signal to
`email_verified` in `ProfileSubject`; providers without such a signal cannot
grant admin access in strict mode. Some providers omit `email_verified`.
[Microsoft warns against using its email claim for authorization](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference);
use application policy based on a stable identifier for Entra ID.

`SetAdmins` compares parsed email addresses with ASCII case ignored. An empty
list allows every authenticated user through the admin handlers.
`Server.IsAdmin(email)` checks only list membership; `JawsAuth.IsAdmin` and the
admin handlers enforce email verification when required.

## Session lifetime

Pending OAuth flows expire after ten minutes. jawsauth extends the original
JaWS session's grace while the user visits the provider. Logout and
authentication expiry clear that server's credentials and reload the session's
JaWS pages. Auth expiry preserves a pending login but cancels a pending link;
explicit logout cancels either flow. Protected operations should check
`CurrentClaims`, plus `JawsAuth.IsAdmin` for administrator actions. Protected
requests during a callback may return 409.

Use an HTTP endpoint for a post-logout redirect. `Server.Logout` reloads pages
and closes their sockets, so a later JaWS `Request.Redirect` cannot deliver the
redirect.
