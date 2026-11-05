// Package jawsauth provides OIDC and OAuth2 profile authentication for JaWS sessions.
//
// OIDC mode uses discovery, PKCE, nonce and ID token verification. Profile mode
// uses explicit provider endpoints, PKCE and an authenticated profile response
// with an application-supplied subject extractor. The resulting claims are
// stored in a JaWS session. OIDC attempts refresh before expiry; profile auth
// expires after a bounded lifetime. Both modes support admin email gates.
//
// Create a [Server] with [New] (or [NewDebug]) and protect handlers with
// [Server.Wrap], [Server.WrapAdmin], [Server.Handler] or [Server.HandlerAdmin].
package jawsauth
