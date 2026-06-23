// Package jawsauth provides OIDC-verified authentication for JaWS HTTP sessions.
//
// It uses OIDC discovery from a configured issuer to run the OAuth2
// authorization-code flow with PKCE and nonce verification, verifies the
// returned id_token, and stores the identity claims in the JaWS session. It
// also refreshes the id_token in the background before it expires and supports
// gating handlers to administrator emails.
//
// Create a [Server] with [New] (or [NewDebug]) and protect handlers with
// [Server.Wrap], [Server.WrapAdmin], [Server.Handler] or [Server.HandlerAdmin].
package jawsauth
