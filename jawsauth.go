package jawsauth

import (
	"time"

	"github.com/linkdata/jaws"
)

// CurrentClaims returns this provider's live authentication claims.
//
// It returns nil until [Server.LoginEvent] completes for in-place login.
// It is useful when several providers share JaWS.
// Treat the returned map as read-only. The session may close, and an in-place
// login may change its identity or permissions after this call. Recheck the
// session and claims before protected writes.
func (srv *Server) CurrentClaims(sess *jaws.Session) map[string]any {
	if srv == nil || srv.Jaws == nil || srv.SessionKey == "" || sess == nil || sess.Jaws() != srv.Jaws {
		return nil
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.RotateSessionOnLogin && srv.loginEvents[sess] != nil {
		return nil
	}
	if current, _ := srv.sessionAuthStatus(sess, time.Now); !current {
		return nil
	}
	claims, _ := sess.Get(srv.SessionKey).(map[string]any)
	if !sessionAlive(sess) {
		return nil
	}
	return claims
}

// JawsAuth exposes authenticated session data to JaWS templates.
// Its zero value is safe to use and reports no user data.
type JawsAuth struct {
	server *Server
	sess   *jaws.Session
}

// Data returns the OIDC or OAuth2 profile claims stored in the session, or nil.
// It does not check expiry; use [Server.CurrentClaims] for access decisions.
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) Data() (x map[string]any) {
	if a != nil && a.server != nil && a.sess != nil {
		x, _ = a.sess.Get(a.server.SessionKey).(map[string]any)
	}
	return
}

// Email returns the email stored in the session, or an empty string.
//
// The value is a parsed address with ASCII letters lowercased.
// It does not check expiry; use [Server.CurrentClaims] for access decisions.
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) Email() (s string) {
	if a != nil && a.server != nil && a.sess != nil {
		s, _ = a.sess.Get(a.server.SessionEmailKey).(string)
	}
	return
}

// EmailVerified reports whether the session address came from a verified email claim.
//
// Addresses taken from mail or public_email claims are unverified.
// It does not check expiry; use [Server.CurrentClaims] for access decisions.
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) EmailVerified() (yes bool) {
	if a != nil && a.server != nil && a.sess != nil {
		yes, _ = a.sess.Get(a.server.SessionEmailVerifiedKey).(bool)
	}
	return
}

// IsAdmin reports whether the stored session email is an administrator.
//
// It applies [Server.RequireVerifiedAdminEmail] to non-empty admin lists.
// It does not check login expiry; use [Server.CurrentClaims] for access decisions.
// With an empty admin list, it can return true without a session.
// A nil or zero-value JawsAuth follows [Server.IsAdmin]'s nil-server behavior and returns true.
func (a *JawsAuth) IsAdmin() (yes bool) {
	if a == nil || a.server == nil {
		yes = true
	} else {
		yes = a.server.sessionIsAdmin(a.sess)
	}
	return
}
