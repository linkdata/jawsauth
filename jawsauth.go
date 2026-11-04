package jawsauth

import (
	"time"

	"github.com/linkdata/jaws"
)

// CurrentClaims returns this provider's claims only while authentication and
// the JaWS session are live. It is useful when several providers share JaWS.
// Treat the returned session map as read-only, and recheck before protected writes
// because the session may close after this call.
func (srv *Server) CurrentClaims(sess *jaws.Session) map[string]any {
	if srv == nil || srv.Jaws == nil || srv.SessionKey == "" || sess == nil || sess.Jaws() != srv.Jaws {
		return nil
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
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

// Data returns the verified OIDC or OAuth2 profile claims stored in the session, or nil.
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) Data() (x map[string]any) {
	if a != nil && a.server != nil && a.sess != nil {
		x, _ = a.sess.Get(a.server.SessionKey).(map[string]any)
	}
	return
}

// Email returns the authenticated email stored in the session, or an empty string.
//
// The value is a parsed address with ASCII letters lowercased.
// Use [JawsAuth.IsAdmin] to check administrator status.
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
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) EmailVerified() (yes bool) {
	if a != nil && a.server != nil && a.sess != nil {
		yes, _ = a.sess.Get(a.server.SessionEmailVerifiedKey).(bool)
	}
	return
}

// IsAdmin reports whether the authenticated email is an administrator.
//
// It applies [Server.RequireVerifiedAdminEmail] to non-empty admin lists.
// A nil or zero-value JawsAuth follows [Server.IsAdmin]'s nil-server behavior and returns true.
func (a *JawsAuth) IsAdmin() (yes bool) {
	if a == nil || a.server == nil {
		yes = true
	} else {
		yes = a.server.sessionIsAdmin(a.sess)
	}
	return
}
