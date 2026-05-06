package jawsauth

import "github.com/linkdata/jaws"

// JawsAuth exposes authenticated session data to JaWS templates.
// Its zero value is safe to use and reports no user data.
type JawsAuth struct {
	server *Server
	sess   *jaws.Session
}

// Data returns the verified OIDC claims stored in the session, or nil.
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) Data() (x map[string]any) {
	if a != nil && a.server != nil && a.sess != nil {
		x, _ = a.sess.Get(a.server.SessionKey).(map[string]any)
	}
	return
}

// Email returns the authenticated email stored in the session, or an empty string.
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) Email() (s string) {
	if a != nil && a.server != nil && a.sess != nil {
		s, _ = a.sess.Get(a.server.SessionEmailKey).(string)
	}
	return
}

// EmailVerified returns whether the authenticated email was marked verified.
// It is safe to call on a nil or zero-value JawsAuth.
func (a *JawsAuth) EmailVerified() (yes bool) {
	if a != nil && a.server != nil && a.sess != nil {
		yes, _ = a.sess.Get(a.server.SessionEmailVerifiedKey).(bool)
	}
	return
}

// IsAdmin reports whether the authenticated email is an administrator.
// A nil or zero-value JawsAuth follows Server.IsAdmin's nil-server behavior and returns true.
func (a *JawsAuth) IsAdmin() (yes bool) {
	if a == nil || a.server == nil {
		yes = true
	} else {
		yes = a.server.IsAdmin(a.Email())
	}
	return
}
