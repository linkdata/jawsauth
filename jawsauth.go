package jawsauth

import "github.com/linkdata/jaws"

type dotWrap struct {
	any
	JawsAuth *JawsAuth
}

type JawsAuth struct {
	server *Server
	sess   *jaws.Session
}

func (a *JawsAuth) Valid() (yes bool) {
	if a != nil {
		yes = a.server.Valid()
	}
	return
}

func (a *JawsAuth) Email() (s string) {
	if a != nil {
		s, _ = a.sess.Get(a.server.SessionEmailKey).(string)
	}
	return
}

func (a *JawsAuth) IsAdmin() (yes bool) {
	return a == nil || a.server.IsAdmin(a.Email())
}
