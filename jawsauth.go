package jawsauth

import "github.com/linkdata/jaws"

type JawsAuth struct {
	server *Server
	sess   *jaws.Session
}

func (a *JawsAuth) Data() (x map[string]any) {
	if a != nil {
		x, _ = a.sess.Get(a.server.SessionKey).(map[string]any)
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
