package jawsauth

import (
	"net/http"
)

type wrapper struct {
	server  *Server
	handler http.Handler
	admin   bool
	auth    *JawsAuth
}

func (w wrapper) ServeHTTP(hw http.ResponseWriter, hr *http.Request) {
	h := w.handler
	sess := w.server.Jaws.GetSession(hr)
	if sess == nil {
		sess = w.server.Jaws.NewSession(hw, hr)
	}
	if sess.Get(w.server.SessionKey) == nil {
		w.server.HandleLogin(hw, hr)
		return
	}

	if w.admin {
		email, _ := sess.Get(w.server.SessionEmailKey).(string)
		if !w.server.IsAdmin(email) {
			h = w.server.handle403
		}
	}
	if w.auth != nil {
		w.auth.sess = sess
	}
	h.ServeHTTP(hw, hr)
}
