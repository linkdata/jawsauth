package jawsauth

import (
	"net/http"
	"time"
)

type wrapper struct {
	server  *Server
	handler http.Handler
	admin   bool
}

func (w wrapper) ServeHTTP(hw http.ResponseWriter, hr *http.Request) {
	h := w.handler
	sess := w.server.Jaws.GetSession(hr)
	if current, present := w.server.sessionAuthStatus(sess, time.Now); !current {
		if present {
			w.server.clearSessionAuth(sess, hr, true, false, nil)
		}
		w.server.HandleLogin(hw, hr)
		return
	}

	if w.admin {
		if !w.server.sessionIsAdmin(sess) {
			h = w.server.get403Handler()
		}
	}
	h.ServeHTTP(hw, hr)
}
