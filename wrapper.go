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
	sess := w.server.Jaws.GetSession(hr)
	if current, present := w.server.sessionAuthStatus(sess, time.Now); !current {
		if present {
			w.server.clearSessionAuth(sess, hr, nil, true)
		}
		if hr.Method != http.MethodGet {
			w.server.writeResult(hw, http.StatusForbidden, nil, nil)
			return
		}
		w.server.startOAuth(hw, hr, false, true)
		return
	}

	if w.admin && !w.server.sessionIsAdmin(sess) {
		w.server.get403Handler().ServeHTTP(hw, hr)
		return
	}
	w.handler.ServeHTTP(hw, hr)
	// A revocation may have taken its request snapshot before rendering attached
	// a new JaWS request. Retire that request before this response completes.
	if current, _ := w.server.sessionAuthStatus(sess, time.Now); !current || (w.admin && !w.server.sessionIsAdmin(sess)) {
		reloadAuthRequests(sess.Requests())
	}
}
