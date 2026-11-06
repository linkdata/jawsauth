package jawsauth

import "net/http"

type wrapper struct {
	server  *Server
	handler http.Handler
	admin   bool
}

func (w wrapper) ServeHTTP(hw http.ResponseWriter, hr *http.Request) {
	sess := w.server.Jaws.GetSession(hr)
	current, present, pending, entry := w.server.sessionAccessStatus(sess)
	if pending {
		if hr.Method == http.MethodGet {
			if w.server.LoginFailed != nil {
				email, _ := sess.Get(w.server.SessionEmailKey).(string)
				if w.server.LoginFailed(hw, hr, http.StatusConflict, ErrOAuth2LoginInProgress, email) {
					return
				}
			}
			w.server.writeResult(hw, http.StatusConflict, ErrOAuth2LoginInProgress)
		} else {
			w.server.writeResult(hw, http.StatusForbidden, nil)
		}
		return
	}
	if !current {
		if present {
			w.server.clearSessionAuth(sess, hr, nil, true)
		}
		if hr.Method != http.MethodGet {
			w.server.writeResult(hw, http.StatusForbidden, nil)
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
	// Revocation or in-place re-login may take a request snapshot before rendering
	// attaches a new JaWS request. Retire it before this response completes.
	if current, _, pending, latestEntry := w.server.sessionAccessStatus(sess); !current || pending || latestEntry != entry || (w.admin && !w.server.sessionIsAdmin(sess)) {
		reloadAuthRequests(sess.Requests())
	}
}
