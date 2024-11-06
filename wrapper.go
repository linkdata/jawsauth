package jawsauth

import (
	"net/http"
)

type wrapper struct {
	server  *Server
	handler http.Handler
}

func (w wrapper) ServeHTTP(hw http.ResponseWriter, hr *http.Request) {
	sess := w.server.Jaws.GetSession(hr)
	if sess == nil {
		sess = w.server.Jaws.NewSession(hw, hr)
	}
	if sess.Get(w.server.SessionKey) == nil {
		w.server.HandleLogin(hw, hr)
		return
	}
	w.handler.ServeHTTP(hw, hr)
}
