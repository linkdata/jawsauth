package jawsauth

import (
	"net/http"
	"net/url"

	"github.com/linkdata/deadlock"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

type Server struct {
	*jaws.Jaws
	SessionKey   string
	OverrideURL  string
	mu           deadlock.Mutex
	cfg          Config
	oauth2cfg    *oauth2.Config
	redirectPath string
}

func New(jw *jaws.Jaws) (srv *Server) {
	srv = &Server{
		Jaws:       jw,
		SessionKey: "user",
	}
	return
}

type HandleFunc func(uri string, handler http.Handler)

func (srv *Server) SetConfig(cfg *Config, handleFn HandleFunc) (err error) {
	if err = cfg.Validate(); err == nil {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		srv.cfg = *cfg
		if srv.oauth2cfg, err = srv.cfg.Build(srv.OverrideURL); err == nil {
			var u *url.URL
			if u, err = url.Parse(srv.oauth2cfg.RedirectURL); err == nil {
				srv.redirectPath = u.Path
				handleFn(u.Path, http.HandlerFunc(srv.HandleAuthResponse))
			}
		}
	}
	return
}

// Wrap returns a http.Handler that requires an authenticated user before invoking h.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
func (srv *Server) Wrap(h http.Handler) http.Handler {
	return wrapper{server: srv, handler: h}
}

// Handler returns a http.Handler using a jaws.Template that requires an authenticated user.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
func (srv *Server) Handler(name string, dot any) http.Handler {
	return srv.Wrap(srv.Jaws.Handler(name, dot))
}
