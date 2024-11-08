package jawsauth

import (
	"net/http"
	"net/url"
	"path"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

type HandleFunc func(uri string, handler http.Handler)

type EventFunc func(sess *jaws.Session, hr *http.Request)

type Server struct {
	Jaws            *jaws.Jaws
	SessionKey      string              // default is "oauth2userinfo", value will be of type map[string]any
	SessionEmailKey string              // default is "email", value will be of type string
	HandledPaths    map[string]struct{} // URI paths we have registered handlers for
	LoginEvent      EventFunc           // if not nil, called after a successful login
	LogoutEvent     EventFunc           // if not nil, called before logout
	oauth2cfg       *oauth2.Config
	userinfoUrl     string
}

func NewDebug(jw *jaws.Jaws, cfg *Config, handleFn HandleFunc, overrideUrl string) (srv *Server, err error) {
	srv = &Server{
		Jaws:            jw,
		SessionKey:      "oauth2userinfo",
		SessionEmailKey: "email",
		HandledPaths:    make(map[string]struct{}),
	}
	if cfg != nil && handleFn != nil && cfg.RedirectURL != "" {
		if srv.oauth2cfg, err = cfg.Build(overrideUrl); err == nil {
			var u *url.URL
			if u, err = url.Parse(srv.oauth2cfg.RedirectURL); err == nil {
				srv.handlePath(u.Path, handleFn, http.HandlerFunc(srv.HandleAuthResponse))
				srv.handlePath(path.Join(path.Dir(u.Path), "login"), handleFn, http.HandlerFunc(srv.HandleLogin))
				srv.handlePath(path.Join(path.Dir(u.Path), "logout"), handleFn, http.HandlerFunc(srv.HandleLogout))
				srv.userinfoUrl = cfg.UserInfoURL
			}
		}
	}
	return
}

func New(jw *jaws.Jaws, cfg *Config, handleFn HandleFunc) (srv *Server, err error) {
	return NewDebug(jw, cfg, handleFn, "")
}

func (srv *Server) handlePath(p string, handleFn HandleFunc, h http.Handler) {
	if _, ok := srv.HandledPaths[p]; !ok {
		srv.HandledPaths[p] = struct{}{}
		handleFn(p, h)
	}
}

// Valid returns true if OAuth2 is configured.
func (srv *Server) Valid() bool {
	return srv.oauth2cfg != nil
}

// Wrap returns a http.Handler that requires an authenticated user before invoking h.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
// If the Server is not Valid, returns h.
func (srv *Server) Wrap(h http.Handler) (rh http.Handler) {
	rh = h
	if srv.Valid() {
		rh = wrapper{server: srv, handler: h}
	}
	return
}

// Handler returns a http.Handler using a jaws.Template that requires an authenticated user.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
func (srv *Server) Handler(name string, dot any) http.Handler {
	return srv.Wrap(srv.Jaws.Handler(name, dot))
}
