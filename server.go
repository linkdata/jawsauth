package jawsauth

import (
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"

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
	mu              sync.Mutex          // protects following
	admins          map[string]struct{} // if not empty, emails of admins
	handle403       http.Handler        // handler for 403 Forbidden
}

func NewDebug(jw *jaws.Jaws, cfg *Config, handleFn HandleFunc, overrideUrl string) (srv *Server, err error) {
	srv = &Server{
		Jaws:            jw,
		SessionKey:      "oauth2userinfo",
		SessionEmailKey: "email",
		HandledPaths:    make(map[string]struct{}),
		admins:          make(map[string]struct{}),
		handle403:       default403handler{},
	}
	if cfg != nil && handleFn != nil && cfg.RedirectURL != "" {
		jw.MakeAuth = srv.makeAuth
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

func (srv *Server) makeAuth(rq *jaws.Request) jaws.Auth {
	return &JawsAuth{server: srv, sess: srv.Jaws.GetSession(rq.Initial())}
}

func (srv *Server) handlePath(p string, handleFn HandleFunc, h http.Handler) {
	if _, ok := srv.HandledPaths[p]; !ok {
		srv.HandledPaths[p] = struct{}{}
		handleFn(p, h)
	}
}

// IsAdmin returns true if email belongs to an admin or if the list of admins is empty or the server is not valod.
func (srv *Server) IsAdmin(email string) (yes bool) {
	yes = true
	if srv != nil {
		srv.mu.Lock()
		_, yes = srv.admins[email]
		yes = yes || len(srv.admins) == 0
		srv.mu.Unlock()
	}
	return
}

// SetAdmins sets the emails of administrators. If empty, everyone is considered an administrator.
func (srv *Server) SetAdmins(emails []string) {
	if srv != nil {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		clear(srv.admins)
		for _, s := range emails {
			if m, e := mail.ParseAddress(s); e == nil {
				s = m.Address
			}
			if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
				srv.admins[s] = struct{}{}
			}
		}
	}
}

// GetAdmins returns a sorted list of the administrator emails. If empty, everyone is considered an administrator.
func (srv *Server) GetAdmins() (emails []string) {
	if srv != nil {
		srv.mu.Lock()
		for k := range srv.admins {
			emails = append(emails, k)
		}
		srv.mu.Unlock()
		sort.Strings(emails)
	}
	return
}

func (srv *Server) Set403Handler(h http.Handler) {
	if h == nil {
		h = default403handler{}
	}
	srv.mu.Lock()
	srv.handle403 = h
	srv.mu.Unlock()
}

// Valid returns true if OAuth2 is configured.
func (srv *Server) Valid() bool {
	return srv != nil && srv.oauth2cfg != nil
}

// Wrap returns a http.Handler that requires an authenticated user before invoking h.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
// If the Server is not Valid, returns h.
func (srv *Server) wrap(h http.Handler, admin bool) (rh http.Handler) {
	rh = h
	if srv.Valid() {
		rh = wrapper{server: srv, handler: h, admin: admin}
	}
	return
}

// WrapAdmin returns a http.Handler that requires an authenticated user
// having an email set using SetAdmins() before invoking h.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
// If the Server is not Valid, returns h.
func (srv *Server) WrapAdmin(h http.Handler) (rh http.Handler) {
	return srv.wrap(h, true)
}

// Wrap returns a http.Handler that requires an authenticated user before invoking h.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
// If the Server is not Valid, returns h.
func (srv *Server) Wrap(h http.Handler) (rh http.Handler) {
	return srv.wrap(h, false)
}

// HandlerAdmin returns a http.Handler using a jaws.Template that requires an authenticated user
// having an email set using SetAdmins() before invoking h.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
func (srv *Server) HandlerAdmin(name string, dot any) http.Handler {
	return srv.wrap(srv.Jaws.Handler(name, dot), true)
}

// Handler returns a http.Handler using a jaws.Template that requires an authenticated user.
// Sets the jaws Session value srv.SessionKey to what UserInfoURL returned.
func (srv *Server) Handler(name string, dot any) http.Handler {
	return srv.wrap(srv.Jaws.Handler(name, dot), false)
}
