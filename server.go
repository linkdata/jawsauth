package jawsauth

//gosec:disable G117

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"github.com/linkdata/jaws/lib/ui"
	"golang.org/x/oauth2"
)

// ErrServerNilJaws is returned by New and NewDebug when the *jaws.Jaws
// argument is nil. Server methods dereference Server.Jaws and require it
// to be non-nil for the lifetime of the Server.
var ErrServerNilJaws = errors.New("jawsauth: nil *jaws.Jaws")

func normalizeEmail(s string) (email string) {
	if m, e := mail.ParseAddress(s); e == nil {
		s = m.Address
	}
	email = strings.ToLower(strings.TrimSpace(s))
	return
}

func callbackPathFromURL(u *url.URL) (callbackPath string) {
	rawPath := u.Path
	callbackPath = path.Clean(rawPath)
	if callbackPath == "" || callbackPath == "." {
		callbackPath = "/"
	} else if strings.HasSuffix(rawPath, "/") && callbackPath != "/" {
		callbackPath += "/"
	}
	return
}

// HandleFunc registers handler to serve requests for the given URI path.
//
// It matches the shape of http.ServeMux.Handle and is supplied to New and NewDebug
// so the login, logout and callback endpoints can be wired into the caller's router.
type HandleFunc func(uri string, handler http.Handler)

// EventFunc is called for login and logout lifecycle events.
//
// For a LogoutEvent triggered by an auth-refresh timer rather than an HTTP request,
// hr may be nil.
type EventFunc func(sess *jaws.Session, hr *http.Request)

// FailedFunc is called when a login attempt fails.
//
// It returns true if it wrote the HTTP response itself, in which case jawsauth writes
// nothing further.
type FailedFunc func(hw http.ResponseWriter, hr *http.Request, httpCode int, err error, email string) (wroteresponse bool)

// Server provides OIDC-verified authentication for JaWS sessions.
//
// Create one with New or NewDebug. Its methods are safe for concurrent use; the
// exported configuration fields and callbacks should be set before serving requests.
type Server struct {
	Jaws                    *jaws.Jaws
	SessionKey              string                  // default is "oidc_claims", value will be of type map[string]any
	SessionTokenKey         string                  // default is "oauth2_tokensource", value will be of type oauth2.TokenSource
	SessionEmailKey         string                  // default is "email", value will be of type string
	SessionEmailVerifiedKey string                  // default is "email_verified", value will be of type bool
	HandledPaths            map[string]struct{}     // URI paths we have registered handlers for
	LoginEvent              EventFunc               // if not nil, called after a successful login
	LogoutEvent             EventFunc               // if not nil, called before logout; hr may be nil for timer-driven logout
	LoginFailed             FailedFunc              // if not nil, called on failed login
	Options                 []oauth2.AuthCodeOption // options to use, see https://pkg.go.dev/golang.org/x/oauth2#AuthCodeOption
	oauth2cfg               *oauth2.Config
	idTokenVerifier         *oidc.IDTokenVerifier
	userinfoUrl             string
	httpClient              *http.Client
	ishttps                 bool
	mu                      sync.Mutex          // protects following
	admins                  map[string]struct{} // if not empty, emails of admins
	handle403               http.Handler        // handler for 403 Forbidden
	authTimers              map[uint64]*authTimerState
	authTimerAfterFunc      authTimerAfterFunc
}

// NewDebug behaves like New but can override the scheme and host of cfg.RedirectURL.
//
// overrideUrl supplies the replacement scheme and host (an empty overrideUrl disables
// the override), which is useful when serving behind a different public address during
// development.
//
// A nil jw returns ErrServerNilJaws and a nil Server. Otherwise a non-nil Server is
// always returned. OIDC is configured, and the login, logout and callback handlers
// registered via handleFn, only when cfg, handleFn and cfg.RedirectURL are all provided;
// any error from OIDC discovery is returned alongside the not-yet-Valid Server.
func NewDebug(jw *jaws.Jaws, cfg *Config, handleFn HandleFunc, overrideUrl string) (srv *Server, err error) {
	if jw == nil {
		err = ErrServerNilJaws
		return
	}
	srv = &Server{
		Jaws:                    jw,
		SessionKey:              "oidc_claims",
		SessionTokenKey:         "oauth2_tokensource",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
		HandledPaths:            make(map[string]struct{}),
		admins:                  make(map[string]struct{}),
		handle403:               default403handler{},
		authTimers:              make(map[uint64]*authTimerState),
		authTimerAfterFunc:      realAuthTimerAfterFunc,
	} // #nosec G101
	if cfg != nil && handleFn != nil && cfg.RedirectURL != "" {
		if srv.oauth2cfg, srv.userinfoUrl, srv.idTokenVerifier, err = cfg.buildContext(context.Background(), overrideUrl); err == nil {
			srv.httpClient = cfg.HTTPClient
			var u *url.URL
			if u, err = url.Parse(srv.oauth2cfg.RedirectURL); err == nil {
				srv.ishttps = (u.Scheme == "https")
				callbackPath := callbackPathFromURL(u)
				dir := path.Dir(path.Clean(callbackPath))
				srv.handlePath(callbackPath, handleFn, http.HandlerFunc(srv.HandleAuthResponse))
				srv.handlePath(path.Join(dir, "login"), handleFn, http.HandlerFunc(srv.HandleLogin))
				srv.handlePath(path.Join(dir, "logout"), handleFn, http.HandlerFunc(srv.HandleLogout))
				jw.MakeAuth = srv.makeAuth
			}
		}
	}
	return
}

// New creates a Server providing OIDC-verified authentication for JaWS sessions.
//
// It configures the Server from cfg and registers the login, logout and OAuth2
// callback endpoints via handleFn. A nil jw returns ErrServerNilJaws. Use Valid to
// test whether OIDC authentication was successfully configured.
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

// IsAdmin returns true if email belongs to an admin, if the list of admins is empty, or if srv is nil.
func (srv *Server) IsAdmin(email string) (yes bool) {
	yes = true
	if srv != nil {
		email = normalizeEmail(email)
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
		if srv.admins == nil {
			srv.admins = make(map[string]struct{})
		}
		clear(srv.admins)
		for _, s := range emails {
			if s = normalizeEmail(s); s != "" {
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

// Set403Handler sets the handler used to serve 403 Forbidden responses to
// authenticated non-admin users.
//
// A nil h restores the default handler. It is safe for concurrent use.
func (srv *Server) Set403Handler(h http.Handler) {
	if h == nil {
		h = default403handler{}
	}
	srv.mu.Lock()
	srv.handle403 = h
	srv.mu.Unlock()
}

func (srv *Server) get403Handler() (h http.Handler) {
	h = default403handler{}
	if srv != nil {
		srv.mu.Lock()
		if srv.handle403 != nil {
			h = srv.handle403
		}
		srv.mu.Unlock()
	}
	return
}

// Valid returns true if OIDC authentication is configured.
func (srv *Server) Valid() bool {
	return srv != nil && srv.oauth2cfg != nil && srv.idTokenVerifier != nil
}

// wrap returns a http.Handler that requires an authenticated user before invoking h.
//
// When admin is true the user must additionally be an administrator (see SetAdmins),
// otherwise the 403 handler is served. Unauthenticated requests are redirected into the
// OIDC login flow (HandleLogin), which verifies the id_token and stores the claims in
// srv.SessionKey (with optional UserInfo fallback) before the user returns. If the
// Server is not Valid, returns h.
func (srv *Server) wrap(h http.Handler, admin bool) (rh http.Handler) {
	rh = h
	if srv.Valid() {
		rh = wrapper{server: srv, handler: h, admin: admin}
	}
	return
}

// WrapAdmin returns a http.Handler that requires an authenticated administrator
// before invoking h.
//
// Unauthenticated requests are redirected into the OIDC login flow (HandleLogin);
// authenticated users whose email is not an admin (see SetAdmins and IsAdmin) are
// served the 403 handler instead of h. If the Server is not Valid, returns h.
func (srv *Server) WrapAdmin(h http.Handler) (rh http.Handler) {
	return srv.wrap(h, true)
}

// Wrap returns a http.Handler that requires an authenticated user before invoking h.
//
// Unauthenticated requests are redirected into the OIDC login flow (HandleLogin), which
// verifies the id_token and stores the claims in srv.SessionKey (with optional UserInfo
// fallback) before the user returns. If the Server is not Valid, returns h.
func (srv *Server) Wrap(h http.Handler) (rh http.Handler) {
	return srv.wrap(h, false)
}

// HandlerAdmin returns a http.Handler that renders the named jaws.Template with dot
// and requires an authenticated administrator.
//
// Unauthenticated requests are redirected into the OIDC login flow (HandleLogin);
// authenticated non-admins (see SetAdmins and IsAdmin) are served the 403 handler.
// If the Server is not Valid, the template handler is returned without the
// authentication requirement.
func (srv *Server) HandlerAdmin(name string, dot any) http.Handler {
	return srv.wrap(ui.Handler(srv.Jaws, name, dot), true)
}

// Handler returns a http.Handler that renders the named jaws.Template with dot
// and requires an authenticated user.
//
// Unauthenticated requests are redirected into the OIDC login flow (HandleLogin),
// which verifies the id_token and stores the claims in srv.SessionKey (with optional
// UserInfo fallback) before the user returns. If the Server is not Valid, the template
// handler is returned without the authentication requirement.
func (srv *Server) Handler(name string, dot any) http.Handler {
	return srv.wrap(ui.Handler(srv.Jaws, name, dot), false)
}
