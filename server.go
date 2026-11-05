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

func foldEmailCase(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

func normalizeEmail(s string) (email string) {
	s = strings.TrimSpace(s)
	if m, e := mail.ParseAddress(s); e == nil {
		s = m.Address
	}
	email = foldEmailCase(s)
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
// jawsauth calls [Server.LogoutEvent] after releasing SessionRotationLock.
// When LoginEvent is set, clearing auth before it begins suppresses both
// events; clearing auth during it defers LogoutEvent until it returns.
// LogoutEvent receives a nil request for timer cleanup, deferred delivery, or
// a call to [Server.Logout] with a nil request.
type EventFunc func(sess *jaws.Session, hr *http.Request)

// FailedFunc is called on callback failures and when a protected request meets
// a running login callback. Other flow-start failures write their own response.
//
// It returns true if it wrote the HTTP response itself, in which case jawsauth writes
// nothing further. Errors can contain untrusted browser-supplied text. Quote errors
// when logging them and escape them for the output format when rendering them.
type FailedFunc func(hw http.ResponseWriter, hr *http.Request, httpCode int, err error, email string) (wroteresponse bool)

// LinkFunc receives the current session and a newly authenticated identity. Recheck
// the existing authentication before a durable link write; with multiple
// providers, use the original provider's CurrentClaims. Logout and flow
// cancellation affect only their own Server. jawsauth holds
// SessionRotationLock while calling LinkFunc; do not acquire it again or call
// Server.Logout in the callback. Claims contain raw provider fields, so their
// types (including email_verified) may differ from stored session values.
// Return zero and nil on success, or an HTTP error status.
type LinkFunc func(sess *jaws.Session, hr *http.Request, claims map[string]any) (statusCode int, err error)

// Server provides OIDC or OAuth2 profile authentication for JaWS sessions.
//
// Create one with New or NewDebug. Its methods are safe for concurrent use; the
// exported configuration fields and callbacks should be set before serving requests.
type Server struct {
	Jaws *jaws.Jaws
	// New appends Config.Namespace to these four session keys when configured.
	SessionKey              string              // default is "oidc_claims", value will be of type map[string]any
	SessionTokenKey         string              // default is "oauth2_tokensource"; an oauth2.TokenSource in OIDC mode, unset in profile mode
	SessionEmailKey         string              // default is "email", value is a parsed string address with ASCII letters lowercased
	SessionEmailVerifiedKey string              // default is "email_verified", value will be of type bool
	HandledPaths            map[string]struct{} // URI paths excluded from OAuth return targets
	LoginEvent              EventFunc           // called after claims are stored; revocation may suppress or follow it
	LogoutEvent             EventFunc           // auth-clear callback; see EventFunc for ordering and nil requests
	LoginFailed             FailedFunc          // callback failures and protected requests during a running login callback
	LinkEvent               LinkFunc            // required by HandleLink; register its POST route separately
	// SessionRotationLock is held during flow start, rotation, auth clearing, and LinkEvent.
	// New supplies a private lock; share one when servers use the same JaWS instance.
	SessionRotationLock sync.Locker
	Options             []oauth2.AuthCodeOption // authorization URL options, e.g. oauth2.AccessTypeOffline; never sent to token exchange

	// RequireVerifiedAdminEmail requires email_verified for a non-empty admin list.
	//
	// It defaults to true in profile mode and false in OIDC mode. When true,
	// providers that omit email_verified cannot grant admin access through a
	// non-empty list. Set before serving requests.
	// Ordinary login is unaffected.
	RequireVerifiedAdminEmail bool

	oauth2cfg          *oauth2.Config
	idTokenVerifier    *oidc.IDTokenVerifier
	userinfoUrl        string
	profileSubject     func(map[string]any) (string, error)
	issuer             string
	httpClient         *http.Client
	ishttps            bool
	mu                 sync.Mutex          // protects following fields and session email/verification pairs
	admins             map[string]struct{} // if not empty, emails of admins
	handle403          http.Handler        // handler for 403 Forbidden
	authTimers         map[uint64]*authTimerState
	loginEvents        map[*jaws.Session]*pendingLoginEvent
	oauthCallbacks     map[*jaws.Session]pendingOAuthFlow
	authTimerAfterFunc authTimerAfterFunc
	namespace          string
}

// NewDebug behaves like New but can override the scheme and host of cfg.RedirectURL.
//
// overrideUrl supplies the replacement scheme and host (an empty overrideUrl disables
// the override), which is useful when serving behind a different public address during
// development.
//
// A nil jw returns ErrServerNilJaws and a nil Server. Otherwise a non-nil Server is
// always returned. Authentication is configured, and the login, logout and callback
// handlers registered via handleFn, only when cfg, handleFn and cfg.RedirectURL are
// all provided; setup errors are returned with the Server.
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
		SessionRotationLock:     &sync.Mutex{},
		admins:                  make(map[string]struct{}),
		handle403:               default403handler{},
		authTimers:              make(map[uint64]*authTimerState),
		authTimerAfterFunc:      realAuthTimerAfterFunc,
	} // #nosec G101
	if cfg != nil {
		srv.namespace = cfg.Namespace
		srv.issuer = cfg.Issuer
		srv.SessionKey = srv.sessionKey(srv.SessionKey)
		srv.SessionTokenKey = srv.sessionKey(srv.SessionTokenKey)
		srv.SessionEmailKey = srv.sessionKey(srv.SessionEmailKey)
		srv.SessionEmailVerifiedKey = srv.sessionKey(srv.SessionEmailVerifiedKey)
	}
	if cfg != nil && handleFn != nil && cfg.RedirectURL != "" {
		setupCtx, cancel := context.WithTimeout(context.Background(), oauth2ProviderTimeout)
		defer cancel()
		if srv.oauth2cfg, srv.userinfoUrl, srv.idTokenVerifier, err = cfg.buildContext(setupCtx, overrideUrl); err == nil {
			srv.httpClient = cfg.HTTPClient
			srv.profileSubject = cfg.ProfileSubject
			srv.RequireVerifiedAdminEmail = srv.profileSubject != nil
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

// New creates a Server providing OIDC or OAuth2 profile authentication for JaWS sessions.
//
// It configures the Server from cfg and registers the login, logout and OAuth2
// callback endpoints via handleFn. A nil jw returns ErrServerNilJaws. Check both
// err and Valid before serving protected routes; an invalid Server leaves its
// wrapped handlers unprotected.
func New(jw *jaws.Jaws, cfg *Config, handleFn HandleFunc) (srv *Server, err error) {
	return NewDebug(jw, cfg, handleFn, "")
}

func (srv *Server) makeAuth(rq *jaws.Request) jaws.Auth {
	return &JawsAuth{server: srv, sess: srv.Jaws.GetSession(rq.Initial())}
}

func (srv *Server) sessionKey(key string) string {
	if srv.namespace != "" {
		return key + "." + srv.namespace
	}
	return key
}

func (srv *Server) handlePath(p string, handleFn HandleFunc, h http.Handler) {
	if _, ok := srv.HandledPaths[p]; !ok {
		srv.HandledPaths[p] = struct{}{}
		handleFn(p, h)
	}
}

// IsAdmin returns true if email belongs to an admin, if the list of admins is empty, or if srv is nil.
//
// It parses a raw address using the rules in [Server.SetAdmins]. This lookup cannot
// verify email ownership. [Server.WrapAdmin], [Server.HandlerAdmin] and
// [JawsAuth.IsAdmin] also enforce [Server.RequireVerifiedAdminEmail].
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

func (srv *Server) sessionIsAdmin(sess *jaws.Session) bool {
	if srv == nil {
		return true
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.sessionIsAdminLocked(sess, srv.admins)
}

// Caller holds srv.mu.
func (srv *Server) sessionIsAdminLocked(sess *jaws.Session, admins map[string]struct{}) bool {
	if len(admins) == 0 {
		return true
	}
	if sess == nil {
		return false
	}
	email, _ := sess.Get(srv.SessionEmailKey).(string)
	verified, _ := sess.Get(srv.SessionEmailVerifiedKey).(bool)
	// Session emails are already parsed; parsing again can change quoted local parts.
	_, listed := admins[foldEmailCase(email)]
	return listed && (!srv.RequireVerifiedAdminEmail || verified)
}

// SetAdmins sets the emails of administrators.
//
// Valid addresses are parsed with [mail.ParseAddress]; other nonempty entries
// are retained. ASCII letters are lowercased.
// Non-ASCII characters are matched exactly. If empty, everyone is considered an
// administrator. Session checks also apply [Server.RequireVerifiedAdminEmail].
//
// Sessions losing admin access have their JaWS requests retired with a page reload;
// they remain authenticated and can reopen non-admin pages.
func (srv *Server) SetAdmins(emails []string) {
	if srv == nil {
		return
	}
	admins := make(map[string]struct{})
	for _, email := range emails {
		if email = normalizeEmail(email); email != "" {
			admins[email] = struct{}{}
		}
	}
	var sessions []*jaws.Session
	if srv.Jaws != nil {
		sessions = srv.Jaws.Sessions()
	}
	var requests []*jaws.Request
	srv.mu.Lock()
	for _, sess := range sessions {
		if sess.Get(srv.SessionKey) != nil && srv.sessionIsAdminLocked(sess, srv.admins) && !srv.sessionIsAdminLocked(sess, admins) {
			requests = append(requests, sess.Requests()...)
		}
	}
	srv.admins = admins
	srv.mu.Unlock()
	reloadAuthRequests(requests)
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

// Valid returns true if OIDC or OAuth2 profile authentication is configured.
func (srv *Server) Valid() bool {
	return srv != nil && srv.oauth2cfg != nil && (srv.idTokenVerifier != nil || srv.profileSubject != nil)
}

// wrap returns a http.Handler that requires an authenticated user before invoking h.
//
// When admin is true, non-admins receive 403. Unauthenticated GET begins login;
// other unauthenticated methods receive 403. An invalid Server returns h.
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
// Unauthenticated GET begins login; other unauthenticated methods receive 403.
// Authenticated non-admins receive 403. [Server.RequireVerifiedAdminEmail]
// applies. A GET request during a running login callback may return 409.
// An invalid Server returns h.
func (srv *Server) WrapAdmin(h http.Handler) (rh http.Handler) {
	return srv.wrap(h, true)
}

// Wrap returns a http.Handler that requires an authenticated user before invoking h.
//
// Unauthenticated GET begins login; other unauthenticated methods receive 403.
// A GET request during a running login callback may return 409.
// An invalid Server returns h.
func (srv *Server) Wrap(h http.Handler) (rh http.Handler) {
	return srv.wrap(h, false)
}

// HandlerAdmin returns a http.Handler that renders the named jaws.Template with dot
// and requires an authenticated administrator.
//
// Unauthenticated GET begins login; other unauthenticated methods receive 403.
// Authenticated non-admins receive 403. [Server.RequireVerifiedAdminEmail]
// applies. A GET request during a running login callback may return 409.
// An invalid, non-nil Server returns the unprotected template handler.
func (srv *Server) HandlerAdmin(name string, dot any) http.Handler {
	return srv.wrap(ui.Handler(srv.Jaws, name, dot), true)
}

// Handler returns a http.Handler that renders the named jaws.Template with dot
// and requires an authenticated user.
//
// Unauthenticated GET begins login; other unauthenticated methods receive 403.
// A GET request during a running login callback may return 409.
// An invalid, non-nil Server returns the unprotected template handler.
func (srv *Server) Handler(name string, dot any) http.Handler {
	return srv.wrap(ui.Handler(srv.Jaws, name, dot), false)
}
