package jawsauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func profileTestResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestOAuthProfileConfigRequiresExplicitSecureEndpoints(t *testing.T) {
	cfg := &Config{RedirectURL: "https://app.example/auth/callback", Issuer: "https://provider.example",
		AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token",
		UserInfoURL: "https://provider.example/user", ClientID: "app",
		ProfileSubject: func(map[string]any) (string, error) { return "42", nil }}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.UserInfoURL = ""
	if err := cfg.Validate(); !errors.Is(err, ErrConfigMissingValue) {
		t.Fatalf("missing profile URL: %v", err)
	}
	cfg.UserInfoURL = "http://provider.example/user"
	if err := cfg.Validate(); !errors.Is(err, ErrConfigEndpointMustBeHTTPS) {
		t.Fatalf("insecure profile URL: %v", err)
	}
}

func TestOAuthProfileConfigInsecureModeAllowsHTTPOnly(t *testing.T) {
	base := Config{RedirectURL: "https://app.example/auth/callback", Issuer: "https://provider.example",
		AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token",
		UserInfoURL: "https://provider.example/user", ClientID: "app", AllowInsecureIssuer: true,
		ProfileSubject: func(map[string]any) (string, error) { return "42", nil }}
	for _, tc := range []struct {
		name string
		set  func(*Config)
		want error
	}{
		{"issuer", func(c *Config) { c.Issuer = "ftp://provider.example" }, ErrConfigIssuerMustBeHTTPS},
		{"authorize", func(c *Config) { c.AuthURL = "ftp://provider.example/authorize" }, ErrConfigEndpointMustBeHTTPS},
		{"token", func(c *Config) { c.TokenURL = "ftp://provider.example/token" }, ErrConfigEndpointMustBeHTTPS},
		{"userinfo", func(c *Config) { c.UserInfoURL = "ftp://provider.example/user" }, ErrConfigEndpointMustBeHTTPS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.set(&cfg)
			if err := cfg.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("scheme validation: %v", err)
			}
		})
	}
	base.Issuer = "http://provider.example"
	base.AuthURL = "http://provider.example/authorize"
	base.TokenURL = "http://provider.example/token"
	base.UserInfoURL = "http://provider.example/user"
	if err := base.Validate(); err != nil {
		t.Fatalf("HTTP dev endpoints: %v", err)
	}
}

func TestOAuthProfileAuthLifetimeCapsLongProviderToken(t *testing.T) {
	srv := &Server{issuer: "https://provider.example", userinfoUrl: "https://provider.example/user",
		profileSubject: func(map[string]any) (string, error) { return "42", nil }}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return profileTestResponse(`{"id":42}`), nil
	})})
	for _, duration := range []time.Duration{30 * time.Minute, 72 * time.Hour} {
		token := &oauth2.Token{AccessToken: "secret", TokenType: "Bearer", Expiry: time.Now().Add(duration)}
		_, _, expiry, status, err := srv.verifyOAuthIdentity(ctx, token, "")
		if err != nil || status != http.StatusUnauthorized {
			t.Fatalf("duration %s: status=%d error=%v", duration, status, err)
		}
		want := min(duration, 24*time.Hour)
		if diff := time.Until(expiry) - want; diff < -time.Second || diff > time.Second {
			t.Fatalf("duration %s: expiry offset %s", duration, diff)
		}
	}
}

func TestOAuthProfileCallbackStateIsSingleUseConcurrently(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Path == "/token" {
			return profileTestResponse(`{"access_token":"secret","token_type":"Bearer"}`), nil
		}
		return profileTestResponse(`{"id":42}`), nil
	})}
	srv, err := New(jw, &Config{Namespace: "one", RedirectURL: "https://app.example/auth/callback",
		Issuer: "https://provider.example", AuthURL: "https://provider.example/authorize",
		TokenURL: "https://provider.example/token", UserInfoURL: "https://provider.example/user",
		ClientID: "app", HTTPClient: client,
		ProfileSubject: func(map[string]any) (string, error) { return "42", nil }}, func(string, http.Handler) {})
	if err != nil {
		t.Fatal(err)
	}
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	responses := make(chan int, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			responses <- profileCallback(srv, cookie, state, "first").Code
		}()
	}
	workers.Wait()
	close(responses)
	seen := map[int]int{}
	for code := range responses {
		seen[code]++
	}
	if seen[http.StatusFound] != 1 || seen[http.StatusBadRequest] != 1 || calls.Load() != 2 {
		t.Fatalf("concurrent replay: statuses=%v provider_calls=%d", seen, calls.Load())
	}
}

type rotationNoticeLock struct {
	mu      sync.Mutex
	entered chan struct{}
	once    sync.Once
}

func (l *rotationNoticeLock) Lock() {
	l.once.Do(func() { close(l.entered) })
	l.mu.Lock()
}

func (l *rotationNoticeLock) Unlock() { l.mu.Unlock() }

func TestOAuthProfileRotationLockDoesNotBlockProvider(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	providerReached := make(chan struct{})
	srv.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			close(providerReached)
			return profileTestResponse(`{"access_token":"proof","token_type":"Bearer"}`), nil
		}
		return profileTestResponse(`{"id":42}`), nil
	})}
	lock := &rotationNoticeLock{entered: make(chan struct{})}
	srv.SessionRotationLock = lock
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	oldRequest := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	oldRequest.AddCookie(cookie)
	old := jw.GetSession(oldRequest)
	lock.mu.Lock()
	release := sync.OnceFunc(func() { lock.mu.Unlock() })
	defer release()
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- profileCallback(srv, cookie, state, "proof") }()
	waitFor(t, providerReached, "provider request blocked by session rotation lock")
	waitFor(t, lock.entered, "callback did not reach session rotation")
	if jw.GetSession(oldRequest) != old {
		t.Fatal("session rotated before acquiring lock")
	}
	release()
	response := waitFor(t, result, "callback did not finish after rotation lock released")
	if response.Code != http.StatusFound || len(response.Result().Cookies()) != 1 || jw.GetSession(oldRequest) != nil {
		t.Fatalf("callback after rotation lock: status=%d cookies=%v", response.Code, response.Result().Cookies())
	}
}

func TestOAuthFailedCallbackDoesNotEraseNewFlow(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseCallback()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			if r.PostForm.Get("code") == "first" {
				enterOnce.Do(func() { close(entered) })
				<-release
				return nil, errors.New("provider unavailable")
			}
			return profileTestResponse(`{"access_token":"secret","token_type":"Bearer"}`), nil
		}
		return profileTestResponse(`{"id":42}`), nil
	})}
	srv, err := New(jw, &Config{Namespace: "one", RedirectURL: "https://app.example/auth/callback",
		Issuer: "https://provider.example", AuthURL: "https://provider.example/authorize",
		TokenURL: "https://provider.example/token", UserInfoURL: "https://provider.example/user",
		ClientID: "app", HTTPClient: client,
		ProfileSubject: func(map[string]any) (string, error) { return "42", nil }}, func(string, http.Handler) {})
	if err != nil {
		t.Fatal(err)
	}
	cookie, firstState := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	firstResult := make(chan int, 1)
	go func() { firstResult <- profileCallback(srv, cookie, firstState, "first").Code }()
	waitFor(t, entered, "first callback did not reach provider")
	r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Referer", "https://app.example/second")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.HandleLogin(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("second start: %d", w.Code)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	secondState := location.Query().Get("state")
	releaseCallback()
	if code := waitFor(t, firstResult, "failed callback did not finish"); code == http.StatusFound {
		t.Fatal("failed callback signed in")
	}
	sess := jw.GetSession(r)
	if sess == nil || testOAuthFlow(sess, srv).state != secondState ||
		testOAuthFlow(sess, srv).referrer != "/second" {
		t.Fatal("failed callback erased the newer flow")
	}
	second := profileCallback(srv, cookie, secondState, "second")
	if second.Code != http.StatusFound || second.Header().Get("Location") != "/second" {
		t.Fatalf("second callback: status=%d location=%q", second.Code, second.Header().Get("Location"))
	}
}

func TestOAuthProfileCallbackCanceledBeforeRotation(t *testing.T) {
	for _, action := range []string{"logout", "new flow"} {
		t.Run(action, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			calls := 0
			srv := newProfileTestServer(t, jw, &calls)
			srv.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/token" {
					close(entered)
					<-release
					return profileTestResponse(`{"access_token":"first-token","token_type":"Bearer"}`), nil
				}
				return profileTestResponse(`{"id":42,"email":"first@example.com"}`), nil
			})}
			logins := 0
			srv.LoginEvent = func(*jaws.Session, *http.Request) { logins++ }
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			request := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
			request.RemoteAddr = "192.0.2.1:1234"
			request.AddCookie(cookie)
			sess := jw.GetSession(request)
			if sess == nil {
				t.Fatal("missing pre-auth session")
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- profileCallback(srv, cookie, state, "first") }()
			waitFor(t, entered, "callback did not reach provider")

			var nextState string
			if action == "logout" {
				if !srv.Logout(sess, nil) {
					t.Fatal("logout did not clear session")
				}
			} else {
				start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
				start.RemoteAddr = "192.0.2.1:1234"
				start.AddCookie(cookie)
				w := httptest.NewRecorder()
				srv.HandleLogin(w, start)
				if w.Code != http.StatusFound {
					t.Fatalf("new flow start: %d", w.Code)
				}
				location, err := url.Parse(w.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				nextState = location.Query().Get("state")
				if nextState == "" || nextState == state {
					t.Fatalf("new flow state = %q", nextState)
				}
			}

			releaseOnce.Do(func() { close(release) })
			var w *httptest.ResponseRecorder
			w = waitFor(t, result, "canceled callback did not finish")
			if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 || logins != 0 {
				t.Fatalf("canceled callback: status=%d cookies=%v logins=%d", w.Code, w.Result().Cookies(), logins)
			}
			storedState := testOAuthFlow(sess, srv).state
			if sess.Get(srv.SessionKey) != nil || storedState != nextState {
				t.Fatalf("canceled callback changed session or new flow: claims=%v state=%v", sess.Get(srv.SessionKey), storedState)
			}
		})
	}
}

func TestOAuthProfileLinkCanceledByLogout(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	srv.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			if r.PostForm.Get("code") == "second" {
				close(entered)
				<-release
			}
			return profileTestResponse(`{"access_token":"first-token","token_type":"Bearer"}`), nil
		}
		return profileTestResponse(`{"id":42,"email":"first@example.com"}`), nil
	})}
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	login := profileCallback(srv, cookie, state, "first")
	if login.Code != http.StatusFound || len(login.Result().Cookies()) != 1 {
		t.Fatalf("initial login: status=%d cookies=%v", login.Code, login.Result().Cookies())
	}
	cookie = login.Result().Cookies()[0]
	request := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.AddCookie(cookie)
	sess := jw.GetSession(request)
	if sess == nil || sess.Get(srv.SessionKey) == nil {
		t.Fatal("missing authenticated session")
	}
	links := 0
	srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
		links++
		return 0, nil
	}
	_, linkState := profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- profileCallback(srv, cookie, linkState, "second") }()
	waitFor(t, entered, "link callback did not reach provider")
	if !srv.Logout(sess, nil) {
		t.Fatal("logout did not clear linked session")
	}
	releaseOnce.Do(func() { close(release) })
	var w *httptest.ResponseRecorder
	w = waitFor(t, result, "canceled link callback did not finish")
	if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 || links != 0 || sess.Get(srv.SessionKey) != nil {
		t.Fatalf("canceled link: status=%d cookies=%v links=%d claims=%v", w.Code, w.Result().Cookies(), links, sess.Get(srv.SessionKey))
	}
}

func TestOAuthProfileLinkRevokedDuringEventRejectsCallback(t *testing.T) {
	for _, action := range []string{"logout", "auth expiry"} {
		t.Run(action, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			calls := 0
			srv := newProfileTestServer(t, jw, &calls)
			factory := &testAuthTimerFactory{}
			srv.authTimerAfterFunc = factory.after
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			first := profileCallback(srv, cookie, state, "first")
			if first.Code != http.StatusFound {
				t.Fatalf("initial login: %d", first.Code)
			}
			cookie = first.Result().Cookies()[0]
			r := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.AddCookie(cookie)
			sess := jw.GetSession(r)
			if sess == nil || sess.Get(srv.SessionKey) == nil {
				t.Fatal("missing original authentication")
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			links := 0
			srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
				links++
				close(entered)
				<-release
				return 0, nil
			}
			_, linkState := profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- profileCallback(srv, cookie, linkState, "second") }()
			waitFor(t, entered, "LinkEvent was not reached")
			if action == "logout" {
				if !srv.Logout(sess, nil) {
					t.Fatal("logout failed")
				}
			} else {
				srv.mu.Lock()
				srv.authTimers[sess.ID()].expiry = time.Now().Add(-time.Second)
				srv.mu.Unlock()
				factory.timer(0).fire()
			}
			releaseOnce.Do(func() { close(release) })
			var response *httptest.ResponseRecorder
			response = waitFor(t, result, "revoked link callback did not finish")
			if response.Code != http.StatusForbidden || response.Header().Get("Location") != "" ||
				len(response.Result().Cookies()) != 0 || links != 1 || sess.Get(srv.SessionKey) != nil {
				t.Fatalf("revoked link: status=%d location=%q cookies=%v links=%d claims=%v",
					response.Code, response.Header().Get("Location"), response.Result().Cookies(), links, sess.Get(srv.SessionKey))
			}
		})
	}
}

type observedRotationLock struct {
	sync.Mutex
	attempts atomic.Int32
	second   chan struct{}
}

func (lock *observedRotationLock) Lock() {
	if lock.attempts.Add(1) == 2 {
		close(lock.second)
	}
	lock.Mutex.Lock()
}

func TestOAuthProfileLinkSerializesManagedRevocation(t *testing.T) {
	for _, revocation := range []string{"timer", "wrapper", "handler logout"} {
		for _, revocationFirst := range []bool{false, true} {
			name := revocation + "/event first"
			if revocationFirst {
				name = revocation + "/revocation first"
			}
			t.Run(name, func(t *testing.T) {
				jw, err := jaws.New()
				if err != nil {
					t.Fatal(err)
				}
				defer jw.Close()
				calls := 0
				srv := newProfileTestServer(t, jw, &calls)
				factory := &testAuthTimerFactory{}
				srv.authTimerAfterFunc = factory.after
				cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
				first := profileCallback(srv, cookie, state, "first")
				if first.Code != http.StatusFound {
					t.Fatalf("initial login: %d", first.Code)
				}
				cookie = first.Result().Cookies()[0]
				req := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
				req.RemoteAddr = "192.0.2.1:1234"
				req.AddCookie(cookie)
				sess := jw.GetSession(req)
				lock := &observedRotationLock{second: make(chan struct{})}
				srv.SessionRotationLock = lock
				var logoutEvents atomic.Int32
				srv.LogoutEvent = func(*jaws.Session, *http.Request) {
					lock.Lock()
					logoutEvents.Add(1)
					lock.Unlock()
				}
				checked := make(chan struct{})
				release := make(chan struct{})
				releaseEvent := sync.OnceFunc(func() { close(release) })
				defer releaseEvent()
				writes := 0
				srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
					lock.Lock()
					defer lock.Unlock()
					if current, _ := srv.sessionAuthStatus(sess, time.Now); !current {
						return http.StatusForbidden, ErrOAuth2MissingSession
					}
					close(checked)
					<-release
					writes++ // durable application write
					return 0, nil
				}
				_, linkState := profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
				revoke := func() {
					switch revocation {
					case "timer":
						srv.mu.Lock()
						srv.authTimers[sess.ID()].expiry = time.Now().Add(-time.Second)
						srv.mu.Unlock()
						factory.timer(0).fire()
					case "wrapper":
						sess.Set(srv.sessionKey(oauth2AuthExpiryKey), time.Now().Add(-time.Second))
						wrapper{server: srv}.ServeHTTP(httptest.NewRecorder(), req)
					case "handler logout":
						srv.HandleLogout(httptest.NewRecorder(), req)
					}
				}
				if revocationFirst {
					revoke()
					response := profileCallback(srv, cookie, linkState, "second")
					if response.Code < http.StatusBadRequest || writes != 0 || logoutEvents.Load() != 1 {
						t.Fatalf("revocation won: status=%d writes=%d logout events=%d", response.Code, writes, logoutEvents.Load())
					}
					return
				}
				callbackDone := make(chan *httptest.ResponseRecorder, 1)
				go func() { callbackDone <- profileCallback(srv, cookie, linkState, "second") }()
				waitFor(t, checked, "link did not check current auth")
				revoked := make(chan struct{})
				go func() { revoke(); close(revoked) }()
				waitFor(t, lock.second, "revocation did not reach rotation lock")
				select {
				case <-revoked:
					t.Fatal("revocation completed before durable link write")
				default:
				}
				releaseEvent()
				waitFor(t, revoked, "revocation did not finish after link write")
				waitFor(t, callbackDone, "link callback did not finish")
				if writes != 1 || logoutEvents.Load() != 1 {
					t.Fatalf("durable link writes = %d, logout events = %d", writes, logoutEvents.Load())
				}
			})
		}
	}
}

func TestOAuthProfileAuthExpiryPreservesOrdinaryLogin(t *testing.T) {
	for _, phase := range []string{"pending", "callback"} {
		t.Run(phase, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			calls := 0
			srv := newProfileTestServer(t, jw, &calls)
			factory := &testAuthTimerFactory{}
			srv.authTimerAfterFunc = factory.after
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			first := profileCallback(srv, cookie, state, "first")
			if first.Code != http.StatusFound {
				t.Fatalf("initial login: %d", first.Code)
			}
			cookie = first.Result().Cookies()[0]
			start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
			start.RemoteAddr = "192.0.2.1:1234"
			start.AddCookie(cookie)
			sess := jw.GetSession(start)
			if sess == nil {
				t.Fatal("missing original session")
			}
			redirect := httptest.NewRecorder()
			srv.HandleLogin(redirect, start)
			if redirect.Code != http.StatusFound {
				t.Fatalf("new login start: %d", redirect.Code)
			}
			location, err := url.Parse(redirect.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			state = location.Query().Get("state")
			if state == "" {
				t.Fatal("missing new login state")
			}
			var result chan *httptest.ResponseRecorder
			var releaseOnce sync.Once
			var release chan struct{}
			if phase == "callback" {
				entered := make(chan struct{})
				release = make(chan struct{})
				defer releaseOnce.Do(func() { close(release) })
				transport := srv.httpClient.Transport
				srv.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/token" {
						if err := r.ParseForm(); err != nil {
							return nil, err
						}
						if r.PostForm.Get("code") == "second" {
							close(entered)
							<-release
						}
					}
					return transport.RoundTrip(r)
				})}
				result = make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- profileCallback(srv, cookie, state, "second") }()
				waitFor(t, entered, "new login callback did not reach token exchange")
			}
			srv.mu.Lock()
			srv.authTimers[sess.ID()].expiry = time.Now().Add(-time.Second)
			srv.mu.Unlock()
			factory.timer(0).fire()
			if sess.Get(srv.SessionKey) != nil {
				t.Fatal("expired original auth remained")
			}
			if phase == "pending" && testOAuthFlow(sess, srv).state != state {
				t.Fatal("auth expiry erased pending login state")
			}
			if phase == "callback" {
				protected := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
				protected.RemoteAddr = start.RemoteAddr
				protected.AddCookie(cookie)
				conflict := httptest.NewRecorder()
				srv.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatal("pending callback reached protected handler")
				})).ServeHTTP(conflict, protected)
				if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), ErrOAuth2LoginInProgress.Error()) {
					t.Fatalf("pending callback: status=%d body=%q", conflict.Code, conflict.Body.String())
				}
			}
			var response *httptest.ResponseRecorder
			if phase == "callback" {
				releaseOnce.Do(func() { close(release) })
				response = waitFor(t, result, "new login callback did not finish")
			} else {
				response = profileCallback(srv, cookie, state, "second")
			}
			if response.Code != http.StatusFound || len(response.Result().Cookies()) != 1 {
				t.Fatalf("new login: status=%d cookies=%v body=%q", response.Code, response.Result().Cookies(), response.Body.String())
			}
			check := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
			check.RemoteAddr = "192.0.2.1:1234"
			check.AddCookie(response.Result().Cookies()[0])
			rotated := jw.GetSession(check)
			if rotated == nil || rotated == sess || rotated.Get(srv.SessionKey).(map[string]any)["sub"] != "99" {
				t.Fatal("new login did not authenticate a fresh session")
			}
		})
	}
}

func newProfileTestServer(t *testing.T, jw *jaws.Jaws, calls *int) *Server {
	t.Helper()
	client := &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*calls++
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil || r.PostForm.Get("code_verifier") == "" {
				return nil, errors.New("missing PKCE verifier")
			}
			if r.PostForm.Get("code") == "second" {
				return profileTestResponse(`{"access_token":"second-token","token_type":"Bearer"}`), nil
			}
			return profileTestResponse(`{"access_token":"first-token","token_type":"Bearer"}`), nil
		case "/user":
			switch r.Header.Get("Authorization") {
			case "Bearer first-token":
				return profileTestResponse(`{"id":9007199254740993,"login":"first","email":"first@example.com"}`), nil
			case "Bearer second-token":
				return profileTestResponse(`{"id":99,"login":"second"}`), nil
			}
		}
		return nil, errors.New("unexpected provider request")
	})}
	srv, err := New(jw, &Config{
		Namespace: "github", RedirectURL: "https://app.example/auth/callback", Issuer: "https://provider.example",
		AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token",
		UserInfoURL: "https://provider.example/user", ClientID: "app", ClientSecret: "secret",
		Scopes: []string{"read:user"}, HTTPClient: client,
		ProfileSubject: func(claims map[string]any) (string, error) {
			id, ok := claims["id"].(json.Number)
			if !ok {
				return "", ErrOAuth2InvalidProfile
			}
			value, err := strconv.ParseUint(string(id), 10, 64)
			if err != nil || value == 0 {
				return "", ErrOAuth2InvalidProfile
			}
			return string(id), nil
		},
	}, func(string, http.Handler) {})
	if err != nil || !srv.Valid() {
		t.Fatalf("profile server: %v", err)
	}
	return srv
}

func profileStart(t *testing.T, srv *Server, method, path string, cookie *http.Cookie) (*http.Cookie, string) {
	t.Helper()
	r := httptest.NewRequest(method, "https://app.example"+path, nil)
	r.RemoteAddr = "192.0.2.1:1234"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	if method == http.MethodPost {
		srv.HandleLink(w, r)
	} else {
		srv.HandleLogin(w, r)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("start %s: %d %s", path, w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("state") == "" {
		t.Fatalf("provider redirect: %v %q", err, w.Header().Get("Location"))
	}
	if method == http.MethodGet {
		if strings.Contains(location.RawQuery, "openid") || location.Query().Has("nonce") {
			t.Fatalf("profile flow sent OIDC-only parameters: %s", location)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("session cookies: %d", len(cookies))
		}
		cookie = cookies[0]
	}
	return cookie, location.Query().Get("state")
}

func profileCallback(srv *Server, cookie *http.Cookie, state, code string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state="+url.QueryEscape(state)+"&code="+code, nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.HandleAuthResponse(w, r)
	return w
}

func TestOAuthProfileSignInAndDualProofLink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		calls := 0
		srv := newProfileTestServer(t, jw, &calls)
		logins, links := 0, 0
		srv.LoginEvent = func(*jaws.Session, *http.Request) { logins++ }
		oldCookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
		wrong := profileCallback(srv, oldCookie, "wrong", "first")
		if wrong.Code != http.StatusBadRequest || calls != 0 {
			t.Fatalf("wrong state consumed login: status=%d calls=%d", wrong.Code, calls)
		}
		time.Sleep(61 * time.Second)
		first := profileCallback(srv, oldCookie, state, "first")
		if first.Code != http.StatusFound || logins != 1 || calls != 2 {
			t.Fatalf("first sign-in: status=%d logins=%d calls=%d", first.Code, logins, calls)
		}
		newCookies := first.Result().Cookies()
		if len(newCookies) != 1 {
			t.Fatalf("rotated cookies: %d", len(newCookies))
		}
		cookie := newCookies[0]
		request := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
		request.RemoteAddr = "192.0.2.1:1234"
		request.AddCookie(cookie)
		sess := jw.GetSession(request)
		claims, _ := sess.Get(srv.SessionKey).(map[string]any)
		if claims["sub"] != "9007199254740993" || claims["iss"] != "https://provider.example" || claims["email"] != "first@example.com" {
			t.Fatalf("verified profile: %#v", claims)
		}
		srv.LinkEvent = func(current *jaws.Session, _ *http.Request, newClaims map[string]any) (int, error) {
			links++
			if current != sess || current.Get(srv.SessionKey).(map[string]any)["sub"] != "9007199254740993" || newClaims["sub"] != "99" {
				return http.StatusForbidden, errors.New("proof mismatch")
			}
			return 0, nil
		}
		_, linkState := profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
		time.Sleep(61 * time.Second)
		linked := profileCallback(srv, cookie, linkState, "second")
		if linked.Code != http.StatusFound || links != 1 || logins != 1 || calls != 4 || len(linked.Result().Cookies()) != 0 {
			t.Fatalf("link: status=%d links=%d logins=%d calls=%d", linked.Code, links, logins, calls)
		}
		if jw.GetSession(request) != sess || sess.Get(srv.SessionKey).(map[string]any)["sub"] != "9007199254740993" {
			t.Fatal("link replaced the original proof")
		}
		replayed := profileCallback(srv, cookie, linkState, "second")
		if replayed.Code != http.StatusBadRequest || calls != 4 || links != 1 {
			t.Fatalf("replay: status=%d calls=%d links=%d", replayed.Code, calls, links)
		}
	})
}

func TestOAuthProfileExpiredLinkStateNeverCallsProvider(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	oldCookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, oldCookie, state, "first")
	cookie := first.Result().Cookies()[0]
	srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
		t.Fatal("expired link reached link event")
		return 0, nil
	}
	_, linkState := profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
	r := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.AddCookie(cookie)
	sess := jw.GetSession(r)
	flow := testOAuthFlow(sess, srv)
	flow.expiry = time.Now().Add(-time.Second)
	setTestOAuthFlow(sess, srv, flow)
	before := calls
	response := profileCallback(srv, cookie, linkState, "second")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), ErrOAuth2ExpiredState.Error()) || calls != before {
		t.Fatalf("expired: status=%d calls=%d body=%q", response.Code, calls, response.Body.String())
	}
}

func TestOAuthLinkRequiresSessionAndSameOriginRequestAndRejectsDeclinedLink(t *testing.T) {
	for _, reject := range []struct {
		name string
		err  error
	}{
		{name: "explicit error", err: errors.New("secret persistence detail")},
		{name: "status alone"},
	} {
		t.Run(reject.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			calls := 0
			srv := newProfileTestServer(t, jw, &calls)
			missing := httptest.NewRequest(http.MethodPost, "https://app.example/auth/link/github", nil)
			missing.RemoteAddr = "192.0.2.1:1234"
			w := httptest.NewRecorder()
			srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
				return http.StatusForbidden, reject.err
			}
			srv.HandleLink(w, missing)
			if w.Code != http.StatusForbidden || calls != 0 {
				t.Fatalf("anonymous link: status=%d calls=%d", w.Code, calls)
			}
			oldCookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			first := profileCallback(srv, oldCookie, state, "first")
			if first.Code != http.StatusFound {
				t.Fatalf("first sign-in: %d", first.Code)
			}
			cookie := first.Result().Cookies()[0]
			cross := httptest.NewRequest(http.MethodPost, "https://app.example/auth/link/github", nil)
			cross.RemoteAddr = "192.0.2.1:1234"
			cross.Header.Set("Origin", "https://evil.example")
			cross.AddCookie(cookie)
			w = httptest.NewRecorder()
			srv.HandleLink(w, cross)
			if w.Code != http.StatusForbidden || calls != 2 {
				t.Fatalf("cross-origin link: status=%d calls=%d", w.Code, calls)
			}
			_, linkState := profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
			declined := profileCallback(srv, cookie, linkState, "second")
			if declined.Code != http.StatusForbidden || declined.Header().Get("Location") != "" ||
				!strings.Contains(declined.Body.String(), ErrOAuth2LinkRejected.Error()) ||
				strings.Contains(declined.Body.String(), "secret persistence detail") || len(declined.Result().Cookies()) != 0 {
				t.Fatalf("declined link: status=%d body=%q", declined.Code, declined.Body.String())
			}
			r := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.AddCookie(cookie)
			sess := jw.GetSession(r)
			if sess == nil || sess.Get(srv.SessionKey).(map[string]any)["sub"] != "9007199254740993" {
				t.Fatal("declined link changed original proof")
			}
		})
	}
}

func TestOAuthProfileRejectsInvalidSubjectAndOversizedResponse(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	srv.profileSubject = func(map[string]any) (string, error) { return "", ErrOAuth2InvalidProfile }
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	response := profileCallback(srv, cookie, state, "first")
	if response.Code != http.StatusUnauthorized || calls != 2 || len(response.Result().Cookies()) != 0 {
		t.Fatalf("invalid subject: status=%d calls=%d", response.Code, calls)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.AddCookie(cookie)
	if sess := jw.GetSession(request); sess == nil || sess.Get(srv.SessionKey) != nil {
		t.Fatal("invalid profile authenticated the preauth session")
	}
	oversized := &Server{profileSubject: srv.profileSubject}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return profileTestResponse(`{"id":42}` + strings.Repeat(" ", 32769)), nil
	})})
	_, err = oversized.fetchUserInfo(ctx, "https://provider.example/user", oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "secret"}))
	if !errors.Is(err, ErrUserInfoTooLarge) {
		t.Fatalf("oversized profile: %v", err)
	}
}

func TestOAuthProfileRejectsTokenExpiredDuringUserInfo(t *testing.T) {
	token := &oauth2.Token{AccessToken: "access", TokenType: "Bearer", Expiry: time.Now().Add(11 * time.Second)}
	srv := &Server{
		userinfoUrl:    "https://provider.example/user",
		profileSubject: func(map[string]any) (string, error) { return "42", nil },
	}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		token.Expiry = time.Now().Add(-time.Second)
		return profileTestResponse(`{"id":42}`), nil
	})})
	claims, source, expiry, status, err := srv.verifyOAuthIdentity(ctx, token, "")
	if !errors.Is(err, ErrOAuth2InvalidProfile) || claims != nil || source != nil || !expiry.IsZero() || status != http.StatusUnauthorized {
		t.Fatalf("expired profile: claims=%v source=%t expiry=%v status=%d err=%v", claims, source != nil, expiry, status, err)
	}
}

func TestOAuthProfileUserInfoCallbackDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		calls := 0
		srv := newProfileTestServer(t, jw, &calls)
		var userinfoErr error
		srv.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/token" {
				return profileTestResponse(`{"access_token":"access","token_type":"Bearer"}`), nil
			}
			select {
			case <-r.Context().Done():
				userinfoErr = r.Context().Err()
				return nil, userinfoErr
			case <-time.After(61 * time.Second):
				userinfoErr = errors.New("UserInfo missed callback deadline")
				return nil, userinfoErr
			}
		})}
		cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
		response := profileCallback(srv, cookie, state, "code")
		request := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
		request.RemoteAddr = "192.0.2.1:1234"
		request.AddCookie(cookie)
		sess := jw.GetSession(request)
		var claims any
		if sess != nil {
			claims = sess.Get(srv.SessionKey)
		}
		if response.Code != http.StatusBadGateway || !errors.Is(userinfoErr, context.DeadlineExceeded) ||
			len(response.Result().Cookies()) != 0 || sess == nil || claims != nil {
			t.Fatalf("profile deadline: status=%d err=%v cookies=%v claims=%v", response.Code, userinfoErr, response.Result().Cookies(), claims)
		}
	})
}

func TestOAuthProfileAcceptsShortUnexpiredToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		srv := &Server{Jaws: jw, issuer: "https://provider.example", userinfoUrl: "https://provider.example/user",
			profileSubject: func(map[string]any) (string, error) { return "42", nil }}
		calls := 0
		ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if got := r.Header.Get("Authorization"); got != "Bearer access" {
				t.Fatalf("userinfo authorization = %q", got)
			}
			return profileTestResponse(`{"id":42}`), nil
		})})
		token := &oauth2.Token{AccessToken: "access", TokenType: "Bearer", Expiry: time.Now().Add(5 * time.Second)}
		if token.Valid() {
			t.Fatal("test token should be inside oauth2's refresh skew")
		}
		claims, source, expiry, status, err := srv.verifyOAuthIdentity(ctx, token, "")
		if err != nil || status != http.StatusUnauthorized || calls != 1 || source != nil || claims["sub"] != "42" ||
			!expiry.Equal(token.Expiry) {
			t.Fatalf("short token: claims=%v source=%v expiry=%v status=%d calls=%d err=%v", claims, source, expiry, status, calls, err)
		}
	})
}

func TestOAuthProfileExplicitZeroExpiryRejectedButOmittedExpiryCapped(t *testing.T) {
	for _, tc := range []struct {
		name, expiryField string
		form              bool
		wantStatus        int
	}{
		{"omitted", "", false, http.StatusFound},
		{"zero", `,"expires_in":0`, false, http.StatusUnauthorized},
		{"zero string", `,"expires_in":"0"`, false, http.StatusUnauthorized},
		{"form omitted", "", true, http.StatusFound},
		{"form zero", "&expires_in=0", true, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			calls := 0
			srv := newProfileTestServer(t, jw, &calls)
			srv.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/token" {
					if tc.form {
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
							Body: io.NopCloser(strings.NewReader("access_token=access&token_type=Bearer" + tc.expiryField))}, nil
					}
					return profileTestResponse(`{"access_token":"access","token_type":"Bearer"` + tc.expiryField + `}`), nil
				}
				return profileTestResponse(`{"id":42}`), nil
			})}
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			response := profileCallback(srv, cookie, state, "code")
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if tc.wantStatus == http.StatusUnauthorized {
				if len(response.Result().Cookies()) != 0 || !strings.Contains(response.Body.String(), ErrOAuth2InvalidProfile.Error()) {
					t.Fatalf("zero expiry authenticated: cookies=%v body=%q", response.Result().Cookies(), response.Body.String())
				}
				return
			}
			cookies := response.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("rotated cookies: %v", cookies)
			}
			r := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			r.AddCookie(cookies[0])
			sess := jw.GetSession(r)
			if sess == nil || sess.Get(srv.SessionKey) == nil {
				t.Fatal("omitted expiry did not authenticate")
			}
			expiry, _ := sess.Get(srv.sessionKey(oauth2AuthExpiryKey)).(time.Time)
			if remaining := time.Until(expiry); remaining < 23*time.Hour || remaining > 24*time.Hour {
				t.Fatalf("omitted expiry cap = %s", remaining)
			}
		})
	}
}

func TestOAuthProfileExpiresWithoutRefresh(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	factory := &testAuthTimerFactory{}
	srv.authTimerAfterFunc = factory.after
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	response := profileCallback(srv, cookie, state, "first")
	if response.Code != http.StatusFound || factory.len() != 1 {
		t.Fatalf("profile sign-in: status=%d timers=%d", response.Code, factory.len())
	}
	if delay := factory.timer(0).delay; delay <= 0 || delay > authSessionCheckInterval {
		t.Fatalf("profile auth cleanup interval: %s", delay)
	}
	r := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.AddCookie(response.Result().Cookies()[0])
	sess := jw.GetSession(r)
	factory.timer(0).fire()
	if sess.Get(srv.SessionKey) == nil || factory.len() != 2 {
		t.Fatal("profile auth cleared before its expiry")
	}
	srv.mu.Lock()
	srv.authTimers[sess.ID()].expiry = time.Now().Add(-time.Second)
	srv.mu.Unlock()
	factory.timer(1).fire()
	if sess.Get(srv.SessionKey) != nil || !factory.timer(1).isStopped() {
		t.Fatal("profile auth remained after expiry timer")
	}
}

func TestOAuthProfileTimerReleasesClosedSession(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	factory := &testAuthTimerFactory{}
	srv.authTimerAfterFunc = factory.after
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	response := profileCallback(srv, cookie, state, "first")
	if response.Code != http.StatusFound || factory.len() != 1 {
		t.Fatalf("profile sign-in: status=%d timers=%d", response.Code, factory.len())
	}
	r := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	r.AddCookie(response.Result().Cookies()[0])
	sess := jw.GetSession(r)
	sess.Close()
	factory.timer(0).fire()
	if sess.Get(srv.SessionKey) != nil || len(srv.authTimers) != 0 || !factory.timer(0).isStopped() {
		t.Fatal("closed profile session remained pinned by auth timer")
	}
}
