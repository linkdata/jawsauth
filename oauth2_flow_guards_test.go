package jawsauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

type infoHookLogger func(string)

func (hook infoHookLogger) Info(msg string, _ ...any) { hook(msg) }
func (infoHookLogger) Warn(string, ...any)            {}
func (infoHookLogger) Error(string, ...any)           {}

type rotationHeaderGate struct {
	*httptest.ResponseRecorder
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (w *rotationHeaderGate) Header() http.Header {
	w.once.Do(func() {
		close(w.entered)
		<-w.release
	})
	return w.ResponseRecorder.Header()
}

func TestLoginStartDuringRotationKeepsFirstCallback(t *testing.T) {
	jw := newTestJaws(t)
	srv := newProfileTestServer(t, jw, nil)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	lock := &observedRotationLock{second: make(chan struct{})}
	srv.SessionRotationLock = lock
	gate := &rotationHeaderGate{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	callbackDone := make(chan struct{})
	go func() {
		r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state="+state+"&code=first", nil)
		r.AddCookie(cookie)
		srv.HandleAuthResponse(gate, r)
		close(callbackDone)
	}()
	waitFor(t, gate.entered, "callback did not reach session rotation")
	startDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.HandleLogin(w, r)
		startDone <- w
	}()
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	waitFor(t, lock.second, "second login did not wait for rotation")
	release()
	waitFor(t, callbackDone, "first callback did not finish")
	second := waitFor(t, startDone, "second login did not finish")
	if gate.Code != http.StatusFound || len(gate.Result().Cookies()) != 1 || second.Code != http.StatusFound || len(second.Result().Cookies()) != 1 {
		t.Fatalf("overlapping logins: first=%d cookies=%v second=%d cookies=%v", gate.Code, gate.Result().Cookies(), second.Code, second.Result().Cookies())
	}
}

func TestCallbackRevokedAfterStoreBalancesEvents(t *testing.T) {
	jw := newTestJaws(t)
	srv := newProfileTestServer(t, jw, nil)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	r := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
	r.AddCookie(cookie)
	old := jw.GetSession(r)
	if old == nil {
		t.Fatal("pending session missing")
	}
	var rotated *jaws.Session
	logins, logouts := 0, 0
	srv.LoginEvent = func(sess *jaws.Session, _ *http.Request) { rotated = sess; logins++ }
	srv.LogoutEvent = func(sess *jaws.Session, _ *http.Request) {
		if sess != old {
			logouts++
		}
	}
	revoked := false
	jw.Debug = true
	jw.Logger = infoHookLogger(func(msg string) {
		if msg == "jawsauth: scheduled auth timer" {
			revoked = srv.Logout(old, nil)
		}
	})
	w := profileCallback(srv, cookie, state, "proof")
	if !revoked || w.Code != http.StatusForbidden || logins != 1 || logouts != 1 || rotated == nil || sessionAlive(rotated) || len(srv.authTimers) != 0 {
		t.Fatalf("post-store revocation: revoked=%t status=%d logins=%d logouts=%d rotated=%v timers=%d", revoked, w.Code, logins, logouts, rotated, len(srv.authTimers))
	}
}

func TestCallbackRejectsAuthInvalidatedByLoginEvent(t *testing.T) {
	for _, action := range []string{"expired auth", "closed session"} {
		t.Run(action, func(t *testing.T) {
			jw := newTestJaws(t)
			srv := newProfileTestServer(t, jw, nil)
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			called := false
			srv.LoginEvent = func(sess *jaws.Session, _ *http.Request) {
				called = true
				if action == "expired auth" {
					sess.Set(srv.sessionKey(oauth2AuthExpiryKey), time.Now().Add(-time.Second))
				} else {
					sess.Close()
				}
			}
			response := profileCallback(srv, cookie, state, "first")
			cookies := response.Result().Cookies()
			if !called || response.Code != http.StatusForbidden || response.Header().Get("Location") != "" || len(cookies) != 2 || cookies[1].MaxAge >= 0 {
				t.Fatalf("invalidated login: called=%t status=%d location=%q cookies=%v", called, response.Code, response.Header().Get("Location"), cookies)
			}
		})
	}
}

func TestProfileTokenExpiresBetweenRotationAndStore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		srv := newProfileTestServer(t, jw, nil)
		cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
		first := profileCallback(srv, cookie, state, "first")
		if first.Code != http.StatusFound {
			t.Fatalf("initial login: %d", first.Code)
		}
		cookie = first.Result().Cookies()[0]
		r := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
		r.AddCookie(cookie)
		old := jw.GetSession(r)
		if old == nil {
			t.Fatal("old session missing")
		}
		_, state = profileStart(t, srv, http.MethodGet, "/auth/login", cookie)
		srv.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/token" {
				return jsonResponse(`{"access_token":"short","token_type":"Bearer","expires_in":30}`), nil
			}
			return jsonResponse(`{"id":42}`), nil
		})}
		logins := 0
		srv.LoginEvent = func(*jaws.Session, *http.Request) { logins++ }
		srv.LogoutEvent = func(sess *jaws.Session, _ *http.Request) {
			if sess == old {
				time.Sleep(31 * time.Second)
			}
		}
		w := profileCallback(srv, cookie, state, "second")
		cookies := w.Result().Cookies()
		if w.Code != http.StatusUnauthorized || w.Header().Get("Location") != "" ||
			len(cookies) != 2 || cookies[1].MaxAge >= 0 || cookies[1].Value != cookies[0].Value ||
			logins != 0 || len(srv.authTimers) != 0 {
			t.Fatalf("expired before store: status=%d location=%q cookies=%v logins=%d timers=%d", w.Code, w.Header().Get("Location"), cookies, logins, len(srv.authTimers))
		}
	})
}

func TestLinkWithoutEventDoesNotStartFlow(t *testing.T) {
	jw := newTestJaws(t)
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	srv.LinkEvent = nil
	r := httptest.NewRequest(http.MethodPost, "https://app.example/auth/link/github", nil)
	if jw.NewSession(httptest.NewRecorder(), r) == nil {
		t.Fatal("missing session")
	}
	w := httptest.NewRecorder()
	srv.HandleLink(w, r)
	if w.Code != http.StatusInternalServerError || w.Header().Get("Location") != "" ||
		!strings.Contains(w.Body.String(), ErrOAuth2NotConfigured.Error()) || calls != 0 {
		t.Fatalf("missing LinkEvent: status=%d location=%q body=%q calls=%d", w.Code, w.Header().Get("Location"), w.Body.String(), calls)
	}
}

func TestLinkRejectsGETBeforeStartingFlow(t *testing.T) {
	jw := newTestJaws(t)
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) { return 0, nil }
	r := httptest.NewRequest(http.MethodGet, "https://app.example/auth/link/github", nil)
	sess := jw.NewSession(httptest.NewRecorder(), r)
	if sess == nil {
		t.Fatal("missing session")
	}
	w := httptest.NewRecorder()
	srv.HandleLink(w, r)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodPost || w.Header().Get("Location") != "" || sess.Get(srv.sessionKey(oauth2FlowKey)) != nil || calls != 0 {
		t.Fatalf("GET link: status=%d allow=%q location=%q flow=%v calls=%d", w.Code, w.Header().Get("Allow"), w.Header().Get("Location"), sess.Get(srv.sessionKey(oauth2FlowKey)), calls)
	}
}

func TestLinkRejectsInvalidEventResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		err    error
		want   int
	}{
		{"error without status", 0, errors.New("secret persistence detail"), http.StatusForbidden},
		{"success status without acceptance", http.StatusOK, nil, http.StatusForbidden},
		{"conflict status", http.StatusConflict, errors.New("secret persistence detail"), http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jw := newTestJaws(t)
			srv := newProfileTestServer(t, jw, nil)
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			first := profileCallback(srv, cookie, state, "first")
			if first.Code != http.StatusFound {
				t.Fatalf("sign-in: %d", first.Code)
			}
			cookie = first.Result().Cookies()[0]
			srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
				return tc.status, tc.err
			}
			_, state = profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
			w := profileCallback(srv, cookie, state, "second")
			if w.Code != tc.want || w.Header().Get("Location") != "" ||
				len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), ErrOAuth2LinkRejected.Error()) ||
				strings.Contains(w.Body.String(), "secret persistence detail") {
				t.Fatalf("invalid LinkEvent result: status=%d location=%q body=%q cookies=%v", w.Code, w.Header().Get("Location"), w.Body.String(), w.Result().Cookies())
			}
		})
	}
}

func TestLinkRejectsIdentityThatExpiresWhileWaitingForLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		srv := newProfileTestServer(t, jw, nil)
		lock := &holdFirstRotationLock{first: make(chan struct{}), releaseFirst: make(chan struct{})}
		srv.SessionRotationLock = lock
		release := sync.OnceFunc(func() { close(lock.releaseFirst) })
		defer release()
		writes := 0
		srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
			writes++
			return 0, nil
		}
		request := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback", nil)
		sess := jw.NewSession(httptest.NewRecorder(), request)
		if sess == nil || jw.GetSession(request) != sess {
			t.Fatal("missing session")
		}
		type completion struct {
			status int
			err    error
		}
		result := make(chan completion, 1)
		go func() {
			status, err := srv.completeLink(sess, request, map[string]any{"sub": "42"}, time.Now().Add(time.Second), pendingOAuthFlow{})
			result <- completion{status, err}
		}()
		<-lock.first
		time.Sleep(2 * time.Second) // synctest advances time while completeLink waits.
		release()
		got := <-result
		if got.status != http.StatusUnauthorized || !errors.Is(got.err, ErrOAuth2InvalidProfile) || writes != 0 {
			t.Fatalf("expired link: status=%d err=%v writes=%d", got.status, got.err, writes)
		}
	})
}

func TestUserInfoRequiresOneJSONObject(t *testing.T) {
	for _, profile := range []bool{false, true} {
		t.Run(map[bool]string{false: "OIDC", true: "profile"}[profile], func(t *testing.T) {
			for _, tc := range []struct{ name, body string }{
				{"trailing", `{"id":42} {"id":43}`},
				{"null", `null`},
				{"array", `[1]`},
				{"string", `"x"`},
				{"number", `1`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					srv := &Server{}
					if profile {
						srv.profileSubject = func(map[string]any) (string, error) { return "42", nil }
					}
					ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
						return jsonResponse(tc.body), nil
					})})
					claims, err := srv.fetchUserInfo(ctx, "https://provider.example/user", oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "proof"}))
					if !errors.Is(err, ErrUserInfoInvalidResponse) || claims != nil {
						t.Fatalf("invalid UserInfo accepted: claims=%v err=%v", claims, err)
					}
				})
			}
		})
	}
}

func TestLinkWithoutRefererReturnsHome(t *testing.T) {
	jw := newTestJaws(t)
	srv := newProfileTestServer(t, jw, nil)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, cookie, state, "first")
	if first.Code != http.StatusFound {
		t.Fatalf("sign-in: %d", first.Code)
	}
	cookie = first.Result().Cookies()[0]
	srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) { return 0, nil }
	_, state = profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
	w := profileCallback(srv, cookie, state, "second")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("link return: status=%d location=%q cookies=%v", w.Code, w.Header().Get("Location"), w.Result().Cookies())
	}
}

func TestProfileUserInfoNullDoesNotCallSubject(t *testing.T) {
	called := false
	srv := &Server{
		userinfoUrl: "https://provider.example/user",
		profileSubject: func(map[string]any) (string, error) {
			called = true
			return "42", nil
		},
	}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(`null`), nil
	})})
	claims, source, expiry, status, err := srv.verifyOAuthIdentity(ctx, &oauth2.Token{AccessToken: "proof", TokenType: "Bearer"}, "")
	if !errors.Is(err, ErrUserInfoInvalidResponse) || claims != nil || source != nil || !expiry.IsZero() || status != http.StatusBadGateway || called {
		t.Fatalf("null profile: claims=%v source=%t expiry=%v status=%d err=%v subject_called=%t", claims, source != nil, expiry, status, err, called)
	}
}

func TestCallbackClosesRotatedSessionOnStoreFailure(t *testing.T) {
	jw := newTestJaws(t)
	srv := newProfileTestServer(t, jw, nil)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, cookie, state, "first")
	if first.Code != http.StatusFound {
		t.Fatalf("sign-in: %d", first.Code)
	}
	cookie = first.Result().Cookies()[0]
	_, state = profileStart(t, srv, http.MethodGet, "/auth/login", cookie)
	closedRotated := false
	srv.LogoutEvent = func(old *jaws.Session, r *http.Request) {
		if rotated := jw.GetSession(r); rotated != nil && rotated != old {
			rotated.Close()
			closedRotated = true
		}
	}
	w := profileCallback(srv, cookie, state, "second")
	cookies := w.Result().Cookies()
	if !closedRotated || w.Code != http.StatusForbidden || w.Header().Get("Location") != "" ||
		len(cookies) != 2 || cookies[1].MaxAge >= 0 || cookies[1].Value != cookies[0].Value {
		t.Fatalf("store after close: closed=%t status=%d location=%q cookies=%v", closedRotated, w.Code, w.Header().Get("Location"), cookies)
	}
}

type revokeAfterRotationLock struct {
	sync.Mutex
	logout func()
}

func (lock *revokeAfterRotationLock) Unlock() {
	lock.Mutex.Unlock()
	if lock.logout != nil {
		logout := lock.logout
		lock.logout = nil
		logout()
	}
}

func TestReloginStopsOldTimerBeforeRotationUnlock(t *testing.T) {
	jw := newTestJaws(t)
	srv := newProfileTestServer(t, jw, nil)
	factory := &testAuthTimerFactory{}
	srv.authTimerAfterFunc = factory.after
	cookie := profileLogin(t, srv)
	oldRequest := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
	oldRequest.AddCookie(cookie)
	old := jw.GetSession(oldRequest)
	if old == nil {
		t.Fatal("old session missing")
	}
	_, state := profileStart(t, srv, http.MethodGet, "/auth/login", cookie)
	timer := factory.timer(0)
	var logoutRequest *http.Request
	logouts := 0
	srv.LogoutEvent = func(sess *jaws.Session, hr *http.Request) {
		if sess == old {
			logouts++
			logoutRequest = hr
		}
	}
	var stoppedBeforeFire bool
	srv.SessionRotationLock = &revokeAfterRotationLock{logout: func() {
		stoppedBeforeFire = timer.isStopped()
		timer.fire()
	}}
	response := profileCallback(srv, cookie, state, "second")
	if response.Code != http.StatusFound || logouts != 1 || logoutRequest == nil || !stoppedBeforeFire {
		t.Fatalf("re-login: status=%d logouts=%d request=%v timer_stopped_before_fire=%t", response.Code, logouts, logoutRequest != nil, stoppedBeforeFire)
	}
}

func TestCallbackRevokedAfterRotationClosesNewSession(t *testing.T) {
	jw := newTestJaws(t)
	srv := newProfileTestServer(t, jw, nil)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, cookie, state, "first")
	if first.Code != http.StatusFound {
		t.Fatalf("sign-in: %d", first.Code)
	}
	cookie = first.Result().Cookies()[0]
	oldRequest := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
	oldRequest.AddCookie(cookie)
	old := jw.GetSession(oldRequest)
	if old == nil {
		t.Fatal("old session missing")
	}
	_, state = profileStart(t, srv, http.MethodGet, "/auth/login", cookie)
	revoked := false
	srv.SessionRotationLock = &revokeAfterRotationLock{logout: func() {
		revoked = srv.Logout(old, nil)
	}}
	w := profileCallback(srv, cookie, state, "second")
	cookies := w.Result().Cookies()
	if !revoked || w.Code != http.StatusForbidden || w.Header().Get("Location") != "" ||
		len(cookies) != 2 || cookies[1].MaxAge >= 0 || cookies[1].Value != cookies[0].Value {
		t.Fatalf("revoked after rotation: revoked=%t status=%d location=%q cookies=%v", revoked, w.Code, w.Header().Get("Location"), cookies)
	}
}
