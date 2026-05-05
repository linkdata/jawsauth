package jawsauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

var errAuthSessionTestToken = errors.New("auth session test token error")

type testAuthTimer struct {
	mu       sync.Mutex
	delay    time.Duration
	callback func()
	stopped  bool
}

func (timer *testAuthTimer) Stop() bool {
	timer.mu.Lock()
	wasActive := !timer.stopped
	timer.stopped = true
	timer.mu.Unlock()
	return wasActive
}

func (timer *testAuthTimer) fire() {
	timer.mu.Lock()
	callback := timer.callback
	timer.mu.Unlock()
	callback()
}

func (timer *testAuthTimer) isStopped() (stopped bool) {
	timer.mu.Lock()
	stopped = timer.stopped
	timer.mu.Unlock()
	return
}

type testAuthTimerFactory struct {
	mu     sync.Mutex
	timers []*testAuthTimer
}

func (factory *testAuthTimerFactory) after(delay time.Duration, callback func()) authTimer {
	timer := &testAuthTimer{
		delay:    delay,
		callback: callback,
	}
	factory.mu.Lock()
	factory.timers = append(factory.timers, timer)
	factory.mu.Unlock()
	return timer
}

func (factory *testAuthTimerFactory) timer(index int) (timer *testAuthTimer) {
	factory.mu.Lock()
	timer = factory.timers[index]
	factory.mu.Unlock()
	return
}

func (factory *testAuthTimerFactory) len() (n int) {
	factory.mu.Lock()
	n = len(factory.timers)
	factory.mu.Unlock()
	return
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (fn tokenSourceFunc) Token() (*oauth2.Token, error) {
	return fn()
}

func makeOAuth2Token(accessToken, idToken, refreshToken string) *oauth2.Token {
	token := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Hour),
	}
	if idToken != "" {
		token = token.WithExtra(map[string]any{"id_token": idToken})
	}
	return token
}

func newTimerTestServer(t *testing.T, jw *jaws.Jaws, issuer string, factory *testAuthTimerFactory) *Server {
	t.Helper()
	srv := newWrapperTestServer(jw, issuer)
	srv.authTimerAfterFunc = factory.after
	return srv
}

func TestStoreSessionAuthClaimsSchedulesTimer(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, "https://issuer.example", factory)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	tokenSource := oauth2.StaticTokenSource(makeOAuth2Token("access", "", ""))

	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{
		"exp":            expiry.Unix(),
		"email":          "User@Example.COM",
		"email_verified": "true",
	}, tokenSource, expiry, nil)
	if err != nil {
		t.Fatal(err)
	}

	if gotEmail, _ := sess.Get(srv.SessionEmailKey).(string); gotEmail != "user@example.com" {
		t.Fatal(gotEmail)
	}
	if gotVerified, _ := sess.Get(srv.SessionEmailVerifiedKey).(bool); !gotVerified {
		t.Fatal(gotVerified)
	}
	if gotExpiry, _ := sess.Get(oauth2IDTokenExpiryKey).(time.Time); !gotExpiry.Equal(expiry) {
		t.Fatal(gotExpiry)
	}
	if factory.len() != 1 {
		t.Fatal(factory.len())
	}
	timer := factory.timer(0)
	if timer.delay <= 0 || timer.delay > time.Hour-authRefreshSkew {
		t.Fatal(timer.delay)
	}
	if !srv.sessionAuthTimerCurrent(sess, srv.authTimers[sess.ID()]) {
		t.Fatal("timer was not current")
	}

	srv.scheduleSessionAuthTimer(sess, time.Now().Add(time.Second))
	if factory.len() != 2 {
		t.Fatal(factory.len())
	}
	if !timer.isStopped() {
		t.Fatal("old timer was not stopped")
	}
	if delay := factory.timer(1).delay; delay != 0 {
		t.Fatal(delay)
	}
}

func TestStoreSessionAuthClaimsErrors(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, "https://issuer.example", factory)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)

	err = (*Server)(nil).storeSessionAuthClaims(t.Context(), sess, map[string]any{}, nil, time.Now().Add(time.Hour), nil)
	if !errors.Is(err, ErrOAuth2NotConfigured) {
		t.Fatal(err)
	}

	err = srv.storeSessionAuthClaims(t.Context(), nil, map[string]any{}, nil, time.Now().Add(time.Hour), nil)
	if !errors.Is(err, ErrOAuth2MissingSession) {
		t.Fatal(err)
	}

	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{}, nil, time.Time{}, nil)
	if !errors.Is(err, ErrOIDCInvalidIDToken) {
		t.Fatal(err)
	}

	entry := &authTimerState{}
	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{}, nil, time.Now().Add(time.Hour), entry)
	if !errors.Is(err, errAuthTimerStale) {
		t.Fatal(err)
	}
}

func TestSetSessionAuthFromTokenErrors(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, issuer, factory)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)

	err = (*Server)(nil).setSessionAuthFromToken(t.Context(), sess, nil, nil, time.Time{}, nil)
	if !errors.Is(err, ErrOAuth2NotConfigured) {
		t.Fatal(err)
	}

	err = srv.setSessionAuthFromToken(t.Context(), sess, nil, nil, time.Time{}, nil)
	if !errors.Is(err, ErrOIDCMissingIDToken) {
		t.Fatal(err)
	}

	err = srv.setSessionAuthFromToken(t.Context(), sess, nil, makeOAuth2Token("access", "not-a-jwt", ""), time.Time{}, nil)
	if !errors.Is(err, ErrOIDCInvalidIDToken) {
		t.Fatal(err)
	}

	srv.idTokenVerifier = oidc.NewVerifier(issuer, passthroughKeySet{}, &oidc.Config{
		ClientID:        "client",
		SkipExpiryCheck: true,
	})
	rawIDToken := makeIDToken(t, map[string]any{
		"iss": issuer,
		"aud": "client",
		"sub": "sub-123",
	})
	err = srv.setSessionAuthFromToken(t.Context(), sess, nil, makeOAuth2Token("access", rawIDToken, ""), time.Time{}, nil)
	if !errors.Is(err, ErrOIDCInvalidIDToken) {
		t.Fatal(err)
	}
}

func TestAuthTimerRefreshesCachedTokenByForcingRefresh(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	initialExpiry := time.Now().Add(30 * time.Second).Truncate(time.Second)
	refreshedExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	cachedIDToken := makeIDToken(t, map[string]any{
		"iss":            issuer,
		"aud":            "client",
		"exp":            initialExpiry.Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"sub":            "sub-123",
		"email":          "cached@example.com",
		"email_verified": false,
	})
	refreshedIDToken := makeIDToken(t, map[string]any{
		"iss":            issuer,
		"aud":            "client",
		"exp":            refreshedExpiry.Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"sub":            "sub-123",
		"email":          "refreshed@example.com",
		"email_verified": true,
	})

	var mu sync.Mutex
	var tokenRequests int
	var refreshGrant string
	var refreshToken string
	var userinfoRequests int
	var userinfoAuth string
	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		switch hr.URL.Path {
		case "/token":
			if err := hr.ParseForm(); err != nil {
				hw.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			tokenRequests++
			refreshGrant = hr.FormValue("grant_type")
			refreshToken = hr.FormValue("refresh_token")
			mu.Unlock()
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh456","id_token":"` + refreshedIDToken + `"}`))
		case "/userinfo":
			mu.Lock()
			userinfoRequests++
			userinfoAuth = hr.Header.Get("Authorization")
			mu.Unlock()
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"name":"Profile Name"}`))
		default:
			hw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()

	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, issuer, factory)
	srv.oauth2cfg.Endpoint.TokenURL = provider.URL + "/token"
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	tokenSource := oauth2.StaticTokenSource(makeOAuth2Token("cached-access", cachedIDToken, "refresh123"))
	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{
		"exp":            initialExpiry.Unix(),
		"email":          "cached@example.com",
		"email_verified": false,
	}, tokenSource, initialExpiry, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.userinfoUrl = provider.URL + "/userinfo"

	factory.timer(0).fire()

	if factory.len() != 2 {
		t.Fatal(factory.len())
	}
	claims, ok := sess.Get(srv.SessionKey).(map[string]any)
	if !ok {
		t.Fatal("missing claims")
	}
	if claims["email"] != "refreshed@example.com" {
		t.Fatal(claims["email"])
	}
	if claims["name"] != "Profile Name" {
		t.Fatal(claims["name"])
	}
	if email, _ := sess.Get(srv.SessionEmailKey).(string); email != "refreshed@example.com" {
		t.Fatal(email)
	}
	if verified, _ := sess.Get(srv.SessionEmailVerifiedKey).(bool); !verified {
		t.Fatal(verified)
	}
	if tokenSource, ok := sess.Get(srv.SessionTokenKey).(oauth2.TokenSource); !ok || tokenSource == nil {
		t.Fatal("missing token source")
	}

	mu.Lock()
	gotTokenRequests := tokenRequests
	gotRefreshGrant := refreshGrant
	gotRefreshToken := refreshToken
	gotUserinfoRequests := userinfoRequests
	gotUserinfoAuth := userinfoAuth
	mu.Unlock()
	if gotTokenRequests != 1 {
		t.Fatal(gotTokenRequests)
	}
	if gotRefreshGrant != "refresh_token" {
		t.Fatal(gotRefreshGrant)
	}
	if gotRefreshToken != "refresh123" {
		t.Fatal(gotRefreshToken)
	}
	if gotUserinfoRequests != 1 {
		t.Fatal(gotUserinfoRequests)
	}
	if gotUserinfoAuth != "Bearer refreshed-access" {
		t.Fatal(gotUserinfoAuth)
	}
}

func TestAuthTimerRefreshFailureClearsAuth(t *testing.T) {
	testCases := []struct {
		name        string
		tokenSource oauth2.TokenSource
		tokenBody   string
	}{
		{
			name: "tokenSourceError",
			tokenSource: tokenSourceFunc(func() (*oauth2.Token, error) {
				return nil, errAuthSessionTestToken
			}),
		},
		{
			name:        "missingIDTokenNoRefreshPath",
			tokenSource: oauth2.StaticTokenSource(makeOAuth2Token("access", "", "")),
		},
		{
			name:        "missingRefreshedIDToken",
			tokenSource: oauth2.StaticTokenSource(makeOAuth2Token("access", "", "refresh123")),
			tokenBody:   `{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh456"}`,
		},
		{
			name:        "invalidRefreshedIDToken",
			tokenSource: oauth2.StaticTokenSource(makeOAuth2Token("access", "", "refresh123")),
			tokenBody:   `{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh456","id_token":"not-a-jwt"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()

			var tokenRequests int
			provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
				if hr.URL.Path != "/token" {
					hw.WriteHeader(http.StatusNotFound)
					return
				}
				tokenRequests++
				hw.Header().Set("Content-Type", "application/json")
				_, _ = hw.Write([]byte(tc.tokenBody))
			}))
			defer provider.Close()

			const issuer = "https://issuer.example"
			factory := &testAuthTimerFactory{}
			srv := newTimerTestServer(t, jw, issuer, factory)
			srv.oauth2cfg.Endpoint.TokenURL = provider.URL + "/token"
			var logoutCount int
			var logoutRequest *http.Request
			srv.LogoutEvent = func(_ *jaws.Session, hr *http.Request) {
				logoutCount++
				logoutRequest = hr
			}
			req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
			sess := jw.NewSession(httptest.NewRecorder(), req)
			expiry := time.Now().Add(30 * time.Second).Truncate(time.Second)
			err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{
				"exp":            expiry.Unix(),
				"email":          "old@example.com",
				"email_verified": true,
			}, tc.tokenSource, expiry, nil)
			if err != nil {
				t.Fatal(err)
			}

			factory.timer(0).fire()

			assertWrapperAuthCleared(t, srv, sess)
			if logoutCount != 1 {
				t.Fatal(logoutCount)
			}
			if logoutRequest != nil {
				t.Fatal(logoutRequest)
			}
			if srv.authTimers[sess.ID()] != nil {
				t.Fatal("timer was not removed")
			}
			if !factory.timer(0).isStopped() {
				t.Fatal("timer was not stopped")
			}
			if tc.tokenBody == "" && tokenRequests != 0 {
				t.Fatal(tokenRequests)
			}
			if tc.tokenBody != "" && tokenRequests != 1 {
				t.Fatal(tokenRequests)
			}
		})
	}
}

func TestAuthTimerStaleCallbackNoOp(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, issuer, factory)
	var logoutCount int
	srv.LogoutEvent = func(*jaws.Session, *http.Request) {
		logoutCount++
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	expiry := time.Now().Add(time.Minute).Truncate(time.Second)

	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{
		"exp":   expiry.Unix(),
		"email": "first@example.com",
	}, tokenSourceFunc(func() (*oauth2.Token, error) {
		t.Fatal("stale timer should not refresh")
		return nil, errAuthSessionTestToken
	}), expiry, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstTimer := factory.timer(0)
	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{
		"exp":   time.Now().Add(time.Hour).Unix(),
		"email": "second@example.com",
	}, oauth2.StaticTokenSource(makeOAuth2Token("access", "", "")), time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}

	firstTimer.fire()

	if logoutCount != 0 {
		t.Fatal(logoutCount)
	}
	claims, _ := sess.Get(srv.SessionKey).(map[string]any)
	if claims["email"] != "second@example.com" {
		t.Fatal(claims)
	}
	if !srv.sessionAuthTimerCurrent(sess, srv.authTimers[sess.ID()]) {
		t.Fatal("current timer missing")
	}
}

func TestAuthTimerStaleAfterRefreshNoOp(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, issuer, factory)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	oldExpiry := time.Now().Add(30 * time.Second).Truncate(time.Second)
	newExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
	rawIDToken := makeIDToken(t, map[string]any{
		"iss":   issuer,
		"aud":   "client",
		"exp":   newExpiry.Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"sub":   "sub-123",
		"email": "refreshed@example.com",
	})
	tokenSource := tokenSourceFunc(func() (*oauth2.Token, error) {
		srv.scheduleSessionAuthTimer(sess, newExpiry)
		return makeOAuth2Token("access", rawIDToken, ""), nil
	})
	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{
		"exp":   oldExpiry.Unix(),
		"email": "old@example.com",
	}, tokenSource, oldExpiry, nil)
	if err != nil {
		t.Fatal(err)
	}

	factory.timer(0).fire()

	claims, _ := sess.Get(srv.SessionKey).(map[string]any)
	if claims["email"] != "old@example.com" {
		t.Fatal(claims)
	}
	if factory.len() != 2 {
		t.Fatal(factory.len())
	}
}

func TestExplicitLogoutStopsAuthTimer(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, "https://issuer.example", factory)
	var logoutCount int
	var logoutRequest *http.Request
	srv.LogoutEvent = func(_ *jaws.Session, hr *http.Request) {
		logoutCount++
		logoutRequest = hr
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/logout", nil)
	rec := httptest.NewRecorder()
	sess := jw.NewSession(rec, req)
	err = srv.storeSessionAuthClaims(t.Context(), sess, map[string]any{
		"exp":   time.Now().Add(time.Hour).Unix(),
		"email": "user@example.com",
	}, oauth2.StaticTokenSource(makeOAuth2Token("access", "", "")), time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}

	rec = httptest.NewRecorder()
	srv.HandleLogout(rec, req)

	if code := rec.Result().StatusCode; code != http.StatusFound {
		t.Fatal(code)
	}
	assertWrapperAuthCleared(t, srv, sess)
	if logoutCount != 1 {
		t.Fatal(logoutCount)
	}
	if logoutRequest != req {
		t.Fatal(logoutRequest)
	}
	if srv.authTimers[sess.ID()] != nil {
		t.Fatal("timer was not removed")
	}
	if !factory.timer(0).isStopped() {
		t.Fatal("timer was not stopped")
	}
}

func TestRefreshSessionAuthErrors(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, issuer, factory)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)

	err = (*Server)(nil).refreshSessionAuth(context.Background(), sess, time.Time{}, nil)
	if !errors.Is(err, ErrOAuth2NotConfigured) {
		t.Fatal(err)
	}
	err = srv.refreshSessionAuth(context.Background(), nil, time.Time{}, nil)
	if !errors.Is(err, ErrOAuth2NotConfigured) {
		t.Fatal(err)
	}
	err = srv.refreshSessionAuth(context.Background(), sess, time.Time{}, nil)
	if !errors.Is(err, ErrOIDCMissingIDToken) {
		t.Fatal(err)
	}
	sess.Set(srv.SessionTokenKey, tokenSourceFunc(func() (*oauth2.Token, error) {
		return nil, errAuthSessionTestToken
	}))
	err = srv.refreshSessionAuth(context.Background(), sess, time.Time{}, nil)
	if !errors.Is(err, errAuthSessionTestToken) {
		t.Fatal(err)
	}
}
