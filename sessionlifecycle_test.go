package jawsauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

type logoutOnWarnLogger struct{ onWarn func() }

func (l logoutOnWarnLogger) Info(string, ...any)  {}
func (l logoutOnWarnLogger) Error(string, ...any) {}
func (l logoutOnWarnLogger) Warn(string, ...any)  { l.onWarn() }

func TestLogoutDuringClaimPreparation(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	factory := &testAuthTimerFactory{}
	srv := newTimerTestServer(t, jw, "https://issuer.example", factory)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	expiry := time.Now().Add(time.Hour)
	if err = srv.storeSessionAuthClaims(sess, map[string]any{"email": "user@example.com"}, nil, expiry, nil); err != nil {
		t.Fatal(err)
	}
	entry := srv.authTimers[sess.ID()]
	jw.Logger = logoutOnWarnLogger{onWarn: func() { srv.Logout(sess, req) }}
	// Claim preparation may invoke application logging while logout completes.
	err = srv.storeSessionAuthClaims(sess, map[string]any{"sub": "one"}, nil, expiry, entry)
	if !errors.Is(err, errAuthTimerStale) {
		t.Fatalf("got %v, want stale refresh", err)
	}
	assertWrapperAuthCleared(t, srv, sess)
	if len(srv.authTimers) != 0 || factory.len() != 1 {
		t.Fatal("logout left a refresh timer")
	}
}

func TestAuthTimerDiscardsClosedSession(t *testing.T) {
	for _, duringRefresh := range []bool{false, true} {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		factory := &testAuthTimerFactory{}
		srv := newTimerTestServer(t, jw, "https://issuer.example", factory)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		sess := jw.NewSession(httptest.NewRecorder(), req)
		expiry := time.Now().Add(time.Hour)
		raw := makeIDToken(t, map[string]any{"iss": "https://issuer.example", "aud": "client", "sub": "one", "exp": expiry.Add(time.Hour).Unix(), "email": "user@example.com"})
		calls := 0
		source := tokenSourceFunc(func() (*oauth2.Token, error) {
			calls++
			sess.Close()
			return makeOAuth2Token("access", raw, "refresh"), nil
		})
		if err = srv.storeSessionAuthClaims(sess, map[string]any{"email": "user@example.com"}, source, expiry, nil); err != nil {
			t.Fatal(err)
		}
		if !duringRefresh {
			sess.Close()
		}
		factory.timer(0).fire()
		wantCalls := 0
		if duringRefresh {
			wantCalls = 1
		}
		if calls != wantCalls || len(srv.authTimers) != 0 || factory.len() != 1 {
			t.Fatalf("calls=%d timers=%d scheduled=%d", calls, len(srv.authTimers), factory.len())
		}
		assertWrapperAuthCleared(t, srv, sess)
		jw.Close()
	}
}

func TestAuthorizationWithdrawalCancelsRequests(t *testing.T) {
	for _, action := range []string{"logout", "httpLogout", "expiry", "demotion", "restrictEveryone"} {
		t.Run(action, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			go jw.Serve()
			defer jw.Close()
			factory := &testAuthTimerFactory{}
			srv := newTimerTestServer(t, jw, "https://issuer.example", factory)
			if action != "restrictEveryone" {
				srv.SetAdmins([]string{"user@example.com"})
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			sess := jw.NewSession(httptest.NewRecorder(), req)
			expiry := time.Now().Add(time.Hour)
			if action == "expiry" {
				expiry = time.Now().Add(-time.Second)
			}
			if err = srv.storeSessionAuthClaims(sess, map[string]any{"email": "user@example.com"}, nil, expiry, nil); err != nil {
				t.Fatal(err)
			}
			rq := jw.NewRequest(httptest.NewRecorder(), req)
			ctx := rq.Context()
			if rq.Session() != sess || len(sess.Requests()) != 1 {
				t.Fatal("request not attached")
			}
			switch action {
			case "logout":
				srv.Logout(sess, req)
			case "httpLogout":
				srv.HandleLogout(httptest.NewRecorder(), req)
			case "expiry":
				factory.timer(0).fire()
			default:
				srv.SetAdmins([]string{"other@example.com"})
			}
			if !errors.Is(context.Cause(ctx), context.Canceled) {
				t.Fatalf("request cancellation cause: %v", context.Cause(ctx))
			}
			if action == "demotion" || action == "restrictEveryone" {
				if current, _ := srv.sessionAuthStatus(sess, time.Now); !current {
					t.Fatal("demotion should preserve ordinary login")
				}
			}
		})
	}
}

func TestLoginRotationExistingAuth(t *testing.T) {
	for _, limit := range []int{1, 2} {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		jw.MaxSessions = limit
		factory := &testAuthTimerFactory{}
		srv := newTimerTestServer(t, jw, "https://issuer.example", factory)
		expiry := time.Now().Add(time.Hour)
		raw := makeIDToken(t, map[string]any{"iss": "https://issuer.example", "aud": "client", "sub": "one", "exp": expiry.Unix(), "nonce": "nonce", "email": "user@example.com"})
		srv.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"access_token":"access","token_type":"Bearer","id_token":"` + raw + `"}`))}, nil
		})}
		req := httptest.NewRequest(http.MethodGet, "/callback?state=state&code=code", nil)
		sess := jw.NewSession(httptest.NewRecorder(), req)
		if err = srv.storeSessionAuthClaims(sess, map[string]any{"email": "existing@example.com"}, nil, expiry, nil); err != nil {
			t.Fatal(err)
		}
		entry := srv.authTimers[sess.ID()]
		logouts, logins := 0, 0
		srv.LogoutEvent = func(old *jaws.Session, hr *http.Request) {
			logouts++
			if old != sess || hr != req {
				t.Fatal("wrong retired session")
			}
			_ = srv.GetAdmins() // Callbacks must run outside srv.mu.
		}
		srv.LoginEvent = func(current *jaws.Session, _ *http.Request) {
			logins++
			if current == sess {
				t.Fatal("login reused old session")
			}
		}
		sess.Set(oauth2StateKey, "state")
		sess.Set(oauth2NonceKey, "nonce")
		sess.Set(oauth2PKCEVerifierKey, oauth2.GenerateVerifier())
		rec := httptest.NewRecorder()
		srv.HandleAuthResponse(rec, req)
		if limit == 1 {
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Location") != "" {
				t.Fatalf("status=%d headers=%v", rec.Code, rec.Header())
			}
			if jw.GetSession(req) != sess || !srv.sessionAuthTimerCurrent(sess, entry) || sess.Get(srv.SessionEmailKey) != "existing@example.com" {
				t.Fatal("failed rotation changed existing auth")
			}
			if logouts != 0 || logins != 0 {
				t.Fatal("failed rotation emitted lifecycle events")
			}
		} else {
			if rec.Code != http.StatusFound || logouts != 1 || logins != 1 {
				t.Fatalf("status=%d logouts=%d logins=%d", rec.Code, logouts, logins)
			}
			if !factory.timer(0).isStopped() || sess.Cookie().MaxAge >= 0 {
				t.Fatal("old session was not retired")
			}
		}
		jw.Close()
	}
}

func TestSetAdminsLeavesAnonymousRequestsOpen(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	srv := newWrapperTestServer(jw, "https://issuer.example")
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	jw.NewSession(httptest.NewRecorder(), req)
	rq := jw.NewRequest(httptest.NewRecorder(), req)
	srv.SetAdmins([]string{"admin@example.com"})
	if rq.Context().Err() != nil {
		t.Fatal("public request was cancelled")
	}
}

func TestWrapperRevocationDuringRender(t *testing.T) {
	for _, admin := range []bool{false, true} {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		srv := newTimerTestServer(t, jw, "https://issuer.example", &testAuthTimerFactory{})
		srv.SetAdmins([]string{"user@example.com"})
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		sess := jw.NewSession(httptest.NewRecorder(), req)
		if err = srv.storeSessionAuthClaims(sess, map[string]any{"email": "user@example.com"}, nil, time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		var ctx context.Context
		h := http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
			if admin {
				srv.SetAdmins([]string{"other@example.com"})
			} else {
				srv.Logout(sess, hr)
			}
			ctx = jw.NewRequest(hw, hr).Context()
		})
		srv.wrap(h, admin).ServeHTTP(httptest.NewRecorder(), req)
		if ctx == nil || ctx.Err() == nil {
			t.Fatal("request attached after revocation was not cancelled")
		}
		jw.Close()
	}
}

func TestSetAdminsUsesSessionPolicy(t *testing.T) {
	const quoted = `"\"quoted\""@example.com`
	for _, tc := range []struct {
		name, email      string
		strict, verified bool
		before, after    []string
		wantAdmin        bool
	}{
		{name: "strictUnverified", email: "user@example.com", strict: true, after: []string{"user@example.com"}},
		{name: "strictVerified", email: "user@example.com", strict: true, verified: true, after: []string{"user@example.com"}, wantAdmin: true},
		{name: "defaultUnverified", email: "user@example.com", after: []string{"user@example.com"}, wantAdmin: true},
		{name: "quotedRemoved", email: quoted, before: []string{quoted}, after: []string{"other@example.com"}},
		{name: "quotedUnchanged", email: quoted, before: []string{quoted}, after: []string{quoted}, wantAdmin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			go jw.Serve()
			defer jw.Close()
			srv := newWrapperTestServer(jw, "https://issuer.example")
			srv.RequireVerifiedAdminEmail = tc.strict
			srv.SetAdmins(tc.before)
			hr := httptest.NewRequest(http.MethodGet, "/", nil)
			sess := jw.NewSession(httptest.NewRecorder(), hr)
			if err = srv.storeSessionAuthClaims(sess, map[string]any{"email": tc.email, "email_verified": tc.verified}, nil, time.Now().Add(time.Hour), nil); err != nil {
				t.Fatal(err)
			}
			defer srv.Logout(sess, nil)
			var ctx context.Context
			srv.WrapAdmin(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
				ctx = jw.NewRequest(hw, hr).Context()
			})).ServeHTTP(httptest.NewRecorder(), hr)
			if ctx == nil || ctx.Err() != nil {
				t.Fatal("initial admin request not live")
			}
			srv.SetAdmins(tc.after)
			if srv.sessionIsAdmin(sess) != tc.wantAdmin || errors.Is(ctx.Err(), context.Canceled) == tc.wantAdmin {
				t.Fatalf("admin=%v cancellation=%v, want admin=%v", srv.sessionIsAdmin(sess), ctx.Err(), tc.wantAdmin)
			}
			if current, _ := srv.sessionAuthStatus(sess, time.Now); !current {
				t.Fatal("admin policy change cleared ordinary login")
			}
		})
	}
}

func TestLoginPreparesUserInfoBeforeRotation(t *testing.T) {
	// UserInfo latency can exceed a new session's one-minute idle lifetime.
	// synctest covers that interval without a wall-clock delay.
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		go jw.ServeWithTimeout(2 * time.Minute)
		defer jw.Close()
		srv := newWrapperTestServer(jw, "https://issuer.example")
		expiry := time.Now().Add(time.Hour)
		hr := httptest.NewRequest(http.MethodGet, "/callback?state=state&code=code", nil)
		sess := jw.NewSession(httptest.NewRecorder(), hr)
		if err = srv.storeSessionAuthClaims(sess, map[string]any{"sub": "user", "email": "user@example.com"}, nil, expiry, nil); err != nil {
			t.Fatal(err)
		}
		defer srv.Logout(sess, nil)
		var ctx context.Context
		srv.Wrap(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
			ctx = jw.NewRequest(hw, hr).Context()
		})).ServeHTTP(httptest.NewRecorder(), hr)
		raw := makeIDToken(t, map[string]any{"iss": "https://issuer.example", "aud": "client", "sub": "user", "exp": expiry.Unix(), "nonce": "nonce", "email": "user@example.com"})
		userinfoCalls := 0
		srv.userinfoUrl = "https://provider.example/userinfo"
		srv.httpClient = &http.Client{Transport: roundTripFunc(func(hr *http.Request) (*http.Response, error) {
			body := `{"access_token":"dummy","token_type":"Bearer","expires_in":3600,"id_token":"` + raw + `"}`
			if hr.URL.Path == "/userinfo" {
				userinfoCalls++
				time.Sleep(61 * time.Second)
				body = `{"sub":"user","email":"user@example.com","email_verified":true}`
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		logins, logouts := 0, 0
		srv.LoginEvent = func(*jaws.Session, *http.Request) { logins++ }
		srv.LogoutEvent = func(*jaws.Session, *http.Request) { logouts++ }
		sess.Set(oauth2StateKey, "state")
		sess.Set(oauth2NonceKey, "nonce")
		sess.Set(oauth2PKCEVerifierKey, oauth2.GenerateVerifier())
		hw := httptest.NewRecorder()
		srv.HandleAuthResponse(hw, hr)
		current := jw.GetSession(hr)
		if current != nil {
			defer srv.Logout(current, nil)
		}
		if hw.Code != http.StatusFound || logins != 1 || logouts != 1 || userinfoCalls != 1 {
			t.Fatalf("status=%d logins=%d logouts=%d userinfo=%d", hw.Code, logins, logouts, userinfoCalls)
		}
		if current == nil || current == sess || sess.Cookie().MaxAge >= 0 || !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("login did not retire the old session and request")
		}
		if current.Get(srv.SessionEmailVerifiedKey) != true {
			t.Fatal("login did not store prepared UserInfo claims")
		}
	})
}
