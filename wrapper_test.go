package jawsauth

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

var errWrapperRefreshFailed = errors.New("wrapper refresh failed")

type testStatusHandler struct {
	statusCode int
}

func (h testStatusHandler) ServeHTTP(hw http.ResponseWriter, _ *http.Request) {
	hw.WriteHeader(h.statusCode)
}

// Run with -race; this used to report a data race between Set403Handler and ServeHTTP.
func TestWrapperServeHTTPSet403HandlerConcurrent(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := &Server{
		Jaws:            jw,
		SessionKey:      "oauth2userinfo",
		SessionEmailKey: "email",
		HandledPaths:    map[string]struct{}{},
		admins:          map[string]struct{}{"admin@example.com": {}},
		handle403:       testStatusHandler{statusCode: http.StatusForbidden},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	sess.Set(srv.SessionKey, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
		"ok":  true,
	})
	sess.Set(srv.SessionEmailKey, "user@example.com")

	w := wrapper{
		server:  srv,
		handler: testStatusHandler{statusCode: http.StatusOK},
		admin:   true,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 2000 {
			srv.Set403Handler(testStatusHandler{statusCode: http.StatusForbidden})
			srv.Set403Handler(testStatusHandler{statusCode: http.StatusUnauthorized})
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			w.ServeHTTP(httptest.NewRecorder(), req)
		}
	}()
	wg.Wait()

	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if code := rec.Result().StatusCode; code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatal(code)
	}
}

func TestWrapperServeHTTPAllowsUnexpiredClaims(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := newWrapperTestServer(jw, "https://issuer.example")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	sess.Set(srv.SessionKey, map[string]any{
		"exp":   time.Now().Add(time.Hour).Unix(),
		"email": "user@example.com",
	})

	w := wrapper{
		server:  srv,
		handler: testStatusHandler{statusCode: http.StatusOK},
	}

	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if code := rec.Result().StatusCode; code != http.StatusOK {
		t.Fatal(code)
	}
}

func TestWrapperServeHTTPRefreshesExpiredClaims(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	refreshedIDToken := makeIDToken(t, map[string]any{
		"iss":            issuer,
		"aud":            "client",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"sub":            "sub-123",
		"email":          "refreshed@example.com",
		"email_verified": true,
	})

	var mu sync.Mutex
	var tokenRequests int
	var userinfoRequests int
	var refreshGrant string
	var refreshToken string
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

	srv := newWrapperTestServer(jw, issuer)
	srv.oauth2cfg.Endpoint.AuthURL = provider.URL + "/auth"
	srv.oauth2cfg.Endpoint.TokenURL = provider.URL + "/token"
	srv.userinfoUrl = provider.URL + "/userinfo"
	var logoutCount int
	srv.LogoutEvent = func(*jaws.Session, *http.Request) {
		logoutCount++
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	sess.Set(srv.SessionKey, map[string]any{
		"exp":   time.Now().Add(-time.Minute).Unix(),
		"email": "old@example.com",
	})
	sess.Set(srv.SessionEmailKey, "old@example.com")
	sess.Set(srv.SessionEmailVerifiedKey, false)
	sess.Set(srv.SessionTokenKey, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken:  "cached-access",
		TokenType:    "Bearer",
		RefreshToken: "refresh123",
		Expiry:       time.Now().Add(time.Hour),
	}))

	w := wrapper{
		server:  srv,
		handler: testStatusHandler{statusCode: http.StatusOK},
	}

	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if code := rec.Result().StatusCode; code != http.StatusOK {
		t.Fatal(code)
	}
	if logoutCount != 0 {
		t.Fatal(logoutCount)
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
	gotUserinfoRequests := userinfoRequests
	gotRefreshGrant := refreshGrant
	gotRefreshToken := refreshToken
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

func TestWrapperServeHTTPClearsExpiredAuthWithoutRefresh(t *testing.T) {
	testCases := []struct {
		name   string
		claims map[string]any
	}{
		{
			name: "expired",
			claims: map[string]any{
				"exp":   time.Now().Add(-time.Minute).Unix(),
				"email": "old@example.com",
			},
		},
		{
			name: "missingExp",
			claims: map[string]any{
				"email": "old@example.com",
			},
		},
		{
			name: "malformedExp",
			claims: map[string]any{
				"exp":   "not-a-number",
				"email": "old@example.com",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()

			srv := newWrapperTestServer(jw, "https://issuer.example")
			var logoutCount int
			srv.LogoutEvent = func(*jaws.Session, *http.Request) {
				logoutCount++
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
			sess := jw.NewSession(httptest.NewRecorder(), req)
			sess.Set(srv.SessionKey, tc.claims)
			sess.Set(srv.SessionTokenKey, "stale-token")
			sess.Set(srv.SessionEmailKey, "old@example.com")
			sess.Set(srv.SessionEmailVerifiedKey, true)

			w := wrapper{
				server:  srv,
				handler: testStatusHandler{statusCode: http.StatusOK},
			}

			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, req)

			if code := rec.Result().StatusCode; code != http.StatusFound {
				t.Fatal(code)
			}
			if loc := rec.Result().Header.Get("Location"); loc == "" {
				t.Fatal("missing login redirect")
			}
			assertWrapperAuthCleared(t, srv, sess)
			if logoutCount != 1 {
				t.Fatal(logoutCount)
			}

			rec = httptest.NewRecorder()
			w.ServeHTTP(rec, req)
			if logoutCount != 1 {
				t.Fatal(logoutCount)
			}
		})
	}
}

func TestWrapperServeHTTPClearsAuthWhenRefreshFails(t *testing.T) {
	const issuer = "https://issuer.example"
	invalidIDToken := makeIDToken(t, map[string]any{
		"iss": "https://attacker.example",
		"aud": "client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
		"sub": "sub-123",
	})
	testCases := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "refreshError",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"invalid_grant"}`,
		},
		{
			name:       "missingRefreshedIDToken",
			statusCode: http.StatusOK,
			body:       `{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh456"}`,
		},
		{
			name:       "invalidRefreshedIDToken",
			statusCode: http.StatusOK,
			body:       `{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh456","id_token":"` + invalidIDToken + `"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()

			var mu sync.Mutex
			var tokenRequests int
			provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
				if hr.URL.Path != "/token" {
					hw.WriteHeader(http.StatusNotFound)
					return
				}
				mu.Lock()
				tokenRequests++
				mu.Unlock()
				hw.Header().Set("Content-Type", "application/json")
				hw.WriteHeader(tc.statusCode)
				_, _ = hw.Write([]byte(tc.body))
			}))
			defer provider.Close()

			srv := newWrapperTestServer(jw, issuer)
			srv.oauth2cfg.Endpoint.AuthURL = provider.URL + "/auth"
			srv.oauth2cfg.Endpoint.TokenURL = provider.URL + "/token"
			var logoutCount int
			srv.LogoutEvent = func(*jaws.Session, *http.Request) {
				logoutCount++
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
			sess := jw.NewSession(httptest.NewRecorder(), req)
			sess.Set(srv.SessionKey, map[string]any{
				"exp":   time.Now().Add(-time.Minute).Unix(),
				"email": "old@example.com",
			})
			sess.Set(srv.SessionEmailKey, "old@example.com")
			sess.Set(srv.SessionEmailVerifiedKey, true)
			sess.Set(srv.SessionTokenKey, oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken:  "cached-access",
				TokenType:    "Bearer",
				RefreshToken: "refresh123",
				Expiry:       time.Now().Add(time.Hour),
			}))

			w := wrapper{
				server:  srv,
				handler: testStatusHandler{statusCode: http.StatusOK},
			}

			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, req)

			if code := rec.Result().StatusCode; code != http.StatusFound {
				t.Fatal(code)
			}
			assertWrapperAuthCleared(t, srv, sess)
			if logoutCount != 1 {
				t.Fatal(logoutCount)
			}
			mu.Lock()
			gotTokenRequests := tokenRequests
			mu.Unlock()
			if gotTokenRequests != 1 {
				t.Fatal(gotTokenRequests)
			}
		})
	}
}

func TestSessionAuthenticatedPreservesConcurrentRefresh(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := newWrapperTestServer(jw, "https://issuer.example")
	var logoutCount int
	srv.LogoutEvent = func(*jaws.Session, *http.Request) {
		logoutCount++
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	sess.Set(srv.SessionKey, map[string]any{
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	sess.Set(srv.SessionTokenKey, refreshingSessionTokenSource{
		srv:  srv,
		sess: sess,
	})

	if !srv.sessionAuthenticated(req.Context(), sess, req) {
		t.Fatal("expected refreshed session to remain authenticated")
	}
	if logoutCount != 0 {
		t.Fatal(logoutCount)
	}
	claims, ok := sess.Get(srv.SessionKey).(map[string]any)
	if !ok {
		t.Fatal("missing claims")
	}
	if oidcClaimsExpired(claims, time.Now()) {
		t.Fatal(claims)
	}
}

func TestSessionAuthenticatedClearsInvalidSessionValue(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := newWrapperTestServer(jw, "https://issuer.example")
	var logoutCount int
	srv.LogoutEvent = func(*jaws.Session, *http.Request) {
		logoutCount++
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	sess.Set(srv.SessionKey, "corrupt")
	sess.Set(srv.SessionTokenKey, "stale-token")
	sess.Set(srv.SessionEmailKey, "old@example.com")
	sess.Set(srv.SessionEmailVerifiedKey, true)

	if srv.sessionAuthenticated(req.Context(), sess, req) {
		t.Fatal("expected invalid auth value to de-auth")
	}
	assertWrapperAuthCleared(t, srv, sess)
	if logoutCount != 1 {
		t.Fatal(logoutCount)
	}
}

func TestOAuth2ContextUsesServerHTTPClient(t *testing.T) {
	client := &http.Client{}
	srv := &Server{httpClient: client}

	ctx := srv.oauth2Context(context.Background())
	if got, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); got != client {
		t.Fatal(got)
	}

	otherClient := &http.Client{}
	base := context.WithValue(context.Background(), oauth2.HTTPClient, otherClient)
	ctx = srv.oauth2Context(base)
	if got, _ := ctx.Value(oauth2.HTTPClient).(*http.Client); got != otherClient {
		t.Fatal(got)
	}
}

func TestOIDCClaimExpiryTypes(t *testing.T) {
	const wantUnix = int64(1893456000)
	testCases := []struct {
		name string
		exp  any
		ok   bool
	}{
		{name: "jsonNumber", exp: json.Number("1893456000"), ok: true},
		{name: "float64", exp: float64(wantUnix), ok: true},
		{name: "float32", exp: float32(wantUnix), ok: true},
		{name: "int", exp: int(wantUnix), ok: true},
		{name: "int8", exp: int8(12), ok: true},
		{name: "int16", exp: int16(1234), ok: true},
		{name: "int32", exp: int32(wantUnix), ok: true},
		{name: "int64", exp: wantUnix, ok: true},
		{name: "uint", exp: uint(wantUnix), ok: true},
		{name: "uint8", exp: uint8(12), ok: true},
		{name: "uint16", exp: uint16(1234), ok: true},
		{name: "uint32", exp: uint32(wantUnix), ok: true},
		{name: "uint64", exp: uint64(wantUnix), ok: true},
		{name: "intString", exp: "1893456000", ok: true},
		{name: "floatString", exp: "1893456000.9", ok: true},
		{name: "emptyString", exp: "", ok: false},
		{name: "badString", exp: "not-a-number", ok: false},
		{name: "unsupported", exp: []string{"1893456000"}, ok: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := oidcClaimExpiry(tc.exp)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got.IsZero() {
				t.Fatal(got)
			}
		})
	}
}

func TestOIDCClaimExpiryRejectsOutOfRangeValues(t *testing.T) {
	testCases := []struct {
		name string
		exp  any
	}{
		{name: "nan", exp: math.NaN()},
		{name: "inf", exp: math.Inf(1)},
		{name: "floatTooLarge", exp: math.MaxFloat64},
		{name: "uintTooLarge", exp: uint64(math.MaxInt64) + 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := oidcClaimExpiry(tc.exp); ok {
				t.Fatal(got)
			}
		})
	}
}

func newWrapperTestServer(jw *jaws.Jaws, issuer string) *Server {
	return &Server{
		Jaws:                    jw,
		SessionKey:              "oauth2userinfo",
		SessionTokenKey:         "oauth2token",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
		HandledPaths:            map[string]struct{}{"/oauth2/login": {}},
		admins:                  map[string]struct{}{},
		handle403:               default403handler{},
		oauth2cfg: &oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://provider.example/auth",
				TokenURL:  "https://provider.example/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
			RedirectURL: "http://example.com/oauth2/callback",
		},
		idTokenVerifier: oidc.NewVerifier(issuer, passthroughKeySet{}, &oidc.Config{ClientID: "client"}),
	}
}

func assertWrapperAuthCleared(t *testing.T, srv *Server, sess *jaws.Session) {
	t.Helper()
	if value := sess.Get(srv.SessionKey); value != nil {
		t.Fatal(value)
	}
	if value := sess.Get(srv.SessionTokenKey); value != nil {
		t.Fatal(value)
	}
	if value := sess.Get(srv.SessionEmailKey); value != nil {
		t.Fatal(value)
	}
	if value := sess.Get(srv.SessionEmailVerifiedKey); value != nil {
		t.Fatal(value)
	}
}

type refreshingSessionTokenSource struct {
	srv  *Server
	sess *jaws.Session
}

func (ts refreshingSessionTokenSource) Token() (*oauth2.Token, error) {
	ts.sess.Set(ts.srv.SessionKey, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	return nil, errWrapperRefreshFailed
}
