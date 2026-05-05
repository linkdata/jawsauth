package jawsauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

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

func TestWrapperServeHTTPAllowsPresentAuthData(t *testing.T) {
	testCases := []struct {
		name      string
		authValue any
	}{
		{
			name: "unexpired",
			authValue: map[string]any{
				"exp":   time.Now().Add(time.Hour).Unix(),
				"email": "user@example.com",
			},
		},
		{
			name: "expired",
			authValue: map[string]any{
				"exp":   time.Now().Add(-time.Minute).Unix(),
				"email": "old@example.com",
			},
		},
		{
			name: "missingExp",
			authValue: map[string]any{
				"email": "old@example.com",
			},
		},
		{
			name:      "nonClaimsValue",
			authValue: "present",
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
			req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
			sess := jw.NewSession(httptest.NewRecorder(), req)
			sess.Set(srv.SessionKey, tc.authValue)

			w := wrapper{
				server:  srv,
				handler: testStatusHandler{statusCode: http.StatusOK},
			}

			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, req)

			if code := rec.Result().StatusCode; code != http.StatusOK {
				t.Fatal(code)
			}
		})
	}
}

func TestWrapperServeHTTPRedirectsWhenAuthDataMissing(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := newWrapperTestServer(jw, "https://issuer.example")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	jw.NewSession(httptest.NewRecorder(), req)

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
