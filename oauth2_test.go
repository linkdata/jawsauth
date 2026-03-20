package jawsauth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

type passthroughKeySet struct {
	forceError error
}

func (ks passthroughKeySet) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	if ks.forceError != nil {
		return nil, ks.forceError
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func makeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"test"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	return header + "." + payload + "." + signature
}

func Test_errtext(t *testing.T) {
	var sb strings.Builder
	writeBody(&sb, http.StatusForbidden, ErrOAuth2WrongState, nil)
	s := sb.String()
	if !strings.Contains(s, "403 Forbidden") {
		t.Fatal()
	}
	if !strings.Contains(s, ErrOAuth2WrongState.Error()) {
		t.Fatal()
	}
}

func Test_writeHeaders(t *testing.T) {
	hw := httptest.NewRecorder()
	DefaultSetHeaders(hw, true)
	if x := hw.Header().Get("Cache-Control"); x != "no-store" {
		t.Errorf("unexpected cache-control header: %q", x)
	}
	if x := hw.Header().Get("Strict-Transport-Security"); x == "" {
		t.Error("STS not set")
	}
}

func Test_sanitizeRedirectTarget(t *testing.T) {
	if s := sanitizeRedirectTarget("example.com", "https://example.com/safe?x=1"); s != "/safe?x=1" {
		t.Fatal(s)
	}
	if s := sanitizeRedirectTarget("example.com", "https://evil.com/attack"); s != "/" {
		t.Fatal(s)
	}
	if s := sanitizeRedirectTarget("example.com:8443", "https://example.com/dashboard"); s != "/dashboard" {
		t.Fatal(s)
	}
	if s := sanitizeRedirectTarget("example.com", "section/page"); s != "/section/page" {
		t.Fatal(s)
	}
	if s := sanitizeRedirectTarget("example.com", "//example.com/dual"); s != "/example.com/dual" {
		t.Fatal(s)
	}
	if s := sanitizeRedirectTarget("example.com", ""); s != "/" {
		t.Fatal(s)
	}
}

func Test_beginSanitizesReferrer(t *testing.T) {
	srv := &Server{HandledPaths: make(map[string]struct{})}
	hr := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/login", nil)
	hr.Header.Set("Referer", "https://evil.com/wrong")
	_, _, location := srv.begin(hr)
	if location != "/" {
		t.Fatal(location)
	}
}

func Test_beginReferrerHandling(t *testing.T) {
	srv := &Server{HandledPaths: map[string]struct{}{"/oauth2/login": {}}}
	hr := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/login", nil)
	hr.Header.Set("Referer", "https://example.com/oauth2/login")
	_, _, location := srv.begin(hr)
	if location != "/" {
		t.Fatal(location)
	}
	hr.Header.Set("Referer", "https://example.com/app/home")
	_, _, location = srv.begin(hr)
	if location != "/app/home" {
		t.Fatal(location)
	}
}

func Test_handleLoginGeneratesOpaqueState(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	srv := &Server{
		Jaws:         jw,
		HandledPaths: map[string]struct{}{"/oauth2/login": {}},
		oauth2cfg: &oauth2.Config{
			ClientID:    "client",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://provider.example/auth"},
			RedirectURL: "https://example.com/oauth2/callback",
		},
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/login", nil)
	req.Header.Set("Referer", "https://example.com/secure")
	rec := httptest.NewRecorder()
	jw.NewSession(rec, req)
	srv.HandleLogin(rec, req)
	resp := rec.Result()
	if resp.StatusCode != http.StatusFound {
		resp.Body.Close()
		t.Fatal(resp.Status)
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.HasPrefix(loc, "https://provider.example/auth?") {
		t.Fatal(loc)
	}
	sess := jw.GetSession(req)
	if sess == nil {
		t.Fatal("missing session")
	}
	state, _ := sess.Get(oauth2StateKey).(string)
	if len(state) != 64 {
		t.Fatal(state)
	}
	if _, err = hex.DecodeString(state); err != nil {
		t.Fatal(err)
	}
	verifier, _ := sess.Get(oauth2PKCEVerifierKey).(string)
	if verifier == "" {
		t.Fatal("missing pkce verifier")
	}
	parsedURL, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	values := parsedURL.Query()
	if gotChallenge := values.Get("code_challenge"); gotChallenge != oauth2.S256ChallengeFromVerifier(verifier) {
		t.Fatal(gotChallenge)
	}
	if gotMethod := values.Get("code_challenge_method"); gotMethod != "S256" {
		t.Fatal(gotMethod)
	}
	nonce, _ := sess.Get(oauth2NonceKey).(string)
	if len(nonce) != 64 {
		t.Fatal(nonce)
	}
	if gotNonce := values.Get("nonce"); gotNonce != nonce {
		t.Fatal(gotNonce)
	}
	referrer, _ := sess.Get(oauth2ReferrerKey).(string)
	if referrer != "/secure" {
		t.Fatal(referrer)
	}
}

func Test_handleAuthResponseUsesPKCEVerifier(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	var mu sync.Mutex
	var gotVerifier string
	var gotCode string
	var gotAuth string
	var providerErr error
	setProviderErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if providerErr == nil {
			providerErr = err
		}
		mu.Unlock()
	}
	const issuer = "https://issuer.example"
	const wantNonce = "nonce123"
	idToken := makeIDToken(t, map[string]any{
		"iss":            issuer,
		"aud":            "client",
		"exp":            time.Now().Add(10 * time.Minute).Unix(),
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"nonce":          wantNonce,
		"sub":            "sub-123",
		"email":          "idtoken@example.com",
		"email_verified": true,
	})
	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		switch hr.URL.Path {
		case "/token":
			if err := hr.ParseForm(); err != nil {
				setProviderErr(err)
				hw.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			gotVerifier = hr.FormValue("code_verifier")
			gotCode = hr.FormValue("code")
			mu.Unlock()
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600,"id_token":"` + idToken + `"}`))
		case "/userinfo":
			mu.Lock()
			gotAuth = hr.Header.Get("Authorization")
			mu.Unlock()
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"email":"userinfo@example.com","name":"Profile Name"}`))
		default:
			setProviderErr(fmt.Errorf("unexpected provider path %s", hr.URL.Path))
			hw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer provider.Close()

	srv := &Server{
		Jaws:                    jw,
		SessionKey:              "oauth2userinfo",
		SessionTokenKey:         "oauth2token",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
		HandledPaths:            map[string]struct{}{"/oauth2/callback": {}},
		oauth2cfg: &oauth2.Config{
			ClientID:     "client",
			ClientSecret: "secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  provider.URL + "/auth",
				TokenURL: provider.URL + "/token",
			},
			RedirectURL: "http://example.com/oauth2/callback",
		},
		idTokenVerifier: oidc.NewVerifier(issuer, passthroughKeySet{}, &oidc.Config{ClientID: "client"}),
		userinfoUrl:     provider.URL + "/userinfo",
	}

	const wantState = "state123"
	const wantCode = "authcode123"
	verifier := oauth2.GenerateVerifier()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback?state="+wantState+"&code="+wantCode, nil)
	sess := jw.NewSession(rec, req)
	sess.Set(oauth2StateKey, wantState)
	sess.Set(oauth2PKCEVerifierKey, verifier)
	sess.Set(oauth2NonceKey, wantNonce)
	sess.Set(oauth2ReferrerKey, "/secure")

	srv.HandleAuthResponse(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusFound {
		resp.Body.Close()
		t.Fatal(resp.Status)
	}
	if gotLocation := resp.Header.Get("Location"); gotLocation != "/secure" {
		resp.Body.Close()
		t.Fatal(gotLocation)
	}
	resp.Body.Close()

	mu.Lock()
	receivedCode := gotCode
	receivedVerifier := gotVerifier
	receivedAuth := gotAuth
	receivedProviderErr := providerErr
	mu.Unlock()

	if receivedCode != wantCode {
		t.Fatal(receivedCode)
	}
	if receivedVerifier != verifier {
		t.Fatal(receivedVerifier)
	}
	if receivedAuth != "Bearer token123" {
		t.Fatal(receivedAuth)
	}
	if receivedProviderErr != nil {
		t.Fatal(receivedProviderErr)
	}
	if gotState, _ := sess.Get(oauth2StateKey).(string); gotState != "" {
		t.Fatal(gotState)
	}
	if gotVerifier, _ := sess.Get(oauth2PKCEVerifierKey).(string); gotVerifier != "" {
		t.Fatal(gotVerifier)
	}
	if gotNonce, _ := sess.Get(oauth2NonceKey).(string); gotNonce != "" {
		t.Fatal(gotNonce)
	}
	if gotEmail, _ := sess.Get(srv.SessionEmailKey).(string); gotEmail != "idtoken@example.com" {
		t.Fatal(gotEmail)
	}
	if gotVerified, _ := sess.Get(srv.SessionEmailVerifiedKey).(bool); !gotVerified {
		t.Fatal(gotVerified)
	}
	if gotUserInfo, ok := sess.Get(srv.SessionKey).(map[string]any); !ok || gotUserInfo["email"] != "idtoken@example.com" || gotUserInfo["name"] != "Profile Name" {
		t.Fatal(gotUserInfo)
	}
	if tokenSource, ok := sess.Get(srv.SessionTokenKey).(oauth2.TokenSource); !ok || tokenSource == nil {
		t.Fatal("missing token source")
	}
}

func Test_handleAuthResponseMissingPKCEVerifier(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	var tokenRequests int
	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		if hr.URL.Path == "/token" {
			tokenRequests++
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600}`))
			return
		}
		hw.WriteHeader(http.StatusNotFound)
	}))
	defer provider.Close()

	srv := &Server{
		Jaws:                    jw,
		SessionKey:              "oauth2userinfo",
		SessionTokenKey:         "oauth2token",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
		httpClient:              &http.Client{},
		oauth2cfg: &oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				TokenURL: provider.URL + "/token",
			},
			RedirectURL: "http://example.com/oauth2/callback",
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback?state=state123&code=authcode123", nil)
	sess := jw.NewSession(rec, req)
	sess.Set(oauth2StateKey, "state123")
	sess.Set(oauth2NonceKey, "nonce123")

	srv.HandleAuthResponse(rec, req)

	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal(resp.Status)
	}
	if !strings.Contains(string(body), ErrOAuth2MissingPKCEVerifier.Error()) {
		t.Fatal(string(body))
	}
	if tokenRequests != 0 {
		t.Fatal(tokenRequests)
	}
}

func Test_extractEmailVerified(t *testing.T) {
	testCases := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{
			name:   "bool",
			claims: map[string]any{"email_verified": true},
			want:   true,
		},
		{
			name:   "string",
			claims: map[string]any{"email_verified": "true"},
			want:   true,
		},
		{
			name:   "float",
			claims: map[string]any{"email_verified": float64(1)},
			want:   true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := extractEmailVerified(tc.claims); got != tc.want {
				t.Fatalf("extractEmailVerified() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServer_fetchUserInfoStatusError(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		_ = hr
		hw.WriteHeader(http.StatusUnauthorized)
	}))
	defer provider.Close()

	srv := &Server{}
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "token",
		TokenType:   "Bearer",
	})

	userinfo, err := srv.fetchUserInfo(t.Context(), provider.URL, tokenSource)
	if err == nil {
		t.Fatal("expected error")
	}
	if userinfo != nil {
		t.Fatal(userinfo)
	}
	if !strings.Contains(err.Error(), "userinfo status 401 Unauthorized") {
		t.Fatal(err)
	}
}

func Test_handleAuthResponseMissingIDToken(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		if hr.URL.Path == "/token" {
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600}`))
			return
		}
		hw.WriteHeader(http.StatusNotFound)
	}))
	defer provider.Close()

	srv := &Server{
		Jaws:                    jw,
		SessionKey:              "oauth2userinfo",
		SessionTokenKey:         "oauth2token",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
		oauth2cfg: &oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				TokenURL: provider.URL + "/token",
			},
			RedirectURL: "http://example.com/oauth2/callback",
		},
		idTokenVerifier: oidc.NewVerifier(issuer, passthroughKeySet{}, &oidc.Config{ClientID: "client"}),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback?state=state123&code=authcode123", nil)
	sess := jw.NewSession(rec, req)
	sess.Set(oauth2StateKey, "state123")
	sess.Set(oauth2PKCEVerifierKey, oauth2.GenerateVerifier())
	sess.Set(oauth2NonceKey, "nonce123")

	srv.HandleAuthResponse(rec, req)

	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.Status)
	}
	if !strings.Contains(string(body), ErrOIDCMissingIDToken.Error()) {
		t.Fatal(string(body))
	}
}

func Test_handleAuthResponseInvalidIDToken(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	idToken := makeIDToken(t, map[string]any{
		"iss":   "https://attacker.example",
		"aud":   "client",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nonce": "nonce123",
		"sub":   "sub-123",
	})

	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		if hr.URL.Path == "/token" {
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600,"id_token":"` + idToken + `"}`))
			return
		}
		hw.WriteHeader(http.StatusNotFound)
	}))
	defer provider.Close()

	srv := &Server{
		Jaws:                    jw,
		SessionKey:              "oauth2userinfo",
		SessionTokenKey:         "oauth2token",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
		oauth2cfg: &oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				TokenURL: provider.URL + "/token",
			},
			RedirectURL: "http://example.com/oauth2/callback",
		},
		idTokenVerifier: oidc.NewVerifier(issuer, passthroughKeySet{}, &oidc.Config{ClientID: "client"}),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback?state=state123&code=authcode123", nil)
	sess := jw.NewSession(rec, req)
	sess.Set(oauth2StateKey, "state123")
	sess.Set(oauth2PKCEVerifierKey, oauth2.GenerateVerifier())
	sess.Set(oauth2NonceKey, "nonce123")

	srv.HandleAuthResponse(rec, req)

	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.Status)
	}
	if !strings.Contains(string(body), ErrOIDCInvalidIDToken.Error()) {
		t.Fatal(string(body))
	}
}

func Test_handleAuthResponseNonceMismatch(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	const issuer = "https://issuer.example"
	idToken := makeIDToken(t, map[string]any{
		"iss":   issuer,
		"aud":   "client",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nonce": "wrongnonce",
		"sub":   "sub-123",
	})

	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		if hr.URL.Path == "/token" {
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"access_token":"token123","token_type":"Bearer","expires_in":3600,"id_token":"` + idToken + `"}`))
			return
		}
		hw.WriteHeader(http.StatusNotFound)
	}))
	defer provider.Close()

	srv := &Server{
		Jaws:                    jw,
		SessionKey:              "oauth2userinfo",
		SessionTokenKey:         "oauth2token",
		SessionEmailKey:         "email",
		SessionEmailVerifiedKey: "email_verified",
		oauth2cfg: &oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{
				TokenURL: provider.URL + "/token",
			},
			RedirectURL: "http://example.com/oauth2/callback",
		},
		idTokenVerifier: oidc.NewVerifier(issuer, passthroughKeySet{}, &oidc.Config{ClientID: "client"}),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback?state=state123&code=authcode123", nil)
	sess := jw.NewSession(rec, req)
	sess.Set(oauth2StateKey, "state123")
	sess.Set(oauth2PKCEVerifierKey, oauth2.GenerateVerifier())
	sess.Set(oauth2NonceKey, "nonce123")

	srv.HandleAuthResponse(rec, req)

	resp := rec.Result()
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.Status)
	}
	if !strings.Contains(string(body), ErrOIDCNonceMismatch.Error()) {
		t.Fatal(string(body))
	}
}

func Test_handleAuthResponseWithoutSession(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	srv := &Server{
		Jaws:         jw,
		HandledPaths: map[string]struct{}{},
		oauth2cfg: &oauth2.Config{
			ClientID:    "client",
			Endpoint:    oauth2.Endpoint{TokenURL: "https://provider.example/token"},
			RedirectURL: "https://example.com/oauth2/callback",
		},
		userinfoUrl: "https://provider.example/userinfo",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback", nil)
	srv.HandleAuthResponse(rec, req)
	resp := rec.Result()
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatal(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), ErrOAuth2MissingSession.Error()) {
		t.Fatal(string(body))
	}
}

func Test_handleAuthResponseLoginFailedFallsBack(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	srv := &Server{Jaws: jw}
	var callbackCount int
	var callbackStatus int
	var callbackErr error
	var callbackEmail string
	srv.LoginFailed = func(hw http.ResponseWriter, hr *http.Request, httpCode int, callErr error, email string) bool {
		callbackCount++
		callbackStatus = httpCode
		callbackErr = callErr
		callbackEmail = email
		return false
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback", nil)
	srv.HandleAuthResponse(rec, req)
	if callbackCount != 1 {
		t.Fatalf("expected LoginFailed callback, got %d", callbackCount)
	}
	if callbackStatus != http.StatusInternalServerError {
		t.Fatal(callbackStatus)
	}
	if !errors.Is(callbackErr, ErrOAuth2NotConfigured) {
		t.Fatal(callbackErr)
	}
	if callbackEmail != "" {
		t.Fatal(callbackEmail)
	}
	resp := rec.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		resp.Body.Close()
		t.Fatal(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), ErrOAuth2NotConfigured.Error()) {
		t.Fatal(string(body))
	}
}

func Test_handleAuthResponseLoginFailedHandlesResponse(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	srv := &Server{Jaws: jw}
	const customBody = "handled by callback"
	srv.LoginFailed = func(hw http.ResponseWriter, hr *http.Request, httpCode int, callErr error, email string) bool {
		if httpCode != http.StatusInternalServerError {
			t.Fatal(httpCode)
		}
		if !errors.Is(callErr, ErrOAuth2NotConfigured) {
			t.Fatal(callErr)
		}
		if email != "" {
			t.Fatal(email)
		}
		hw.WriteHeader(http.StatusTeapot)
		if _, err := hw.Write([]byte(customBody)); err != nil {
			t.Fatal(err)
		}
		return true
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback", nil)
	srv.HandleAuthResponse(rec, req)
	resp := rec.Result()
	if resp.StatusCode != http.StatusTeapot {
		resp.Body.Close()
		t.Fatal(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != customBody {
		t.Fatal(string(body))
	}
}

func TestServerExtractEmail(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	testCases := []struct {
		name       string
		userinfo   map[string]any
		want       string
		expectNil  bool
		expectWarn bool
	}{
		{
			name:     "emailFieldNormalized",
			userinfo: map[string]any{"email": " Test.User+Tag@Example.COM "},
			want:     "test.user+tag@example.com",
		},
		{
			name:     "emailFieldWithDisplayName",
			userinfo: map[string]any{"email": `"Test User" <TestUser@Example.com>`},
			want:     "testuser@example.com",
		},
		{
			name:     "mailFieldFallback",
			userinfo: map[string]any{"mail": "Secondary@Example.com "},
			want:     "secondary@example.com",
		},
		{
			name:     "mailFieldFallbackWhenEmailIsWrongType",
			userinfo: map[string]any{"email": 123, "mail": "AltUser@Example.com"},
			want:     "altuser@example.com",
		},
		{
			name:       "missingEmailInformation",
			userinfo:   map[string]any{"email": 123, "mail": nil},
			expectNil:  true,
			expectWarn: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			handler := &recordingHandler{}
			jw.Logger = slog.New(handler)
			srv := &Server{Jaws: jw}
			var got any
			got = srv.extractEmail(tc.userinfo)
			if tc.expectNil {
				if got != nil {
					t.Fatalf("expected nil email value, got %v", got)
				}
			} else {
				s, ok := got.(string)
				if !ok {
					t.Fatalf("expected string email value, got %T", got)
				}
				if s != tc.want {
					t.Fatalf("unexpected email value: want %s got %s", tc.want, s)
				}
			}
			if tc.expectWarn {
				if !handler.called {
					t.Fatal("expected warning log when email information is missing")
				}
				if handler.level != slog.LevelWarn {
					t.Fatalf("unexpected log level: %s", handler.level)
				}
				if handler.message != "jawsauth: no email found" {
					t.Fatalf("unexpected log message: %s", handler.message)
				}
				var attrFound bool
				for _, attr := range handler.attrs {
					if attr.Key == "userinfo" {
						attrFound = true
						if !reflect.DeepEqual(attr.Value.Any(), tc.userinfo) {
							t.Fatalf("logged userinfo mismatch: %#v", attr.Value.Any())
						}
					}
				}
				if !attrFound {
					t.Fatal("userinfo attribute missing from log entry")
				}
			} else {
				if handler.called {
					t.Fatal("unexpected warning log for userinfo containing email data")
				}
			}
		})
	}
}

type recordingHandler struct {
	called  bool
	level   slog.Level
	message string
	attrs   []slog.Attr
}

func (h *recordingHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *recordingHandler) Handle(_ context.Context, rec slog.Record) error {
	h.called = true
	h.level = rec.Level
	h.message = rec.Message
	h.attrs = nil
	rec.Attrs(func(attr slog.Attr) bool {
		h.attrs = append(h.attrs, attr)
		return true
	})
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	_ = attrs
	return h
}

func (h *recordingHandler) WithGroup(string) slog.Handler {
	return h
}
