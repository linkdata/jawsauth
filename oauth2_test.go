package jawsauth

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

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
	referrer, _ := sess.Get(oauth2ReferrerKey).(string)
	if referrer != "/secure" {
		t.Fatal(referrer)
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
