package jawsauth

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
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
