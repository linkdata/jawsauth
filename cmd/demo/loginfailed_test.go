package main

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoLoginFailed(t *testing.T) {
	underlyingErr := errors.New("token exchange failed: client_secret=super-secret")
	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/oauth2/callback", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()

	var logs strings.Builder
	origLogger := demoLoginFailedLogger
	demoLoginFailedLogger = log.New(&logs, "", 0)
	t.Cleanup(func() {
		demoLoginFailedLogger = origLogger
	})

	if !demoLoginFailed(rr, req, http.StatusUnauthorized, underlyingErr, "demo@example.com") {
		t.Fatal("expected LoginFailed handler to handle response")
	}

	resp := rr.Result()
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	if got, want := resp.StatusCode, http.StatusUnauthorized; got != want {
		t.Fatalf("status code = %d, want %d", got, want)
	}
	if got, want := resp.Header.Get("Content-Type"), "text/html; charset=utf-8"; got != want {
		t.Fatalf("content type = %q, want %q", got, want)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	bodyText := string(body)
	if !strings.Contains(bodyText, "Sign-in failed") {
		t.Fatalf("response missing generic error title: %q", bodyText)
	}
	if strings.Contains(bodyText, underlyingErr.Error()) {
		t.Fatalf("response leaked internal error details: %q", bodyText)
	}
	if strings.Contains(bodyText, "demo@example.com") {
		t.Fatalf("response leaked user data: %q", bodyText)
	}

	logText := logs.String()
	if !strings.Contains(logText, "demo login failed") {
		t.Fatalf("log output missing failure message: %q", logText)
	}
	if !strings.Contains(logText, underlyingErr.Error()) {
		t.Fatalf("log output missing underlying error: %q", logText)
	}
}
