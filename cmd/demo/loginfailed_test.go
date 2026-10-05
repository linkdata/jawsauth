package main

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestDemoLoginFailedQuotesError(t *testing.T) {
	var output strings.Builder
	original := demoLoginFailedLogger
	demoLoginFailedLogger = log.New(&output, "", 0)
	t.Cleanup(func() { demoLoginFailedLogger = original })
	for _, email := range []string{"", "user@example.com"} {
		output.Reset()
		err := errors.New("provider error\r\nTrace ID: 123\x1b")
		demoLoginFailed(httptest.NewRecorder(), nil, http.StatusBadRequest, err, email)
		if got := output.String(); strings.Count(got, "\n") != 1 || strings.ContainsAny(got, "\r\x1b") || !strings.Contains(got, strconv.Quote(err.Error())) {
			t.Fatalf("unquoted log: %q", got)
		}
	}
}
