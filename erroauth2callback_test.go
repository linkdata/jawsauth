package jawsauth

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func Test_oauth2CallbackError(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantStatus int
		wantErr    string
	}{
		{
			name:       "none",
			url:        "http://example.com/oauth2/callback",
			wantStatus: http.StatusTeapot,
		},
		{
			name:       "accessDenied",
			url:        "http://example.com/oauth2/callback?error=access_denied&error_description=User+cancelled&error_uri=https%3A%2F%2Fprovider.example%2Fdocs%2Ferrors%23access_denied",
			wantStatus: http.StatusForbidden,
			wantErr:    "access_denied",
		},
		{
			name:       "otherError",
			url:        "http://example.com/oauth2/callback?error=server_error&error_description=boom",
			wantStatus: http.StatusBadRequest,
			wantErr:    "server_error",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			statusCode, err := oauth2CallbackError(http.StatusTeapot, req)
			if statusCode != tc.wantStatus {
				t.Fatal(statusCode)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected callback error")
			}
			if !errors.Is(err, ErrOAuth2Callback) {
				t.Fatal(err)
			}
			var callbackErr *OAuth2CallbackError
			if !errors.As(err, &callbackErr) {
				t.Fatal(err)
			}
			if callbackErr.Code != tc.wantErr {
				t.Fatal(callbackErr.Code)
			}
		})
	}
	req := httptest.NewRequest(
		http.MethodGet,
		"http://example.com/oauth2/callback?error=access_denied&error_description=User+cancelled&error_uri=https%3A%2F%2Fprovider.example%2Fdocs%2Ferrors%23access_denied",
		nil,
	)
	_, err := oauth2CallbackError(http.StatusTeapot, req)
	var callbackErr *OAuth2CallbackError
	if !errors.As(err, &callbackErr) {
		t.Fatal(err)
	}
	if callbackErr.Description != "User cancelled" {
		t.Fatal(callbackErr.Description)
	}
	if callbackErr.URI != "https://provider.example/docs/errors#access_denied" {
		t.Fatal(callbackErr.URI)
	}
	if !strings.Contains(err.Error(), "oauth2 callback error: access_denied") {
		t.Fatal(err.Error())
	}
}

func Test_oauth2CallbackErrorNilReceiver(t *testing.T) {
	var nilErr *OAuth2CallbackError
	if s := nilErr.Error(); s != ErrOAuth2Callback.Error() {
		t.Fatal(s)
	}
}

func Test_handleAuthResponseOAuthErrorCallback(t *testing.T) {
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
	var callbackStatus int
	var callbackErr error
	srv.LoginFailed = func(hw http.ResponseWriter, hr *http.Request, httpCode int, callErr error, email string) bool {
		callbackStatus = httpCode
		callbackErr = callErr
		if email != "" {
			t.Fatal(email)
		}
		return false
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"http://example.com/oauth2/callback?state=state123&error=access_denied&error_description=User+cancelled",
		nil,
	)
	sess := jw.NewSession(rec, req)
	sess.Set(oauth2StateKey, "state123")
	srv.HandleAuthResponse(rec, req)
	if callbackStatus != http.StatusForbidden {
		t.Fatal(callbackStatus)
	}
	if !errors.Is(callbackErr, ErrOAuth2Callback) {
		t.Fatal(callbackErr)
	}
	var oauthErr *OAuth2CallbackError
	if !errors.As(callbackErr, &oauthErr) {
		t.Fatal(callbackErr)
	}
	if oauthErr.Code != "access_denied" {
		t.Fatal(oauthErr.Code)
	}
	resp := rec.Result()
	if resp.StatusCode != http.StatusForbidden {
		resp.Body.Close()
		t.Fatal(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "oauth2 callback error: access_denied") {
		t.Fatal(string(body))
	}
	state, _ := sess.Get(oauth2StateKey).(string)
	if state != "" {
		t.Fatal(state)
	}
}
