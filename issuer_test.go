package jawsauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/linkdata/jaws"
)

func TestServerValidateIssuer(t *testing.T) {
	tests := []struct {
		name        string
		issuer      string
		query       string
		wantStatus  int
		wantErrIs   error
		wantErrNil  bool
		initialCode int
	}{
		{
			name:        "noExpectedIssuerIgnoresMissingIss",
			issuer:      "",
			query:       "",
			wantStatus:  http.StatusTeapot,
			wantErrNil:  true,
			initialCode: http.StatusTeapot,
		},
		{
			name:        "noExpectedIssuerIgnoresPresentIss",
			issuer:      "",
			query:       "iss=https%3A%2F%2Fattacker.example",
			wantStatus:  http.StatusTeapot,
			wantErrNil:  true,
			initialCode: http.StatusTeapot,
		},
		{
			name:        "expectedIssuerMissingIss",
			issuer:      "https://issuer.example",
			query:       "",
			wantStatus:  http.StatusBadRequest,
			wantErrIs:   ErrOAuth2MissingIssuer,
			initialCode: http.StatusTeapot,
		},
		{
			name:        "wrongIssuer",
			issuer:      "https://issuer.example",
			query:       "iss=https%3A%2F%2Fattacker.example",
			wantStatus:  http.StatusBadRequest,
			wantErrIs:   ErrOAuth2WrongIssuer,
			initialCode: http.StatusTeapot,
		},
		{
			name:        "matchingIssuer",
			issuer:      "https://issuer.example",
			query:       "iss=https%3A%2F%2Fissuer.example",
			wantStatus:  http.StatusTeapot,
			wantErrNil:  true,
			initialCode: http.StatusTeapot,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			url := "http://example.com/oauth2/callback"
			if tc.query != "" {
				url += "?" + tc.query
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			srv := &Server{issuer: tc.issuer}
			statusCode, err := srv.validateIssuer(req, tc.initialCode)
			if statusCode != tc.wantStatus {
				t.Fatal(statusCode)
			}
			if tc.wantErrNil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, tc.wantErrIs) {
				t.Fatal(err)
			}
		})
	}
}

func TestNewStoresConfiguredIssuer(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	cfg := &Config{
		RedirectURL:  "https://application.example.com/oauth2/callback",
		AuthURL:      "https://login.example.com/oauth2/authorize",
		TokenURL:     "https://login.example.com/oauth2/token",
		UserInfoURL:  "https://api.example.com/me",
		Issuer:       "https://login.example.com",
		Scopes:       []string{"openid"},
		ClientID:     "client",
		ClientSecret: "secret",
	}
	srv, err := New(jw, cfg, func(string, http.Handler) {})
	if err != nil {
		t.Fatal(err)
	}
	if srv.issuer != "https://login.example.com" {
		t.Fatal(srv.issuer)
	}
}
