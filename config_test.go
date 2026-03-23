package jawsauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/oauth2"
)

func newOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(hw http.ResponseWriter, hr *http.Request) {
		_ = hr
		data := map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/oauth2/auth",
			"token_endpoint":         server.URL + "/oauth2/token",
			"userinfo_endpoint":      server.URL + "/oauth2/userinfo",
			"jwks_uri":               server.URL + "/oauth2/jwks",
		}
		hw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(hw).Encode(data)
	})
	mux.HandleFunc("/oauth2/jwks", func(hw http.ResponseWriter, hr *http.Request) {
		_ = hr
		hw.Header().Set("Content-Type", "application/json")
		_, _ = hw.Write([]byte(`{"keys":[]}`))
	})
	server = httptest.NewServer(mux)
	return server
}

func assertOAuth2ConfigEqual(t *testing.T, got, want *oauth2.Config) {
	t.Helper()
	if got == nil || want == nil {
		if got != want {
			t.Fatalf("oauth2 config mismatch: got %#v want %#v", got, want)
		}
		return
	}
	if got.ClientID != want.ClientID {
		t.Fatalf("ClientID mismatch: got %q want %q", got.ClientID, want.ClientID)
	}
	if got.ClientSecret != want.ClientSecret {
		t.Fatalf("ClientSecret mismatch: got %q want %q", got.ClientSecret, want.ClientSecret)
	}
	if got.Endpoint.AuthURL != want.Endpoint.AuthURL {
		t.Fatalf("AuthURL mismatch: got %q want %q", got.Endpoint.AuthURL, want.Endpoint.AuthURL)
	}
	if got.Endpoint.TokenURL != want.Endpoint.TokenURL {
		t.Fatalf("TokenURL mismatch: got %q want %q", got.Endpoint.TokenURL, want.Endpoint.TokenURL)
	}
	if got.RedirectURL != want.RedirectURL {
		t.Fatalf("RedirectURL mismatch: got %q want %q", got.RedirectURL, want.RedirectURL)
	}
	gotScopes := append([]string(nil), got.Scopes...)
	wantScopes := append([]string(nil), want.Scopes...)
	slices.Sort(gotScopes)
	slices.Sort(wantScopes)
	if !reflect.DeepEqual(gotScopes, wantScopes) {
		t.Fatalf("Scopes mismatch: got %#v want %#v", got.Scopes, want.Scopes)
	}
}

func TestConfig_buildContext(t *testing.T) {
	discovery := newOIDCDiscoveryServer(t)
	defer discovery.Close()

	type fields struct {
		RedirectURL         string
		Issuer              string
		AuthURL             string
		TokenURL            string
		UserInfoURL         string
		AllowInsecureIssuer bool
		Scopes              []string
		ClientID            string
		ClientSecret        string
	}

	stdfields := fields{
		RedirectURL:         "https://application.example.com/oauth2/callback",
		Issuer:              discovery.URL,
		AllowInsecureIssuer: true,
		Scopes:              []string{"profile"},
		ClientID:            "the-client-id",
		ClientSecret:        "the-client-secret",
	}

	tests := []struct {
		name          string
		fields        fields
		overrideURL   string
		wantOAuth2cfg *oauth2.Config
		wantErr       bool
	}{
		{
			name:          "empty",
			overrideURL:   "",
			wantOAuth2cfg: nil,
			wantErr:       true,
		},
		{
			name:        "discovery",
			fields:      stdfields,
			overrideURL: "",
			wantOAuth2cfg: &oauth2.Config{
				ClientID:     stdfields.ClientID,
				ClientSecret: stdfields.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  discovery.URL + "/oauth2/auth",
					TokenURL: discovery.URL + "/oauth2/token",
				},
				RedirectURL: stdfields.RedirectURL,
				Scopes:      []string{"profile", "openid", "email"},
			},
			wantErr: false,
		},
		{
			name: "endpointOverrides",
			fields: fields{
				RedirectURL:         stdfields.RedirectURL,
				Issuer:              stdfields.Issuer,
				AllowInsecureIssuer: true,
				AuthURL:             "https://override.example.com/authorize",
				TokenURL:            "https://override.example.com/token",
				UserInfoURL:         "https://override.example.com/userinfo",
				Scopes:              []string{"openid email", "profile", "email"},
				ClientID:            stdfields.ClientID,
				ClientSecret:        stdfields.ClientSecret,
			},
			overrideURL: "http://127.0.0.1:8080",
			wantOAuth2cfg: &oauth2.Config{
				ClientID:     stdfields.ClientID,
				ClientSecret: stdfields.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://override.example.com/authorize",
					TokenURL: "https://override.example.com/token",
				},
				RedirectURL: "http://127.0.0.1:8080/oauth2/callback",
				Scopes:      []string{"openid", "email", "profile"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				RedirectURL:         tt.fields.RedirectURL,
				Issuer:              tt.fields.Issuer,
				AuthURL:             tt.fields.AuthURL,
				TokenURL:            tt.fields.TokenURL,
				UserInfoURL:         tt.fields.UserInfoURL,
				AllowInsecureIssuer: tt.fields.AllowInsecureIssuer,
				Scopes:              tt.fields.Scopes,
				ClientID:            tt.fields.ClientID,
				ClientSecret:        tt.fields.ClientSecret,
			}
			gotOAuth2cfg, _, _, err := cfg.buildContext(t.Context(), tt.overrideURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assertOAuth2ConfigEqual(t, gotOAuth2cfg, tt.wantOAuth2cfg)
		})
	}
}

func TestConfig_buildContextUserInfoSource(t *testing.T) {
	discovery := newOIDCDiscoveryServer(t)
	defer discovery.Close()

	cfg := &Config{
		RedirectURL:         "https://application.example.com/oauth2/callback",
		Issuer:              discovery.URL,
		AllowInsecureIssuer: true,
		ClientID:            "the-client-id",
		ClientSecret:        "the-client-secret",
	}

	_, userinfo, _, err := cfg.buildContext(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if userinfo != discovery.URL+"/oauth2/userinfo" {
		t.Fatal(userinfo)
	}

	cfg.UserInfoURL = "https://override.example.com/userinfo"
	_, userinfo, _, err = cfg.buildContext(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if userinfo != "https://override.example.com/userinfo" {
		t.Fatal(userinfo)
	}
}

func TestConfig_buildContextWithHTTPClient(t *testing.T) {
	discovery := newOIDCDiscoveryServer(t)
	defer discovery.Close()

	cfg := &Config{
		RedirectURL:         "https://application.example.com/oauth2/callback",
		Issuer:              discovery.URL,
		AllowInsecureIssuer: true,
		HTTPClient:          discovery.Client(),
		ClientID:            "the-client-id",
		ClientSecret:        "the-client-secret",
	}

	got, _, _, err := cfg.buildContext(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected oauth2 config")
	}
}
