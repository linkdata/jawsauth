package jawsauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func newOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(hw http.ResponseWriter, _ *http.Request) {
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
	mux.HandleFunc("/oauth2/jwks", func(hw http.ResponseWriter, _ *http.Request) {
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

	_, userinfo, _, err := cfg.buildContext(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if userinfo != discovery.URL+"/oauth2/userinfo" {
		t.Fatal(userinfo)
	}

	cfg.UserInfoURL = "https://override.example.com/userinfo"
	_, userinfo, _, err = cfg.buildContext(t.Context(), "")
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

func TestConfig_buildContextDiscoveryStillFollowsRedirect(t *testing.T) {
	var issuer string
	target := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, _ *http.Request) {
		hw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(hw).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		http.Redirect(hw, hr, target.URL+"/metadata", http.StatusFound)
	}))
	defer redirector.Close()
	issuer = redirector.URL
	cfg := &Config{RedirectURL: "https://app.example/callback", Issuer: issuer,
		AllowInsecureIssuer: true, ClientID: "client", HTTPClient: redirector.Client()}
	got, _, _, err := cfg.buildContext(t.Context(), "")
	if err != nil || got == nil || got.Endpoint.TokenURL != issuer+"/token" {
		t.Fatalf("redirected discovery: config=%v err=%v", got, err)
	}
}

func TestConfigValidateRejectsInsecureOIDCOverrides(t *testing.T) {
	for _, field := range []string{"AuthURL", "TokenURL", "UserInfoURL"} {
		t.Run(field, func(t *testing.T) {
			cfg := Config{RedirectURL: "https://app.example/callback", Issuer: "https://issuer.example", ClientID: "client"}
			var endpoint *string
			switch field {
			case "AuthURL":
				endpoint = &cfg.AuthURL
			case "TokenURL":
				endpoint = &cfg.TokenURL
			case "UserInfoURL":
				endpoint = &cfg.UserInfoURL
			}
			*endpoint = "http://provider.example/endpoint"
			err := cfg.Validate()
			var configErr errConfig
			if !errors.Is(err, ErrConfigEndpointMustBeHTTPS) || !errors.As(err, &configErr) || configErr.field != field {
				t.Fatalf("%s override validation: %v", field, err)
			}
			cfg.AllowInsecureIssuer = true
			if err := cfg.Validate(); err != nil {
				t.Fatalf("dev override validation: %v", err)
			}
			*endpoint = "ftp://provider.example/endpoint"
			if err := cfg.Validate(); !errors.Is(err, ErrConfigEndpointMustBeHTTPS) {
				t.Fatalf("non-HTTP dev override validation: %v", err)
			}
		})
	}
}

func TestConfigBuildContextRejectsInsecureOIDCMetadata(t *testing.T) {
	for _, tc := range []struct {
		key, field, value string
		allowInsecure     bool
	}{
		{"authorization_endpoint", "AuthURL", "http://provider.example/auth", false},
		{"token_endpoint", "TokenURL", "http://provider.example/token", false},
		{"userinfo_endpoint", "UserInfoURL", "http://provider.example/userinfo", false},
		{"jwks_uri", "JWKSURI", "http://provider.example/jwks", false},
		{"jwks_uri", "JWKSURI", "", false},
		{"jwks_uri", "JWKSURI", "", true},
		{"jwks_uri", "JWKSURI", "ftp://provider.example/jwks", true},
	} {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			var issuer string
			provider := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, _ *http.Request) {
				metadata := map[string]string{
					"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token",
					"userinfo_endpoint": issuer + "/userinfo", "jwks_uri": issuer + "/jwks",
				}
				metadata[tc.key] = tc.value
				_ = json.NewEncoder(hw).Encode(metadata)
			}))
			defer provider.Close()
			issuer = provider.URL
			cfg := Config{RedirectURL: "https://app.example/callback", Issuer: issuer, ClientID: "client", HTTPClient: provider.Client(),
				AllowInsecureIssuer: tc.allowInsecure}
			_, _, _, err := cfg.buildContext(t.Context(), "")
			var configErr errConfig
			if !errors.Is(err, ErrOIDCProviderMetadata) || !errors.As(err, &configErr) || configErr.field != tc.field {
				t.Fatalf("%s metadata validation: %v", tc.key, err)
			}
			if tc.value != "" && !errors.Is(err, ErrConfigEndpointMustBeHTTPS) {
				t.Fatalf("%s did not reject HTTP: %v", tc.key, err)
			}
		})
	}
}

func TestConfigBuildContextUsesSecureOverridesForInsecureMetadata(t *testing.T) {
	var issuer string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(hw).Encode(map[string]string{
			"issuer": issuer, "authorization_endpoint": "http://provider.example/auth",
			"token_endpoint":    "http://provider.example/token",
			"userinfo_endpoint": "http://provider.example/userinfo", "jwks_uri": issuer + "/jwks",
		})
	}))
	defer provider.Close()
	issuer = provider.URL
	cfg := Config{RedirectURL: "https://app.example/callback", Issuer: issuer, ClientID: "client", HTTPClient: provider.Client(),
		AuthURL: "https://override.example/auth", TokenURL: "https://override.example/token", UserInfoURL: "https://override.example/userinfo"}
	got, userInfoURL, _, err := cfg.buildContext(t.Context(), "")
	if err != nil || got == nil || got.Endpoint.AuthURL != cfg.AuthURL || got.Endpoint.TokenURL != cfg.TokenURL || userInfoURL != cfg.UserInfoURL {
		t.Fatalf("secure overrides: config=%v userInfoURL=%q err=%v", got, userInfoURL, err)
	}
}

func TestConfigBuildContextDiscoveryRedirectScheme(t *testing.T) {
	for _, tc := range []struct {
		name, target  string
		allowInsecure bool
		wantSuccess   bool
	}{
		{"https", "https", false, true},
		{"http blocked", "http", false, false},
		{"http dev", "http", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var issuer string
			var insecureHits atomic.Int32
			insecure := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, _ *http.Request) {
				insecureHits.Add(1)
				_ = json.NewEncoder(hw).Encode(map[string]string{
					"issuer": issuer, "authorization_endpoint": issuer + "/auth",
					"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
				})
			}))
			defer insecure.Close()
			var secureHits atomic.Int32
			provider := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
				if hr.URL.Path == "/metadata" {
					secureHits.Add(1)
					_ = json.NewEncoder(hw).Encode(map[string]string{
						"issuer": issuer, "authorization_endpoint": issuer + "/auth",
						"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
					})
					return
				}
				location := issuer + "/metadata"
				if tc.target == "http" {
					location = insecure.URL + "/metadata"
				}
				http.Redirect(hw, hr, location, http.StatusFound)
			}))
			defer provider.Close()
			issuer = provider.URL
			client := provider.Client()
			var redirectChecks atomic.Int32
			client.CheckRedirect = func(*http.Request, []*http.Request) error {
				redirectChecks.Add(1)
				return nil
			}
			cfg := Config{RedirectURL: "https://app.example/callback", Issuer: issuer, ClientID: "client",
				AllowInsecureIssuer: tc.allowInsecure, HTTPClient: client}
			_, _, _, err := cfg.buildContext(t.Context(), "")
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("discovery redirect: %v, want success %t", err, tc.wantSuccess)
			}
			if !tc.wantSuccess && !errors.Is(err, ErrOIDCDiscovery) {
				t.Fatalf("discovery error kind: %v", err)
			}
			if tc.target == "https" && (secureHits.Load() != 1 || redirectChecks.Load() != 1) {
				t.Fatalf("HTTPS redirect not followed: hits=%d checks=%d", secureHits.Load(), redirectChecks.Load())
			}
			wantInsecureHits := int32(0)
			if tc.allowInsecure {
				wantInsecureHits = 1
			}
			if tc.target == "http" && insecureHits.Load() != wantInsecureHits {
				t.Fatalf("HTTP redirect hits=%d, allow insecure=%t", insecureHits.Load(), tc.allowInsecure)
			}
		})
	}
}

func TestConfigBuildContextDiscoveryRedirectLimit(t *testing.T) {
	var hits atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		hits.Add(1)
		http.Redirect(hw, hr, "/again", http.StatusFound)
	}))
	defer provider.Close()
	cfg := Config{RedirectURL: "https://app.example/callback", Issuer: provider.URL,
		ClientID: "client", HTTPClient: provider.Client()}
	_, _, _, err := cfg.buildContext(t.Context(), "")
	if !errors.Is(err, ErrOIDCDiscovery) || hits.Load() != 10 || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("discovery redirect limit: err=%v hits=%d", err, hits.Load())
	}
}

func TestConfigBuildContextJWKSRedirectScheme(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "http blocked"
		if secure {
			name = "https allowed"
		}
		t.Run(name, func(t *testing.T) {
			var insecureHits atomic.Int32
			insecure := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, _ *http.Request) {
				insecureHits.Add(1)
				_, _ = hw.Write([]byte(`{"keys":[]}`))
			}))
			defer insecure.Close()
			var issuer string
			var secureHits atomic.Int32
			provider := httptest.NewTLSServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
				switch hr.URL.Path {
				case "/.well-known/openid-configuration":
					_ = json.NewEncoder(hw).Encode(map[string]string{
						"issuer": issuer, "authorization_endpoint": issuer + "/auth",
						"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
					})
				case "/jwks":
					location := issuer + "/keys"
					if !secure {
						location = insecure.URL + "/keys"
					}
					http.Redirect(hw, hr, location, http.StatusFound)
				case "/keys":
					secureHits.Add(1)
					_, _ = hw.Write([]byte(`{"keys":[]}`))
				}
			}))
			defer provider.Close()
			issuer = provider.URL
			cfg := Config{RedirectURL: "https://app.example/callback", Issuer: issuer, ClientID: "client", HTTPClient: provider.Client()}
			_, _, verifier, err := cfg.buildContext(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			token := makeIDToken(t, map[string]any{"iss": issuer, "aud": "client", "exp": time.Now().Add(time.Hour).Unix()})
			_, err = verifier.Verify(t.Context(), token)
			if err == nil {
				t.Fatal("unsigned test token unexpectedly verified")
			}
			if secure && secureHits.Load() != 1 {
				t.Fatalf("HTTPS JWKS redirect hits=%d, error=%v", secureHits.Load(), err)
			}
			if !secure && (insecureHits.Load() != 0 || !strings.Contains(err.Error(), "oidc redirect must use https")) {
				t.Fatalf("HTTP JWKS redirect hits=%d, error=%v", insecureHits.Load(), err)
			}
		})
	}
}

func TestConfigBuildContextJWKSTimeout(t *testing.T) {
	for _, configuredTimeout := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run(configuredTimeout.String(), func(t *testing.T) {
			const issuer = "https://issuer.example"
			var jwksHits atomic.Int32
			deadlineObserved := make(chan time.Duration, 1)
			client := &http.Client{Timeout: configuredTimeout, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				switch req.URL.Path {
				case "/.well-known/openid-configuration":
					return profileTestResponse(`{"issuer":"https://issuer.example","authorization_endpoint":"https://issuer.example/auth","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks"}`), nil
				case "/jwks":
					jwksHits.Add(1)
					deadline, ok := req.Context().Deadline()
					if !ok {
						deadlineObserved <- -1
						return nil, errors.New("JWKS request has no deadline")
					}
					deadlineObserved <- time.Until(deadline)
					if configuredTimeout > 0 {
						<-req.Context().Done()
						return nil, req.Context().Err()
					}
					return nil, errors.New("JWKS request stopped by test")
				}
				return nil, errors.New("unexpected provider request")
			})}
			cfg := Config{RedirectURL: "https://app.example/callback", Issuer: issuer, ClientID: "client", HTTPClient: client}
			_, _, verifier, err := cfg.buildContext(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.Verify(t.Context(), makeIDToken(t, map[string]any{"iss": issuer, "aud": "client", "exp": time.Now().Add(time.Hour).Unix()}))
			if err == nil || jwksHits.Load() != 1 || client.Timeout != configuredTimeout {
				t.Fatalf("JWKS verify: err=%v hits=%d original timeout=%s", err, jwksHits.Load(), client.Timeout)
			}
			want := configuredTimeout
			if want == 0 {
				want = oauth2ProviderTimeout
			}
			if remaining := <-deadlineObserved; remaining <= 0 || remaining > want {
				t.Fatalf("JWKS deadline %s, want at most %s", remaining, want)
			}
		})
	}
}
