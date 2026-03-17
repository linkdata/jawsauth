package jawsauth

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestConfig_Build(t *testing.T) {
	type fields struct {
		RedirectURL  string
		AuthURL      string
		TokenURL     string
		UserInfoURL  string
		Issuer       string
		Scopes       []string
		ClientID     string
		ClientSecret string
	}

	stdfields := fields{
		RedirectURL:  "https://application.example.com/oauth2/callback",
		AuthURL:      "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/v1.0/me?$select=displayName,mail",
		Issuer:       "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0",
		Scopes:       []string{"user.read"},
		ClientID:     "the-client-id",
		ClientSecret: "the-client-secret",
	}

	tests := []struct {
		name          string
		fields        fields
		overrideUrl   string
		wantOauth2cfg *oauth2.Config
		wantErr       bool
	}{
		{
			name:          "empty",
			overrideUrl:   "",
			wantOauth2cfg: nil,
			wantErr:       true,
		},
		{
			name:        "basic",
			fields:      stdfields,
			overrideUrl: "",
			wantOauth2cfg: &oauth2.Config{
				ClientID:     stdfields.ClientID,
				ClientSecret: stdfields.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  stdfields.AuthURL,
					TokenURL: stdfields.TokenURL,
				},
				RedirectURL: stdfields.RedirectURL,
				Scopes:      stdfields.Scopes,
			},
			wantErr: false,
		},
		{
			name:        "override",
			fields:      stdfields,
			overrideUrl: "http://127.0.0.1:8080",
			wantOauth2cfg: &oauth2.Config{
				ClientID:     stdfields.ClientID,
				ClientSecret: stdfields.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  stdfields.AuthURL,
					TokenURL: stdfields.TokenURL,
				},
				RedirectURL: "http://127.0.0.1:8080/oauth2/callback",
				Scopes:      stdfields.Scopes,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				RedirectURL:  tt.fields.RedirectURL,
				AuthURL:      tt.fields.AuthURL,
				TokenURL:     tt.fields.TokenURL,
				UserInfoURL:  tt.fields.UserInfoURL,
				Issuer:       tt.fields.Issuer,
				Scopes:       tt.fields.Scopes,
				ClientID:     tt.fields.ClientID,
				ClientSecret: tt.fields.ClientSecret,
			}
			gotOauth2cfg, err := cfg.Build(tt.overrideUrl)
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOauth2cfg, tt.wantOauth2cfg) {
				t.Errorf("Config.Build() = %v, want %v", gotOauth2cfg, tt.wantOauth2cfg)
			}
		})
	}
}

func TestConfig_ValidateRequiresAbsoluteURLs(t *testing.T) {
	base := Config{
		RedirectURL:  "https://application.example.com/oauth2/callback",
		AuthURL:      "https://login.example.com/oauth2/authorize",
		TokenURL:     "https://login.example.com/oauth2/token",
		UserInfoURL:  "https://api.example.com/me",
		Scopes:       []string{"user.read"},
		ClientID:     "the-client-id",
		ClientSecret: "the-client-secret",
	}

	testCases := []struct {
		name      string
		patch     func(*Config)
		wantField string
		wantCause error
	}{
		{
			name: "redirectRelativePath",
			patch: func(cfg *Config) {
				cfg.RedirectURL = "/oauth2/callback"
			},
			wantField: "RedirectURL",
			wantCause: ErrConfigURLNotAbsolute,
		},
		{
			name: "authRelativePath",
			patch: func(cfg *Config) {
				cfg.AuthURL = "authorize"
			},
			wantField: "AuthURL",
			wantCause: ErrConfigURLNotAbsolute,
		},
		{
			name: "tokenRelativePath",
			patch: func(cfg *Config) {
				cfg.TokenURL = "token"
			},
			wantField: "TokenURL",
			wantCause: ErrConfigURLNotAbsolute,
		},
		{
			name: "userinfoRelativePath",
			patch: func(cfg *Config) {
				cfg.UserInfoURL = "userinfo"
			},
			wantField: "UserInfoURL",
			wantCause: ErrConfigURLNotAbsolute,
		},
		{
			name: "authMissingHost",
			patch: func(cfg *Config) {
				cfg.AuthURL = "https:///authorize"
			},
			wantField: "AuthURL",
			wantCause: ErrConfigURLMissingHost,
		},
		{
			name: "issuerRelativePath",
			patch: func(cfg *Config) {
				cfg.Issuer = "issuer"
			},
			wantField: "Issuer",
			wantCause: ErrConfigURLNotAbsolute,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.patch(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			var fieldErr configFieldError
			if !errors.As(err, &fieldErr) {
				t.Fatalf("expected configFieldError, got %T (%v)", err, err)
			}
			if fieldErr.field != tc.wantField {
				t.Fatalf("unexpected field: %s", fieldErr.field)
			}
			if !errors.Is(err, tc.wantCause) {
				t.Fatalf("unexpected cause: %v", err)
			}
		})
	}
}

func TestConfigFieldErrorHelpers(t *testing.T) {
	errValue := configFieldError{
		field: "AuthURL",
		cause: ErrConfigURLNotAbsolute,
	}

	if errValue.Error() != "invalid AuthURL: url is not absolute" {
		t.Fatal(errValue.Error())
	}

	if !errValue.Is(configFieldError{field: "AuthURL", cause: ErrConfigURLNotAbsolute}) {
		t.Fatal("expected matching field/cause")
	}

	if errValue.Is(configFieldError{field: "TokenURL", cause: ErrConfigURLNotAbsolute}) {
		t.Fatal("unexpected match for wrong field")
	}

	if errValue.Is(configFieldError{field: "AuthURL", cause: ErrConfigURLMissingHost}) {
		t.Fatal("unexpected match for wrong cause")
	}

	if errValue.Is(ErrConfigURLNotAbsolute) {
		t.Fatal("unexpected match for non-configFieldError target")
	}
}
