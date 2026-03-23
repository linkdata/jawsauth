package jawsauth

import (
	"errors"
	"testing"
)

func TestConfig_ValidateRequiresHTTPSIssuerByDefault(t *testing.T) {
	cfg := Config{
		RedirectURL:  "https://application.example.com/oauth2/callback",
		Issuer:       "http://issuer.example.com",
		ClientID:     "the-client-id",
		ClientSecret: "the-client-secret",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !errors.Is(err, ErrConfigIssuerMustBeHTTPS) {
		t.Fatal(err)
	}
	var fieldErr errConfig
	if !errors.As(err, &fieldErr) {
		t.Fatal(err)
	}
	if fieldErr.field != "Issuer" {
		t.Fatal(fieldErr.field)
	}
}

func TestConfig_ValidateAllowsInsecureIssuerWhenEnabled(t *testing.T) {
	cfg := Config{
		RedirectURL:         "https://application.example.com/oauth2/callback",
		Issuer:              "http://issuer.example.com",
		AllowInsecureIssuer: true,
		ClientID:            "the-client-id",
		ClientSecret:        "the-client-secret",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestConfig_ValidateRequiresAbsoluteURLs(t *testing.T) {
	base := Config{
		RedirectURL:  "https://application.example.com/oauth2/callback",
		Issuer:       "https://issuer.example.com",
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
			name: "issuerRelativePath",
			patch: func(cfg *Config) {
				cfg.Issuer = "issuer"
			},
			wantField: "Issuer",
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
			var fieldErr errConfig
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
