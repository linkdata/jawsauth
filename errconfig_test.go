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
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.patch(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			var fieldErr errConfig
			if !errors.As(err, &fieldErr) {
				t.Fatalf("expected errConfig, got %T (%v)", err, err)
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

func TestConfig_ValidateRequiresRequiredFields(t *testing.T) {
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
	}{
		{
			name: "missingRedirectURL",
			patch: func(cfg *Config) {
				cfg.RedirectURL = ""
			},
			wantField: "RedirectURL",
		},
		{
			name: "missingIssuer",
			patch: func(cfg *Config) {
				cfg.Issuer = ""
			},
			wantField: "Issuer",
		},
		{
			name: "missingClientID",
			patch: func(cfg *Config) {
				cfg.ClientID = " "
			},
			wantField: "ClientID",
		},
		{
			name: "missingClientSecret",
			patch: func(cfg *Config) {
				cfg.ClientSecret = " "
			},
			wantField: "ClientSecret",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.patch(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			var configErr errConfig
			if !errors.As(err, &configErr) {
				t.Fatalf("expected errConfig, got %T (%v)", err, err)
			}
			if configErr.field != tc.wantField {
				t.Fatal(configErr.field)
			}
			if !errors.Is(err, ErrConfig) {
				t.Fatal("expected errors.Is(err, ErrConfig)")
			}
			if !errors.Is(err, ErrConfigMissingValue) {
				t.Fatal("expected errors.Is(err, ErrConfigMissingValue)")
			}
		})
	}
}

func TestConfig_ValidateWrapsURLParseErrorAsErrConfig(t *testing.T) {
	cfg := Config{
		RedirectURL:  "https://application.example.com/oauth2/callback",
		Issuer:       "https://issuer.example.com",
		AuthURL:      "https://example.com/%zz",
		ClientID:     "the-client-id",
		ClientSecret: "the-client-secret",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	var configErr errConfig
	if !errors.As(err, &configErr) {
		t.Fatalf("expected errConfig, got %T (%v)", err, err)
	}
	if configErr.field != "AuthURL" {
		t.Fatal(configErr.field)
	}
	if !errors.Is(err, ErrConfig) {
		t.Fatal("expected errors.Is(err, ErrConfig)")
	}
	if errors.Is(err, ErrConfigURLNotAbsolute) {
		t.Fatal("unexpected url not absolute match")
	}
}

func TestErrConfigMethods(t *testing.T) {
	if s := ErrConfig.Error(); s != "invalid config" {
		t.Fatal(s)
	}

	cause := errors.New("boom")
	err := errConfig{
		field: "AuthURL",
		cause: cause,
	}
	if s := err.Error(); s != "invalid AuthURL: boom" {
		t.Fatal(s)
	}
	if !errors.Is(err, ErrConfig) {
		t.Fatal("expected errors.Is(err, ErrConfig)")
	}
	if !errors.Is(err, cause) {
		t.Fatal("expected errors.Is(err, cause)")
	}
}
