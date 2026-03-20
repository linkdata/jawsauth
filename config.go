package jawsauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	RedirectURL string // required. e.g. "https://application.example.com/oauth2/callback"
	Issuer      string // required. e.g. "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
	AuthURL     string // optional override for discovered authorization_endpoint
	TokenURL    string // optional override for discovered token_endpoint
	UserInfoURL string // optional override for discovered userinfo_endpoint
	// AllowInsecureIssuer permits "http://" Issuer URLs and should only be used for tests/dev.
	AllowInsecureIssuer bool
	// HTTPClient is used for OIDC discovery at startup.
	HTTPClient *http.Client
	Scopes     []string // optional additional scopes, "openid" and "email" are always ensured
	ClientID   string
	//gosec:disable G117
	ClientSecret string
}

func requireLen(k string, n int) (err error) {
	if n < 1 {
		err = fmt.Errorf("missing %s", k)
	}
	return
}

func requireStr(k, u string) error {
	return requireLen(k, len(strings.TrimSpace(u)))
}

func validateUrl(k, u, defaultURL string, optional bool) (value string, err error) {
	value = u
	if value == "" {
		value = defaultURL
	}
	if optional && value == "" {
		return
	}
	if err = requireStr(k, value); err == nil {
		var parsed *url.URL
		if parsed, err = url.Parse(value); err == nil {
			err = ErrConfigURLNotAbsolute
			if parsed.IsAbs() {
				err = ErrConfigURLMissingHost
				if parsed.Hostname() != "" {
					err = nil
				}
			}
			if err != nil {
				err = configFieldError{field: k, cause: err}
			}
		}
	}
	return
}

var ErrConfigURLNotAbsolute = errors.New("url is not absolute")
var ErrConfigURLMissingHost = errors.New("url host is missing")
var ErrConfigIssuerMustBeHTTPS = errors.New("issuer url must use https")

type configFieldError struct {
	field string
	cause error
}

func (e configFieldError) Error() string {
	return "invalid " + e.field + ": " + e.cause.Error()
}

func (e configFieldError) Unwrap() error {
	return e.cause
}

func (e configFieldError) Is(target error) (matches bool) {
	if t, ok := target.(configFieldError); ok {
		matches = e.field == t.field
		if matches {
			matches = errors.Is(e.cause, t.cause)
		}
	}
	return
}

func (cfg *Config) Validate() (err error) {
	if _, err = validateUrl("RedirectURL", cfg.RedirectURL, "", false); err == nil {
		if _, err = validateUrl("Issuer", cfg.Issuer, "", false); err == nil {
			if !cfg.AllowInsecureIssuer {
				var issuer *url.URL
				if issuer, err = url.Parse(cfg.Issuer); err == nil {
					if issuer.Scheme != "https" {
						err = configFieldError{field: "Issuer", cause: ErrConfigIssuerMustBeHTTPS}
					}
				}
			}
			if err == nil {
				if _, err = validateUrl("AuthURL", cfg.AuthURL, "", true); err == nil {
					if _, err = validateUrl("TokenURL", cfg.TokenURL, "", true); err == nil {
						if _, err = validateUrl("UserInfoURL", cfg.UserInfoURL, "", true); err == nil {
							if err = requireStr("ClientID", cfg.ClientID); err == nil {
								err = requireStr("ClientSecret", cfg.ClientSecret)
							}
						}
					}
				}
			}
		}
	}
	return
}

func overrideStr(a *string, b string) {
	if b != "" {
		*a = b
	}
}

func ensureScopes(rawScopes []string) (scopes []string) {
	scopes = append(scopes, "openid")
	scopes = append(scopes, "email")
	for _, set := range rawScopes {
		for scope := range strings.FieldsSeq(set) {
			scopes = append(scopes, scope)
		}
	}
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	return
}

func (cfg *Config) buildContext(ctx context.Context, overrideUrl string) (oauth2cfg *oauth2.Config, userInfoURL string, verifier *oidc.IDTokenVerifier, err error) {
	if err = cfg.Validate(); err == nil {
		if cfg.HTTPClient != nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, cfg.HTTPClient)
		}

		var provider *oidc.Provider
		if provider, err = oidc.NewProvider(ctx, cfg.Issuer); wrapOIDC(ErrOIDCDiscovery, &err) == nil {
			var metadata struct {
				AuthorizationEndpoint string `json:"authorization_endpoint"`
				TokenEndpoint         string `json:"token_endpoint"`
				UserinfoEndpoint      string `json:"userinfo_endpoint"`
			}
			if err = provider.Claims(&metadata); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
				var authURL string
				var tokenURL string
				if authURL, err = validateUrl("AuthURL", cfg.AuthURL, metadata.AuthorizationEndpoint, true); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
					if tokenURL, err = validateUrl("TokenURL", cfg.TokenURL, metadata.TokenEndpoint, false); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
						if userInfoURL, err = validateUrl("UserInfoURL", cfg.UserInfoURL, metadata.UserinfoEndpoint, true); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
							var redir *url.URL
							if redir, err = url.Parse(cfg.RedirectURL); err == nil {
								if u, e := url.Parse(overrideUrl); e == nil {
									overrideStr(&redir.Scheme, u.Scheme)
									overrideStr(&redir.Host, u.Host)
								}
								oauth2cfg = &oauth2.Config{
									ClientID:     cfg.ClientID,
									ClientSecret: cfg.ClientSecret,
									Endpoint: oauth2.Endpoint{
										AuthURL:  authURL,
										TokenURL: tokenURL,
									},
									RedirectURL: redir.String(),
									Scopes:      ensureScopes(cfg.Scopes),
								}
								verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
							}
						}
					}
				}
			}
		}
	}
	return
}

// Build creates a oauth2.Config using OIDC discovery.
// If overrideUrl is provided, its scheme, host and port are used instead of
// the ones in RedirectURL. This is useful when testing.
func (cfg *Config) Build(overrideUrl string) (oauth2cfg *oauth2.Config, err error) {
	oauth2cfg, _, _, err = cfg.buildContext(context.Background(), overrideUrl)
	return
}
