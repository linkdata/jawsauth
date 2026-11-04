package jawsauth

//gosec:disable G117

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds the OIDC/OAuth2 settings used by New and NewDebug to construct a Server.
//
// RedirectURL, Issuer and ClientID are required. OIDC mode discovers endpoints;
// URL fields may override them. Profile mode requires explicit AuthURL, TokenURL,
// UserInfoURL and ProfileSubject.
type Config struct {
	RedirectURL string // required. e.g. "https://application.example.com/oauth2/callback"
	Issuer      string // required. e.g. "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
	// Namespace isolates this provider's session values when multiple Servers share one JaWS instance.
	Namespace   string
	AuthURL     string // OIDC override; required in profile mode
	TokenURL    string // OIDC override; required in profile mode
	UserInfoURL string // OIDC override; required in profile mode
	// AllowInsecureIssuer permits HTTP issuer and provider endpoints and is only for tests/dev.
	AllowInsecureIssuer bool
	// HTTPClient is used for OIDC discovery and JWKS requests and, unless a per-request
	// oauth2.HTTPClient is supplied via the request context, as the default client
	// for token exchange/refresh and UserInfo requests.
	HTTPClient   *http.Client
	Scopes       []string // optional; OIDC adds "openid" and "email", profile mode uses only these scopes
	ClientID     string
	ClientSecret string
	// ProfileSubject enables OAuth2 profile authentication without an OIDC ID token.
	// AuthURL, TokenURL and UserInfoURL are required in this mode. It must return
	// a stable, non-empty provider subject from the authenticated profile response.
	ProfileSubject func(map[string]any) (string, error)
}

func requireLen(k string, n int) (err error) {
	if n < 1 {
		err = errConfig{field: k, cause: ErrConfigMissingValue}
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
				err = errConfig{field: k, cause: err}
			}
		} else {
			err = errConfig{field: k, cause: err}
		}
	}
	return
}

func validateOIDCEndpoint(field, value string, optional, allowInsecure bool) error {
	value, err := validateUrl(field, value, "", optional)
	if err != nil || value == "" {
		return err
	}
	parsed, _ := url.Parse(value)
	if parsed.Scheme != "https" && (!allowInsecure || parsed.Scheme != "http") {
		return errConfig{field: field, cause: ErrConfigOIDCEndpointMustBeHTTPS}
	}
	return nil
}

// Validate checks whether cfg contains usable OIDC/OAuth2 settings.
//
// RedirectURL, Issuer and ClientID must be present. URL fields must be absolute
// and include a host. OIDC endpoint overrides are optional; profile endpoints
// are required and must use HTTPS, or HTTP when AllowInsecureIssuer is true.
// OIDC endpoints and Issuer must use HTTPS unless AllowInsecureIssuer is true.
// Returned failures match [ErrConfig].
func (cfg *Config) Validate() (err error) {
	if _, err = validateUrl("RedirectURL", cfg.RedirectURL, "", false); err == nil {
		if _, err = validateUrl("Issuer", cfg.Issuer, "", false); err == nil {
			issuer, _ := url.Parse(cfg.Issuer)
			if issuer.Scheme != "https" && (!cfg.AllowInsecureIssuer || issuer.Scheme != "http") {
				err = errConfig{field: "Issuer", cause: ErrConfigIssuerMustBeHTTPS}
			}
			if err == nil {
				if cfg.ProfileSubject != nil {
					for _, field := range []struct{ name, value string }{
						{"AuthURL", cfg.AuthURL}, {"TokenURL", cfg.TokenURL}, {"UserInfoURL", cfg.UserInfoURL},
					} {
						if _, err = validateUrl(field.name, field.value, "", false); err != nil {
							return err
						}
						parsed, _ := url.Parse(field.value)
						if parsed.Scheme != "https" && (!cfg.AllowInsecureIssuer || parsed.Scheme != "http") {
							return errConfig{field: field.name, cause: ErrConfigProfileEndpointMustBeHTTPS}
						}
					}
					return requireStr("ClientID", cfg.ClientID)
				}
				if err = validateOIDCEndpoint("AuthURL", cfg.AuthURL, true, cfg.AllowInsecureIssuer); err == nil {
					if err = validateOIDCEndpoint("TokenURL", cfg.TokenURL, true, cfg.AllowInsecureIssuer); err == nil {
						if err = validateOIDCEndpoint("UserInfoURL", cfg.UserInfoURL, true, cfg.AllowInsecureIssuer); err == nil {
							err = requireStr("ClientID", cfg.ClientID)
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
		var redir *url.URL
		if redir, err = url.Parse(cfg.RedirectURL); err != nil {
			return
		}
		if u, parseErr := url.Parse(overrideUrl); parseErr == nil {
			overrideStr(&redir.Scheme, u.Scheme)
			overrideStr(&redir.Host, u.Host)
		}
		if cfg.ProfileSubject != nil {
			var scopes []string
			for _, set := range cfg.Scopes {
				scopes = append(scopes, strings.Fields(set)...)
			}
			slices.Sort(scopes)
			scopes = slices.Compact(scopes)
			oauth2cfg = &oauth2.Config{
				ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
				Endpoint:    oauth2.Endpoint{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL},
				RedirectURL: redir.String(), Scopes: scopes,
			}
			return oauth2cfg, cfg.UserInfoURL, nil, nil
		}
		client := cfg.HTTPClient
		if client == nil {
			client, _ = ctx.Value(oauth2.HTTPClient).(*http.Client)
		}
		if client == nil {
			client = http.DefaultClient
		}
		clientCopy := *client
		if clientCopy.Timeout <= 0 || clientCopy.Timeout > oauth2ProviderTimeout {
			clientCopy.Timeout = oauth2ProviderTimeout
		}
		if !cfg.AllowInsecureIssuer {
			checkRedirect := clientCopy.CheckRedirect
			clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" {
					return errors.New("oidc redirect must use https")
				}
				if checkRedirect != nil {
					return checkRedirect(req, via)
				}
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				return nil
			}
		}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &clientCopy)

		var provider *oidc.Provider
		if provider, err = oidc.NewProvider(ctx, cfg.Issuer); wrapOIDC(ErrOIDCDiscovery, &err) == nil {
			var metadata struct {
				AuthorizationEndpoint string `json:"authorization_endpoint"`
				TokenEndpoint         string `json:"token_endpoint"`
				UserinfoEndpoint      string `json:"userinfo_endpoint"`
				JWKSURI               string `json:"jwks_uri"`
			}
			if err = provider.Claims(&metadata); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
				for _, field := range []struct {
					name, value string
					optional    bool
				}{
					{"AuthURL", metadata.AuthorizationEndpoint, true},
					{"TokenURL", metadata.TokenEndpoint, true},
					{"UserInfoURL", metadata.UserinfoEndpoint, true},
					{"JWKSURI", metadata.JWKSURI, false},
				} {
					if err = validateOIDCEndpoint(field.name, field.value, field.optional, cfg.AllowInsecureIssuer); wrapOIDC(ErrOIDCProviderMetadata, &err) != nil {
						return
					}
				}
				var authURL string
				var tokenURL string
				if authURL, err = validateUrl("AuthURL", cfg.AuthURL, metadata.AuthorizationEndpoint, false); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
					if tokenURL, err = validateUrl("TokenURL", cfg.TokenURL, metadata.TokenEndpoint, false); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
						if userInfoURL, err = validateUrl("UserInfoURL", cfg.UserInfoURL, metadata.UserinfoEndpoint, true); wrapOIDC(ErrOIDCProviderMetadata, &err) == nil {
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
	return
}
