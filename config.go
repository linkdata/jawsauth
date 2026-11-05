package jawsauth

//gosec:disable G117

import (
	"cmp"
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
// RedirectURL, Issuer and ClientID are required. Setting ProfileSubject selects
// profile mode and requires AuthURL, TokenURL and UserInfoURL. Otherwise OIDC
// mode discovers endpoints; URL fields may override them.
type Config struct {
	RedirectURL string // required. e.g. "https://application.example.com/oauth2/callback"
	Issuer      string // required. e.g. "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"
	// Namespace isolates providers sharing one JaWS instance. New appends it to
	// the four exported Server session-key fields; use a distinct value per provider.
	Namespace   string
	AuthURL     string // OIDC override; required in profile mode
	TokenURL    string // OIDC override; required in profile mode
	UserInfoURL string // OIDC override; required in profile mode
	// AllowInsecureIssuer permits HTTP issuer and provider endpoints and is only for tests/dev.
	AllowInsecureIssuer bool
	// HTTPClient is used for OIDC discovery and JWKS, and by default for token
	// exchange/refresh and UserInfo. All provider requests cap its timeout at 15
	// seconds. Discovery/JWKS follow only HTTPS redirects unless AllowInsecureIssuer
	// is set; token and UserInfo requests follow none. A request context may supply
	// a different oauth2.HTTPClient for code exchange and UserInfo requests;
	// background refresh uses this configured client.
	HTTPClient   *http.Client
	Scopes       []string // optional; OIDC adds "openid" and "email"; profile mode adds none
	ClientID     string
	ClientSecret string
	// ProfileSubject enables OAuth2 profile authentication without an OIDC ID token.
	// AuthURL, TokenURL and UserInfoURL are required in this mode. It must return
	// a stable, non-empty provider subject from the authenticated profile response.
	// Profile mode sets claims["iss"] to Issuer and claims["sub"] to this subject;
	// use a distinct Issuer per provider.
	// JSON numbers arrive as json.Number to preserve large numeric IDs.
	// Profile emails can be unverified. For a non-empty admin list, set
	// Server.RequireVerifiedAdminEmail unless the provider guarantees verified
	// addresses; ProfileSubject may map a provider signal to claims["email_verified"].
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

func validateUrl(k, value string, optional bool) (*url.URL, error) {
	if optional && value == "" {
		return nil, nil
	}
	if err := requireStr(k, value); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, errConfig{field: k, cause: err}
	}
	if !parsed.IsAbs() {
		return nil, errConfig{field: k, cause: ErrConfigURLNotAbsolute}
	}
	if parsed.Hostname() == "" {
		return nil, errConfig{field: k, cause: ErrConfigURLMissingHost}
	}
	return parsed, nil
}

func validateEndpoint(field, value string, optional, allowInsecure bool) error {
	parsed, err := validateUrl(field, value, optional)
	if err != nil || parsed == nil {
		return err
	}
	if parsed.Scheme != "https" && (!allowInsecure || parsed.Scheme != "http") {
		return errConfig{field: field, cause: ErrConfigEndpointMustBeHTTPS}
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
func (cfg *Config) Validate() error {
	if _, err := validateUrl("RedirectURL", cfg.RedirectURL, false); err != nil {
		return err
	}
	issuer, err := validateUrl("Issuer", cfg.Issuer, false)
	if err != nil {
		return err
	}
	if issuer.Scheme != "https" && (!cfg.AllowInsecureIssuer || issuer.Scheme != "http") {
		return errConfig{field: "Issuer", cause: ErrConfigIssuerMustBeHTTPS}
	}
	for _, field := range []struct{ name, value string }{
		{"AuthURL", cfg.AuthURL}, {"TokenURL", cfg.TokenURL}, {"UserInfoURL", cfg.UserInfoURL},
	} {
		if err := validateEndpoint(field.name, field.value, cfg.ProfileSubject == nil, cfg.AllowInsecureIssuer); err != nil {
			return err
		}
	}
	return requireStr("ClientID", cfg.ClientID)
}

func overrideStr(a *string, b string) {
	if b != "" {
		*a = b
	}
}

func ensureScopes(rawScopes []string, required ...string) (scopes []string) {
	scopes = append(scopes, required...)
	for _, set := range rawScopes {
		for scope := range strings.FieldsSeq(set) {
			scopes = append(scopes, scope)
		}
	}
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	return
}

func boundedProviderClient(client *http.Client) (bounded http.Client) {
	if client == nil {
		client = http.DefaultClient
	}
	bounded = *client
	if bounded.Timeout <= 0 || bounded.Timeout > oauth2ProviderTimeout {
		bounded.Timeout = oauth2ProviderTimeout
	}
	return
}

func (cfg *Config) buildContext(ctx context.Context, overrideUrl string) (oauth2cfg *oauth2.Config, userInfoURL string, verifier *oidc.IDTokenVerifier, err error) {
	if err = cfg.Validate(); err == nil {
		redir, _ := url.Parse(cfg.RedirectURL)
		if u, parseErr := url.Parse(overrideUrl); parseErr == nil {
			overrideStr(&redir.Scheme, u.Scheme)
			overrideStr(&redir.Host, u.Host)
		}
		if cfg.ProfileSubject != nil {
			scopes := ensureScopes(cfg.Scopes)
			oauth2cfg = &oauth2.Config{
				ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
				Endpoint:    oauth2.Endpoint{AuthURL: cfg.AuthURL, TokenURL: cfg.TokenURL},
				RedirectURL: redir.String(), Scopes: scopes,
			}
			return oauth2cfg, cfg.UserInfoURL, nil, nil
		}
		clientCopy := boundedProviderClient(cfg.HTTPClient)
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
				authURL := cmp.Or(cfg.AuthURL, metadata.AuthorizationEndpoint)
				tokenURL := cmp.Or(cfg.TokenURL, metadata.TokenEndpoint)
				userInfoURL = cmp.Or(cfg.UserInfoURL, metadata.UserinfoEndpoint)
				for _, field := range []struct {
					name, value string
					optional    bool
				}{
					{"AuthURL", authURL, false},
					{"TokenURL", tokenURL, false},
					{"UserInfoURL", userInfoURL, true},
					{"JWKSURI", metadata.JWKSURI, false},
				} {
					if err = validateEndpoint(field.name, field.value, field.optional, cfg.AllowInsecureIssuer); wrapOIDC(ErrOIDCProviderMetadata, &err) != nil {
						return
					}
				}
				oauth2cfg = &oauth2.Config{
					ClientID:     cfg.ClientID,
					ClientSecret: cfg.ClientSecret,
					Endpoint: oauth2.Endpoint{
						AuthURL:  authURL,
						TokenURL: tokenURL,
					},
					RedirectURL: redir.String(),
					Scopes:      ensureScopes(cfg.Scopes, "openid", "email"),
				}
				verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
			}
		}
	}
	return
}
