package jawsauth

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type Config struct {
	RedirectURL  string   // e.g. "https://application.example.com/oauth2/callback"
	AuthURL      string   // e.g. "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/authorize"
	TokenURL     string   // e.g. "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token"
	UserInfoURL  string   // e.g. "https://graph.microsoft.com/v1.0/me?$select=displayName,mail"
	Scopes       []string // e.g. []string{"user.read"}
	ClientID     string
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

func validateUrl(k, u string) (err error) {
	if err = requireStr(k, u); err == nil {
		_, err = url.Parse(u)
	}
	return
}

func (cfg *Config) Validate() (err error) {
	if err = validateUrl("RedirectURL", cfg.RedirectURL); err == nil {
		if err = validateUrl("AuthURL", cfg.AuthURL); err == nil {
			if err = validateUrl("TokenURL", cfg.TokenURL); err == nil {
				if err = validateUrl("UserInfoURL", cfg.UserInfoURL); err == nil {
					if err = requireStr("ClientID", cfg.ClientID); err == nil {
						if err = requireStr("ClientSecret", cfg.ClientSecret); err == nil {
							err = requireLen("Scopes", len(cfg.Scopes))
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

// Build creates a oauth2.Config. If overrideUrl is provided, it's scheme, host
// and port are used instead of the ones in RedirectURL. This is useful when testing.
func (cfg *Config) Build(overrideUrl string) (oauth2cfg *oauth2.Config, err error) {
	if err = cfg.Validate(); err == nil {
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
					AuthURL:  cfg.AuthURL,
					TokenURL: cfg.TokenURL,
				},
				RedirectURL: redir.String(),
				Scopes:      cfg.Scopes,
			}
		}
	}
	return
}
