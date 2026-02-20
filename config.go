package jawsauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type Config struct {
	RedirectURL string   // e.g. "https://application.example.com/oauth2/callback"
	AuthURL     string   // e.g. "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/authorize"
	TokenURL    string   // e.g. "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token"
	UserInfoURL string   // e.g. "https://graph.microsoft.com/v1.0/me?$select=displayName,mail"
	Scopes      []string // e.g. []string{"user.read"}
	ClientID    string
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

func validateUrl(k, u string) (err error) {
	if err = requireStr(k, u); err == nil {
		var parsed *url.URL
		if parsed, err = url.Parse(u); err == nil {
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
