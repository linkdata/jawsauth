package jawsauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

var ErrInconsistentState = errors.New("oauth2 inconsistent state")

const oauth2ReferrerKey = "oauth2referrer"
const oauth2StateKey = "oauth2state"

func normalizeHost(hostport string) (normalized string) {
	normalized = strings.TrimSpace(hostport)
	if normalized != "" {
		normalized = strings.TrimSuffix(normalized, ".")
		normalized = strings.ToLower(normalized)
		if strings.Contains(normalized, ":") {
			if h, _, err := net.SplitHostPort(normalized); err == nil {
				normalized = h
			}
		}
	}
	return
}

func sanitizeRedirectTarget(requestHost, location string) (sanitized string) {
	if trimmed := strings.TrimSpace(location); trimmed != "" {
		if u, err := url.Parse(trimmed); err == nil {
			if u.IsAbs() {
				if host := normalizeHost(requestHost); host != "" {
					if normalizeHost(u.Host) == host {
						sanitized = u.RequestURI()
					}
				}
			} else {
				sanitized = trimmed
			}
		}
	}
	sanitized = strings.TrimSpace(sanitized)
	if sanitized != "" {
		if !strings.HasPrefix(sanitized, "/") {
			sanitized = "/" + sanitized
		}
		for strings.HasPrefix(sanitized, "//") {
			sanitized = "/" + strings.TrimLeft(sanitized, "/")
		}
	}
	if sanitized == "" {
		sanitized = "/"
	}
	return
}

func (srv *Server) begin(hr *http.Request) (oauth2cfg *oauth2.Config, userinfourl, location string) {
	oauth2cfg = srv.oauth2cfg
	userinfourl = srv.userinfoUrl
	if location = strings.TrimSpace(hr.Referer()); location == "" {
		location = hr.RequestURI
	}
	location = sanitizeRedirectTarget(hr.Host, location)
	for s := range srv.HandledPaths {
		if strings.HasSuffix(location, s) {
			location = strings.TrimSuffix(location, s)
			break
		}
	}
	if location == "" {
		location = "/"
	}
	return
}

func (srv *Server) HandleLogin(hw http.ResponseWriter, hr *http.Request) {
	oauth2cfg, _, location := srv.begin(hr)
	if oauth2cfg != nil {
		if sess := srv.Jaws.GetSession(hr); sess != nil {
			b := make([]byte, 32)
			var n int
			var err error
			if n, err = rand.Read(b); srv.Jaws.Log(err) == nil {
				state := hex.EncodeToString(b[:n])
				sess.Set(oauth2StateKey, state)
				sess.Set(oauth2ReferrerKey, location)
				location = oauth2cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
			}
		}
	}
	hw.Header().Add("Location", location)
	hw.WriteHeader(http.StatusFound)
}

func (srv *Server) HandleLogout(hw http.ResponseWriter, hr *http.Request) {
	_, _, location := srv.begin(hr)
	if sess := srv.Jaws.GetSession(hr); sess != nil {
		if srv.LogoutEvent != nil {
			srv.LogoutEvent(sess, hr)
		}
		sess.Set(srv.SessionKey, nil)
		sess.Set(srv.SessionTokenKey, nil)
		sess.Set(srv.SessionEmailKey, nil)
		srv.Jaws.Dirty(sess)
	}
	hw.Header().Add("Location", location)
	hw.WriteHeader(http.StatusFound)
}

func writeBody(w io.Writer, statusCode int, err error, body []byte) {
	const tmpl = `<html><body><h2>%03d %s</h2><p>%s</p></body></html>`
	if body == nil {
		if err != nil {
			body = []byte(fmt.Sprintf(tmpl, statusCode, http.StatusText(statusCode), html.EscapeString(err.Error())))
		}
	}
	_, _ = w.Write(body)
}

func writeResult(hw http.ResponseWriter, statusCode int, err error, body []byte) {
	hw.WriteHeader(statusCode)
	writeBody(hw, statusCode, err, body)
}

var ErrOAuth2NotConfigured = errors.New("oauth2 not configured")
var ErrOAuth2MissingSession = errors.New("oauth2 missing session")
var ErrOAuth2WrongState = errors.New("oauth2 wrong state")

func (srv *Server) HandleAuthResponse(hw http.ResponseWriter, hr *http.Request) {
	oauth2Config, userinfourl, location := srv.begin(hr)

	var body []byte
	var sessValue any
	var sessEmailValue any
	var sessTokenValue any
	sess := srv.Jaws.GetSession(hr)
	err := ErrOAuth2NotConfigured
	statusCode := http.StatusInternalServerError

	if oauth2Config != nil {
		err = ErrOAuth2MissingSession
		statusCode = http.StatusBadRequest
		if sess != nil {
			gotState := hr.FormValue("state")
			wantState, _ := sess.Get(oauth2StateKey).(string)
			sess.Set(oauth2StateKey, nil)
			err = ErrOAuth2WrongState
			if wantState != "" && wantState == gotState {
				var token *oauth2.Token
				if token, err = oauth2Config.Exchange(hr.Context(), hr.FormValue("code"), oauth2.AccessTypeOffline); srv.Jaws.Log(err) == nil {
					tokensource := oauth2Config.TokenSource(context.Background(), token)
					client := oauth2.NewClient(hr.Context(), tokensource)
					var resp *http.Response
					if resp, err = client.Get(userinfourl); srv.Jaws.Log(err) == nil {
						defer resp.Body.Close()
						if body, err = io.ReadAll(io.LimitReader(resp.Body, 32768)); srv.Jaws.Log(err) == nil {
							if statusCode = resp.StatusCode; statusCode == http.StatusOK {
								var userinfo map[string]any
								if err = json.Unmarshal(body, &userinfo); srv.Jaws.Log(err) == nil {
									body = nil
									sessValue = userinfo
									sessTokenValue = tokensource
									for _, k := range []string{"email", "mail"} {
										if s, ok := userinfo[k].(string); ok {
											if m, e := mail.ParseAddress(s); e == nil {
												s = m.Address
											}
											sessEmailValue = strings.ToLower(strings.TrimSpace(s))
											break
										}
									}
									if s, ok := sess.Get(oauth2ReferrerKey).(string); ok {
										location = sanitizeRedirectTarget(hr.Host, s)
									}
									sess.Set(oauth2ReferrerKey, nil)
									hw.Header().Add("Location", location)
									statusCode = http.StatusFound
								}
							}
						}
					}
				}
			}
		}
	}
	if sess != nil {
		sess.Set(srv.SessionKey, sessValue)
		sess.Set(srv.SessionTokenKey, sessTokenValue)
		sess.Set(srv.SessionEmailKey, sessEmailValue)
		if srv.LoginEvent != nil && sessValue != nil {
			srv.LoginEvent(sess, hr)
		}
		srv.Jaws.Dirty(sess)
	}
	writeResult(hw, statusCode, err, body)
}
