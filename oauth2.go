package jawsauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

var ErrInconsistentState = errors.New("oauth2 inconsistent state")

const oauth2ReferrerKey = "oauth2referrer"
const oauth2StateKey = "oauth2state"

func (srv *Server) begin(hr *http.Request) (oauth2cfg *oauth2.Config, userinfourl, location string) {
	oauth2cfg = srv.oauth2cfg
	userinfourl = srv.userinfoUrl
	location = strings.TrimSpace(hr.Referer())
	for s := range srv.HandledPaths {
		location = strings.TrimSuffix(location, s)
	}
	if location == "" {
		location = "/"
	}
	return
}

func (srv *Server) HandleLogin(hw http.ResponseWriter, hr *http.Request) {
	oauth2cfg, _, location := srv.begin(hr)
	if sess := srv.Jaws.GetSession(hr); sess != nil {
		b := make([]byte, 4)
		n, _ := rand.Read(b)
		state := fmt.Sprintf("%x%#p", b[:n], srv)
		sess.Set(oauth2StateKey, state)
		sess.Set(oauth2ReferrerKey, location)
		location = oauth2cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
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
		srv.Jaws.Dirty(sess)
	}
	hw.Header().Add("Location", location)
	hw.WriteHeader(http.StatusFound)
}

func errtext(statusCode int, err error) (s string) {
	if err != nil {
		s = fmt.Sprintf(`<html><body><h2>%03d %s</h2><p>%s</p></body></html>`,
			statusCode, http.StatusText(statusCode), html.EscapeString(err.Error()),
		)
	}
	return
}

func writeResult(hw http.ResponseWriter, statusCode int, err error) {
	hw.WriteHeader(statusCode)
	_, _ = hw.Write([]byte(errtext(statusCode, err)))
}

var ErrOAuth2NotConfigured = errors.New("oauth2 not configured")
var ErrOAuth2MissingSession = errors.New("oauth2 missing session")
var ErrOAuth2WrongState = errors.New("oauth2 wrong state")

func (srv *Server) HandleAuthResponse(hw http.ResponseWriter, hr *http.Request) {
	oauth2Config, userinfourl, location := srv.begin(hr)

	var sessValue any
	var sessEmailValue any
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
				if token, err = oauth2Config.Exchange(context.Background(), hr.FormValue("code"), oauth2.AccessTypeOffline); srv.Jaws.Log(err) == nil {
					client := oauth2Config.Client(context.Background(), token)
					var resp *http.Response
					if resp, err = client.Get(userinfourl); srv.Jaws.Log(err) == nil {
						if statusCode = resp.StatusCode; statusCode == http.StatusOK {
							var b []byte
							if b, err = io.ReadAll(resp.Body); srv.Jaws.Log(err) == nil {
								var userinfo map[string]any
								if err = json.Unmarshal(b, &userinfo); srv.Jaws.Log(err) == nil {
									sessValue = userinfo
									for _, k := range []string{"email", "mail"} {
										if s, ok := userinfo[k].(string); ok {
											sessEmailValue = s
											break
										}
									}
									if s, ok := sess.Get(oauth2ReferrerKey).(string); ok {
										location = s
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
	sess.Set(srv.SessionKey, sessValue)
	sess.Set(srv.SessionEmailKey, sessEmailValue)
	if srv.LoginEvent != nil && sessValue != nil {
		srv.LoginEvent(sess, hr)
	}
	srv.Jaws.Dirty(sess)
	writeResult(hw, statusCode, err)
}
