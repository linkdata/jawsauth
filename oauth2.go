package jawsauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

var ErrInconsistentState = errors.New("oauth2 inconsistent state")

const oauth2ReferrerKey = "oauth2referrer"
const oauth2StateKey = "oauth2state"

func (srv *Server) begin(hr *http.Request) (oauth2cfg *oauth2.Config, userinfourl, location string) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	oauth2cfg = srv.oauth2cfg
	userinfourl = srv.cfg.UserInfoURL
	location = strings.TrimSuffix(strings.TrimSpace(hr.Referer()), srv.redirectPath)
	if location == "" {
		location = "/"
	}
	return
}

func (srv *Server) HandleLogin(hw http.ResponseWriter, hr *http.Request) {
	oauth2cfg, _, location := srv.begin(hr)
	if oauth2cfg != nil {
		if sess := srv.Jaws.GetSession(hr); sess != nil {
			b := make([]byte, 4)
			n, _ := rand.Read(b)
			state := fmt.Sprintf("%x%#p", b[:n], srv)
			sess.Set(oauth2StateKey, state)
			sess.Set(oauth2ReferrerKey, location)
			location = oauth2cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
		}
	}
	hw.Header().Add("Location", location)
	hw.WriteHeader(http.StatusFound)
}

func (srv *Server) HandleLogout(hw http.ResponseWriter, hr *http.Request) {
	_, _, location := srv.begin(hr)
	if sess := srv.Jaws.GetSession(hr); sess != nil {
		sess.Set(srv.SessionKey, nil)
		srv.Jaws.Dirty(sess)
	}
	hw.Header().Add("Location", location)
	hw.WriteHeader(http.StatusFound)
}

func requireCorrectState(gotState, wantState string) error {
	if wantState == "" || wantState != gotState {
		return fmt.Errorf("oauth2: got session state %q, wanted %q", gotState, wantState)
	}
	return nil
}

func (srv *Server) HandleAuthResponse(hw http.ResponseWriter, hr *http.Request) {
	oauth2Config, userinfourl, location := srv.begin(hr)

	err := ErrInconsistentState
	sess := srv.Jaws.GetSession(hr)

	defer func() {
		if err != nil {
			if srv.Log(err) != ErrInconsistentState {
				sess.Set(srv.SessionKey, nil)
				srv.Jaws.Dirty(sess)
			}
			hw.WriteHeader(http.StatusBadRequest)
		}
	}()

	if oauth2Config != nil && sess != nil {
		gotState := hr.FormValue("state")
		wantState, _ := sess.Get(oauth2StateKey).(string)
		sess.Set(oauth2StateKey, nil)

		if err = requireCorrectState(gotState, wantState); err == nil {
			var token *oauth2.Token
			if token, err = oauth2Config.Exchange(context.Background(), hr.FormValue("code")); err == nil {
				client := oauth2Config.Client(context.Background(), token)
				var resp *http.Response
				if resp, err = client.Get(userinfourl); err == nil {
					if resp.StatusCode == http.StatusOK {
						var b []byte
						if b, err = io.ReadAll(resp.Body); err == nil {
							var userinfo any
							if err = json.Unmarshal(b, &userinfo); err == nil {
								sess.Set(srv.SessionKey, userinfo)
								if s, ok := sess.Get(oauth2ReferrerKey).(string); ok {
									location = s
								}
								sess.Set(oauth2ReferrerKey, nil)
								if l := srv.Jaws.Logger; l != nil {
									if b2, e := json.Marshal(userinfo); e == nil {
										b = b2
									}
									l.Info("oauth2 login", "session", sess.CookieValue(), srv.SessionKey, string(b))
								}
								srv.Jaws.Dirty(sess)

								hw.Header().Add("Location", location)
								hw.WriteHeader(http.StatusFound)
								return
							}
						}
					}
				}
			}
		}
	}
}
