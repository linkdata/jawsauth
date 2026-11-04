package jawsauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func TestOIDCCallbackRejectsEmptySubject(t *testing.T) {
	for _, link := range []bool{false, true} {
		name := "sign-in"
		if link {
			name = "link"
		}
		t.Run(name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			srv := newWrapperTestServer(jw, "https://issuer.example")
			idToken := makeIDToken(t, map[string]any{
				"iss": "https://issuer.example", "aud": "client", "sub": "", "nonce": "nonce",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			srv.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return profileTestResponse(`{"access_token":"access","token_type":"Bearer","id_token":"` + idToken + `"}`), nil
			})}
			logins, links := 0, 0
			srv.LoginEvent = func(*jaws.Session, *http.Request) { logins++ }
			srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
				links++
				return 0, nil
			}
			req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback?state=state&code=code", nil)
			w := httptest.NewRecorder()
			sess := jw.NewSession(w, req)
			setTestOAuthFlow(sess, nil, pendingOAuthFlow{
				state: "state", expiry: time.Now().Add(oauth2FlowLifetime),
				verifier: oauth2.GenerateVerifier(), nonce: "nonce", link: link,
			})
			if link {
				sess.Set(srv.SessionKey, map[string]any{"sub": "existing"})
			}

			srv.HandleAuthResponse(w, req)
			if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ErrOIDCInvalidIDToken.Error()) ||
				jw.GetSession(req) != sess || logins != 0 || links != 0 || len(w.Result().Cookies()) != 1 {
				t.Fatalf("empty subject: status=%d body=%q logins=%d links=%d cookies=%v", w.Code, w.Body.String(), logins, links, w.Result().Cookies())
			}
			if link && sess.Get(srv.SessionKey).(map[string]any)["sub"] != "existing" {
				t.Fatal("link callback changed original authentication")
			}
			if !link && sess.Get(srv.SessionKey) != nil {
				t.Fatal("empty subject authenticated pre-auth session")
			}
			if !link {
				refreshReq := httptest.NewRequest(http.MethodGet, "http://example.com/refresh", nil)
				refreshSess := jw.NewSession(httptest.NewRecorder(), refreshReq)
				err := srv.setSessionAuthFromToken(t.Context(), refreshSess, nil, makeOAuth2Token("access", idToken, ""), time.Time{}, nil)
				if !errors.Is(err, ErrOIDCInvalidIDToken) || refreshSess.Get(srv.SessionKey) != nil {
					t.Fatalf("empty subject refresh: claims=%v err=%v", refreshSess.Get(srv.SessionKey), err)
				}
			}
		})
	}
}

func TestOIDCExpiryDuringUserInfoRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		srv := newWrapperTestServer(jw, "https://issuer.example")
		srv.userinfoUrl = "https://provider.example/userinfo"
		idToken := makeIDToken(t, map[string]any{
			"iss": "https://issuer.example", "aud": "client", "sub": "person", "nonce": "nonce",
			"exp": time.Now().Add(5 * time.Second).Unix(),
		})
		srv.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/userinfo" {
				time.Sleep(6 * time.Second)
				return profileTestResponse(`{"sub":"person","email":"user@example.com"}`), nil
			}
			return profileTestResponse(`{"access_token":"access","token_type":"Bearer","id_token":"` + idToken + `"}`), nil
		})}
		req := httptest.NewRequest(http.MethodGet, "http://example.com/oauth2/callback?state=state&code=code", nil)
		w := httptest.NewRecorder()
		sess := jw.NewSession(w, req)
		setTestOAuthFlow(sess, nil, pendingOAuthFlow{
			state: "state", expiry: time.Now().Add(oauth2FlowLifetime),
			verifier: oauth2.GenerateVerifier(), nonce: "nonce",
		})

		srv.HandleAuthResponse(w, req)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), ErrOIDCInvalidIDToken.Error()) ||
			jw.GetSession(req) != sess || sess.Get(srv.SessionKey) != nil || len(w.Result().Cookies()) != 1 {
			t.Fatalf("expired during UserInfo: status=%d body=%q cookies=%v", w.Code, w.Body.String(), w.Result().Cookies())
		}
		idToken = makeIDToken(t, map[string]any{
			"iss": "https://issuer.example", "aud": "client", "sub": "person", "nonce": "nonce",
			"exp": time.Now().Add(5 * time.Second).Unix(),
		})
		refreshReq := httptest.NewRequest(http.MethodGet, "http://example.com/refresh", nil)
		refreshSess := jw.NewSession(httptest.NewRecorder(), refreshReq)
		refreshToken := makeOAuth2Token("access", idToken, "")
		err = srv.setSessionAuthFromToken(srv.oauth2Context(t.Context()), refreshSess,
			oauth2.StaticTokenSource(refreshToken), refreshToken, time.Time{}, nil)
		if !errors.Is(err, ErrOIDCInvalidIDToken) || refreshSess.Get(srv.SessionKey) != nil {
			t.Fatalf("expired refresh during UserInfo: claims=%v err=%v", refreshSess.Get(srv.SessionKey), err)
		}
	})
}

func TestProfileExpiryDuringSubjectAndFinalStoreRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		srv := &Server{Jaws: jw, userinfoUrl: "https://provider.example/user",
			profileSubject: func(map[string]any) (string, error) {
				time.Sleep(12 * time.Second)
				return "person", nil
			}}
		ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return profileTestResponse(`{"id":42}`), nil
		})})
		token := &oauth2.Token{AccessToken: "access", TokenType: "Bearer", Expiry: time.Now().Add(11 * time.Second)}
		claims, _, _, status, err := srv.verifyOAuthIdentity(ctx, token, "")
		if !errors.Is(err, ErrOAuth2InvalidProfile) || claims != nil || status != http.StatusUnauthorized {
			t.Fatalf("expiry during subject: claims=%v status=%d err=%v", claims, status, err)
		}

		req := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
		sess := jw.NewSession(httptest.NewRecorder(), req)
		srv.SessionKey = "claims"
		srv.SessionTokenKey = "token"
		srv.SessionEmailKey = "email"
		srv.SessionEmailVerifiedKey = "verified"
		canceled := make(chan struct{})
		err = srv.storeSessionAuthClaimsIfActive(sess, map[string]any{"sub": "person"}, nil, time.Now().Add(-time.Second), nil, canceled)
		if !errors.Is(err, ErrOAuth2InvalidProfile) || sess.Get(srv.SessionKey) != nil {
			t.Fatalf("final store of expired profile: claims=%v err=%v", sess.Get(srv.SessionKey), err)
		}
	})
}

func TestOAuthLogoutDuringLoginEventClosesRotatedSession(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	entered := make(chan *jaws.Session, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	srv.LoginEvent = func(sess *jaws.Session, _ *http.Request) {
		entered <- sess
		<-release
	}
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	req := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
	req.AddCookie(cookie)
	preauth := jw.GetSession(req)
	if preauth == nil {
		t.Fatal("missing pre-auth session")
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- profileCallback(srv, cookie, state, "first") }()
	rotated := waitFor(t, entered, "LoginEvent was not reached")
	if rotated == preauth || rotated.Get(srv.SessionKey) == nil {
		t.Fatal("LoginEvent did not receive an authenticated rotated session")
	}
	if !srv.Logout(preauth, nil) {
		t.Fatal("logout failed")
	}
	releaseOnce.Do(func() { close(release) })
	w := waitFor(t, result, "canceled callback did not finish")
	cookies := w.Result().Cookies()
	if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" || len(cookies) != 2 || cookies[1].MaxAge >= 0 ||
		cookies[1].Name != cookies[0].Name || cookies[1].Value != cookies[0].Value ||
		rotated.Cookie().MaxAge >= 0 || rotated.Get(srv.SessionKey) != nil || srv.authTimers[rotated.ID()] != nil {
		t.Fatalf("superseded login: status=%d location=%q cookies=%v claims=%v", w.Code, w.Header().Get("Location"), cookies, rotated.Get(srv.SessionKey))
	}
}
