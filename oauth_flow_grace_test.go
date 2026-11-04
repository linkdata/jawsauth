package jawsauth

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func TestOAuthProviderVisitKeepsOnlyPendingSessionAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		srv := &Server{Jaws: jw, oauth2cfg: &oauth2.Config{
			ClientID: "test", RedirectURL: "https://app.example/auth/callback",
			Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/auth", TokenURL: "https://provider.example/token"},
		}}
		start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
		start.RemoteAddr = "192.0.2.1:1234"
		response := httptest.NewRecorder()
		srv.HandleLogin(response, start)
		if response.Code != http.StatusFound {
			t.Fatalf("start: %d", response.Code)
		}
		cookies := response.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies: %d", len(cookies))
		}
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state=wrong&code=unused", nil)
		callback.RemoteAddr = start.RemoteAddr
		callback.AddCookie(cookies[0])
		unrelated := httptest.NewRequest(http.MethodGet, "https://app.example/other", nil)
		unrelated.RemoteAddr = "192.0.2.2:1234"
		if jw.NewSession(httptest.NewRecorder(), unrelated) == nil {
			t.Fatal("unrelated session missing")
		}
		time.Sleep(61 * time.Second)
		if jw.GetSession(callback) == nil {
			t.Fatal("pending preauth session expired during provider visit")
		}
		if jw.GetSession(unrelated) != nil {
			t.Fatal("unrelated idle session gained OAuth grace")
		}
		time.Sleep(oauth2FlowLifetime)
		if jw.GetSession(callback) != nil {
			t.Fatal("pending preauth session survived its bounded grace")
		}
	})
}

func TestOAuthFlowExpiresEvenWithLiveSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		providerCalls := 0
		srv := &Server{Jaws: jw, oauth2cfg: &oauth2.Config{
			ClientID: "test", RedirectURL: "https://app.example/auth/callback",
			Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/auth", TokenURL: "https://provider.example/token"},
		}, httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			providerCalls++
			return nil, errors.New("provider should not be called")
		})}}
		start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
		start.RemoteAddr = "192.0.2.1:1234"
		response := httptest.NewRecorder()
		srv.HandleLogin(response, start)
		if response.Code != http.StatusFound {
			t.Fatalf("start: %d", response.Code)
		}
		cookies := response.Result().Cookies()
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state=wrong&code=unused", nil)
		callback.RemoteAddr = start.RemoteAddr
		callback.AddCookie(cookies[0])
		sess := jw.GetSession(callback)
		if sess == nil {
			t.Fatal("session missing")
		}
		state, _ := sess.Get(oauth2StateKey).(string)
		callback.URL.RawQuery = "state=" + state + "&code=unused"
		page := jw.NewRequest(httptest.NewRecorder(), callback)
		if page.Session() != sess {
			t.Fatal("page did not attach")
		}
		time.Sleep(oauth2FlowLifetime + time.Second)
		if jw.GetSession(callback) == nil {
			t.Fatal("live page should hold session")
		}
		result := httptest.NewRecorder()
		srv.HandleAuthResponse(result, callback)
		if result.Code != http.StatusBadRequest || !strings.Contains(result.Body.String(), ErrOAuth2ExpiredState.Error()) || sess.Get(oauth2StateKey) != nil || providerCalls != 0 {
			t.Fatalf("expired flow: status=%d state=%v provider_calls=%d body=%q", result.Code, sess.Get(oauth2StateKey), providerCalls, result.Body.String())
		}
	})
}

func TestOIDCInitialCallbackAfterProviderVisit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		var idToken string
		exchanges := 0
		srv := &Server{Jaws: jw,
			SessionKey: "claims", SessionTokenKey: "token", SessionEmailKey: "email", SessionEmailVerifiedKey: "email_verified",
			oauth2cfg: &oauth2.Config{ClientID: "app", RedirectURL: "https://app.example/auth/callback",
				Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
			idTokenVerifier: oidc.NewVerifier("https://issuer.example", passthroughKeySet{}, &oidc.Config{ClientID: "app"}),
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				exchanges++
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
					Body: io.NopCloser(strings.NewReader(`{"access_token":"access","token_type":"Bearer","id_token":"` + idToken + `"}`))}, nil
			})},
		}
		start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
		start.RemoteAddr = "192.0.2.1:1234"
		response := httptest.NewRecorder()
		srv.HandleLogin(response, start)
		if response.Code != http.StatusFound {
			t.Fatalf("start: %d", response.Code)
		}
		cookie := response.Result().Cookies()[0]
		preauth := jw.GetSession(start)
		state, _ := preauth.Get(oauth2StateKey).(string)
		nonce, _ := preauth.Get(oauth2NonceKey).(string)
		idToken = makeIDToken(t, map[string]any{
			"iss": "https://issuer.example", "aud": "app", "sub": "subject-1", "nonce": nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})
		time.Sleep(61 * time.Second)
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state="+state+"&code=code", nil)
		callback.RemoteAddr = start.RemoteAddr
		callback.AddCookie(cookie)
		result := httptest.NewRecorder()
		srv.HandleAuthResponse(result, callback)
		if result.Code != http.StatusFound || exchanges != 1 || jw.GetSession(callback) == preauth {
			t.Fatalf("delayed OIDC callback: status=%d exchanges=%d body=%q", result.Code, exchanges, result.Body.String())
		}
		rotated := result.Result().Cookies()
		if len(rotated) != 1 {
			t.Fatalf("rotated cookies: %d", len(rotated))
		}
		authorized := httptest.NewRequest(http.MethodGet, "https://app.example/", nil)
		authorized.RemoteAddr = start.RemoteAddr
		authorized.AddCookie(rotated[0])
		sess := jw.GetSession(authorized)
		if sess == nil || sess.Get(srv.SessionKey).(map[string]any)["sub"] != "subject-1" {
			t.Fatal("delayed OIDC sign-in missing verified subject")
		}
	})
}

func TestOAuthLinkCallbackNearDeadlineCanFinishProviderExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw, err := jaws.New()
		if err != nil {
			t.Fatal(err)
		}
		defer jw.Close()
		linked := false
		srv := &Server{Jaws: jw, SessionKey: "claims", issuer: "https://provider.example",
			profileSubject: func(map[string]any) (string, error) { return "42", nil },
			userinfoUrl:    "https://provider.example/user",
			oauth2cfg: &oauth2.Config{ClientID: "app", RedirectURL: "https://app.example/auth/callback",
				Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/auth", TokenURL: "https://provider.example/token"}},
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/token" {
					time.Sleep(10 * time.Second)
					return profileTestResponse(`{"access_token":"access","token_type":"Bearer"}`), nil
				}
				return profileTestResponse(`{"id":42}`), nil
			})},
		}
		start := httptest.NewRequest(http.MethodPost, "https://app.example/auth/link", nil)
		start.RemoteAddr = "192.0.2.1:1234"
		created := httptest.NewRecorder()
		sess := jw.NewSession(created, start)
		if sess == nil {
			t.Fatal("original session missing")
		}
		sess.Set(srv.SessionKey, map[string]any{"sub": "original"})
		srv.LinkEvent = func(current *jaws.Session, _ *http.Request, claims map[string]any) (int, error) {
			if current != sess || current.Get(srv.SessionKey).(map[string]any)["sub"] != "original" || claims["sub"] != "42" {
				return http.StatusForbidden, ErrOAuth2LinkRejected
			}
			linked = true
			return 0, nil
		}
		startResult := httptest.NewRecorder()
		srv.HandleLink(startResult, start)
		if startResult.Code != http.StatusFound {
			t.Fatalf("link start: %d", startResult.Code)
		}
		state, _ := sess.Get(oauth2StateKey).(string)
		cookie := created.Result().Cookies()[0]
		time.Sleep(oauth2FlowLifetime - time.Second)
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state="+state+"&code=code", nil)
		callback.RemoteAddr = start.RemoteAddr
		callback.AddCookie(cookie)
		result := httptest.NewRecorder()
		srv.HandleAuthResponse(result, callback)
		if result.Code != http.StatusFound || !linked || jw.GetSession(callback) != sess {
			t.Fatalf("near-deadline link: status=%d linked=%t body=%q", result.Code, linked, result.Body.String())
		}
	})
}
