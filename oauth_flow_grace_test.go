package jawsauth

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		jw := newTestJaws(t)
		srv := &Server{Jaws: jw, oauth2cfg: &oauth2.Config{
			ClientID: "test", RedirectURL: "https://app.example/auth/callback",
			Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/auth", TokenURL: "https://provider.example/token"},
		}}
		start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
		response := httptest.NewRecorder()
		srv.HandleLogin(response, start)
		if response.Code != http.StatusFound {
			t.Fatalf("start: %d", response.Code)
		}
		cookies := response.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies: %d", len(cookies))
		}
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback", nil)
		callback.AddCookie(cookies[0])
		unrelated := httptest.NewRequest(http.MethodGet, "https://app.example/other", nil)
		unrelated.RemoteAddr = "192.0.2.2:1234"
		if jw.NewSession(httptest.NewRecorder(), unrelated) == nil {
			t.Fatal("unrelated session missing")
		}
		time.Sleep(time.Minute + time.Second)
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

func TestOAuthInPlaceLoginKeepsSessionForReturnRedirectNearGraceDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		srv := newProfileTestServer(t, jw, nil)
		srv.RotateSessionOnLogin = false
		srv.LoginEvent = func(*jaws.Session, *http.Request) {
			time.Sleep(45 * time.Second)
		}
		srv.httpClient.Timeout = oauth2ProviderTimeout
		transport := srv.httpClient.Transport
		srv.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/token" {
				time.Sleep(oauth2ProviderTimeout - time.Second)
			}
			return transport.RoundTrip(r)
		})

		cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
		request := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
		request.AddCookie(cookie)
		sess := jw.GetSession(request)
		if sess == nil {
			t.Fatal("pending session missing")
		}
		time.Sleep(oauth2FlowLifetime - time.Second)
		response := profileCallback(srv, cookie, state, "first")
		if response.Code != http.StatusFound || len(response.Result().Cookies()) != 0 {
			t.Fatalf("near-deadline callback: status=%d cookies=%v body=%q", response.Code, response.Result().Cookies(), response.Body.String())
		}

		// Provider exchange ends three seconds before pending grace; LoginEvent uses 45 seconds of the renewed grace.
		time.Sleep(time.Minute - time.Second)
		if got := jw.GetSession(request); got != sess {
			t.Fatalf("session expired before return redirect: got %p, want %p", got, sess)
		}
		location := response.Header().Get("Location")
		if location == "" {
			t.Fatal("return redirect missing")
		}
		redirect := httptest.NewRequest(http.MethodGet, "https://app.example"+location, nil)
		redirect.AddCookie(cookie)
		if page := jw.NewRequest(httptest.NewRecorder(), redirect); page.Session() != sess {
			t.Fatal("return redirect did not attach to authenticated session")
		}
		claims, ok := sess.Get(srv.SessionKey).(map[string]any)
		if !ok || claims["sub"] != "9007199254740993" {
			t.Fatalf("return redirect lost authentication: %v", claims)
		}
	})
}

func TestPendingLoginProtectedRequestDoesNotRestartOrRenewGrace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		srv := newProfileTestServer(t, jw, nil)
		cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
		protected := httptest.NewRequest(http.MethodGet, "https://app.example/protected", nil)
		protected.AddCookie(cookie)
		time.Sleep(7 * time.Minute)
		response := httptest.NewRecorder()
		srv.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("pending login reached protected handler")
		})).ServeHTTP(response, protected)
		if response.Code != http.StatusFound || response.Header().Get("Location") == "" {
			t.Fatalf("pending login: status=%d location=%q body=%q", response.Code, response.Header().Get("Location"), response.Body.String())
		}
		stored := testOAuthFlow(jw.GetSession(protected), srv)
		if stored.state != state {
			t.Fatalf("pending login replaced state: want %q got %q", state, stored.state)
		}
		time.Sleep(3*time.Minute + oauth2ProviderTimeout + 2*time.Second)
		if jw.GetSession(protected) != nil {
			t.Fatal("protected request renewed pending session grace")
		}
	})
}

func TestPendingLoginProtectedRequestRenewsNearExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		srv := newProfileTestServer(t, jw, nil)
		cookie, oldState := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
		protected := httptest.NewRequest(http.MethodGet, "https://app.example/protected", nil)
		protected.AddCookie(cookie)
		time.Sleep(oauth2FlowLifetime - time.Second)
		response := httptest.NewRecorder()
		srv.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("pending login reached protected handler")
		})).ServeHTTP(response, protected)
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil || response.Code != http.StatusFound {
			t.Fatalf("new login: status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
		}
		newState := location.Query().Get("state")
		if newState == "" || newState == oldState || testOAuthFlow(jw.GetSession(protected), srv).state != newState {
			t.Fatalf("near-expiry flow was reused: old=%q new=%q", oldState, newState)
		}
		// Complete the renewed flow after the original session's grace deadline.
		time.Sleep(oauth2ProviderTimeout + 3*time.Second)
		if result := profileCallback(srv, cookie, newState, "first"); result.Code != http.StatusFound {
			t.Fatalf("renewed login callback: status=%d body=%q", result.Code, result.Body.String())
		}
	})
}

func TestExpiredPendingLoginStartsFreshFlow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		srv := newProfileTestServer(t, jw, nil)
		cookie, oldState := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
		request := httptest.NewRequest(http.MethodGet, "https://app.example/protected", nil)
		request.AddCookie(cookie)
		sess := jw.GetSession(request)
		if sess == nil || jw.NewRequest(httptest.NewRecorder(), request).Session() != sess {
			t.Fatal("pending session not attached to live page")
		}
		time.Sleep(oauth2FlowLifetime + time.Second)
		response := httptest.NewRecorder()
		srv.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("expired pending flow reached protected handler")
		})).ServeHTTP(response, request)
		if response.Code != http.StatusFound || jw.GetSession(request) != sess {
			t.Fatalf("fresh login: status=%d session=%v", response.Code, jw.GetSession(request))
		}
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil || location.Query().Get("state") == "" || location.Query().Get("state") == oldState || testOAuthFlow(sess, srv).state != location.Query().Get("state") {
			t.Fatalf("expired flow was reused: location=%q err=%v", response.Header().Get("Location"), err)
		}
	})
}

func TestOAuthFlowExpiresEvenWithLiveSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		providerCalls := 0
		srv := &Server{Jaws: jw, oauth2cfg: &oauth2.Config{
			ClientID: "test", RedirectURL: "https://app.example/auth/callback",
			Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/auth", TokenURL: "https://provider.example/token"},
		}, httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			providerCalls++
			return nil, errors.New("provider should not be called")
		})}}
		start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
		response := httptest.NewRecorder()
		srv.HandleLogin(response, start)
		if response.Code != http.StatusFound {
			t.Fatalf("start: %d", response.Code)
		}
		cookies := response.Result().Cookies()
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback", nil)
		callback.AddCookie(cookies[0])
		sess := jw.GetSession(callback)
		if sess == nil {
			t.Fatal("session missing")
		}
		state := testOAuthFlow(sess, nil).state
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
		if result.Code != http.StatusBadRequest || !strings.Contains(result.Body.String(), ErrOAuth2ExpiredState.Error()) || sess.Get(srv.sessionKey(oauth2FlowKey)) != nil || providerCalls != 0 {
			t.Fatalf("expired flow: status=%d state=%v provider_calls=%d body=%q", result.Code, sess.Get(srv.sessionKey(oauth2FlowKey)), providerCalls, result.Body.String())
		}
	})
}

func TestOIDCInitialCallbackAfterProviderVisit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
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
		srv.RotateSessionOnLogin = true
		start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
		response := httptest.NewRecorder()
		srv.HandleLogin(response, start)
		if response.Code != http.StatusFound {
			t.Fatalf("start: %d", response.Code)
		}
		cookie := response.Result().Cookies()[0]
		preauth := jw.GetSession(start)
		flow := testOAuthFlow(preauth, nil)
		state, nonce := flow.state, flow.nonce
		idToken = makeIDToken(t, map[string]any{
			"iss": "https://issuer.example", "aud": "app", "sub": "subject-1", "nonce": nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		})
		time.Sleep(time.Minute + time.Second)
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state="+state+"&code=code", nil)
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
		authorized.AddCookie(rotated[0])
		sess := jw.GetSession(authorized)
		if sess == nil || sess.Get(srv.SessionKey).(map[string]any)["sub"] != "subject-1" {
			t.Fatal("delayed OIDC sign-in missing verified subject")
		}
	})
}

func TestOAuthLinkCallbackNearDeadlineCanFinishProviderExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		jw := newTestJaws(t)
		linked := false
		srv := &Server{Jaws: jw, SessionKey: "claims", issuer: "https://provider.example",
			profileSubject: func(map[string]any) (string, error) { return "42", nil },
			userinfoUrl:    "https://provider.example/user",
			oauth2cfg: &oauth2.Config{ClientID: "app", RedirectURL: "https://app.example/auth/callback",
				Endpoint: oauth2.Endpoint{AuthURL: "https://provider.example/auth", TokenURL: "https://provider.example/token"}},
			httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/token" {
					time.Sleep(10 * time.Second)
					return jsonResponse(`{"access_token":"access","token_type":"Bearer"}`), nil
				}
				return jsonResponse(`{"id":42}`), nil
			})},
		}
		start := httptest.NewRequest(http.MethodPost, "https://app.example/auth/link", nil)
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
		if startResult.Code != http.StatusSeeOther {
			t.Fatalf("link start: %d", startResult.Code)
		}
		state := testOAuthFlow(sess, nil).state
		cookie := created.Result().Cookies()[0]
		time.Sleep(oauth2FlowLifetime - time.Second)
		callback := httptest.NewRequest(http.MethodGet, "https://app.example/auth/callback?state="+state+"&code=code", nil)
		callback.AddCookie(cookie)
		result := httptest.NewRecorder()
		srv.HandleAuthResponse(result, callback)
		if result.Code != http.StatusFound || !linked || jw.GetSession(callback) != sess {
			t.Fatalf("near-deadline link: status=%d linked=%t body=%q", result.Code, linked, result.Body.String())
		}
	})
}
