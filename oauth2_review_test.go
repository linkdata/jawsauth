package jawsauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func TestLinkWithoutEventDoesNotStartFlow(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	srv.LinkEvent = nil
	r := httptest.NewRequest(http.MethodPost, "https://app.example/auth/link/github", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	if jw.NewSession(httptest.NewRecorder(), r) == nil {
		t.Fatal("missing session")
	}
	w := httptest.NewRecorder()
	srv.HandleLink(w, r)
	if w.Code != http.StatusInternalServerError || w.Header().Get("Location") != "" ||
		!strings.Contains(w.Body.String(), ErrOAuth2NotConfigured.Error()) || calls != 0 {
		t.Fatalf("missing LinkEvent: status=%d location=%q body=%q calls=%d", w.Code, w.Header().Get("Location"), w.Body.String(), calls)
	}
}

func TestLinkRejectsInvalidEventResults(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		err    error
	}{
		{"error without status", 0, errors.New("secret persistence detail")},
		{"success status without acceptance", http.StatusOK, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jw, err := jaws.New()
			if err != nil {
				t.Fatal(err)
			}
			defer jw.Close()
			calls := 0
			srv := newProfileTestServer(t, jw, &calls)
			cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
			first := profileCallback(srv, cookie, state, "first")
			if first.Code != http.StatusFound {
				t.Fatalf("sign-in: %d", first.Code)
			}
			cookie = first.Result().Cookies()[0]
			srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) {
				return tc.status, tc.err
			}
			_, state = profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
			w := profileCallback(srv, cookie, state, "second")
			if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" ||
				len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), ErrOAuth2LinkRejected.Error()) ||
				strings.Contains(w.Body.String(), "secret persistence detail") {
				t.Fatalf("invalid LinkEvent result: status=%d location=%q body=%q cookies=%v", w.Code, w.Header().Get("Location"), w.Body.String(), w.Result().Cookies())
			}
		})
	}
}

func TestUserInfoRejectsTrailingJSON(t *testing.T) {
	for _, profile := range []bool{false, true} {
		t.Run(map[bool]string{false: "OIDC", true: "profile"}[profile], func(t *testing.T) {
			srv := &Server{}
			if profile {
				srv.profileSubject = func(map[string]any) (string, error) { return "42", nil }
			}
			ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return profileTestResponse(`{"id":42} {"id":43}`), nil
			})})
			claims, err := srv.fetchUserInfo(ctx, "https://provider.example/user", oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "proof"}))
			if !errors.Is(err, ErrUserInfoInvalidResponse) || claims != nil {
				t.Fatalf("trailing JSON accepted: claims=%v err=%v", claims, err)
			}
		})
	}
}

func TestLinkWithoutRefererReturnsHome(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, cookie, state, "first")
	if first.Code != http.StatusFound {
		t.Fatalf("sign-in: %d", first.Code)
	}
	cookie = first.Result().Cookies()[0]
	srv.LinkEvent = func(*jaws.Session, *http.Request, map[string]any) (int, error) { return 0, nil }
	_, state = profileStart(t, srv, http.MethodPost, "/auth/link/github", cookie)
	w := profileCallback(srv, cookie, state, "second")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" || len(w.Result().Cookies()) != 0 {
		t.Fatalf("link return: status=%d location=%q cookies=%v", w.Code, w.Header().Get("Location"), w.Result().Cookies())
	}
}

func TestProfileUserInfoNullDoesNotCallSubject(t *testing.T) {
	called := false
	srv := &Server{
		userinfoUrl: "https://provider.example/user",
		profileSubject: func(map[string]any) (string, error) {
			called = true
			return "42", nil
		},
	}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return profileTestResponse(`null`), nil
	})})
	claims, source, expiry, status, err := srv.verifyOAuthIdentity(ctx, &oauth2.Token{AccessToken: "proof", TokenType: "Bearer"}, "")
	if !errors.Is(err, ErrOAuth2InvalidProfile) || claims != nil || source != nil || !expiry.IsZero() || status != http.StatusUnauthorized || called {
		t.Fatalf("null profile: claims=%v source=%t expiry=%v status=%d err=%v subject_called=%t", claims, source != nil, expiry, status, err, called)
	}
}

func TestCallbackClosesRotatedSessionOnStoreFailure(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, cookie, state, "first")
	if first.Code != http.StatusFound {
		t.Fatalf("sign-in: %d", first.Code)
	}
	cookie = first.Result().Cookies()[0]
	state = startProfileLoginWithCookie(t, srv, cookie)
	closedRotated := false
	srv.LogoutEvent = func(old *jaws.Session, r *http.Request) {
		if rotated := jw.GetSession(r); rotated != nil && rotated != old {
			rotated.Close()
			closedRotated = true
		}
	}
	w := profileCallback(srv, cookie, state, "second")
	cookies := w.Result().Cookies()
	if !closedRotated || w.Code != http.StatusForbidden || w.Header().Get("Location") != "" ||
		len(cookies) != 2 || cookies[1].MaxAge >= 0 || cookies[1].Value != cookies[0].Value {
		t.Fatalf("store after close: closed=%t status=%d location=%q cookies=%v", closedRotated, w.Code, w.Header().Get("Location"), cookies)
	}
}

func startProfileLoginWithCookie(t *testing.T, srv *Server, cookie *http.Cookie) string {
	t.Helper()
	start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
	start.RemoteAddr = "192.0.2.1:1234"
	start.AddCookie(cookie)
	begin := httptest.NewRecorder()
	srv.HandleLogin(begin, start)
	if begin.Code != http.StatusFound {
		t.Fatalf("second start: %d", begin.Code)
	}
	providerURL, err := url.Parse(begin.Header().Get("Location"))
	if err != nil || providerURL.Query().Get("state") == "" {
		t.Fatalf("second provider redirect: %v %q", err, begin.Header().Get("Location"))
	}
	return providerURL.Query().Get("state")
}

type revokeAfterRotationLock struct {
	sync.Mutex
	logout func()
}

func (lock *revokeAfterRotationLock) Unlock() {
	lock.Mutex.Unlock()
	if lock.logout != nil {
		logout := lock.logout
		lock.logout = nil
		logout()
	}
}

func TestCallbackRevokedAfterRotationClosesNewSession(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	calls := 0
	srv := newProfileTestServer(t, jw, &calls)
	cookie, state := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, cookie, state, "first")
	if first.Code != http.StatusFound {
		t.Fatalf("sign-in: %d", first.Code)
	}
	cookie = first.Result().Cookies()[0]
	oldRequest := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
	oldRequest.RemoteAddr = "192.0.2.1:1234"
	oldRequest.AddCookie(cookie)
	old := jw.GetSession(oldRequest)
	if old == nil {
		t.Fatal("old session missing")
	}
	state = startProfileLoginWithCookie(t, srv, cookie)
	revoked := false
	srv.SessionRotationLock = &revokeAfterRotationLock{logout: func() {
		revoked = srv.Logout(old, nil)
	}}
	w := profileCallback(srv, cookie, state, "second")
	cookies := w.Result().Cookies()
	if !revoked || w.Code != http.StatusForbidden || w.Header().Get("Location") != "" ||
		len(cookies) != 2 || cookies[1].MaxAge >= 0 || cookies[1].Value != cookies[0].Value {
		t.Fatalf("revoked after rotation: revoked=%t status=%d location=%q cookies=%v", revoked, w.Code, w.Header().Get("Location"), cookies)
	}
}
