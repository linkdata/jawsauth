package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/linkdata/jaws"
)

func TestProtectedRequestPreservesPendingLoginOnAuthExpiry(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	srv := newProfileTestServer(t, jw, nil)
	cookie, initialState := profileStart(t, srv, http.MethodGet, "/auth/login", nil)
	first := profileCallback(srv, cookie, initialState, "first")
	if first.Code != http.StatusFound {
		t.Fatalf("initial sign-in %d", first.Code)
	}
	cookie = first.Result().Cookies()[0]
	start := httptest.NewRequest(http.MethodGet, "https://app.example/auth/login", nil)
	start.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.HandleLogin(w, start)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	pendingState := loc.Query().Get("state")
	sess := jw.GetSession(start)
	if sess == nil || pendingState == "" {
		t.Fatal("missing pending flow")
	}
	sess.Set(srv.sessionKey(oauth2AuthExpiryKey), time.Now().Add(-time.Second))
	protected := httptest.NewRequest(http.MethodGet, "https://app.example/protected", nil)
	protected.AddCookie(cookie)
	response := httptest.NewRecorder()
	srv.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("expired auth reached protected handler") })).ServeHTTP(response, protected)
	redirect, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusFound || len(response.Result().Cookies()) != 0 ||
		redirect.Query().Get("state") != pendingState {
		t.Fatalf("protected request during login: status=%d location=%q body=%q cookies=%v", response.Code, response.Header().Get("Location"), response.Body.String(), response.Result().Cookies())
	}
	gotState := testOAuthFlow(sess, srv).state
	if gotState != pendingState {
		t.Fatalf("protected request replaced pending login state: want %q got %q", pendingState, gotState)
	}
	completed := profileCallback(srv, cookie, pendingState, "second")
	if completed.Code != http.StatusFound || len(completed.Result().Cookies()) != 1 {
		t.Fatalf("pending login callback: status=%d cookies=%v", completed.Code, completed.Result().Cookies())
	}
}
