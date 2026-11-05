package jawsauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/linkdata/jaws"
)

func newConcurrentProfileProvider(t *testing.T, jw *jaws.Jaws, client *http.Client, namespace string) *Server {
	t.Helper()
	srv, err := New(jw, &Config{
		Namespace: namespace, RedirectURL: "https://app.example/auth/" + namespace + "/callback",
		Issuer: "https://" + namespace + ".provider.example", AuthURL: "https://provider.example/authorize",
		TokenURL: "https://provider.example/token", UserInfoURL: "https://provider.example/user",
		ClientID: "app", HTTPClient: client,
		ProfileSubject: func(profile map[string]any) (string, error) { return string(profile["id"].(json.Number)), nil },
	}, func(string, http.Handler) {})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

type gateRotationLock struct {
	mu       sync.Mutex
	entrants atomic.Int32
	both     chan struct{}
	release  chan struct{}
}

func (l *gateRotationLock) Lock() {
	if l.entrants.Add(1) == 2 {
		close(l.both)
	}
	<-l.release
	l.mu.Lock()
}
func (l *gateRotationLock) Unlock() { l.mu.Unlock() }

func TestConcurrentProviderCallbacksRotateOriginalSessionOnce(t *testing.T) {
	jw := newTestJaws(t)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			return jsonResponse(`{"access_token":"proof","token_type":"Bearer"}`), nil
		}
		return jsonResponse(`{"id":42}`), nil
	})}
	gate := &gateRotationLock{both: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	defer release()
	a := newConcurrentProfileProvider(t, jw, client, "a")
	b := newConcurrentProfileProvider(t, jw, client, "b")
	cookie, stateA := profileStart(t, a, http.MethodGet, "/auth/a/login", nil)
	startB := httptest.NewRequest(http.MethodGet, "https://app.example/auth/b/login", nil)
	startB.AddCookie(cookie)
	wB := httptest.NewRecorder()
	b.HandleLogin(wB, startB)
	if wB.Code != http.StatusFound {
		t.Fatalf("second start %d", wB.Code)
	}
	locB, err := url.Parse(wB.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	stateB := locB.Query().Get("state")
	a.SessionRotationLock, b.SessionRotationLock = gate, gate
	callback := func(srv *Server, ns, state string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "https://app.example/auth/"+ns+"/callback?state="+url.QueryEscape(state)+"&code=proof", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.HandleAuthResponse(w, req)
		return w
	}
	out := make(chan *httptest.ResponseRecorder, 2)
	go func() { out <- callback(a, "a", stateA) }()
	go func() { out <- callback(b, "b", stateB) }()
	waitFor(t, gate.both, "provider callbacks did not reach rotation")
	release()
	responses := make([]*httptest.ResponseRecorder, 0, 2)
	for range 2 {
		responses = append(responses, waitFor(t, out, "provider callback did not finish"))
	}
	success, rejected := 0, 0
	for _, response := range responses {
		switch response.Code {
		case http.StatusFound:
			success++
			if len(response.Result().Cookies()) != 1 {
				t.Fatalf("successful callback cookies=%v", response.Result().Cookies())
			}
		case http.StatusForbidden:
			rejected++
			if len(response.Result().Cookies()) != 0 {
				t.Fatalf("stale callback published cookie=%v", response.Result().Cookies())
			}
		default:
			t.Fatalf("callback status=%d", response.Code)
		}
	}
	if success != 1 || rejected != 1 || jw.SessionCount() != 1 {
		t.Fatalf("callbacks: success=%d rejected=%d sessions=%d", success, rejected, jw.SessionCount())
	}
}

// holdFirstRotationLock lets a later caller acquire the lock before the first.
type holdFirstRotationLock struct {
	mu           sync.Mutex
	attempts     atomic.Int32
	first        chan struct{}
	releaseFirst chan struct{}
}

func (l *holdFirstRotationLock) Lock() {
	if l.attempts.Add(1) == 1 {
		close(l.first)
		<-l.releaseFirst
	}
	l.mu.Lock()
}

func (l *holdFirstRotationLock) Unlock() { l.mu.Unlock() }

func TestLinkedProviderLogoutBeforeLinkWrite(t *testing.T) {
	for _, logoutProvider := range []string{"linked", "original"} {
		t.Run(logoutProvider, func(t *testing.T) {
			jw := newTestJaws(t)
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/token" {
					return jsonResponse(`{"access_token":"proof","token_type":"Bearer"}`), nil
				}
				return jsonResponse(`{"id":42}`), nil
			})}
			a := newConcurrentProfileProvider(t, jw, client, "a")
			b := newConcurrentProfileProvider(t, jw, client, "b")
			cookie, state := profileStart(t, a, http.MethodGet, "/auth/a/login", nil)
			login := profileCallback(a, cookie, state, "proof")
			if login.Code != http.StatusFound || len(login.Result().Cookies()) != 1 {
				t.Fatalf("initial login: status=%d cookies=%v", login.Code, login.Result().Cookies())
			}
			cookie = login.Result().Cookies()[0]
			req := httptest.NewRequest(http.MethodGet, "https://app.example/account", nil)
			req.AddCookie(cookie)
			sess := jw.GetSession(req)
			if a.CurrentClaims(sess) == nil {
				t.Fatal("missing first provider authentication")
			}
			lock := &holdFirstRotationLock{first: make(chan struct{}), releaseFirst: make(chan struct{})}
			var writes atomic.Int32
			b.LinkEvent = func(current *jaws.Session, _ *http.Request, _ map[string]any) (int, error) {
				if a.CurrentClaims(current) == nil {
					return http.StatusForbidden, ErrOAuth2MissingSession
				}
				writes.Add(1)
				return 0, nil
			}
			_, linkState := profileStart(t, b, http.MethodPost, "/auth/b/link", cookie)
			a.SessionRotationLock, b.SessionRotationLock = lock, lock
			callbackDone := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				callbackRequest := httptest.NewRequest(http.MethodGet, "https://app.example/auth/b/callback?state="+url.QueryEscape(linkState)+"&code=proof", nil)
				callbackRequest.AddCookie(cookie)
				callback := httptest.NewRecorder()
				b.HandleAuthResponse(callback, callbackRequest)
				callbackDone <- callback
			}()
			release := sync.OnceFunc(func() { close(lock.releaseFirst) })
			defer release()
			waitFor(t, lock.first, "link callback did not reach shared lock")
			b.mu.Lock()
			flow := b.oauthCallbacks[sess]
			b.mu.Unlock()
			if flow.canceled == nil || flow.revoked() {
				t.Fatal("link callback was not active before logout")
			}
			logoutServer := b
			if logoutProvider == "original" {
				logoutServer = a
			}
			logout := httptest.NewRecorder()
			logoutServer.HandleLogout(logout, req)
			if logout.Code != http.StatusFound || flow.revoked() != (logoutProvider == "linked") || (a.CurrentClaims(sess) != nil) != (logoutProvider == "linked") {
				t.Fatalf("%s provider logout: status=%d revoked=%t original_valid=%t", logoutProvider, logout.Code, flow.revoked(), a.CurrentClaims(sess) != nil)
			}
			release()
			callback := waitFor(t, callbackDone, "revoked link callback did not finish")
			if callback.Code != http.StatusForbidden || writes.Load() != 0 || len(callback.Result().Cookies()) != 0 {
				t.Fatalf("revoked link: status=%d writes=%d cookies=%v", callback.Code, writes.Load(), callback.Result().Cookies())
			}
		})
	}
}
