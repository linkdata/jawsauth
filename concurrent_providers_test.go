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
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			return profileTestResponse(`{"access_token":"proof","token_type":"Bearer"}`), nil
		}
		return profileTestResponse(`{"id":42}`), nil
	})}
	gate := &gateRotationLock{both: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	defer release()
	mk := func(ns string) *Server {
		srv, err := New(jw, &Config{Namespace: ns, RedirectURL: "https://app.example/auth/" + ns + "/callback", Issuer: "https://provider.example", AuthURL: "https://provider.example/authorize", TokenURL: "https://provider.example/token", UserInfoURL: "https://provider.example/user", ClientID: "app", HTTPClient: client, ProfileSubject: func(m map[string]any) (string, error) { return string(m["id"].(json.Number)), nil }}, func(string, http.Handler) {})
		if err != nil {
			t.Fatal(err)
		}
		srv.SessionRotationLock = gate
		return srv
	}
	a, b := mk("a"), mk("b")
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
	callback := func(srv *Server, ns, state string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "https://app.example/auth/"+ns+"/callback?state="+url.QueryEscape(state)+"&code=proof", nil)
		req.RemoteAddr = "192.0.2.1:1234"
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
