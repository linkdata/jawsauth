package jawsauth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/linkdata/jaws"
	"github.com/linkdata/jaws/lib/what"
	"github.com/linkdata/jaws/lib/wire"
)

func TestLogoutReloadsOtherTabs(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	go jw.Serve()
	defer jw.Close()
	hs := httptest.NewServer(jw)
	defer hs.Close()
	srv := newTimerTestServer(t, jw, "https://issuer.example", &testAuthTimerFactory{})
	srv.SetAdmins([]string{"admin@example.com"})
	hr := httptest.NewRequest(http.MethodGet, hs.URL+"/", nil)
	hr.RemoteAddr = "127.0.0.1:1"
	sess := jw.NewSession(httptest.NewRecorder(), hr)
	if err = srv.storeSessionAuthClaims(sess, map[string]any{"email": "admin@example.com"}, nil, time.Now().Add(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var conns []*websocket.Conn
	for _, admin := range []bool{false, true} {
		var rq *jaws.Request
		ready := make(chan struct{})
		srv.wrap(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
			rq = jw.NewRequest(hw, hr)
			rq.SetConnectFn(func(*jaws.Request) error { close(ready); return nil })
		}), admin).ServeHTTP(httptest.NewRecorder(), hr.Clone(ctx))
		if rq == nil {
			t.Fatal("protected page did not render")
		}
		conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(hs.URL, "http")+"/jaws/"+rq.JawsKeyString(),
			&websocket.DialOptions{HTTPHeader: http.Header{"Origin": {hs.URL}}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.CloseNow() }()
		conns = append(conns, conn)
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	srv.Logout(sess, hr)
	for tab, conn := range conns {
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("tab %d disconnected without reloading: %v", tab, err)
		}
		reload := false
		for record := range bytes.Lines(data) {
			if msg, ok := wire.Parse(record); ok && msg.What == what.Reload {
				reload = true
			}
		}
		if !reload {
			t.Fatalf("tab %d received %q, want Reload", tab, data)
		}
	}
}
