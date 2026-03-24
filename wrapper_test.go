package jawsauth

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/linkdata/jaws"
)

type testStatusHandler struct {
	statusCode int
}

func (h testStatusHandler) ServeHTTP(hw http.ResponseWriter, _ *http.Request) {
	hw.WriteHeader(h.statusCode)
}

// Run with -race; this used to report a data race between Set403Handler and ServeHTTP.
func TestWrapperServeHTTPSet403HandlerConcurrent(t *testing.T) {
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	defer jw.Close()

	srv := &Server{
		Jaws:            jw,
		SessionKey:      "oauth2userinfo",
		SessionEmailKey: "email",
		HandledPaths:    map[string]struct{}{},
		admins:          map[string]struct{}{"admin@example.com": {}},
		handle403:       testStatusHandler{statusCode: http.StatusForbidden},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	sess := jw.NewSession(httptest.NewRecorder(), req)
	sess.Set(srv.SessionKey, map[string]any{"ok": true})
	sess.Set(srv.SessionEmailKey, "user@example.com")

	w := wrapper{
		server:  srv,
		handler: testStatusHandler{statusCode: http.StatusOK},
		admin:   true,
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 2000 {
			srv.Set403Handler(testStatusHandler{statusCode: http.StatusForbidden})
			srv.Set403Handler(testStatusHandler{statusCode: http.StatusUnauthorized})
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			w.ServeHTTP(httptest.NewRecorder(), req)
		}
	}()
	wg.Wait()

	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if code := rec.Result().StatusCode; code != http.StatusForbidden && code != http.StatusUnauthorized {
		t.Fatal(code)
	}
}
